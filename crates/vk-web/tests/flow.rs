//! The passkey ceremony end to end, over real loopback listeners, with
//! `webauthn-rs`'s software authenticator standing in for Windows Hello:
//! enrol, then approve a task and watch the scheduler's `Approve` step
//! complete; what the record then lets an auditor re-verify; and every way
//! the ceremony must *not* record anything.
use base64::Engine;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::{ApprovalKind, HumanKey, Principal, SoftwareHumanKey};
use vk_contracts::syscalls::{Ctx, Kernel};
use vk_contracts::testing::KernelTestHooks;
use vk_kernel::tasks::{StepKind, TaskStatus};
use vk_kernel::{now_ms, RealKernel};
use vk_web::{Links, Shared};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

/// A kernel behind the pages on an ephemeral loopback port, both families.
struct Node {
    kernel: Shared,
    links: Arc<Links>,
    port: u16,
    base: String,
    http: reqwest::Client,
    dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(Mutex::new(
        RealKernel::open(
            dir.path(),
            vk_store::keys::KeySource::File(dir.path().join("m.key")),
            "n1",
        )
        .unwrap(),
    ));
    let listeners = vk_web::bind(0).await.unwrap();
    assert!(listeners.has_v6(), "both loopback families are held");
    let port = listeners.port();
    let web = vk_web::build(kernel.clone(), "n1", port).unwrap();
    let server = tokio::spawn(vk_web::serve(listeners, web.router));
    Node {
        kernel,
        links: web.links,
        port,
        base: vk_web::passkey::origin(port),
        http: reqwest::Client::new(),
        dir,
        server,
    }
}

fn ctx() -> Ctx {
    Ctx {
        principal: Principal::Machine {
            node_id: "n1".into(),
            lease_id: "test".into(),
        },
        clearance: Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        },
        partition: "local".into(),
        now_ms: now_ms(),
    }
}

/// A mock arch's manifest, as the kernel's own tests build one.
fn mock_manifest(name: &str) -> vk_contracts::arch::ArchManifest {
    use vk_contracts::arch::*;
    ArchManifest {
        name: name.into(),
        capabilities: [Capability::Generate, Capability::Plan].into(),
        locality: Locality::Local,
        jurisdiction: "FR".into(),
        retention_days: None,
        cost_per_1k_tokens_eur: 0.0,
        latency_ms_p50: 1,
        context_ceiling: 4096,
        determinism: Determinism::SeededDeterministic,
        identity: ArchIdentity {
            weights_sha256: format!("sha256:mock-{name}"),
            engine: "mock".into(),
            engine_version: "1".into(),
            backend: "cpu".into(),
            quant: "-".into(),
            kv_cache: "-".into(),
            threads: 1,
            batch: 1,
            sampling: Default::default(),
            seed: Some(1),
        },
        clearance: Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        },
        governed: true,
    }
}

/// A task drafted through a mock arch and waiting at its approve step; its
/// id and the subject an approval of it must name. `tail` is what follows
/// the approve step.
fn waiting_task_with(kernel: &Shared, name: &str, tail: Vec<StepKind>) -> (String, String) {
    let mut k = kernel.lock().unwrap();
    let arch = k.register_arch(mock_manifest(name));
    let mut steps = vec![StepKind::Draft { arch_id: arch }, StepKind::Approve];
    steps.extend(tail);
    let id = k
        .create_task(
            &ctx(),
            "Draft a proposal for Acme",
            "proposal",
            Label::bottom(),
            steps,
        )
        .unwrap()
        .id;
    k.run_task_step(&ctx(), &id).unwrap();
    assert_eq!(
        k.run_task_step(&ctx(), &id).unwrap().status,
        TaskStatus::WaitingHuman
    );
    let subject = k.approval_subject(&ctx(), &id).unwrap();
    (id, subject)
}

fn waiting_task(kernel: &Shared) -> (String, String) {
    waiting_task_with(kernel, "mock", vec![])
}

fn token_of(url: &str) -> String {
    url.rsplit("?t=").next().unwrap().to_string()
}

fn from_b64url(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .unwrap()
}

/// One raw HTTP/1.1 request on `addr`, with exactly the headers given: what
/// a client that does not resolve `localhost`, or names another host, sends.
/// On the blocking pool: the server under test runs on this test's own
/// runtime, which a blocking read on the runtime thread would stall.
async fn raw_request(addr: String, request_line: &str, headers: &[&str]) -> (u16, String) {
    let mut req = format!("{request_line}\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&addr).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {text:?}"));
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    })
    .await
    .unwrap()
}

impl Node {
    async fn get(&self, path_and_query: &str) -> (u16, String) {
        self.get_at(&self.base, path_and_query).await
    }

    async fn get_at(&self, origin: &str, path_and_query: &str) -> (u16, String) {
        let r = self
            .http
            .get(format!("{origin}{path_and_query}"))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, v)
    }

    /// Enrol `authenticator`'s passkey through the pages, as the browser
    /// would: link, page, start, `navigator.credentials.create`, finish.
    async fn enroll(&self, authenticator: &mut WebauthnAuthenticator<SoftPasskey>) -> String {
        let link = self.links.enroll_link(now_ms());
        let t = token_of(&link);
        let (status, html) = self.get(&format!("/enroll?t={t}")).await;
        assert_eq!(status, 200, "{html}");
        assert!(html.contains("Enrol") && html.contains("/vk.js"), "{html}");
        let (status, started) = self.post("/enroll/start", json!({ "t": t })).await;
        assert_eq!(status, 200, "{started}");
        let options: CreationChallengeResponse =
            serde_json::from_value(started["options"].clone()).unwrap();
        let credential = authenticator
            .do_registration(Url::parse(&self.base).unwrap(), options)
            .unwrap();
        let (status, done) = self
            .post(
                "/enroll/finish",
                json!({ "t": t, "state_id": started["state_id"], "credential": credential }),
            )
            .await;
        assert_eq!(status, 200, "{done}");
        assert_eq!(done["ok"], true);
        let device_id = done["device_id"].as_str().unwrap().to_string();
        assert!(device_id.starts_with("passkey:"), "{device_id}");
        device_id
    }
}

fn events_of_kind(kernel: &Shared, kind: &str) -> usize {
    kernel
        .lock()
        .unwrap()
        .ledger()
        .events()
        .iter()
        .filter(|e| e.kind == kind)
        .count()
}

fn task_status(kernel: &Shared, id: &str) -> TaskStatus {
    kernel.lock().unwrap().task(&ctx(), id).unwrap().status
}

/// The whole ceremony: a passkey is enrolled through the pages and then
/// approves a waiting task — the kernel holds one human approval for the
/// task's artefact hash, naming the passkey, the minted challenge and the
/// assertion's signature, with `proof: webauthn` on the ledger — and the
/// scheduler's `Approve` step completes on it. The nonce the kernel minted is
/// the challenge the authenticator signed, and the record holds what it
/// signed, so the recorded signature verifies again with the enrolled public
/// key. A second finish with the same assertion, or with the same state,
/// records nothing.
#[tokio::test]
async fn a_passkey_enrols_through_the_pages_and_approves_a_waiting_task() {
    let n = node().await;
    let mut hello = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let device_id = n.enroll(&mut hello).await;
    {
        let k = n.kernel.lock().unwrap();
        let rows = k.passkeys().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, device_id);
        assert_eq!(k.device_ids(), vec![device_id.clone()]);
        assert!(
            k.devices().ids().is_empty(),
            "a passkey is not an ed25519 key"
        );
    }
    assert_eq!(events_of_kind(&n.kernel, "device.enrolled"), 1);

    let (task, subject) = waiting_task(&n.kernel);
    let link = n.links.approve_link(&task, now_ms());
    let t = token_of(&link);
    let (status, html) = n.get(&format!("/approve/{task}?t={t}")).await;
    assert_eq!(status, 200, "{html}");
    assert!(
        html.contains("Draft a proposal for Acme") && html.contains(&subject),
        "the page shows the goal and the hash: {html}"
    );
    let (status, started) = n
        .post(&format!("/approve/{task}/start"), json!({ "t": t }))
        .await;
    assert_eq!(status, 200, "{started}");
    // The page is told what it approves and until when — and nothing else
    // of the minted challenge (review Minor 1).
    assert_eq!(started["subject_hash"], subject);
    assert!(started["expires_at_ms"].as_u64().unwrap() > now_ms());
    assert!(started.get("challenge").is_none(), "{started}");
    let options: RequestChallengeResponse =
        serde_json::from_value(started["options"].clone()).unwrap();
    // The WebAuthn challenge the browser is handed **is** the nonce the
    // kernel minted for the task (review Important 1).
    let minted = {
        let pending = n.kernel.lock().unwrap().pending_approvals(now_ms());
        assert_eq!(pending.len(), 1, "the kernel minted it");
        assert_eq!(pending[0].task_id, task);
        pending[0].challenge.clone()
    };
    assert_eq!(minted.resource, format!("task:{task}"));
    assert_eq!(minted.action_digest, subject);
    assert_eq!(
        from_b64url(&minted.nonce),
        options.public_key.challenge.as_ref().to_vec(),
        "the minted nonce is the WebAuthn challenge"
    );
    let assertion = hello
        .do_authentication(Url::parse(&n.base).unwrap(), options)
        .unwrap();
    let signature_hex = hex::encode(assertion.response.signature.as_ref());
    let (status, done) = n
        .post(
            &format!("/approve/{task}/finish"),
            json!({ "t": t, "state_id": started["state_id"], "credential": assertion }),
        )
        .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["ok"], true);
    assert_eq!(done["device_id"], device_id);
    assert_eq!(done["subject_hash"], subject);
    assert_eq!(done["stepped"], true);
    assert_eq!(done["status"], "done", "the waiting step completed: {done}");

    {
        let k = n.kernel.lock().unwrap();
        let approvals = k.approvals_for(&subject);
        assert_eq!(approvals.len(), 1);
        let a = &approvals[0];
        assert_eq!(a.kind, ApprovalKind::Human);
        assert_eq!(
            a.approver,
            Principal::Human {
                device_id: device_id.clone()
            }
        );
        assert_eq!(a.challenge.as_ref(), Some(&minted));
        assert_eq!(a.signature_hex.as_deref(), Some(signature_hex.as_str()));
        assert!(k.pending_approvals(now_ms()).is_empty(), "spent");
        assert_eq!(k.task(&ctx(), &task).unwrap().status, TaskStatus::Done);

        // The recorded nonce is the challenge inside the signed client data.
        let client_data: Value =
            serde_json::from_slice(assertion.response.client_data_json.as_ref()).unwrap();
        assert_eq!(
            from_b64url(client_data["challenge"].as_str().unwrap()),
            from_b64url(&a.challenge.as_ref().unwrap().nonce)
        );
        // The origin the authenticator saw, as `Url` spells it (a trailing
        // slash on an empty path), is the pages' origin.
        assert_eq!(
            client_data["origin"]
                .as_str()
                .unwrap()
                .trim_end_matches('/'),
            n.base
        );

        // What the authenticator signed is on the record beside the approval,
        // and the recorded signature verifies with the enrolled public key —
        // from the store alone, as an auditor would (review Important 1).
        let rec = k
            .assertion_for(a)
            .unwrap()
            .expect("the assertion is recorded");
        assert_eq!(
            rec.credential_id,
            device_id.strip_prefix("passkey:").unwrap()
        );
        assert_eq!(
            from_b64url(&rec.authenticator_data),
            assertion.response.authenticator_data.as_ref().to_vec()
        );
        assert_eq!(
            from_b64url(&rec.client_data_json),
            assertion.response.client_data_json.as_ref().to_vec()
        );
        let (_, stored) = vk_web::passkey::load(k.passkeys().unwrap())
            .into_iter()
            .find(|(d, _)| *d == device_id)
            .unwrap();
        let mut signed = from_b64url(&rec.authenticator_data);
        signed.extend_from_slice(&openssl::sha::sha256(&from_b64url(&rec.client_data_json)));
        let sig = hex::decode(a.signature_hex.as_ref().unwrap()).unwrap();
        assert!(
            stored
                .get_public_key()
                .verify_signature(&sig, &signed)
                .unwrap(),
            "the recorded signature re-verifies"
        );
        let mut tampered = signed.clone();
        tampered[0] ^= 1;
        assert!(
            !stored
                .get_public_key()
                .verify_signature(&sig, &tampered)
                .unwrap(),
            "a flipped bit must not verify"
        );
    }
    assert_eq!(events_of_kind(&n.kernel, "approval.recorded"), 1);

    // Replayed: the same state and the same assertion, refused — the link
    // was spent by the ceremony. Nothing new on the record.
    let (status, again) = n
        .post(
            &format!("/approve/{task}/finish"),
            json!({ "t": t, "state_id": started["state_id"], "credential": assertion }),
        )
        .await;
    assert_eq!(status, 404, "the link was spent by the ceremony: {again}");
    assert_eq!(events_of_kind(&n.kernel, "approval.recorded"), 1);
}

/// An assertion for a different challenge or state is rejected and nothing
/// is recorded; a replayed assertion is rejected; the state, once answered,
/// is gone — and the task still waits until a genuine assertion arrives.
#[tokio::test]
async fn an_assertion_for_another_challenge_or_state_records_nothing() {
    let n = node().await;
    let mut hello = WebauthnAuthenticator::new(SoftPasskey::new(true));
    n.enroll(&mut hello).await;
    let (task, subject) = waiting_task(&n.kernel);
    let t = token_of(&n.links.approve_link(&task, now_ms()));
    let start_path = format!("/approve/{task}/start");
    let finish_path = format!("/approve/{task}/finish");
    let start = || n.post(&start_path, json!({ "t": t }));
    let finish = |state_id: Value, credential: Value| {
        n.post(
            &finish_path,
            json!({ "t": t, "state_id": state_id, "credential": credential }),
        )
    };
    let recorded = || events_of_kind(&n.kernel, "approval.recorded");

    let (_, a) = start().await;
    let (_, b) = start().await;
    let options_a: RequestChallengeResponse = serde_json::from_value(a["options"].clone()).unwrap();
    let origin = Url::parse(&n.base).unwrap();
    let assertion_a = hello.do_authentication(origin.clone(), options_a).unwrap();

    // A's assertion under B's state: the verifier's challenge check fails.
    let (status, err) = finish(b["state_id"].clone(), json!(assertion_a)).await;
    assert_eq!(status, 403, "{err}");
    assert!(err["error"].as_str().unwrap().contains("rejected"), "{err}");
    assert_eq!(recorded(), 0);
    assert_eq!(task_status(&n.kernel, &task), TaskStatus::WaitingHuman);
    assert!(
        n.kernel.lock().unwrap().approvals_for(&subject).is_empty(),
        "nothing recorded"
    );

    // B's state was taken by that attempt: it cannot be answered any more.
    let options_b: RequestChallengeResponse = serde_json::from_value(b["options"].clone()).unwrap();
    let assertion_b = hello.do_authentication(origin.clone(), options_b).unwrap();
    let (status, err) = finish(b["state_id"].clone(), json!(assertion_b)).await;
    assert_eq!(status, 400, "{err}");
    assert!(
        err["error"].as_str().unwrap().contains("already used"),
        "{err}"
    );
    assert_eq!(recorded(), 0);

    // An unknown state, and an assertion nobody made (a garbage signature
    // over A's real state): refused.
    let (status, err) = finish(json!("no-such-state"), json!(assertion_a)).await;
    assert_eq!(status, 400, "{err}");
    let mut forged = serde_json::to_value(&assertion_a).unwrap();
    forged["response"]["signature"] = json!("AAAA");
    let (_, c) = start().await;
    let (status, err) = finish(c["state_id"].clone(), forged).await;
    assert_eq!(status, 403, "{err}");
    assert_eq!(recorded(), 0);
    assert_eq!(task_status(&n.kernel, &task), TaskStatus::WaitingHuman);

    // A's own assertion under A's own state: the genuine answer, accepted.
    let (status, done) = finish(a["state_id"].clone(), json!(assertion_a)).await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(recorded(), 1);
    assert_eq!(task_status(&n.kernel, &task), TaskStatus::Done);
    // And replayed under any later start it is refused: the link is spent.
    let (status, err) = start().await;
    assert_eq!(status, 404, "{err}");
}

/// Review Minor 2: `finish` records the approval, and runs a step only if the
/// task is still waiting at its approve step for that very subject. A task
/// that moved on between `start` and `finish` — approved with the node key
/// and stepped — is not pushed into its next step by the page.
#[tokio::test]
async fn finish_records_but_never_steps_a_task_that_has_moved_on() {
    let n = node().await;
    let mut hello = WebauthnAuthenticator::new(SoftPasskey::new(true));
    n.enroll(&mut hello).await;
    let (task, subject) = waiting_task_with(
        &n.kernel,
        "mock",
        vec![StepKind::Release {
            to_dir: "out".into(),
        }],
    );
    let t = token_of(&n.links.approve_link(&task, now_ms()));
    let (status, started) = n
        .post(&format!("/approve/{task}/start"), json!({ "t": t }))
        .await;
    assert_eq!(status, 200, "{started}");
    let options: RequestChallengeResponse =
        serde_json::from_value(started["options"].clone()).unwrap();
    let assertion = hello
        .do_authentication(Url::parse(&n.base).unwrap(), options)
        .unwrap();

    // Meanwhile the node key approves and the shell steps: the approve step
    // is done and the release step is next.
    {
        let mut k = n.kernel.lock().unwrap();
        let laptop = SoftwareHumanKey::generate("laptop");
        k.enroll_device("laptop", laptop.verifying_key_bytes());
        let minted = k.mint_approval_challenge(&ctx(), &task).unwrap();
        let human = Ctx {
            principal: Principal::Human {
                device_id: "laptop".into(),
            },
            ..ctx()
        };
        let approval = vk_contracts::principal::Approval {
            subject_hash: subject.clone(),
            kind: ApprovalKind::Human,
            approver: Principal::Human {
                device_id: "laptop".into(),
            },
            signature_hex: Some(hex::encode(laptop.sign(&minted.digest()))),
            challenge: Some(minted),
        };
        k.approve(&human, approval).unwrap();
        let stepped = k.run_task_step(&ctx(), &task).unwrap();
        assert_eq!(stepped.status, TaskStatus::Running, "{stepped:?}");
    }
    let released = || events_of_kind(&n.kernel, "artefact.released");
    assert_eq!(released(), 0);

    // The passkey's finish: the approval is recorded — it is a genuine
    // human approval of that subject — but the release step is not run.
    let (status, done) = n
        .post(
            &format!("/approve/{task}/finish"),
            json!({ "t": t, "state_id": started["state_id"], "credential": assertion }),
        )
        .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["stepped"], false, "{done}");
    assert_eq!(done["status"], "running", "{done}");
    assert_eq!(released(), 0, "the page must not run the release step");
    assert!(
        !n.dir.path().join("exports").join("out").exists(),
        "nothing was released"
    );
    assert_eq!(task_status(&n.kernel, &task), TaskStatus::Running);
    assert_eq!(n.kernel.lock().unwrap().approvals_for(&subject).len(), 2);
}

/// Review Critical 1: the pages hold **both** loopback addresses — a browser
/// asked for `localhost` may connect to either — and refuse to start when
/// either is already taken, so no rogue local listener can sit on the family
/// the daemon left free and receive the link.
#[tokio::test]
async fn both_loopback_families_answer_and_a_taken_family_refuses_the_start() {
    let n = node().await;
    let (status, v4) = n.get_at(&format!("http://127.0.0.1:{}", n.port), "/").await;
    assert_eq!(status, 200);
    let (status, v6) = n.get_at(&format!("http://[::1]:{}", n.port), "/").await;
    assert_eq!(status, 200);
    assert_eq!(v4, v6);
    assert!(v4.contains("vk passkey enroll"), "{v4}");
    let (status, _) = n.get("/").await;
    assert_eq!(
        status, 200,
        "and by name, whichever family the resolver picks"
    );

    // A port held on IPv6 only: the start is refused, naming the address —
    // never served on IPv4 alone.
    let rogue_v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
    let p = rogue_v6.local_addr().unwrap().port();
    let err = match vk_web::bind(p).await {
        Ok(_) => panic!("[::1]:{p} is taken; the bind must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains(&format!("[::1]:{p}")) && err.contains("taken"),
        "{err}"
    );
    drop(rogue_v6);

    // A port held on IPv4 only: refused too.
    let rogue_v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = rogue_v4.local_addr().unwrap().port();
    let err = match vk_web::bind(p).await {
        Ok(_) => panic!("127.0.0.1:{p} is taken; the bind must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains(&format!("127.0.0.1:{p}")) && err.contains("taken"),
        "{err}"
    );
    drop(rogue_v4);

    // A second daemon over the port this one serves: refused on the first
    // family it tries, while this one keeps answering.
    let err = match vk_web::bind(n.port).await {
        Ok(_) => panic!("the served port must not be bound twice"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("taken"), "{err}");
    let (status, _) = n.get("/").await;
    assert_eq!(status, 200);
}

/// Review Minor 3: a request that names another host — a page on some
/// origin whose name was rebound to loopback — is refused before any route,
/// whichever family it arrives on; the server's own three names on its own
/// port are answered.
#[tokio::test]
async fn a_request_that_names_another_host_is_refused() {
    let n = node().await;
    let p = n.port;
    for addr in [format!("127.0.0.1:{p}"), format!("[::1]:{p}")] {
        let (status, body) = raw_request(
            addr.clone(),
            "GET / HTTP/1.1",
            &[&format!("Host: evil.example:{p}")],
        )
        .await;
        assert_eq!(status, 400, "{addr}: {body}");
        assert!(body.contains("localhost"), "{body}");
        let (status, _) = raw_request(
            addr.clone(),
            "GET / HTTP/1.1",
            &[&format!("Host: localhost:{}", p + 1)],
        )
        .await;
        assert_eq!(status, 400, "another port is another server");
        let (status, _) = raw_request(addr.clone(), "GET / HTTP/1.1", &["Host: localhost"]).await;
        assert_eq!(status, 400, "the port is part of the name");
        let (status, _) = raw_request(addr.clone(), "GET / HTTP/1.0", &[]).await;
        assert_eq!(status, 400, "no host at all");
        for own in [
            format!("Host: localhost:{p}"),
            format!("Host: 127.0.0.1:{p}"),
            format!("Host: [::1]:{p}"),
            format!("Host: LOCALHOST:{p}"),
        ] {
            let (status, body) = raw_request(addr.clone(), "GET / HTTP/1.1", &[&own]).await;
            assert_eq!(status, 200, "{addr} {own}: {body}");
        }
    }
    // The refusal carries the security headers too: read them raw.
    let (status, _) = raw_request(format!("127.0.0.1:{p}"), "GET / HTTP/1.1", &["Host: x:1"]).await;
    assert_eq!(status, 400);
}

/// The pages open only from a link the endpoint minted, for the page and
/// the task the link names, until the ceremony spends it.
#[tokio::test]
async fn the_pages_open_only_from_a_link_for_their_page_and_task() {
    let n = node().await;
    let (task, _) = waiting_task(&n.kernel);
    let (status, _) = n.get("/enroll").await;
    assert_eq!(status, 404);
    let (status, _) = n.get("/enroll?t=made-up").await;
    assert_eq!(status, 404);
    let (status, _) = n.post("/enroll/start", json!({ "t": "made-up" })).await;
    assert_eq!(status, 404);
    let (status, _) = n.get(&format!("/approve/{task}")).await;
    assert_eq!(status, 404);
    let (status, _) = n.post(&format!("/approve/{task}/start"), json!({})).await;
    assert_eq!(status, 404);

    // A link for one page or task does not open another.
    let enroll = token_of(&n.links.enroll_link(now_ms()));
    let (status, _) = n.get(&format!("/approve/{task}?t={enroll}")).await;
    assert_eq!(status, 404);
    let other = token_of(&n.links.approve_link("task-other", now_ms()));
    let (status, _) = n.get(&format!("/approve/{task}?t={other}")).await;
    assert_eq!(status, 404);
    let (status, _) = n.get(&format!("/enroll?t={other}")).await;
    assert_eq!(status, 404);
    let (status, _) = n.get(&format!("/enroll?t={enroll}")).await;
    assert_eq!(status, 200);

    // The root says what to run and hands out nothing; the script is public.
    let (status, text) = n.get("/").await;
    assert_eq!(status, 200);
    assert!(text.contains("vk passkey enroll"), "{text}");
    let (status, js) = n.get("/vk.js").await;
    assert_eq!(status, 200);
    assert!(js.contains("navigator.credentials"), "{js}");

    // Nothing minted a challenge on the way.
    assert!(n
        .kernel
        .lock()
        .unwrap()
        .pending_approvals(now_ms())
        .is_empty());
}

/// Without an enrolled passkey the approval page says so and mints nothing;
/// a task that is not waiting gets no page; a goal that looks like a
/// template slot is shown as text.
#[tokio::test]
async fn without_a_passkey_or_a_waiting_task_no_challenge_is_minted() {
    let n = node().await;
    let (task, _) = waiting_task(&n.kernel);
    let t = token_of(&n.links.approve_link(&task, now_ms()));
    let (status, err) = n
        .post(&format!("/approve/{task}/start"), json!({ "t": t }))
        .await;
    assert_eq!(status, 409, "{err}");
    assert!(
        err["error"].as_str().unwrap().contains("vk passkey enroll"),
        "{err}"
    );
    assert!(n
        .kernel
        .lock()
        .unwrap()
        .pending_approvals(now_ms())
        .is_empty());

    // A task that is not at its approve step: the page refuses with the
    // scheduler's own reason.
    let queued = {
        let mut k = n.kernel.lock().unwrap();
        let arch = k.register_arch(mock_manifest("mock2"));
        k.create_task(
            &ctx(),
            "later",
            "note",
            Label::bottom(),
            vec![StepKind::Draft { arch_id: arch }, StepKind::Approve],
        )
        .unwrap()
        .id
    };
    let t = token_of(&n.links.approve_link(&queued, now_ms()));
    let (status, body) = n.get(&format!("/approve/{queued}?t={t}")).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("not waiting"), "{body}");

    // A goal that contains a slot and markup is text on the page, once.
    let tricky = {
        let mut k = n.kernel.lock().unwrap();
        let arch = k.register_arch(mock_manifest("mock3"));
        let id = k
            .create_task(
                &ctx(),
                "show {{subject}} <b>bold</b>",
                "note",
                Label::bottom(),
                vec![StepKind::Draft { arch_id: arch }, StepKind::Approve],
            )
            .unwrap()
            .id;
        k.run_task_step(&ctx(), &id).unwrap();
        k.run_task_step(&ctx(), &id).unwrap();
        id
    };
    let t = token_of(&n.links.approve_link(&tricky, now_ms()));
    let (status, body) = n.get(&format!("/approve/{tricky}?t={t}")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("show {{subject}} &lt;b&gt;bold&lt;/b&gt;"),
        "{body}"
    );
    assert!(!body.contains("<b>bold</b>"), "{body}");
}
