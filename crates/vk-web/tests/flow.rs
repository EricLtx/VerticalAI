//! The passkey ceremony end to end, over a real loopback listener, with
//! `webauthn-rs`'s software authenticator standing in for Windows Hello:
//! enrol, then approve a task and watch the scheduler's `Approve` step
//! complete; and every way the ceremony must *not* record anything.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::{ApprovalKind, Challenge, Principal};
use vk_contracts::syscalls::Ctx;
use vk_contracts::testing::KernelTestHooks;
use vk_kernel::tasks::{StepKind, TaskStatus};
use vk_kernel::{now_ms, RealKernel};
use vk_web::{Links, Shared};
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

/// A kernel behind the pages on an ephemeral loopback port.
struct Node {
    kernel: Shared,
    links: Arc<Links>,
    base: String,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
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
    let listener = vk_web::bind(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let web = vk_web::build(kernel.clone(), "n1", port).unwrap();
    let server = tokio::spawn(vk_web::serve(listener, web.router));
    Node {
        kernel,
        links: web.links,
        base: vk_web::passkey::origin(port),
        http: reqwest::Client::new(),
        _dir: dir,
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

/// A task drafted through a mock arch and waiting at its approve step; its
/// id and the subject an approval of it must name.
fn waiting_task(kernel: &Shared) -> (String, String) {
    let mut k = kernel.lock().unwrap();
    let arch = k.register_arch(mock_manifest("mock"));
    let id = k
        .create_task(
            &ctx(),
            "Draft a proposal for Acme",
            "proposal",
            Label::bottom(),
            vec![StepKind::Draft { arch_id: arch }, StepKind::Approve],
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

fn token_of(url: &str) -> String {
    url.rsplit("?t=").next().unwrap().to_string()
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

impl Node {
    async fn get(&self, path_and_query: &str) -> (u16, String) {
        let r = self
            .http
            .get(format!("{}{path_and_query}", self.base))
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
    use vk_contracts::syscalls::Kernel;
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
/// scheduler's `Approve` step completes on it. A second finish with the same
/// assertion, or with the same state, records nothing.
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
    let minted: Challenge = serde_json::from_value(started["challenge"].clone()).unwrap();
    assert_eq!(minted.resource, format!("task:{task}"));
    assert_eq!(minted.action_digest, subject);
    assert_eq!(
        n.kernel.lock().unwrap().pending_approvals(now_ms()).len(),
        1,
        "the kernel minted it"
    );
    let options: RequestChallengeResponse =
        serde_json::from_value(started["options"].clone()).unwrap();
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
    }
    assert_eq!(events_of_kind(&n.kernel, "approval.recorded"), 1);

    // Replayed: the same state and the same assertion, refused; and the same
    // assertion against a fresh start, refused by the verifier — its
    // challenge is not the new state's. Nothing new on the record.
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
/// a task that is not waiting gets no page.
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
}
