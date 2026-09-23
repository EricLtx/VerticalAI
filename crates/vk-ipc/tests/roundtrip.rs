//! End-to-end: a real kernel behind a real local endpoint, driven by the client.
//! What these tests pin down is the principal derivation rule (spec §3.6, I1):
//! a connection is a machine principal, and only a presence proof signed by an
//! enrolled device against a server-issued nonce makes a request human.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use vk_contracts::labels::{Clearance, Scope};
use vk_contracts::principal::{
    Approval, ApprovalKind, Challenge, HumanKey, Principal, SoftwareHumanKey,
};
use vk_ipc::client::{CallError, Client};
use vk_ipc::PresenceProof;

/// Write one raw line and read back one raw line, decoded as JSON.
async fn exchange<W, R>(w: &mut W, lines: &mut tokio::io::Lines<R>, bytes: &[u8]) -> Value
where
    W: AsyncWriteExt + Unpin,
    R: AsyncBufReadExt + Unpin,
{
    w.write_all(bytes).await.unwrap();
    let line = lines.next_line().await.unwrap().unwrap();
    serde_json::from_str(&line).unwrap()
}

fn kernel(dir: &std::path::Path) -> Arc<Mutex<vk_kernel::RealKernel>> {
    Arc::new(Mutex::new(
        vk_kernel::RealKernel::open(
            dir,
            vk_store::keys::KeySource::File(dir.join("m.key")),
            "n1",
        )
        .unwrap(),
    ))
}

#[tokio::test]
async fn cli_principal_cannot_stop_but_presence_proof_can() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let device = vk_contracts::principal::SoftwareHumanKey::generate("laptop");
    {
        use vk_contracts::testing::KernelTestHooks;
        k.lock()
            .unwrap()
            .enroll_device("laptop", device.verifying_key_bytes());
    }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let err = c
        .call("stop", json!({"scope": "node"}), None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("I1"),
        "machine principal must not STOP: {err}"
    );
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap().to_string();
    let proof = vk_ipc::PresenceProof::sign(&device, &nonce);
    let ok = c
        .call("stop", json!({"scope": "node"}), Some(proof))
        .await
        .unwrap();
    assert!(ok["stop_id"].as_str().unwrap().starts_with("stop-"));
    {
        use vk_contracts::testing::KernelTestHooks;
        assert!(k.lock().unwrap().stops().stopped("node"));
    }
    server.abort();
}

#[tokio::test]
async fn ns_and_task_flow_over_ipc() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let arch = c
        .call(
            "arch.mount_mock",
            json!({"name": "mock", "context_ceiling": 200}),
            None,
        )
        .await
        .unwrap()["arch_id"]
        .as_str()
        .unwrap()
        .to_string();
    let t = c
        .call(
            "task.create",
            json!({
                "goal": "Draft a proposal",
                "artefact_type": "proposal",
                "steps": [
                    {"kind": "plan", "arch_id": arch},
                    {"kind": "draft", "arch_id": arch},
                    {"kind": "approve"}
                ]
            }),
            None,
        )
        .await
        .unwrap();
    let id = t["id"].as_str().unwrap().to_string();
    c.call("task.step", json!({"task_id": id}), None)
        .await
        .unwrap();
    c.call("task.step", json!({"task_id": id}), None)
        .await
        .unwrap();
    let waiting = c
        .call("task.step", json!({"task_id": id}), None)
        .await
        .unwrap();
    assert_eq!(waiting["status"], "waiting_human");
    let ls = c
        .call("ns.ls", json!({"path": "/tasks"}), None)
        .await
        .unwrap();
    assert!(ls["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e == &json!(id)));
    assert_eq!(
        c.call("ledger.verify", json!({}), None).await.unwrap()["ok"],
        true
    );
    server.abort();
}

#[tokio::test]
async fn a_presence_nonce_is_single_use_and_expires() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let device = vk_contracts::principal::SoftwareHumanKey::generate("laptop");
    {
        use vk_contracts::testing::KernelTestHooks;
        k.lock()
            .unwrap()
            .enroll_device("laptop", device.verifying_key_bytes());
    }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let stopped = || {
        use vk_contracts::testing::KernelTestHooks;
        k.lock().unwrap().stops().stopped("node")
    };

    // A challenge is issued with a bounded lifetime.
    let issued_at = vk_kernel::now_ms();
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap().to_string();
    let expires = ch["expires_at_ms"].as_u64().unwrap();
    assert!(
        expires > issued_at && expires <= issued_at + 61_000,
        "expiry must be about a minute out: {expires} vs {issued_at}"
    );

    // First use: the proof upgrades the request to a human principal.
    let proof = vk_ipc::PresenceProof::sign(&device, &nonce);
    let stop_id = c
        .call("stop", json!({"scope": "node"}), Some(proof.clone()))
        .await
        .unwrap()["stop_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(stopped());

    // Replay: same nonce, same (valid) signature. Refused, and nothing changed.
    let err = c
        .call("resume", json!({"stop_id": stop_id}), Some(proof))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("I1"), "replayed nonce: {err}");
    assert!(stopped());

    // A nonce the server never issued is refused even with a valid signature.
    let forged = vk_ipc::PresenceProof::sign(&device, "never-issued");
    let err = c
        .call("resume", json!({"stop_id": stop_id}), Some(forged))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("I1"), "unknown nonce: {err}");
    assert!(stopped());

    // A failed verification consumes the nonce too: an impostor's attempt
    // cannot be followed by the real key reusing the same challenge.
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap().to_string();
    let impostor = vk_contracts::principal::SoftwareHumanKey::generate("laptop");
    let bad = vk_ipc::PresenceProof::sign(&impostor, &nonce);
    let err = c
        .call("resume", json!({"stop_id": stop_id}), Some(bad))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("I1"), "impostor: {err}");
    let good = vk_ipc::PresenceProof::sign(&device, &nonce);
    let err = c
        .call("resume", json!({"stop_id": stop_id}), Some(good))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("I1"),
        "nonce burnt by impostor: {err}"
    );
    assert!(stopped());

    // A fresh challenge with the enrolled key is the only thing that lifts it.
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap().to_string();
    let proof = vk_ipc::PresenceProof::sign(&device, &nonce);
    c.call("resume", json!({"stop_id": stop_id}), Some(proof))
        .await
        .unwrap();
    assert!(!stopped());
    server.abort();
}

#[tokio::test]
async fn device_enroll_node_only_enrols_this_nodes_own_device() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    let node = vk_kernel::presence::NodeDevice::load_or_create(
        vk_kernel::presence::KeySource::File(d.path().join("node.key")),
        "n1",
    )
    .unwrap();
    let vk_hex = hex::encode(node.verifying_key_bytes());

    // Any other device id is refused: that is the admin ceremony's job.
    let err = c
        .call(
            "device.enroll_node",
            json!({"device_id": "laptop", "vk_hex": vk_hex}),
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("I1"), "{err}");
    let ls = c
        .call("ns.ls", json!({"path": "/devices"}), None)
        .await
        .unwrap();
    assert!(ls["entries"].as_array().unwrap().is_empty());

    // The node's own device: enrolled once, a repeat is a no-op.
    for _ in 0..2 {
        let ok = c
            .call(
                "device.enroll_node",
                json!({"device_id": "node:n1", "vk_hex": vk_hex}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(ok["ok"], true);
    }
    let ls = c
        .call("ns.ls", json!({"path": "/devices"}), None)
        .await
        .unwrap();
    assert_eq!(ls["entries"], json!(["node:n1"]));

    // A different key for the same id is refused, and the first key still works.
    let other = vk_contracts::principal::SoftwareHumanKey::generate("node:n1");
    let err = c
        .call(
            "device.enroll_node",
            json!({"device_id": "node:n1", "vk_hex": hex::encode(other.verifying_key_bytes())}),
            None,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("I1"), "{err}");
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    let nonce = ch["nonce"].as_str().unwrap();
    let proof = vk_ipc::PresenceProof::sign(&node, nonce);
    let ok = c
        .call("stop", json!({"scope": "node"}), Some(proof))
        .await
        .unwrap();
    assert!(ok["stop_id"].as_str().unwrap().starts_with("stop-"));

    // Malformed key material is a parameter error, not an invariant one.
    let err = c
        .call(
            "device.enroll_node",
            json!({"device_id": "node:n1", "vk_hex": "zz"}),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<vk_ipc::client::CallError>()
            .unwrap()
            .code,
        vk_ipc::E_BAD_PARAMS
    );
    server.abort();
}

#[tokio::test]
async fn garbage_lines_get_a_parse_error_and_the_connection_survives() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Raw stream, so the test controls every byte on the wire.
    let stream = vk_ipc::transport::os::connect(&endpoint).await.unwrap();
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();

    // Not JSON at all.
    let v = exchange(&mut w, &mut lines, b"this is not json\n").await;
    assert_eq!(v["error"]["code"], vk_ipc::E_BAD_PARAMS);
    assert_eq!(v["id"], 0);
    assert!(v.get("result").is_none());

    // JSON, but not a request.
    let v = exchange(&mut w, &mut lines, b"{\"jsonrpc\":\"2.0\",\"id\":7}\n").await;
    assert_eq!(v["error"]["code"], vk_ipc::E_BAD_PARAMS);

    // Unknown method: a proper JSON-RPC "method not found", with the id echoed.
    let v = exchange(
        &mut w,
        &mut lines,
        b"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"nope\",\"params\":{}}\n",
    )
    .await;
    assert_eq!(v["error"]["code"], -32601);
    assert_eq!(v["id"], 5);

    // The same connection still serves a real request afterwards.
    let v = exchange(
        &mut w,
        &mut lines,
        b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"boot.info\",\"params\":{}}\n",
    )
    .await;
    assert_eq!(v["id"], 3);
    assert_eq!(v["result"]["node_id"], "n1");

    // Half a request, then the client goes away mid-line.
    w.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":4,")
        .await
        .unwrap();
    drop(w);
    drop(lines);

    // The server is still there for the next client.
    let c = vk_ipc::client::Client::connect(&endpoint).await.unwrap();
    assert_eq!(
        c.call("boot.info", json!({}), None).await.unwrap()["node_id"],
        "n1"
    );
    server.abort();
}

/// The JSON-RPC code the server answered with.
fn code_of(err: &anyhow::Error) -> i32 {
    err.downcast_ref::<CallError>()
        .unwrap_or_else(|| panic!("not a server error: {err}"))
        .code
}

/// One fresh challenge, signed by `key`: a proof good for exactly one request.
async fn prove(c: &Client, key: &impl HumanKey) -> PresenceProof {
    let ch = c.call("presence.challenge", json!({}), None).await.unwrap();
    PresenceProof::sign(key, ch["nonce"].as_str().unwrap())
}

/// A full SP0 human approval of `subject` by `key`: the challenge names the
/// subject as its action digest, and the key signs the challenge's digest.
fn human_approval(key: &impl HumanKey, subject: &str) -> Approval {
    let challenge = Challenge {
        resource: "task".into(),
        action_digest: subject.into(),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        expires_at_ms: vk_kernel::now_ms() + 60_000,
    };
    Approval {
        subject_hash: subject.into(),
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: key.device_id(),
        },
        signature_hex: Some(hex::encode(key.sign(&challenge.digest()))),
        challenge: Some(challenge),
    }
}

#[tokio::test]
async fn approve_over_ipc_requires_presence_and_a_matching_human_approval() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let laptop = SoftwareHumanKey::generate("laptop");
    let tablet = SoftwareHumanKey::generate("tablet");
    {
        use vk_contracts::testing::KernelTestHooks;
        let mut kk = k.lock().unwrap();
        kk.enroll_device("laptop", laptop.verifying_key_bytes());
        kk.enroll_device("tablet", tablet.verifying_key_bytes());
    }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = Client::connect(&endpoint).await.unwrap();

    // A task that has drafted and now waits at its `approve` step.
    let arch = c
        .call("arch.mount_mock", json!({"name": "mock"}), None)
        .await
        .unwrap()["arch_id"]
        .as_str()
        .unwrap()
        .to_string();
    let t = c
        .call(
            "task.create",
            json!({
                "goal": "Draft a proposal",
                "artefact_type": "proposal",
                "steps": [
                    {"kind": "plan", "arch_id": arch},
                    {"kind": "draft", "arch_id": arch},
                    {"kind": "approve"}
                ]
            }),
            None,
        )
        .await
        .unwrap();
    let id = t["id"].as_str().unwrap().to_string();
    let step = || c.call("task.step", json!({"task_id": id}), None);
    step().await.unwrap();
    step().await.unwrap();
    assert_eq!(step().await.unwrap()["status"], "waiting_human");

    // What the scheduler wants approved: the latest artefact, or the register
    // itself when none is attached — read through the kernel, as it does.
    let subject = {
        use vk_contracts::syscalls::{Ctx, Kernel};
        let mut kk = k.lock().unwrap();
        let register = kk.task(&id).unwrap().register;
        let ctx = Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "test".into(),
            },
            clearance: Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            },
            partition: "local".into(),
            now_ms: vk_kernel::now_ms(),
        };
        let reg = kk.read_register(&ctx, &register).unwrap();
        reg.artefacts
            .last()
            .map(|a| a.hash.clone())
            .unwrap_or_else(|| vk_contracts::hash_canonical(&reg))
    };
    let params = |a: Approval| json!({ "approval": a });

    // (a) No presence: the connection is a machine principal, and I1 refuses
    // a human approval that did not arrive on the human's own channel.
    let err = c
        .call("approve", params(human_approval(&laptop, &subject)), None)
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_INVARIANT, "{err}");
    assert!(err.to_string().contains("I1"), "{err}");

    // (c) Presence from the laptop, approval signed by the tablet: the
    // approver is not the principal the connection proved.
    let proof = prove(&c, &laptop).await;
    let err = c
        .call(
            "approve",
            params(human_approval(&tablet, &subject)),
            Some(proof),
        )
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_INVARIANT, "{err}");
    assert!(err.to_string().contains("I1"), "{err}");

    // (d) Only human approvals cross the transport: `kind: test` is a
    // parameter error, refused before the kernel sees it, presence or not.
    let mut test_kind = human_approval(&laptop, &subject);
    test_kind.kind = ApprovalKind::Test;
    let proof = prove(&c, &laptop).await;
    let err = c
        .call("approve", params(test_kind), Some(proof))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_BAD_PARAMS, "{err}");
    assert!(
        err.to_string()
            .contains("only human approvals are accepted over the transport"),
        "{err}"
    );

    // None of the above was recorded: the task still waits.
    assert_eq!(step().await.unwrap()["status"], "waiting_human");

    // (b) Presence from the laptop and the laptop's own approval of the
    // subject: accepted, and the waiting step completes the task.
    let proof = prove(&c, &laptop).await;
    let ok = c
        .call(
            "approve",
            params(human_approval(&laptop, &subject)),
            Some(proof),
        )
        .await
        .unwrap();
    assert_eq!(ok["ok"], true);
    let done = step().await.unwrap();
    assert_eq!(done["status"], "done", "{done}");
    server.abort();
}

/// A client cannot read a register, so the subject of an approval is something
/// it has to be told. `task.subject` is that answer, and this pins it to the
/// only thing that makes it useful: the waiting step accepts what it names.
#[tokio::test]
async fn task_subject_is_what_the_approve_step_accepts() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let laptop = SoftwareHumanKey::generate("laptop");
    {
        use vk_contracts::testing::KernelTestHooks;
        k.lock()
            .unwrap()
            .enroll_device("laptop", laptop.verifying_key_bytes());
    }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = Client::connect(&endpoint).await.unwrap();

    let arch = c
        .call("arch.mount_mock", json!({"name": "mock"}), None)
        .await
        .unwrap()["arch_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = c
        .call(
            "task.create",
            json!({
                "goal": "Draft a proposal",
                "artefact_type": "proposal",
                "steps": [
                    {"kind": "draft", "arch_id": arch},
                    {"kind": "approve"}
                ]
            }),
            None,
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let step = || c.call("task.step", json!({"task_id": id}), None);
    step().await.unwrap();
    assert_eq!(step().await.unwrap()["status"], "waiting_human");

    // The draft attached the task's artefact, so the subject is that blob.
    let subject = c
        .call("task.subject", json!({"task_id": id}), None)
        .await
        .unwrap()["subject_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(subject.starts_with("sha256:"), "{subject}");

    // An approval built from nothing but that answer completes the step.
    let proof = prove(&c, &laptop).await;
    let ok = c
        .call(
            "approve",
            json!({ "approval": human_approval(&laptop, &subject) }),
            Some(proof),
        )
        .await
        .unwrap();
    assert_eq!(ok["ok"], true);
    assert_eq!(step().await.unwrap()["status"], "done");
    server.abort();
}

#[tokio::test]
async fn a_presence_proof_on_a_method_that_takes_none_is_refused_and_still_spent() {
    let d = tempfile::tempdir().unwrap();
    let k = kernel(d.path());
    let laptop = SoftwareHumanKey::generate("laptop");
    {
        use vk_contracts::testing::KernelTestHooks;
        k.lock()
            .unwrap()
            .enroll_device("laptop", laptop.verifying_key_bytes());
    }
    let endpoint = vk_ipc::transport::test_endpoint();
    let server = tokio::spawn(vk_ipc::server::serve(k.clone(), endpoint.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c = Client::connect(&endpoint).await.unwrap();
    let stopped = || {
        use vk_contracts::testing::KernelTestHooks;
        k.lock().unwrap().stops().stopped("node")
    };

    // `task.show` derives no principal, so a proof there is a parameter error...
    let proof = prove(&c, &laptop).await;
    let err = c
        .call("task.show", json!({"task_id": "t-1"}), Some(proof.clone()))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_BAD_PARAMS, "{err}");
    assert!(
        err.to_string()
            .contains("this method does not take a presence proof"),
        "{err}"
    );
    // ...and the nonce it carried is spent all the same: re-presented on
    // `stop`, it is unknown, and nothing stops.
    let err = c
        .call("stop", json!({"scope": "node"}), Some(proof))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_INVARIANT, "{err}");
    assert!(err.to_string().contains("I1"), "{err}");
    assert!(!stopped());

    // The same holds for the one method answered before the kernel lock.
    let proof = prove(&c, &laptop).await;
    let err = c
        .call("presence.challenge", json!({}), Some(proof.clone()))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_BAD_PARAMS, "{err}");
    let err = c
        .call("stop", json!({"scope": "node"}), Some(proof))
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), vk_ipc::E_INVARIANT, "{err}");
    assert!(!stopped());

    // A fresh proof on a method that takes one is still the human path.
    let proof = prove(&c, &laptop).await;
    c.call("stop", json!({"scope": "node"}), Some(proof))
        .await
        .unwrap();
    assert!(stopped());
    server.abort();
}
