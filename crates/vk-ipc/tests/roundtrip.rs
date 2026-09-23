//! End-to-end: a real kernel behind a real local endpoint, driven by the client.
//! What these tests pin down is the principal derivation rule (spec §3.6, I1):
//! a connection is a machine principal, and only a presence proof signed by an
//! enrolled device against a server-issued nonce makes a request human.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use vk_contracts::principal::HumanKey;

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
