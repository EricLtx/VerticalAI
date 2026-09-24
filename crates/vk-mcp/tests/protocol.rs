//! The façade speaks MCP: `initialize` and `tools/list` answered locally, and a
//! `tools/call` turned into a `harness.*` syscall over the transport, carrying
//! the lease token the model never sees.
//!
//! A fake kernel stands in for the daemon — it accepts the transport, records
//! the `harness.log` call and answers it — so this test needs no real kernel,
//! lease or task.
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A fake daemon: accepts the `vk-ipc` transport and answers `harness.*` with a
/// canned reply, capturing the params so the test can check the token rode along.
async fn fake_kernel(endpoint: vk_ipc::transport::Endpoint, seen: Arc<Mutex<Vec<Value>>>) {
    let mut listener = vk_ipc::transport::os::bind(&endpoint)
        .await
        .expect("bind fake endpoint");
    while let Ok(stream) = listener.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(stream);
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let id = req.get("id").cloned().unwrap_or(json!(0));
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");
                seen.lock().unwrap().push(req.clone());
                let result = match method {
                    "harness.log" => json!({ "ok": true }),
                    _ => json!({ "ok": true }),
                };
                let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                let mut out = serde_json::to_string(&resp).unwrap();
                out.push('\n');
                if w.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_lists_tools_and_calls_a_tool_as_a_syscall() {
    let endpoint = vk_ipc::transport::test_endpoint();
    let seen = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(fake_kernel(endpoint.clone(), seen.clone()));
    // The fake needs a moment to bind before the façade dials it.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_vk-mcp"))
        .env("VK_ENDPOINT", &endpoint.0)
        .env("VK_LEASE_TOKEN", "lease-token-42")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vk-mcp");
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap()).lines();

    // The three MCP messages a client sends, newline-delimited.
    let requests = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05", "capabilities": {} } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "vk_log", "arguments": { "message": "hello from the harness" } } }),
    ];
    for r in &requests {
        let mut line = serde_json::to_string(r).unwrap();
        line.push('\n');
        stdin.write_all(line.as_bytes()).await.unwrap();
    }
    stdin.flush().await.unwrap();
    drop(stdin);

    async fn read_json(
        out: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    ) -> Value {
        let line = out.next_line().await.unwrap().expect("a response line");
        serde_json::from_str::<Value>(&line).expect("JSON-RPC")
    }
    // 1: initialize — the server identifies as `vk` and echoes the version.
    let init = read_json(&mut out).await;
    assert_eq!(init["id"], 1, "{init}");
    assert_eq!(init["result"]["serverInfo"]["name"], "vk", "{init}");
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05", "{init}");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );

    // 2: tools/list — the five vk_* tools, so Claude Code lists mcp__vk__*.
    let list = read_json(&mut out).await;
    assert_eq!(list["id"], 2, "{list}");
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or(""))
        .collect();
    for expected in [
        "vk_read_register",
        "vk_write_decision",
        "vk_attach_artefact",
        "vk_request_approval",
        "vk_log",
    ] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }

    // 3: tools/call vk_log — bridged to the harness.log syscall and back.
    let called = read_json(&mut out).await;
    assert_eq!(called["id"], 3, "{called}");
    assert_eq!(
        called["result"]["isError"], false,
        "the tool call succeeded: {called}"
    );
    assert_eq!(called["result"]["content"][0]["text"], "logged", "{called}");

    let _ = child.kill().await;

    // The syscall reached the fake kernel as harness.log, carrying the injected
    // token the model never supplied, plus the message. The guard is taken and
    // dropped here, after the last await, so nothing holds a lock across one.
    let calls = seen.lock().unwrap();
    let log = calls
        .iter()
        .find(|r| r["method"] == "harness.log")
        .unwrap_or_else(|| panic!("no harness.log syscall seen: {calls:?}"));
    assert_eq!(log["params"]["token"], "lease-token-42", "{log}");
    assert_eq!(log["params"]["message"], "hello from the harness", "{log}");
}
