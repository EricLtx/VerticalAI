//! `vk-mcp`: the MCP façade.
//!
//! A stdio MCP server Claude Code speaks to, that turns every tool call into a
//! kernel syscall under a lease. It is launched by the confined harness with
//! `VK_ENDPOINT` (the daemon to reach) and `VK_LEASE_TOKEN` (the lease that
//! authenticates it) in its environment; it speaks MCP on stdin/stdout and holds
//! a `vk-ipc` client to the daemon.
//!
//! The lease token never reaches the model: the façade injects it into each
//! `harness.*` call. `initialize` and `tools/list` are answered locally, so a
//! client can connect and discover the tools before any lease is live (spike
//! 4a(ii)); the daemon is dialled lazily, on the first tool call.
//!
//! **stdout is the MCP channel** — only JSON-RPC goes there. Diagnostics go to
//! stderr.

mod protocol;
mod tools;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use vk_ipc::client::Client;
use vk_ipc::transport::Endpoint;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let endpoint = std::env::var("VK_ENDPOINT").ok();
    let token = std::env::var("VK_LEASE_TOKEN").ok();

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    let mut client: Option<Client> = None;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vk-mcp: not JSON-RPC: {e}");
                continue;
            }
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        // A request has an id; a notification does not, and gets no response.
        let id = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        let response = handle(
            method,
            id.clone(),
            &params,
            endpoint.as_deref(),
            token.as_deref(),
            &mut client,
        )
        .await;

        if let Some(resp) = response {
            let mut out = serde_json::to_string(&resp)?;
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Answer one MCP message. `None` for a notification (no `id`) and for anything
/// this façade does not answer.
async fn handle(
    method: &str,
    id: Option<Value>,
    params: &Value,
    endpoint: Option<&str>,
    token: Option<&str>,
    client: &mut Option<Client>,
) -> Option<Value> {
    match method {
        "initialize" => {
            let ver = params.get("protocolVersion").and_then(Value::as_str);
            Some(protocol::ok(id?, protocol::initialize_result(ver)))
        }
        "tools/list" => Some(protocol::ok(id?, tools::tool_list())),
        "tools/call" => {
            let id = id?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let result = call_tool(&name, &args, endpoint, token, client).await;
            let (text, is_error) = match result {
                Ok(text) => (text, false),
                Err(text) => (text, true),
            };
            Some(protocol::ok(id, protocol::tool_result(text, is_error)))
        }
        "ping" => Some(protocol::ok(id?, serde_json::json!({}))),
        // Notifications (no id): nothing to answer. A request for an unknown
        // method gets a proper "method not found".
        _ => id.map(|id| protocol::err(id, -32601, &format!("method not found: {method}"))),
    }
}

/// Run one tool: dial the daemon (lazily, once) with the lease token, and bridge
/// the call. `Err(text)` becomes an MCP error result the model can read.
async fn call_tool(
    name: &str,
    args: &Value,
    endpoint: Option<&str>,
    token: Option<&str>,
    client: &mut Option<Client>,
) -> Result<String, String> {
    let token = token.ok_or("VK_LEASE_TOKEN is not set: this façade has no lease to act under")?;
    let c = connect(client, endpoint).await?;
    tools::call(c, token, name, args).await
}

/// Connect to the daemon on first use, and reuse the connection after.
async fn connect<'a>(
    client: &'a mut Option<Client>,
    endpoint: Option<&str>,
) -> Result<&'a Client, String> {
    if client.is_none() {
        let ep = endpoint.ok_or("VK_ENDPOINT is not set")?;
        let c = Client::connect(&Endpoint(ep.to_string()))
            .await
            .map_err(|e| format!("cannot reach the kernel on {ep}: {e}"))?;
        *client = Some(c);
    }
    Ok(client.as_ref().expect("just set"))
}
