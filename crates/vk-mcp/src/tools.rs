//! The tools this façade exposes, and how each becomes a kernel syscall.
//!
//! Every tool maps to one `harness.*` IPC method, and the façade injects the
//! lease token (`VK_LEASE_TOKEN`) into the call — the model never sees it. The
//! server maps that token to the harness principal at the harness clearance and
//! answers as if the harness itself had made the syscall.

use serde_json::{json, Value};
use vk_ipc::client::Client;

/// The five tools, in the MCP `tools/list` shape. Names are `vk_*`; Claude Code
/// exposes them as `mcp__vk__vk_*`, which `--allowedTools "mcp__vk__*"` admits.
pub fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "vk_read_register",
                "description": "Read the task register the kernel is running: its goal, constraints, plan decisions and evidence, as the harness clearance may see them.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
            },
            {
                "name": "vk_write_decision",
                "description": "Append a decision to the task register.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "text": { "type": "string", "description": "The decision to record." } },
                    "required": ["text"],
                    "additionalProperties": false
                }
            },
            {
                "name": "vk_attach_artefact",
                "description": "Attach a file from the workspace to the register as an artefact of the given kind. Path is relative to the workspace (e.g. OUT/proposal.md).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "description": "The artefact kind, e.g. \"proposal\"." },
                        "path": { "type": "string", "description": "Workspace-relative path to the file." }
                    },
                    "required": ["kind", "path"],
                    "additionalProperties": false
                }
            },
            {
                "name": "vk_request_approval",
                "description": "Ask a human to approve the task's latest artefact.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
            },
            {
                "name": "vk_log",
                "description": "Record a line in the harness log.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "message": { "type": "string" } },
                    "required": ["message"],
                    "additionalProperties": false
                }
            }
        ]
    })
}

/// Run a tool: map it to a `harness.*` syscall carrying `token`, and render the
/// answer as text. `Err(text)` is a tool error (an unknown tool, or a syscall
/// the kernel refused); the caller turns it into an MCP `isError` result.
pub async fn call(
    client: &Client,
    token: &str,
    name: &str,
    args: &Value,
) -> Result<String, String> {
    let str_arg = |key: &str| -> Result<String, String> {
        args.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("{name} needs a string `{key}`"))
    };
    let (method, params) = match name {
        "vk_read_register" => ("harness.read_register", json!({ "token": token })),
        "vk_write_decision" => (
            "harness.write_decision",
            json!({ "token": token, "text": str_arg("text")? }),
        ),
        "vk_attach_artefact" => (
            "harness.attach_artefact",
            json!({ "token": token, "kind": str_arg("kind")?, "path": str_arg("path")? }),
        ),
        "vk_request_approval" => ("harness.request_approval", json!({ "token": token })),
        "vk_log" => (
            "harness.log",
            json!({ "token": token, "message": str_arg("message")? }),
        ),
        other => return Err(format!("no such tool: {other}")),
    };
    match client.call(method, params, None).await {
        Ok(v) => Ok(render(name, &v)),
        Err(e) => Err(format!("{name} refused by the kernel: {e}")),
    }
}

/// The text a tool's answer reads as for the model.
fn render(name: &str, v: &Value) -> String {
    match name {
        "vk_read_register" => serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()),
        "vk_attach_artefact" => v
            .get("hash")
            .and_then(Value::as_str)
            .map(|h| format!("attached: {h}"))
            .unwrap_or_else(|| "attached".into()),
        "vk_write_decision" => "decision recorded".into(),
        "vk_request_approval" => "approval requested".into(),
        "vk_log" => "logged".into(),
        _ => v.to_string(),
    }
}
