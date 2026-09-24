//! The Model Context Protocol framing this façade speaks over stdio.
//!
//! MCP stdio is newline-delimited JSON-RPC 2.0: one JSON object per line, no
//! embedded newlines, requests carry an `id`, notifications do not. This module
//! is only the shapes — `initialize`, the error and result envelopes — while
//! [`crate::tools`] holds what the tools are and does the work.

use serde_json::{json, Value};

/// The MCP revision this server implements. `initialize` echoes the client's
/// requested version when it sends one (every current client does), falling back
/// to this — the behaviour a server is expected to have when it supports the
/// version asked for.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// The server name. Claude Code exposes this server's tools as
/// `mcp__vk__<tool>`, so this `vk` is the `vk` in `mcp__vk__*`.
pub const SERVER_NAME: &str = "vk";

/// The `initialize` result: the protocol version, the one capability this server
/// has (tools), and who it is.
pub fn initialize_result(client_version: Option<&str>) -> Value {
    json!({
        "protocolVersion": client_version.unwrap_or(PROTOCOL_VERSION),
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
    })
}

/// A JSON-RPC success response for request `id`.
pub fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A JSON-RPC error response for request `id`.
pub fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A `tools/call` result carrying one text block, flagged as an error or not —
/// the MCP shape a client renders back to the model.
pub fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": is_error,
    })
}
