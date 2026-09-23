//! Syscall transport (spec §3.11): newline-delimited JSON-RPC 2.0 on a local
//! endpoint (named pipe on Windows, Unix socket elsewhere).
//!
//! The endpoint's OS ACL is the first authentication factor: on Unix a `0600`
//! socket inside a `0700` directory; on Windows, in SP1a, the default DACL of
//! a named pipe, which SP1b hardens with an explicit one. From there the
//! server derives every principal from the connection itself (`server::ctx_for`
//! is the only place a `Ctx` is built) and never from a request field. A
//! connection is a machine principal; one request becomes human only by
//! carrying a [`PresenceProof`] — a signature by an enrolled device key over a
//! server-issued, single-use, expiring nonce (spec §3.6, invariant I1).
//!
//! A proof is spent by the request that carries it, whatever the method: the
//! server removes its nonce from the challenge map before dispatching
//! anything, so a nonce shown once is never live for a later request. Only
//! the methods that derive a principal (`task.create`, `task.step`, `stop`,
//! `resume`, `approve`) take a proof; every other method refuses a request
//! carrying one with `-32602` (`"this method does not take a presence
//! proof"`) — the nonce spent all the same.
pub mod client;
pub mod server;
pub mod transport;

use serde::{Deserialize, Serialize};
use vk_contracts::principal::HumanKey;

/// Proof that an enrolled device's key was present for *this* request. It is
/// not a session: the nonce is spent by the request that carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProof {
    pub device_id: String,
    pub nonce: String,
    pub signature_hex: String,
}

impl PresenceProof {
    /// What the device signs: the `sha256:<hex>` text of `presence|<nonce>`.
    /// Domain-separated from an approval's `Challenge::digest`, so a presence
    /// signature can never be replayed as an approval, nor the reverse.
    pub fn message(nonce: &str) -> Vec<u8> {
        vk_contracts::hash_bytes(format!("presence|{nonce}").as_bytes()).into_bytes()
    }

    pub fn sign(key: &impl HumanKey, nonce: &str) -> PresenceProof {
        PresenceProof {
            device_id: key.device_id(),
            nonce: nonce.into(),
            signature_hex: hex::encode(key.sign(&Self::message(nonce))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    /// Present only on a request the caller wants treated as human. It is a
    /// proof to be verified, never a principal to be believed.
    #[serde(default)]
    pub presence: Option<PresenceProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A kernel invariant (I1–I4′), a STOP, a lock or a gate refused the call.
pub const E_INVARIANT: i32 = -32001;
/// The object the call names does not exist.
pub const E_NOT_FOUND: i32 = -32004;
/// A durable read or write failed; the call had no effect it can vouch for.
pub const E_STORE: i32 = -32005;
/// JSON-RPC 2.0: method not found.
pub const E_METHOD: i32 = -32601;
/// JSON-RPC 2.0: invalid params (also: a line that is not a request at all).
pub const E_BAD_PARAMS: i32 = -32602;
/// JSON-RPC 2.0: internal error (a response that could not be built).
pub const E_INTERNAL: i32 = -32603;
