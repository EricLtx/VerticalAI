//! The server side of the syscall transport: accept, read a line, dispatch,
//! write a line. This module is where principals come from (`ctx_for`), and
//! it is the only place in the workspace that builds a `Ctx` from a live
//! connection — spec §3.6, invariant I1.
use crate::transport::{self, AcceptError, Endpoint};
use crate::{
    PresenceProof, Request, Response, RpcError, E_BAD_PARAMS, E_INTERNAL, E_INVARIANT, E_METHOD,
    E_NOT_FOUND, E_STORE,
};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use vk_contracts::arch::ArchManifest;
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::{Approval, ApprovalKind, Principal};
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_kernel::arch::MockAdapter;
use vk_kernel::tasks::StepKind;
use vk_kernel::{now_ms, RealKernel};

type Shared = Arc<Mutex<RealKernel>>;

/// How long a presence challenge stays answerable.
pub const CHALLENGE_TTL_MS: u64 = 60_000;
/// Open challenges are bounded: past this many, the one closest to expiry is
/// dropped to make room. A local client that mints nonces it never spends
/// cannot grow the map without limit.
const MAX_CHALLENGES: usize = 1024;
/// Longest request line accepted. Longer, and the connection is dropped
/// rather than buffered without bound.
const MAX_LINE: usize = 1 << 20;
/// Pause after a connection that could not be accepted, so a condition that
/// is not ours to fix (a burst past the descriptor limit, say) is not spun on.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Outstanding presence nonces, each with its expiry. Single use: `spend`
/// removes a nonce before looking at anything else about it, so a nonce that
/// fails verification is as gone as one that passed.
#[derive(Default)]
struct Challenges {
    open: BTreeMap<String, u64>,
}

impl Challenges {
    fn issue(&mut self, now: u64) -> (String, u64) {
        self.open.retain(|_, exp| *exp > now);
        if self.open.len() >= MAX_CHALLENGES {
            if let Some(oldest) = self
                .open
                .iter()
                .min_by_key(|(_, exp)| **exp)
                .map(|(n, _)| n.clone())
            {
                self.open.remove(&oldest);
            }
        }
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let exp = now + CHALLENGE_TTL_MS;
        self.open.insert(nonce.clone(), exp);
        (nonce, exp)
    }

    fn spend(&mut self, nonce: &str, now: u64) -> Result<(), RpcError> {
        let exp = self
            .open
            .remove(nonce)
            .ok_or_else(|| invariant("I1: unknown or already used presence nonce"))?;
        if now >= exp {
            return Err(invariant("I1: presence challenge expired"));
        }
        Ok(())
    }
}

pub async fn serve(kernel: Shared, endpoint: Endpoint) -> Result<()> {
    let mut listener = transport::os::bind(&endpoint).await?;
    let challenges = Arc::new(Mutex::new(Challenges::default()));
    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            // One connection that could not be taken (a peer gone before the
            // accept, a burst past the descriptor limit, a pipe instance that
            // could not be created this once): the listener is still armed,
            // so say so, let the moment pass and keep serving.
            Err(AcceptError::Connection(e)) => {
                tracing::warn!(error = %e, "connection not accepted; still serving");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
            // The listener itself is gone: there is nothing left to serve with.
            Err(e @ AcceptError::Listener(_)) => return Err(e.into()),
        };
        let (k, ch) = (kernel.clone(), challenges.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, k, ch).await {
                tracing::debug!(error = %e, "connection closed");
            }
        });
    }
}

async fn handle_connection(
    stream: Box<dyn transport::Stream>,
    kernel: Shared,
    challenges: Arc<Mutex<Challenges>>,
) -> Result<()> {
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    let mut buf = Vec::new();
    while let Some(line) = read_line(&mut reader, &mut buf).await? {
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let id = req.id;
                // The kernel does its own disk IO, so a call runs on the
                // blocking pool. `dispatch` is synchronous: the kernel lock is
                // taken and released inside it, never held across an await.
                let (k, ch) = (kernel.clone(), challenges.clone());
                let outcome = tokio::task::spawn_blocking(move || dispatch(&k, &ch, req))
                    .await
                    .unwrap_or_else(|e| Err(internal(&format!("dispatch aborted: {e}"))));
                reply(id, outcome)
            }
            Err(e) => reply(0, Err(bad(&format!("not a request: {e}")))),
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        w.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

/// One line without its terminator; `None` at a clean end of stream. A line
/// that ends with the connection instead of a newline, or that exceeds
/// `MAX_LINE`, is an error and ends the connection.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    buf.clear();
    let n = (&mut *reader)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        let why = if buf.len() > MAX_LINE {
            "line too long"
        } else {
            "connection closed mid-line"
        };
        return Err(std::io::Error::new(ErrorKind::InvalidData, why));
    }
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    std::str::from_utf8(buf)
        .map(|s| Some(s.to_owned()))
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "line is not utf-8"))
}

fn reply(id: u64, outcome: Result<Value, RpcError>) -> Response {
    let (result, error) = match outcome {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e)),
    };
    Response {
        jsonrpc: "2.0".into(),
        id,
        result,
        error,
    }
}

fn kerr(e: KernelError) -> RpcError {
    let code = match e {
        KernelError::NotFound(_) => E_NOT_FOUND,
        KernelError::Store(_) => E_STORE,
        KernelError::I1(_)
        | KernelError::I2(_)
        | KernelError::I3(_)
        | KernelError::I4(_)
        | KernelError::I4Prime(_)
        | KernelError::Stopped(_)
        | KernelError::Lock(_)
        | KernelError::Principal(_)
        | KernelError::Stop(_)
        | KernelError::Module(_)
        | KernelError::Gate(_) => E_INVARIANT,
    };
    RpcError {
        code,
        message: e.to_string(),
    }
}

fn bad(msg: &str) -> RpcError {
    RpcError {
        code: E_BAD_PARAMS,
        message: msg.into(),
    }
}

fn invariant(msg: &str) -> RpcError {
    RpcError {
        code: E_INVARIANT,
        message: msg.into(),
    }
}

fn not_found(what: &str) -> RpcError {
    RpcError {
        code: E_NOT_FOUND,
        message: format!("not found: {what}"),
    }
}

fn internal(msg: &str) -> RpcError {
    RpcError {
        code: E_INTERNAL,
        message: msg.into(),
    }
}

/// A poisoned lock is reported, not unwrapped: one panicking dispatch must not
/// take every later connection down with it.
fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, RpcError> {
    m.lock().map_err(|_| internal("kernel lock poisoned"))
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, RpcError> {
    serde_json::to_value(v).map_err(|e| internal(&format!("cannot encode response: {e}")))
}

/// A proof as `ctx_for` receives it: its nonce already taken from the map by
/// `dispatch`, along with the verdict of that taking. The taking happens for
/// every request that carries a proof, before the method is even looked at.
struct Presented {
    proof: PresenceProof,
    nonce: Result<(), RpcError>,
}

/// The methods that derive their principal from the request, and so the only
/// ones a presence proof may accompany. Every other method refuses a request
/// carrying one — after `dispatch` has spent it.
fn takes_presence(method: &str) -> bool {
    matches!(
        method,
        "task.create" | "task.step" | "stop" | "resume" | "approve"
    )
}

/// The only place a `Ctx` is built. Machine by default — the endpoint's ACL
/// already proved the peer is this user's process — and human only for the
/// one request that carries a presence proof the enrolled device key made
/// over a nonce this server issued, still unexpired, that no earlier request
/// had spent.
fn ctx_for(k: &RealKernel, presence: Option<Presented>, now: u64) -> Result<Ctx, RpcError> {
    let principal = match presence {
        None => Principal::Machine {
            node_id: k.node_id.clone(),
            lease_id: "cli".into(),
        },
        Some(Presented { proof: p, nonce }) => {
            nonce?;
            let sig: [u8; 64] = hex::decode(&p.signature_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| invariant("I1: presence signature is not 64 bytes of hex"))?;
            k.devices()
                .verify(&p.device_id, &PresenceProof::message(&p.nonce), &sig)
                .map_err(|e| invariant(&format!("I1: {e}")))?;
            Principal::Human {
                device_id: p.device_id,
            }
        }
    };
    Ok(Ctx {
        principal,
        clearance: Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        },
        partition: "local".into(),
        now_ms: now,
    })
}

fn dispatch(
    kernel: &Shared,
    challenges: &Mutex<Challenges>,
    req: Request,
) -> Result<Value, RpcError> {
    let now = now_ms();
    // A nonce presented is a nonce spent, whatever the method and whatever
    // happens next: it leaves the map here, before anything is dispatched, so
    // a proof sent to a method that would ignore it cannot be shown again to
    // one that would not.
    let presence = match req.presence {
        None => None,
        Some(proof) => {
            let nonce = lock(challenges)?.spend(&proof.nonce, now);
            Some(Presented { proof, nonce })
        }
    };
    if presence.is_some() && !takes_presence(&req.method) {
        return Err(bad("this method does not take a presence proof"));
    }
    // Issuing a challenge touches no kernel state.
    if req.method == "presence.challenge" {
        let (nonce, exp) = lock(challenges)?.issue(now);
        return Ok(json!({ "nonce": nonce, "expires_at_ms": exp }));
    }
    let mut k = lock(kernel)?;
    let p = req.params;
    match req.method.as_str() {
        "boot.info" => Ok(json!({
            "node_id": k.node_id,
            "arches": k.arches().len(),
            "devices": k.devices().ids().len(),
            "ledger_len": k.ledger().events().len(),
            "ledger_ok": k.ledger().verify_chain(),
            // Fixed when this daemon opened its store: one event short of its
            // record is a thing every caller is told, not only the log line
            // nobody read.
            "recovered_partial_line": k.recovered_partial_line(),
            // Read live, not remembered from boot — a STOP issued a minute ago
            // is exactly the one an operator is asking about.
            "stopped_scopes": k.stopped_scopes(),
            // What boot wrote down; `null` on a node that has never booted.
            // There is no policy engine in SP1a, but a placeholder nothing can
            // read is a predecessor the first real policy set cannot migrate
            // from.
            "policies_version": k.policies_version(),
            "state_dir": k.store().state_dir.display().to_string(),
            // Where a `release` step's `to_dir` is resolved: the client names a
            // subpath and prints the resolved path, so "where did my artefact
            // go?" is answerable without the client guessing the layout.
            "export_root": k.export_root().display().to_string(),
        })),
        "ns.ls" => {
            let path = p["path"].as_str().unwrap_or("/");
            vk_kernel::ns::resolve(&k, path)
                .map_err(kerr)
                .and_then(to_value)
        }
        "arch.ls" => to_value(
            k.arches()
                .into_iter()
                .map(|(id, m)| json!({ "arch_id": id, "manifest": m }))
                .collect::<Vec<_>>(),
        ),
        "arch.mount_mock" => {
            let name = p["name"].as_str().unwrap_or("mock");
            let ceiling = p["context_ceiling"]
                .as_u64()
                .map_or(Ok(4096), u32::try_from)
                .map_err(|_| bad("context_ceiling"))?;
            let adapter = MockAdapter {
                manifest: mock_manifest(name, ceiling),
                budget: ceiling,
            };
            let id = k
                .mount(Arc::new(adapter))
                .map_err(|e| bad(&e.to_string()))?;
            Ok(json!({ "arch_id": id }))
        }
        "arch.unmount" => {
            let id = p["arch_id"].as_str().ok_or_else(|| bad("arch_id"))?;
            k.unmount(id).map_err(|e| RpcError {
                code: E_STORE,
                message: e.to_string(),
            })?;
            Ok(json!({ "ok": true }))
        }
        "task.create" => {
            let ctx = ctx_for(&k, presence, now)?;
            let goal = p["goal"].as_str().ok_or_else(|| bad("goal"))?;
            let artefact_type = p["artefact_type"].as_str().unwrap_or("note");
            let steps: Vec<StepKind> = serde_json::from_value(p["steps"].clone())
                .map_err(|e| bad(&format!("steps: {e}")))?;
            k.create_task(&ctx, goal, artefact_type, Label::bottom(), steps)
                .map_err(kerr)
                .and_then(to_value)
        }
        "task.step" => {
            let ctx = ctx_for(&k, presence, now)?;
            let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
            k.run_task_step(&ctx, id).map_err(kerr).and_then(to_value)
        }
        // What a human approval of this task must name. Reading a hash is not
        // a human act, so no proof is asked for and the machine principal the
        // connection already is does the reading; signing what comes back is
        // the human part, and `approve` is where that is proved.
        "task.subject" => {
            let ctx = ctx_for(&k, presence, now)?;
            let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
            k.approval_subject(&ctx, id)
                .map(|h| json!({ "subject_hash": h }))
                .map_err(kerr)
        }
        "task.show" => {
            let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
            k.task(id).ok_or_else(|| not_found(id)).and_then(to_value)
        }
        "task.ls" => to_value(k.tasks()),
        "top" => to_value(k.top()),
        "stop" => {
            let ctx = ctx_for(&k, presence, now)?;
            let scope = p["scope"].as_str().unwrap_or("node");
            k.stop(&ctx, scope)
                .map(|id| json!({ "stop_id": id }))
                .map_err(kerr)
        }
        "resume" => {
            let ctx = ctx_for(&k, presence, now)?;
            let id = p["stop_id"].as_str().ok_or_else(|| bad("stop_id"))?;
            k.resume(&ctx, id)
                .map(|_| json!({ "ok": true }))
                .map_err(kerr)
        }
        "approve" => {
            let ctx = ctx_for(&k, presence, now)?;
            let a: Approval = serde_json::from_value(p["approval"].clone())
                .map_err(|e| bad(&format!("approval: {e}")))?;
            // The other kinds are the harness's and the auditor's to record,
            // not a local client's to assert: over the pipe, human only, and
            // refused here rather than left to the kernel.
            if a.kind != ApprovalKind::Human {
                return Err(bad("only human approvals are accepted over the transport"));
            }
            k.approve(&ctx, a)
                .map(|_| json!({ "ok": true }))
                .map_err(kerr)
        }
        // The node's own device only. Enrolling any other device would let a
        // same-user process mint the human principals I1 exists to withhold
        // from it; other devices arrive by the admin ceremony (SP1b/SP4).
        "device.enroll_node" => {
            let id = p["device_id"].as_str().ok_or_else(|| bad("device_id"))?;
            let vk_hex = p["vk_hex"].as_str().ok_or_else(|| bad("vk_hex"))?;
            let vk: [u8; 32] = hex::decode(vk_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| bad("vk_hex must be 32 bytes of hex"))?;
            if id != format!("node:{}", k.node_id) {
                return Err(invariant(
                    "I1: only the node's own device may be enrolled over the local endpoint",
                ));
            }
            k.enroll_node_key(vk).map_err(kerr)?;
            Ok(json!({ "ok": true, "device_id": id }))
        }
        "ledger.tail" => {
            let n = p["n"]
                .as_u64()
                .map_or(50, |n| usize::try_from(n).unwrap_or(usize::MAX));
            to_value(k.store().ledger.tail(n))
        }
        "ledger.verify" => Ok(json!({
            "ok": k.ledger().verify_chain(),
            "len": k.ledger().events().len(),
        })),
        m => Err(RpcError {
            code: E_METHOD,
            message: format!("unknown method {m}"),
        }),
    }
}

fn mock_manifest(name: &str, ctx: u32) -> ArchManifest {
    use vk_contracts::arch::*;
    ArchManifest {
        name: name.into(),
        capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
        locality: Locality::Local,
        jurisdiction: "FR".into(),
        retention_days: None,
        cost_per_1k_tokens_eur: 0.0,
        latency_ms_p50: 1,
        context_ceiling: ctx,
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
            max_scope: Scope::Holdout,
            third_party_allowed: true,
        },
        governed: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_expires_after_its_ttl_and_is_gone_once_spent() {
        let mut c = Challenges::default();
        let (nonce, exp) = c.issue(1_000);
        assert_eq!(exp, 1_000 + CHALLENGE_TTL_MS);
        // Past expiry: refused, and removed by the refusal.
        let err = c.spend(&nonce, exp).unwrap_err();
        assert!(err.message.contains("expired"), "{}", err.message);
        assert!(
            c.spend(&nonce, exp - 1).is_err(),
            "spent nonce must be gone"
        );
        // Fresh one, spent in time, then unknown.
        let (nonce, _) = c.issue(2_000);
        assert!(c.spend(&nonce, 2_001).is_ok());
        assert!(c.spend(&nonce, 2_001).is_err());
        assert!(c.spend("never-issued", 2_001).is_err());
    }

    #[test]
    fn open_challenges_are_bounded() {
        let mut c = Challenges::default();
        for i in 0..(MAX_CHALLENGES as u64 + 100) {
            c.issue(i);
        }
        assert!(c.open.len() <= MAX_CHALLENGES);
        // Expired ones are swept when issuing.
        c.issue(CHALLENGE_TTL_MS + MAX_CHALLENGES as u64 + 100);
        assert_eq!(c.open.len(), 1);
    }
}
