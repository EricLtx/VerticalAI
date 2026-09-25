//! The server side of the syscall transport: accept, read a line, dispatch,
//! write a line. This module is where principals come from (`ctx_for`), and
//! it is the only place in the workspace that builds a `Ctx` from a live
//! connection — spec §3.6, invariant I1.
use crate::transport::{self, AcceptError, Endpoint};
use crate::{
    PresenceProof, Request, Response, RpcError, E_BAD_PARAMS, E_INTERNAL, E_INVARIANT, E_METHOD,
    E_NOT_FOUND, E_RETRY, E_STORE,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use vk_arch_claude_code::{ClaudeCodeAdapter, ClaudeCodeConfig};
use vk_arch_ollama::{ContainerSpec, OllamaAdapter, OllamaConfig};
use vk_contracts::arch::ArchManifest;
use vk_contracts::labels::{Clearance, Label, Scope};
use vk_contracts::principal::{Approval, ApprovalKind, Principal};
use vk_contracts::syscalls::{Ctx, Kernel, KernelError};
use vk_harness::launch::{self, ExitReason, HarnessConfig, HarnessRun};
use vk_kernel::arch::{ArchAdapter, MockAdapter, MountSpec};
use vk_kernel::tasks::StepKind;
use vk_kernel::{now_ms, RealKernel, Remount};

type Shared = Arc<Mutex<RealKernel>>;

/// What the daemon was started with, beyond the kernel: the endpoint it serves
/// on (a harness's `vk-mcp` dials back on it) and the harness settings — the
/// binary, the model and the run budget — which are the daemon's to set and
/// never a request's (Ruling 20: a pipe client that could name the binary the
/// daemon executes would be code execution as the daemon's account once Task 6
/// puts it under one).
#[derive(Clone)]
pub struct ServerConfig {
    pub endpoint: String,
    pub harness: HarnessSettings,
    /// The loopback web pages this daemon serves (SP1b Task 5), if it serves
    /// any: what `web.link` mints an addressed link into. `None` on a daemon
    /// started without them, and in every transport test.
    pub web: Option<Arc<dyn WebLinks>>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("endpoint", &self.endpoint)
            .field("harness", &self.harness)
            .field("web", &self.web.as_ref().map(|w| w.origin()))
            .finish()
    }
}

impl ServerConfig {
    /// A config with the default harness settings and no web pages, for a
    /// caller (a test) that has only an endpoint.
    pub fn new(endpoint: String) -> ServerConfig {
        ServerConfig {
            endpoint,
            harness: HarnessSettings::default(),
            web: None,
        }
    }
}

/// The web pages' side of `web.link` (SP1b Task 5): mint a link a person can
/// open, carrying a token the pages check. The pages live in `vk-web`, which
/// this crate does not depend on; `vkd` wires the two together. A link is the
/// pipe's ACL carried over to loopback HTTP: only a process that could open
/// this endpoint can obtain one, so only such a process — the interactive
/// user's, in SP1b — can reach the enrolment and approval pages.
pub trait WebLinks: Send + Sync {
    /// `http://localhost:<port>`.
    fn origin(&self) -> String;
    /// A link to the enrolment page, good for a few minutes.
    fn enroll_link(&self, now_ms: u64) -> String;
    /// A link to the approval page of `task_id`, good for a few minutes.
    fn approve_link(&self, task_id: &str, now_ms: u64) -> String;
}

/// How this daemon launches a harness: `vkd --harness-bin`, `--harness-model`,
/// `--harness-timeout-secs`.
#[derive(Debug, Clone)]
pub struct HarnessSettings {
    /// The Claude Code binary: `claude` by default, resolved on the daemon's
    /// own `PATH` to `claude.exe` on Windows (never a `.cmd` shim); a test's
    /// daemon is started with a stand-in.
    pub binary: PathBuf,
    /// The model the harness is pinned to.
    pub model: Option<String>,
    /// How long one run may take before its tree is killed.
    pub timeout: Duration,
}

impl Default for HarnessSettings {
    fn default() -> Self {
        HarnessSettings {
            binary: PathBuf::from("claude"),
            model: Some("claude-sonnet-5".into()),
            timeout: Duration::from_secs(300),
        }
    }
}

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
    let listener = transport::os::bind(&endpoint).await?;
    serve_on(kernel, listener, ServerConfig::new(endpoint.0)).await
}

/// Serve on an endpoint the caller has already bound. `vkd` binds before it
/// boots the kernel, so a daemon refused its endpoint — another one is
/// serving there — has not yet appended its `boot` event to a record it will
/// never serve.
pub async fn serve_on(
    kernel: Shared,
    mut listener: transport::os::Listener,
    config: ServerConfig,
) -> Result<()> {
    let challenges = Arc::new(Mutex::new(Challenges::default()));
    // The endpoint the harness's `vk-mcp` must dial back on and the daemon's
    // harness settings, threaded to every connection for `harness.run`.
    let endpoint = Arc::new(config);
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
        let (k, ch, ep) = (kernel.clone(), challenges.clone(), endpoint.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, k, ch, ep).await {
                tracing::debug!(error = %e, "connection closed");
            }
        });
    }
}

/// Build every arch this node had mounted, one at a time, while the node
/// serves (Task 1b review, Important 1).
///
/// `vkd` spawns this once, after the endpoint is bound and `boot()` has run.
/// Until an arch is installed its state is `Starting`: it is listed, and a
/// step that names it is told to retry rather than failed. Re-creation used to
/// happen inside `RealKernel::open`, before the bind, which left the node
/// answering nothing for the sum of the adapters' mount timeouts — minutes,
/// for a cold container — so `vk boot` timed out at 10 s and killed the daemon
/// it had just started.
///
/// **The kernel mutex is never held across a factory call.** Each iteration
/// takes the lock only to read the queue at the start and, inside the blocking
/// task, for the length of an `install_arch`. The adapter an install did not
/// want goes back out and is dropped here, with the lock released, because
/// dropping one can `docker stop` a container.
///
/// One at a time, not all at once: two cold model loads racing each other help
/// nobody, and the order is the id order an operator sees in `vk ls /arches`.
pub async fn start_arches(kernel: Shared) {
    let Ok((factory, pending)) = kernel
        .lock()
        .map(|k| (k.adapter_factory(), k.pending_mounts()))
    else {
        tracing::error!("kernel lock poisoned; no arch was re-created");
        return;
    };
    if pending.is_empty() {
        return;
    }
    tracing::info!(
        arches = pending.len(),
        "re-creating the arches this node had mounted; it is serving while they come up"
    );
    for (arch_id, spec) in pending {
        let (kernel, factory) = (kernel.clone(), factory.clone());
        // The blocking pool: building an adapter runs child processes and
        // blocking HTTP, which must not sit on a runtime worker.
        let built = tokio::task::spawn_blocking(move || {
            let made = factory(&spec);
            let stale = match kernel.lock() {
                Ok(mut k) => k.install_arch(&arch_id, made),
                Err(_) => None,
            };
            // Here, not in the match: the guard above is gone by now, so an
            // Ollama adapter's `Drop` does its `docker stop` unlocked.
            drop(stale);
        })
        .await;
        if let Err(e) = built {
            tracing::error!("an arch could not be re-created: {e}");
        }
    }
    tracing::info!("every arch has been re-created; `vk ls /arches` says how each one came up");
}

async fn handle_connection(
    stream: Box<dyn transport::Stream>,
    kernel: Shared,
    challenges: Arc<Mutex<Challenges>>,
    endpoint: Arc<ServerConfig>,
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
                let (k, ch, ep) = (kernel.clone(), challenges.clone(), endpoint.clone());
                let outcome = tokio::task::spawn_blocking(move || dispatch(&k, &ch, req, &ep))
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
        // Not `E_NOT_FOUND`: the arch is there and the client can see it in
        // `arch.ls`. What failed is the machinery behind it, which is the
        // store class — the same class an adapter's non-invariant failure
        // already reports (SP1b review, Important 2).
        KernelError::ArchUnavailable(_) | KernelError::Store(_) => E_STORE,
        // Its own code, because it asks the caller for something no other
        // code does: wait and send this again. A client that cannot tell it
        // from `E_STORE` has to treat a four-second container start as a
        // failure (Task 1b review, Important 1).
        KernelError::ArchStarting(_) => E_RETRY,
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
        "task.create" | "task.step" | "stop" | "resume" | "approve" | "web.link"
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
    config: &ServerConfig,
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
    // Mounting a Claude Code arch means running the binary to ask its version,
    // because the version is in the arch identity. That happens here, *before*
    // the kernel lock, so a binary that is slow — or missing, and about to be
    // waited out — delays this one mount rather than every other syscall on
    // the node (SP1b review, Minor 8 / ruling 8).
    let claude_version = (req.method == "arch.mount" && req.params["kind"] == "claude-code")
        .then(|| claude_code_version(&req.params["config"]))
        .transpose()
        .map_err(|e| bad(&format!("{e:#}")))?;
    // The same, and more so, for an Ollama arch: mounting one starts a
    // container, waits for the server and may pull gigabytes of weights. None
    // of that may happen with the kernel lock held.
    let ollama = (req.method == "arch.mount" && req.params["kind"] == "ollama")
        .then(|| ollama_adapter(&req.params["config"]))
        .transpose()
        .map_err(|e| bad(&format!("{e:#}")))?;
    // Handled before the general lock, and taking the kernel lock only in short
    // phases of its own: a harness run launches Claude Code and *waits* for it,
    // and the harness calls back over MCP (`harness.*`) while it runs — so a lock
    // held across the wait would deadlock the harness against its own syscalls
    // (SP1b Task 4).
    if req.method == "harness.run" {
        return harness_run(kernel, config, req.params);
    }
    let mut k = lock(kernel)?;
    let p = req.params;
    match req.method.as_str() {
        "boot.info" => Ok(json!({
            "node_id": k.node_id,
            "arches": k.arches().len(),
            // Which of them came up usable (SP1b ruling 14). The count alone
            // would let a node report two arches on a morning when neither
            // can run, which is the morning somebody most needs to be told.
            "arch_states": k.arch_states().into_iter().map(|(id, _, state)| json!({
                "arch_id": id,
                "state": state.name(),
                "reason": state.reason(),
            })).collect::<Vec<_>>(),
            // How many are still being built. `vk boot` prints it, so the
            // person who just started the node knows the arches are coming
            // rather than wondering why a step says to retry.
            "arches_starting": k.arches_starting(),
            "devices": k.devices().ids().len(),
            "ledger_len": k.ledger().events().len(),
            // The verdict boot reports, not a recomputation of the chain
            // alone: a chain shortened since the store last wrote it still
            // links, and only the kernel knows where its head was.
            "ledger_ok": k.ledger_holds(),
            // Set for this run only, by `record_forced_boot`: this daemon
            // decided to serve `--force` on a chain it just said does not
            // verify. The event naming why is on the record; this is the
            // live marker so `vk status` need not go read it.
            "forced": k.forced_boot(),
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
            // The loopback origin of the passkey pages (SP1b Task 5), `null`
            // on a daemon that serves none. The origin only: a link into the
            // pages is minted by `web.link`, per person, per purpose.
            "web": config.web.as_ref().map(|w| w.origin()),
        })),
        // The link a person opens to enrol a passkey or to approve a task with
        // one (SP1b Task 5). Minted here, over the endpoint, so only a process
        // that could open this pipe gets one; the link is single-use, short
        // and page-bound, and the pages themselves hold both loopback
        // addresses and check the `Host` — see `contracts/tcb.md` for what
        // that does and does not protect. The approve link is minted only for
        // a task that is waiting at its approve step, for the same reason
        // `task.subject` answers only then. The **enrol** link is a human act
        // (review Important 2): a new passkey is admitted only under an
        // existing ceremony — a presence proof by the node's device key
        // today, so a same-user process with the pipe and nothing else cannot
        // enrol a passkey of its own.
        "web.link" => {
            let web = config.web.as_ref().ok_or_else(|| RpcError {
                code: E_STORE,
                message: "this daemon serves no web pages: start vkd with --web-port".into(),
            })?;
            let ctx = ctx_for(&k, presence, now)?;
            match p["page"].as_str().ok_or_else(|| bad("page"))? {
                "enroll" => {
                    if !ctx.principal.is_human() {
                        return Err(invariant(
                            "I1: enrolling a passkey requires a human ceremony: present a presence \
                             proof by this node's device key (`vk passkey enroll` signs one)",
                        ));
                    }
                    Ok(json!({ "url": web.enroll_link(now) }))
                }
                "approve" => {
                    let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
                    let subject = k.approval_subject(&ctx, id).map_err(kerr)?;
                    Ok(json!({ "url": web.approve_link(id, now), "subject_hash": subject }))
                }
                other => Err(bad(&format!("no web page {other}"))),
            }
        }
        // The enrolled passkeys, by id and enrolment time. Never the
        // credential: a public key is a public value, but nothing outside the
        // verifier needs it and a listing that carries one invites it into a
        // log (SP1b Task 5).
        "passkey.ls" => to_value(
            k.passkeys()
                .map_err(kerr)?
                .into_iter()
                .map(|p| json!({ "device_id": p.device_id, "enrolled_ms": p.enrolled_ms }))
                .collect::<Vec<_>>(),
        ),
        // The read surfaces carry a `Ctx` too: a task shows its register's
        // goal, and what a caller may see of it is the register's label
        // against the caller's clearance (I2), as for `read_register`.
        "ns.ls" => {
            let ctx = ctx_for(&k, presence, now)?;
            let path = p["path"].as_str().unwrap_or("/");
            vk_kernel::ns::resolve(&k, &ctx, path)
                .map_err(kerr)
                .and_then(to_value)
        }
        // Every arch this node has mounted, with the state that says whether
        // calling it would work (SP1b ruling 14). An unavailable arch is
        // listed rather than hidden: it is the thing an operator has to go and
        // fix, and leaving it out is how nobody ever does.
        "arch.ls" => to_value(
            k.arch_states()
                .into_iter()
                .map(|(id, m, state)| {
                    json!({
                        "arch_id": id,
                        "manifest": m,
                        "state": state.name(),
                        "reason": state.reason(),
                    })
                })
                .collect::<Vec<_>>(),
        ),
        // The one door a *real* arch comes in by. `kind` picks the adapter and
        // `config` is that adapter's own shape, because every engine is
        // configured differently and the transport should not have to know
        // how; what comes back is the same pair for all of them, so a client
        // that mounts a new kind needs no new verb (SP1b ruling 4).
        "arch.mount" => {
            let kind = p["kind"].as_str().ok_or_else(|| bad("kind"))?;
            // Recorded before anything is mounted, so a config this node could
            // not make a spec out of — one carrying a credential — is refused
            // rather than mounted into an arch no boot can bring back.
            let spec = mount_spec_of(kind, &p["config"])?;
            let adapter: Arc<dyn ArchAdapter> = match kind {
                "claude-code" => {
                    let version = claude_version.ok_or_else(|| internal("no claude version"))?;
                    let state_dir = k.store().state_dir.clone();
                    Arc::new(
                        claude_code_adapter(&state_dir, &p["config"], &version)
                            .map_err(|e| bad(&format!("{e:#}")))?,
                    )
                }
                // Already mounted, above, before the lock: all that is left
                // here is to hand the kernel the adapter it produced.
                "ollama" => Arc::new(ollama.ok_or_else(|| internal("no ollama adapter"))?),
                other => return Err(bad(&format!("no arch kind {other}"))),
            };
            let name = adapter.manifest().name.clone();
            // Said here rather than looked up afterwards: whether the kernel
            // contains the process is the first thing a person mounting an
            // arch needs to know, and it is the difference between the two
            // kinds this node can mount.
            let governed = adapter.manifest().governed;
            // A repeat mount keeps the arch that is there (Ruling 13). The
            // exception is a caller who has just re-made what is behind it:
            // `--recreate` replaced the container, so the adapter holding the
            // old one is stale however identical its manifest looks.
            let remount = if kind == "ollama" && p["config"]["recreate"] == Value::Bool(true) {
                Remount::Replace
            } else {
                Remount::Keep
            };
            let outcome = k
                .mount_with(adapter, spec, remount)
                .map_err(|e| bad(&e.to_string()))?;
            let answer = json!({
                "arch_id": outcome.arch_id,
                "name": name,
                "governed": governed,
                "already_mounted": outcome.already_mounted,
            });
            // Out from under the kernel mutex before anything it replaced is
            // dropped: an Ollama adapter's `Drop` is a `docker stop`.
            drop(k);
            drop(outcome.replaced);
            Ok(answer)
        }
        "arch.mount_mock" => {
            let name = p["name"].as_str().unwrap_or("mock");
            let ceiling = p["context_ceiling"]
                .as_u64()
                .map_or(Ok(4096), u32::try_from)
                .map_err(|_| bad("context_ceiling"))?;
            let manifest = mock_manifest(name, ceiling);
            // The mock gets a spec like every other kind: a mock arch that
            // vanished on restart would be a second, quieter version of the
            // bug this task is about.
            let spec = MountSpec::mock(&manifest, ceiling);
            let adapter = MockAdapter {
                manifest,
                budget: ceiling,
            };
            let outcome = k
                .mount(Arc::new(adapter), spec)
                .map_err(|e| bad(&e.to_string()))?;
            Ok(json!({
                "arch_id": outcome.arch_id,
                "already_mounted": outcome.already_mounted,
            }))
        }
        "arch.unmount" => {
            let id = p["arch_id"].as_str().ok_or_else(|| bad("arch_id"))?;
            let removed = k.unmount(id).map_err(|e| RpcError {
                code: E_STORE,
                message: e.to_string(),
            })?;
            // Out from under the kernel mutex *before* the adapter is dropped.
            // Dropping an Ollama arch stops the container it started, which is
            // a `docker stop` of ten seconds or more, and the kernel lock is
            // the one thing that must never be held across a slow external
            // call (SP1b Task 1 review, Minor 10). The row and the ledger
            // event are already durable at this point; what is left is the
            // process, and every other syscall can proceed while it winds up.
            drop(k);
            drop(removed);
            Ok(json!({ "ok": true }))
        }
        // The harness's own syscalls (SP1b Task 4). Each carries the lease token
        // `vk-mcp` was launched with; the kernel maps it to the harness principal
        // at the harness clearance. No presence proof is accepted (they are not
        // in `takes_presence`), because a lease is a machine capability, not a
        // human's presence; an unknown or expired token is an I1 refusal.
        "harness.read_register" => {
            let s = harness_session(&k, &p, now)?;
            k.read_register(&s.ctx, &s.register)
                .map_err(kerr)
                .and_then(to_value)
        }
        "harness.write_decision" => {
            let s = harness_session(&k, &p, now)?;
            let text = p["text"].as_str().ok_or_else(|| bad("text"))?;
            let mut reg = k.read_register(&s.ctx, &s.register).map_err(kerr)?;
            reg.decisions.push(format!("harness: {text}"));
            k.write_register(&s.ctx, reg).map_err(kerr)?;
            Ok(json!({ "ok": true }))
        }
        "harness.attach_artefact" => {
            let token = p["token"].as_str().ok_or_else(|| bad("token"))?;
            let kind = p["kind"].as_str().ok_or_else(|| bad("kind"))?;
            let path = p["path"].as_str().ok_or_else(|| bad("path"))?;
            // The kernel resolves the token, confines the path to the
            // workspace, holds the file to the per-file and per-run caps and
            // attaches it at the harness clearance (Ruling 21.6).
            let env = k
                .harness_attach_file(token, now, kind, path)
                .map_err(kerr)?;
            Ok(json!({ "hash": env.hash }))
        }
        "harness.request_approval" => {
            let s = harness_session(&k, &p, now)?;
            let mut reg = k.read_register(&s.ctx, &s.register).map_err(kerr)?;
            reg.open_questions
                .push("approval requested by the harness".into());
            k.write_register(&s.ctx, reg).map_err(kerr)?;
            Ok(json!({ "ok": true, "requested": true }))
        }
        "harness.log" => {
            // Validate the token even though the message only goes to the log:
            // an unknown token is refused here rather than quietly accepted.
            let s = harness_session(&k, &p, now)?;
            let msg = p["message"].as_str().unwrap_or("");
            tracing::info!(task = %s.task_id, harness = %msg, "harness log");
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
        // The challenge a human approval of this task must answer (SP1b Task
        // 5, invariant I1): minted by the kernel — the subject, the resource,
        // a fresh nonce and a short expiry are all its — and never by the
        // client, which used to build its own. `approve` accepts only a
        // challenge that came out of here (or out of the passkey page's own
        // mint), unspent and unexpired. Minting is not a human act, so no
        // proof is asked for; answering it is, and `approve` is where that is
        // proved. Not a `harness.*` method: a harness cannot mint one.
        "approval.challenge" => {
            let ctx = ctx_for(&k, presence, now)?;
            let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
            k.mint_approval_challenge(&ctx, id)
                .map_err(kerr)
                .and_then(to_value)
        }
        // A task, plus what each of its steps left in the register's
        // `decisions` — a count, a length and a hash per step, never the text
        // (Ruling 28). `decisions` is a field of `Register`, so this is the one
        // place a caller with no lease learns that a step left the next one
        // something to read; the summary is computed through `read_register`,
        // under the same I2 check, so a register the caller is not cleared for
        // yields no counts either. It rides on the task object rather than
        // beside it because it is per step, and the steps are there.
        "task.show" => {
            let ctx = ctx_for(&k, presence, now)?;
            let id = p["task_id"].as_str().ok_or_else(|| bad("task_id"))?;
            let task = k.task(&ctx, id).ok_or_else(|| not_found(id))?;
            let decisions = k.task_decisions(&ctx, &task).map_err(kerr)?;
            let mut out = to_value(task)?;
            if let Some(o) = out.as_object_mut() {
                o.insert("decisions".into(), to_value(decisions)?);
            }
            Ok(out)
        }
        "task.ls" => {
            let ctx = ctx_for(&k, presence, now)?;
            to_value(k.tasks(&ctx))
        }
        "top" => {
            let ctx = ctx_for(&k, presence, now)?;
            to_value(k.top(&ctx))
        }
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
            "ok": k.ledger_holds(),
            "len": k.ledger().events().len(),
        })),
        m => Err(RpcError {
            code: E_METHOD,
            message: format!("unknown method {m}"),
        }),
    }
}

/// The `claude` binary a `config` names, defaulted.
fn claude_binary(config: &Value) -> std::path::PathBuf {
    config.get("binary").and_then(Value::as_str).map_or_else(
        || ClaudeCodeConfig::default().binary,
        std::path::PathBuf::from,
    )
}

/// Ask that binary its version, and refuse the mount if it cannot say.
///
/// The version is part of the arch identity: a mount without it would mint an
/// arch id naming no particular Claude Code, and every call on it would fail
/// anyway — so it is refused here, where the person mounting is still
/// listening. Called before the kernel lock is taken, and again at boot by the
/// factory, where a binary that is gone is what makes the arch unavailable.
fn claude_code_version(config: &Value) -> anyhow::Result<String> {
    let binary = claude_binary(config);
    vk_arch_claude_code::probe_version(&binary).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot run `{} --version`: install Claude Code, or pass the binary's path",
            binary.display()
        )
    })
}

/// How this node makes an adapter out of a persisted [`MountSpec`] — the three
/// kinds it is compiled with (SP1b ruling 14).
///
/// `vkd` hands this to `RealKernel::open_with_factory`, and the kernel calls
/// it once per persisted arch at boot. It is the *same* code `arch.mount`
/// runs, reached by the same `kind` and the same `config`, which is the only
/// way a re-created arch can be relied on to be the arch that was mounted:
/// two construction paths would drift, and the drift would show up as an arch
/// id that changed under an operator who did nothing.
///
/// `state_dir` is this node's, not a client's: it is where the Claude Code
/// arch's working directory lives, and a spec does not get to name it.
///
/// Everything slow is inside the adapters and bounded by their own timeouts —
/// `claude --version`, a `docker start`, waiting for the Ollama server — so a
/// boot costs at worst one such timeout per arch. An error is an unavailable
/// arch, never a boot that fails: an engine that is not running is not a
/// reason for a node to stop serving everything else it has.
pub fn adapter_factory(state_dir: std::path::PathBuf) -> vk_kernel::AdapterFactory {
    let mock = vk_kernel::mock_factory();
    Arc::new(move |spec: &MountSpec| -> Result<Box<dyn ArchAdapter>> {
        match spec.kind.as_str() {
            "mock" => mock(spec),
            "claude-code" => {
                let version = claude_code_version(&spec.config)?;
                Ok(Box::new(claude_code_adapter(
                    &state_dir,
                    &spec.config,
                    &version,
                )?))
            }
            "ollama" => Ok(Box::new(ollama_adapter(&spec.config)?)),
            other => anyhow::bail!("no arch kind {other}"),
        }
    })
}

/// The spec `arch.mount` records for what it just mounted.
///
/// `recreate` never survives into it: it destroys and rebuilds a container, so
/// a spec carrying it would throw the container away on every boot (Ruling
/// 10). It is an action a person asks for once, not a property of the arch.
fn mount_spec_of(kind: &str, config: &Value) -> Result<MountSpec, RpcError> {
    let mut config = config.clone();
    if let Some(map) = config.as_object_mut() {
        map.remove("recreate");
    }
    MountSpec::new(kind, config).map_err(|e| bad(&format!("{e:#}")))
}

/// Build the Claude Code adapter `arch.mount { kind: "claude-code" }` asks
/// for. Everything in `config` is optional and falls back to the adapter's own
/// defaults; the working directory does not, because it is this node's to
/// choose and not a client's (SP1b ruling 4).
fn claude_code_adapter(
    state_dir: &std::path::Path,
    config: &Value,
    claude_version: &str,
) -> anyhow::Result<ClaudeCodeAdapter> {
    let defaults = ClaudeCodeConfig::default();
    let u32_of = |name: &str, fallback: u32| -> anyhow::Result<u32> {
        match config.get(name) {
            None | Some(Value::Null) => Ok(fallback),
            Some(v) => v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| anyhow::anyhow!("{name} must be a whole number of tokens")),
        }
    };
    // One fixed, empty directory under the state directory, not a temp
    // directory per call: `claude` creates `~/.claude/projects/<mangled
    // cwd>/memory/` for wherever it runs, so a new directory each time would
    // leave a new one of those behind each time (spike 2a).
    let cwd = state_dir.join("claude-code-cwd");
    vk_store::paths::private_dir(&cwd).with_context(|| format!("create {}", cwd.display()))?;
    let default_timeout = u32::try_from(defaults.timeout.as_secs()).unwrap_or(u32::MAX);
    let cfg = ClaudeCodeConfig {
        binary: claude_binary(config),
        model: config
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(&defaults.model)
            .to_string(),
        max_turns: u32_of("max_turns", defaults.max_turns)?,
        timeout: Duration::from_secs(u64::from(u32_of("timeout_secs", default_timeout)?)),
        context_ceiling: u32_of("context_ceiling", defaults.context_ceiling)?,
        cwd,
    };
    // `with_version`, not `new`: the binary was already asked, before the lock.
    Ok(ClaudeCodeAdapter::with_version(cfg, claude_version))
}

/// Build and mount the Ollama adapter `arch.mount { kind: "ollama" }` asks
/// for. Called before the kernel lock is taken, because this is the call that
/// starts a container, waits up to a minute for the server and pulls the model
/// if it is not there yet (SP1b ruling 4).
///
/// A `base_url` in the config is what asks for the ungoverned mode: naming a
/// server that is already running says this node did not start it. Saying
/// nothing gets the container, on loopback, under this node's caps — the
/// ungoverned arch is one a person has to ask for by name.
fn ollama_adapter(config: &Value) -> anyhow::Result<OllamaAdapter> {
    let defaults = OllamaConfig::default();
    let u32_of = |name: &str, fallback: u32| -> anyhow::Result<u32> {
        match config.get(name) {
            None | Some(Value::Null) => Ok(fallback),
            Some(v) => v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| anyhow::anyhow!("{name} must be a whole number")),
        }
    };
    let string_of = |name: &str, fallback: &str| -> String {
        config
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or(fallback)
            .to_string()
    };
    // Ungoverned only when the client names the server it wants: no `base_url`
    // means the container, on loopback, under this node's caps.
    let external = config.get("base_url").and_then(Value::as_str);
    let container = external.is_none().then(|| ContainerSpec {
        image: string_of("image", &ContainerSpec::default().image),
        memory: string_of("memory", &ContainerSpec::default().memory),
        cpus: string_of("cpus", &ContainerSpec::default().cpus),
        ..ContainerSpec::default()
    });
    let cfg = OllamaConfig {
        base_url: external.unwrap_or(&defaults.base_url).to_string(),
        model: string_of("model", &defaults.model),
        num_ctx: u32_of("num_ctx", defaults.num_ctx)?,
        max_tokens: u32_of("max_tokens", defaults.max_tokens)?,
        seed: match config.get("seed") {
            None | Some(Value::Null) => defaults.seed,
            Some(v) => v
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("seed must be a whole number"))?,
        },
        temperature: defaults.temperature,
        container,
        // Only ever what the client said, and only in container mode: this
        // one destroys a container, so it is never a default (Ruling 10).
        recreate: config.get("recreate") == Some(&Value::Bool(true)),
    };
    OllamaAdapter::mount(cfg)
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

/// Resolve the lease token in a `harness.*` request to the session it names.
fn harness_session(
    k: &RealKernel,
    p: &Value,
    now: u64,
) -> Result<vk_kernel::HarnessSession, RpcError> {
    let token = p["token"].as_str().ok_or_else(|| bad("token"))?;
    k.harness_session(token, now).map_err(kerr)
}

/// The `vk-mcp` binary this daemon launches a harness's MCP server as: next to
/// this executable, same target directory.
fn mcp_server_path() -> PathBuf {
    let name = format!("vk-mcp{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .map(|p| p.with_file_name(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The prompt a harness is launched with: the fixed instruction, plus — when
/// the daemon's **own process environment** carries `VK_HARNESS_PROMPT_SUFFIX`
/// — an operator's addendum. A diagnostic seam of the same class as `VK_DOCKER`:
/// read from `vkd`'s environment, never from a request, so no pipe client can
/// reach it. It exists so the fence can be proved from the operator's side of
/// the prompt — a "try to read `C:\Windows\win.ini`" placed in a task's files is
/// content the model rightly treats as an injection and refuses to act on,
/// which proves the model's judgement and nothing about the fence.
fn harness_prompt(base: &str) -> String {
    match std::env::var("VK_HARNESS_PROMPT_SUFFIX") {
        Ok(suffix) if !suffix.trim().is_empty() => format!("{base}\n\n{}", suffix.trim()),
        _ => base.to_string(),
    }
}

/// The operator's *system-prompt* addendum, from the daemon's own environment
/// (`VK_HARNESS_SYSTEM_SUFFIX`), same class of seam as `harness_prompt`'s. The
/// channel a confinement diagnostic has to use: in the two proof runs of the
/// Task 4 fix round the model refused to act on the diagnostic when it came as
/// task content and again when it came in the user turn — "not delivered
/// through a trusted system channel" — so this is that channel. Empty in every
/// ordinary run.
fn harness_system_suffix() -> Option<String> {
    std::env::var("VK_HARNESS_SYSTEM_SUFFIX")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// A run record for a launch that never started (the binary could not be
/// spawned, or the launch panicked): nothing ran, so nothing was contained and
/// nothing was reached.
fn failed_run() -> HarnessRun {
    HarnessRun {
        exit_code: None,
        exit_reason: ExitReason::NotStarted,
        stdout_json: String::new(),
        outcome: None,
        connections: Vec::new(),
        samples: 0,
        duration_ms: 0,
        governed: false,
    }
}

/// `--harness-bin` as `vkd` settles it at start (Ruling 22, M14). A path is
/// made absolute against the daemon's own working directory and must exist and
/// be a file — refused at start, not at the first run, and never resolved
/// against the workspace the child runs in. (Absolute, not canonical: the OS
/// follows a symlink at exec, and Windows' canonical form carries a `\\?\`
/// prefix the launch line should not print.) A bare name is looked up on the
/// daemon's `PATH` now and pinned to what was found; one that is not there is a
/// warning here and a refusal of each run until the daemon is restarted with a
/// path — a node serves without its harness, it does not refuse to start.
pub fn harness_binary_at_start(binary: &std::path::Path) -> Result<PathBuf> {
    if binary.components().count() > 1 || binary.is_absolute() {
        let abs = std::path::absolute(binary)
            .with_context(|| format!("resolve --harness-bin {}", binary.display()))?;
        anyhow::ensure!(
            abs.is_file(),
            "--harness-bin {} is not a file (resolved from {})",
            abs.display(),
            binary.display()
        );
        return resolve_harness_binary(&abs);
    }
    match resolve_harness_binary(binary) {
        // Absolute even when found through a relative `PATH` entry.
        Ok(found) => Ok(std::path::absolute(&found).unwrap_or(found)),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "no harness binary at start: every harness run will be refused until vkd is started with --harness-bin <path>");
            Ok(binary.to_path_buf())
        }
    }
}

/// The harness binary as the daemon will execute it (Ruling 20).
///
/// An explicit path must be absolute — `vkd` makes it so at start
/// ([`harness_binary_at_start`]), so a relative one here is a configuration no
/// daemon produced — and must be a file. A bare name is looked up on the
/// daemon's own `PATH`: on Windows as `<name>.exe` — never `<name>.cmd` or
/// `<name>.bat`, a shim that would spawn the real binary as a grandchild before
/// the governor can contain the tree — and elsewhere as `<name>`.
pub fn resolve_harness_binary(binary: &std::path::Path) -> Result<PathBuf> {
    if binary.components().count() > 1 || binary.is_absolute() {
        anyhow::ensure!(
            binary.is_absolute(),
            "harness binary {} is a relative path: vkd resolves --harness-bin at start, so give an absolute path or a bare name",
            binary.display()
        );
        anyhow::ensure!(
            binary.is_file(),
            "harness binary {} does not exist (vkd --harness-bin)",
            binary.display()
        );
        if binary
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
        {
            tracing::warn!(binary = %binary.display(), "the harness binary is a .cmd/.bat shim: its child may escape containment");
        }
        return Ok(binary.to_path_buf());
    }
    let name = binary.to_string_lossy().into_owned();
    let candidates: Vec<String> = if cfg!(windows) {
        if name.to_ascii_lowercase().ends_with(".exe") {
            vec![name.clone()]
        } else {
            vec![format!("{name}.exe")]
        }
    } else {
        vec![name.clone()]
    };
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        for c in &candidates {
            let p = dir.join(c);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    anyhow::bail!(
        "harness binary `{name}` not found on the daemon's PATH{}; start vkd with --harness-bin <path>",
        if cfg!(windows) { " (as an .exe)" } else { "" }
    )
}

/// What `harness.run` takes, and nothing else (Rulings 20 and 22): an unknown
/// key is a bad request, not a silently ignored one.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessRunParams {
    task_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    keep: bool,
}

/// `harness.run`: the confined Claude Code harness, driven in three phases so the
/// kernel lock is never held across the wait (SP1b Task 4).
///
/// The request carries `task_id`, `name`, `dry_run` and `keep` — nothing that
/// chooses what executes: the binary, the model and the budget are the daemon's
/// (Ruling 20), and a request that names them, or anything else, is refused
/// (−32602). Everything that can be refused is refused *before* phase one, so a
/// refusal leases nothing.
///
/// Phase one leases, mints the token and materialises under the lock; phase two
/// launches and waits with the lock released, so the harness's own `harness.*`
/// syscalls can be served; phase three settles under the lock — on every
/// outcome, a panic in the launch included (Ruling 21.4). `--dry-run` returns
/// the launch line, the `mcp.json` (token redacted) and the `settings.json`,
/// and runs nothing.
fn harness_run(kernel: &Shared, config: &ServerConfig, p: Value) -> Result<Value, RpcError> {
    for forbidden in ["bin", "binary", "model", "timeout_secs", "timeout"] {
        if p.get(forbidden).is_some() {
            return Err(bad(&format!(
                "harness.run does not take `{forbidden}`: the harness binary, model and timeout \
                 are daemon configuration (vkd --harness-bin, --harness-model, --harness-timeout-secs)"
            )));
        }
    }
    let params: HarnessRunParams = serde_json::from_value(p).map_err(|e| {
        bad(&format!(
            "harness.run takes task_id, name, dry_run and keep, nothing else: {e}"
        ))
    })?;
    let task_id = params.task_id;
    let name = params.name.unwrap_or_else(|| "claude-code".to_string());
    let dry_run = params.dry_run;
    let keep = params.keep;
    let settings = &config.harness;
    let timeout = settings.timeout;

    // Refused before anything is leased: a binary that is not there, a `vk-mcp`
    // that is not there (a tool-less Claude that "succeeds" is not a run), or a
    // governor the OS will not give.
    let binary =
        resolve_harness_binary(&settings.binary).map_err(|e| internal(&format!("{e:#}")))?;
    let mcp_server = mcp_server_path();
    if !dry_run && !mcp_server.is_file() {
        return Err(internal(&format!(
            "no vk-mcp next to this daemon at {}: the harness would run without its kernel channel",
            mcp_server.display()
        )));
    }
    let (state_dir, workspace, config_dir) = {
        let k = lock(kernel)?;
        (
            k.store().state_dir.clone(),
            k.harness_workspace_dir(&task_id),
            k.harness_config_dir(&task_id),
        )
    };

    if dry_run {
        let cfg = HarnessConfig {
            binary,
            workspace: workspace.clone(),
            config_dir: config_dir.clone(),
            state_dir,
            lease_token: launch::REDACTED_TOKEN.to_string(),
            endpoint: config.endpoint.clone(),
            mcp_server,
            prompt: harness_prompt(vk_kernel::tasks::HARNESS_PROMPT),
            model: settings.model.clone(),
            timeout,
            system_suffix: harness_system_suffix(),
        };
        return Ok(json!({
            "dry_run": true,
            "task_id": task_id,
            "workspace": workspace.display().to_string(),
            "config_dir": config_dir.display().to_string(),
            "launch_line": launch::launch_line(&cfg),
            "mcp_json": launch::mcp_json(&cfg, launch::REDACTED_TOKEN),
            "settings_json": launch::settings_json(&cfg),
        }));
    }

    // JobGovernor::new(2 GiB, None) on Windows; the Noop elsewhere. Made before
    // the lease, so a refused governor leases nothing.
    let governor = vk_harness::confine::for_this_platform(2 * 1024 * 1024 * 1024, None)
        .map_err(|e| internal(&format!("governor: {e:#}")))?;

    // Phase one: lease, token, workspace, under the lock.
    let launch_plan = {
        let mut k = lock(kernel)?;
        let ctx = ctx_for(&k, None, now_ms())?;
        k.harness_launch(&ctx, &task_id, &name, timeout.as_millis() as u64)
            .map_err(kerr)?
    };

    // Phase two: launch and wait, lock released, so `harness.*` callbacks serve.
    // A panic here is a run that did not start, not a step left `Running`.
    let cfg = HarnessConfig {
        binary,
        workspace: launch_plan.workspace.clone(),
        config_dir: launch_plan.config_dir.clone(),
        state_dir,
        lease_token: launch_plan.token.clone(),
        endpoint: config.endpoint.clone(),
        mcp_server,
        prompt: harness_prompt(&launch_plan.prompt),
        model: settings.model.clone(),
        timeout,
        system_suffix: harness_system_suffix(),
    };
    let stop_kernel = kernel.clone();
    let should_stop = move || {
        stop_kernel
            .lock()
            .map(|k| k.stopped_scopes().iter().any(|s| s == "node"))
            .unwrap_or(false)
    };
    let launched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        launch::launch_claude_code(&cfg, governor, &should_stop)
    }));
    let (run, launch_error) = match launched {
        Ok(Ok(run)) => (run, None),
        Ok(Err(e)) => (failed_run(), Some(format!("{e:#}"))),
        Err(_) => (
            failed_run(),
            Some("the harness launch panicked".to_string()),
        ),
    };

    // Phase three: settle, under the lock — whatever the run was.
    let mut k = lock(kernel)?;
    let ctx = ctx_for(&k, None, now_ms())?;
    let task = k
        .harness_settle(&ctx, &task_id, &launch_plan, &run, keep)
        .map_err(kerr)?;
    let (artefact, artefacts) = k
        .read_register(&ctx, &task.register)
        .ok()
        .map(|r| {
            (
                r.artefacts.last().map(|a| a.hash.clone()),
                r.artefacts.len(),
            )
        })
        .unwrap_or((None, 0));
    let step_status = task
        .steps
        .get(launch_plan.step_index)
        .map(|s| serde_json::to_value(&s.status).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let outcome = run.outcome.as_ref();
    Ok(json!({
        "task_id": task.id,
        "status": serde_json::to_value(task.status).unwrap_or(Value::Null),
        "step_status": step_status,
        "exit": run.exit_reason.label(),
        "governed": run.governed,
        "connections": run.connections,
        "samples": run.samples,
        "duration_ms": run.duration_ms,
        "artefact_hash": artefact,
        "artefacts": artefacts,
        "cost_list_usd": outcome.map(|o| o.total_cost_usd),
        "num_turns": outcome.map(|o| o.num_turns),
        "permission_denials": outcome.map(|o| o.permission_denials.clone()).unwrap_or_default(),
        "kept": keep,
        "error": launch_error,
    }))
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
