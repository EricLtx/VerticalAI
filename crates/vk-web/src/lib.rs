//! The human ceremony's web surface (SP1b Task 5): passkey enrolment and
//! approval pages, served by `vkd` on `127.0.0.1:<port>` — loopback only,
//! never a routable address — and verified in this process with
//! `webauthn-rs`. Windows Hello today, a phone's passkey later, the same page.
//!
//! What this crate is and is not, for invariant I1:
//!
//! - **The kernel mints every challenge.** `POST /approve/<task>/start` asks
//!   the kernel for the task's approval `Challenge` and keeps it server-side,
//!   beside the WebAuthn request state; `finish` hands the kernel that very
//!   challenge back with the verified assertion. No request field ever
//!   carries a challenge in, and no request field ever names a principal:
//!   the approver is the passkey the verifier identified.
//! - **The pages are reachable only by a link the pipe minted.** Loopback
//!   HTTP has no ACL — any local process, of any user, can open the port —
//!   so every page and every call carries a token that `vk passkey enroll`
//!   and `vk approve --passkey` obtained over the kernel's endpoint, whose OS
//!   ACL already restricts it to this user's processes. The link is that ACL
//!   carried over; it is short-lived, bound to a page (and a task), and spent
//!   by the ceremony it served. There is no cookie and no session: the
//!   ceremony state is a random, single-use id the page hands back.
//! - **What is verified, and by whom.** `webauthn-rs` checks the origin, the
//!   relying-party id, its own challenge, the signature over the
//!   authenticator data with the enrolled public key, the user-verification
//!   flag (required) and the signature counter. This crate checks the link,
//!   the state and the task; the kernel checks the minted challenge and
//!   records. Nothing about the *attestation* of the authenticator is
//!   claimed (`attestation: none`): a passkey is trusted because it was
//!   enrolled through the admin link, not because of what made it.
pub mod passkey;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use vk_contracts::labels::{Clearance, Scope};
use vk_contracts::principal::{Approval, ApprovalKind, Challenge, Principal};
use vk_contracts::syscalls::{Ctx, KernelError};
use vk_kernel::{now_ms, RealKernel};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn,
};

/// The kernel, shared with the transport: one mutex, taken for the length of
/// a call and never across an await.
pub type Shared = Arc<Mutex<RealKernel>>;

/// The port `vkd --web-port` defaults to.
pub const DEFAULT_PORT: u16 = 7734;

/// How long a minted link opens its page: long enough to switch to a browser
/// and read what is being approved, and no longer.
pub const LINK_TTL_MS: u64 = 10 * 60 * 1000;
/// How long an enrolment's request state waits for the authenticator.
const ENROL_STATE_TTL_MS: u64 = 5 * 60 * 1000;
/// Open links and open ceremonies are bounded: past this many, the one
/// closest to expiry is dropped. A local process that mints links it never
/// opens cannot grow the maps without limit.
const MAX_OPEN: usize = 64;

/// The proof name the kernel records for an approval verified here.
pub const PROOF: &str = "webauthn";

const ENROLL_HTML: &str = include_str!("../static/enroll.html");
const APPROVE_HTML: &str = include_str!("../static/approve.html");
const VK_JS: &str = include_str!("../static/vk.js");

/// Which page a link opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Enroll,
    Approve,
}

struct Link {
    page: Page,
    task_id: Option<String>,
    expires_at_ms: u64,
}

/// The links this daemon has minted and not yet spent (see the module doc):
/// what `web.link` mints into and every handler checks against.
pub struct Links {
    origin: String,
    open: Mutex<BTreeMap<String, Link>>,
}

impl Links {
    pub fn new(origin: String) -> Links {
        Links {
            origin,
            open: Mutex::new(BTreeMap::new()),
        }
    }

    /// `http://localhost:<port>`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// A link to the enrolment page.
    pub fn enroll_link(&self, now_ms: u64) -> String {
        let t = self.mint(Page::Enroll, None, now_ms);
        format!("{}/enroll?t={t}", self.origin)
    }

    /// A link to the approval page of `task_id`.
    pub fn approve_link(&self, task_id: &str, now_ms: u64) -> String {
        let t = self.mint(Page::Approve, Some(task_id.into()), now_ms);
        format!("{}/approve/{task_id}?t={t}", self.origin)
    }

    fn mint(&self, page: Page, task_id: Option<String>, now_ms: u64) -> String {
        let token = random_token();
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        sweep(&mut open, now_ms, |l| l.expires_at_ms);
        open.insert(
            token.clone(),
            Link {
                page,
                task_id,
                expires_at_ms: now_ms + LINK_TTL_MS,
            },
        );
        token
    }

    /// Does `token` open `page` (for `task_id`) right now? Says nothing about
    /// why not: an unknown token and a token for another page are the same
    /// "not found" to the caller.
    fn admits(&self, token: &str, page: Page, task_id: Option<&str>, now_ms: u64) -> bool {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.get(token).is_some_and(|l| {
            l.page == page && l.task_id.as_deref() == task_id && now_ms < l.expires_at_ms
        })
    }

    /// The ceremony a link was minted for has completed: the link is done.
    fn spend(&self, token: &str) {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    /// How many links are open right now, for a test.
    #[doc(hidden)]
    pub fn open_count(&self, now_ms: u64) -> usize {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|l| l.expires_at_ms > now_ms)
            .count()
    }
}

/// 32 random bytes, base64url: a link token or a ceremony state id.
fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Drop what has expired and, past the cap, what expires soonest.
fn sweep<T>(map: &mut BTreeMap<String, T>, now_ms: u64, expiry: impl Fn(&T) -> u64) {
    map.retain(|_, v| expiry(v) > now_ms);
    while map.len() >= MAX_OPEN {
        let Some(soonest) = map
            .iter()
            .min_by_key(|(_, v)| expiry(v))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&soonest);
    }
}

/// An enrolment under way: the verifier's registration state, waiting for
/// the authenticator's answer.
struct Enrolment {
    state: PasskeyRegistration,
    expires_at_ms: u64,
}

/// An approval under way: the verifier's authentication state **together
/// with the challenge the kernel minted** for the task — the two halves of
/// one ceremony, stored server-side under one single-use id, so the
/// assertion that answers the first can only ever be recorded against the
/// second.
struct PendingAuth {
    state: PasskeyAuthentication,
    task_id: String,
    challenge: Challenge,
}

struct App {
    kernel: Shared,
    node_id: String,
    webauthn: Webauthn,
    links: Arc<Links>,
    enrolments: Mutex<BTreeMap<String, Enrolment>>,
    approvals: Mutex<BTreeMap<String, PendingAuth>>,
}

/// What `build` returns: the router to serve and the links the transport
/// mints into.
pub struct Web {
    pub router: Router,
    pub links: Arc<Links>,
}

/// Bind the pages' listener on loopback. `port` 0 asks the OS for one — for
/// tests, and for a daemon that will report the port it got.
pub async fn bind(port: u16) -> Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("bind 127.0.0.1:{port} for the passkey pages"))
}

/// The pages over `kernel`, for the listener bound on `port`.
pub fn build(kernel: Shared, node_id: &str, port: u16) -> Result<Web> {
    let origin = passkey::origin(port);
    let links = Arc::new(Links::new(origin));
    let app = Arc::new(App {
        kernel,
        node_id: node_id.into(),
        webauthn: passkey::webauthn(port)?,
        links: links.clone(),
        enrolments: Mutex::new(BTreeMap::new()),
        approvals: Mutex::new(BTreeMap::new()),
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/vk.js", get(script))
        .route("/enroll", get(enroll_page))
        .route("/enroll/start", post(enroll_start))
        .route("/enroll/finish", post(enroll_finish))
        .route("/approve/{task_id}", get(approve_page))
        .route("/approve/{task_id}/start", post(approve_start))
        .route("/approve/{task_id}/finish", post(approve_finish))
        .layer(middleware::from_fn(secure_headers))
        .with_state(app);
    Ok(Web { router, links })
}

/// Serve until the listener fails.
pub async fn serve(listener: TcpListener, router: Router) -> Result<()> {
    axum::serve(listener, router)
        .await
        .context("serve the passkey pages")
}

/// Every response, whatever it is: no framing (a Windows Hello prompt must
/// not be raised from inside somebody else's page), no scripts but this
/// origin's own, no referrer (the link token is in the URL), nothing cached.
async fn secure_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; \
             connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// A refusal, as the page's script and a test read it: a status and one line.
#[derive(Debug)]
pub struct WebError {
    status: StatusCode,
    message: String,
}

impl WebError {
    fn new(status: StatusCode, message: impl Into<String>) -> WebError {
        WebError {
            status,
            message: message.into(),
        }
    }
    /// A link that does not open this page: said as little as possible.
    fn not_found() -> WebError {
        WebError::new(StatusCode::NOT_FOUND, "not found")
    }
    fn bad(message: impl Into<String>) -> WebError {
        WebError::new(StatusCode::BAD_REQUEST, message)
    }
    fn forbidden(message: impl Into<String>) -> WebError {
        WebError::new(StatusCode::FORBIDDEN, message)
    }
    fn internal(message: impl Into<String>) -> WebError {
        WebError::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<KernelError> for WebError {
    fn from(e: KernelError) -> WebError {
        let status = match &e {
            KernelError::NotFound(_) => StatusCode::NOT_FOUND,
            KernelError::Gate(_) | KernelError::Stopped(_) => StatusCode::CONFLICT,
            KernelError::Store(_)
            | KernelError::ArchUnavailable(_)
            | KernelError::ArchStarting(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::FORBIDDEN,
        };
        WebError::new(status, e.to_string())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

/// A kernel call from a handler: on the blocking pool, under the lock for
/// its own length only, never across an await — as the transport does it.
async fn with_kernel<T: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&mut RealKernel) -> Result<T, KernelError> + Send + 'static,
) -> Result<T, WebError> {
    let kernel = app.kernel.clone();
    tokio::task::spawn_blocking(move || {
        let mut k = kernel
            .lock()
            .map_err(|_| WebError::internal("kernel lock poisoned"))?;
        f(&mut k).map_err(WebError::from)
    })
    .await
    .map_err(|e| WebError::internal(format!("kernel call aborted: {e}")))?
}

/// The principal a page's own reads run as: this daemon, a machine, at the
/// local endpoint's clearance. Never the approver — that is the passkey.
fn machine_ctx(node_id: &str, now_ms: u64) -> Ctx {
    Ctx {
        principal: Principal::Machine {
            node_id: node_id.into(),
            lease_id: "web".into(),
        },
        clearance: Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        },
        partition: "local".into(),
        now_ms,
    }
}

fn require_link(
    app: &App,
    token: &str,
    page: Page,
    task_id: Option<&str>,
    now_ms: u64,
) -> Result<(), WebError> {
    if app.links.admits(token, page, task_id, now_ms) {
        Ok(())
    } else {
        Err(WebError::not_found())
    }
}

/// The five characters HTML needs escaped, for the values the approve page
/// carries in its markup.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn page(html: String) -> Response {
    Html(html).into_response()
}

#[derive(Deserialize)]
struct TokenQuery {
    #[serde(default)]
    t: String,
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    t: String,
}

#[derive(Deserialize)]
struct EnrollFinish {
    #[serde(default)]
    t: String,
    state_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct ApproveFinish {
    #[serde(default)]
    t: String,
    state_id: String,
    credential: PublicKeyCredential,
}

async fn index() -> &'static str {
    "VerticalAI kernel. The passkey pages open from a link: `vk passkey enroll`, `vk approve <task> --passkey`.\n"
}

async fn script() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        VK_JS,
    )
        .into_response()
}

async fn enroll_page(
    State(app): State<Arc<App>>,
    Query(q): Query<TokenQuery>,
) -> Result<Response, WebError> {
    require_link(&app, &q.t, Page::Enroll, None, now_ms())?;
    Ok(page(
        ENROLL_HTML.replace("{{node_id}}", &escape(&app.node_id)),
    ))
}

/// Start an enrolment: the verifier's creation options, under a fresh state
/// id. Every passkey already enrolled is excluded, so one authenticator does
/// not end up holding two credentials for this node.
async fn enroll_start(
    State(app): State<Arc<App>>,
    Json(body): Json<TokenBody>,
) -> Result<Json<Value>, WebError> {
    let now = now_ms();
    require_link(&app, &body.t, Page::Enroll, None, now)?;
    let existing = with_kernel(&app, |k| k.passkeys()).await?;
    let exclude = passkey::load(existing)
        .into_iter()
        .map(|(_, p)| p.cred_id().clone())
        .collect();
    let (options, state) = app
        .webauthn
        .start_passkey_registration(
            passkey::operator_uuid(&app.node_id),
            &app.node_id,
            "VerticalAI operator",
            Some(exclude),
        )
        .map_err(|e| WebError::internal(format!("cannot start a registration: {e}")))?;
    let state_id = random_token();
    {
        let mut open = app.enrolments.lock().unwrap_or_else(|e| e.into_inner());
        sweep(&mut open, now, |e| e.expires_at_ms);
        open.insert(
            state_id.clone(),
            Enrolment {
                state,
                expires_at_ms: now + ENROL_STATE_TTL_MS,
            },
        );
    }
    Ok(Json(json!({ "state_id": state_id, "options": options })))
}

/// Finish an enrolment: the verifier checks the attestation response against
/// the state; what it hands back is enrolled as a device of the passkey
/// class, and the link that opened this ceremony is spent.
async fn enroll_finish(
    State(app): State<Arc<App>>,
    Json(body): Json<EnrollFinish>,
) -> Result<Json<Value>, WebError> {
    let now = now_ms();
    require_link(&app, &body.t, Page::Enroll, None, now)?;
    // Taken before it is looked at: a state is answered once.
    let Enrolment {
        state,
        expires_at_ms,
    } = app
        .enrolments
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&body.state_id)
        .ok_or_else(|| WebError::bad("unknown or already used enrolment; start again"))?;
    if now >= expires_at_ms {
        return Err(WebError::bad("the enrolment took too long; start again"));
    }
    let passkey = app
        .webauthn
        .finish_passkey_registration(&body.credential, &state)
        .map_err(|e| WebError::forbidden(format!("registration rejected: {e}")))?;
    let device_id = passkey::device_id_of(passkey.cred_id());
    let credential = serde_json::to_value(&passkey)
        .map_err(|e| WebError::internal(format!("cannot serialise the passkey: {e}")))?;
    let id = device_id.clone();
    with_kernel(&app, move |k| k.enroll_passkey(&id, credential, now)).await?;
    app.links.spend(&body.t);
    tracing::info!(device = %device_id, "passkey enrolled");
    Ok(Json(json!({ "ok": true, "device_id": device_id })))
}

/// The approval page: what is being approved — the task's goal and the hash
/// the approval will name — and the one button. Rendered here rather than
/// fetched by the page, so the person reads it before any script runs.
async fn approve_page(
    State(app): State<Arc<App>>,
    Path(task_id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Response, WebError> {
    let now = now_ms();
    require_link(&app, &q.t, Page::Approve, Some(&task_id), now)?;
    let node_id = app.node_id.clone();
    let id = task_id.clone();
    let (goal, artefact_type, subject) = with_kernel(&app, move |k| {
        let ctx = machine_ctx(&node_id, now);
        let t = k
            .task(&ctx, &id)
            .ok_or_else(|| KernelError::NotFound(id.clone()))?;
        let subject = k.approval_subject(&ctx, &id)?;
        Ok((t.goal, t.artefact_type, subject))
    })
    .await?;
    Ok(page(
        APPROVE_HTML
            .replace("{{task_id}}", &escape(&task_id))
            .replace("{{goal}}", &escape(&goal))
            .replace("{{artefact}}", &escape(&artefact_type))
            .replace("{{subject}}", &escape(&subject)),
    ))
}

/// Start an approval: the kernel mints the task's challenge, the verifier
/// makes its request options over every enrolled passkey, and the two are
/// kept together under one state id. The challenge's own expiry bounds the
/// state.
async fn approve_start(
    State(app): State<Arc<App>>,
    Path(task_id): Path<String>,
    Json(body): Json<TokenBody>,
) -> Result<Json<Value>, WebError> {
    let now = now_ms();
    require_link(&app, &body.t, Page::Approve, Some(&task_id), now)?;
    let node_id = app.node_id.clone();
    let id = task_id.clone();
    let (rows, challenge) = with_kernel(&app, move |k| {
        let rows = k.passkeys()?;
        if rows.is_empty() {
            // Before anything is minted: a challenge nobody could answer is
            // a challenge that should not exist.
            return Err(KernelError::Gate(
                "no passkey is enrolled on this node; run `vk passkey enroll` first".into(),
            ));
        }
        let challenge = k.mint_approval_challenge(&machine_ctx(&node_id, now), &id)?;
        Ok((rows, challenge))
    })
    .await?;
    let passkeys: Vec<Passkey> = passkey::load(rows).into_iter().map(|(_, p)| p).collect();
    if passkeys.is_empty() {
        return Err(WebError::new(
            StatusCode::CONFLICT,
            "no enrolled passkey can be read by this verifier; run `vk passkey enroll` again",
        ));
    }
    let (options, state) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| WebError::internal(format!("cannot start an authentication: {e}")))?;
    let state_id = random_token();
    {
        let mut open = app.approvals.lock().unwrap_or_else(|e| e.into_inner());
        sweep(&mut open, now, |p| p.challenge.expires_at_ms);
        open.insert(
            state_id.clone(),
            PendingAuth {
                state,
                task_id,
                challenge: challenge.clone(),
            },
        );
    }
    Ok(Json(json!({
        "state_id": state_id,
        "options": options,
        "challenge": challenge,
    })))
}

/// Finish an approval.
///
/// **I1 argument.** This handler is the only path to a human approval that
/// involves no ed25519 device key. Its verification is `webauthn-rs`'s,
/// against a passkey enrolled through the admin link; the *approver* is the
/// credential the verifier identified, and the *challenge* is the one the
/// kernel minted at `start` and kept beside the request state — the client
/// supplied neither, and could not: there is no request field for either.
/// The state is taken before it is looked at, so an assertion is recorded at
/// most once; an assertion for another state's challenge fails the
/// verifier's challenge check; and the kernel's own spend of the minted
/// challenge is the last word, in-process, through
/// `record_verified_human_approval`, which no syscall reaches.
async fn approve_finish(
    State(app): State<Arc<App>>,
    Path(task_id): Path<String>,
    Json(body): Json<ApproveFinish>,
) -> Result<Json<Value>, WebError> {
    let now = now_ms();
    require_link(&app, &body.t, Page::Approve, Some(&task_id), now)?;
    let pending = app
        .approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&body.state_id)
        .ok_or_else(|| WebError::bad("unknown or already used approval; start again"))?;
    if pending.task_id != task_id {
        return Err(WebError::bad("this approval was started for another task"));
    }
    if now >= pending.challenge.expires_at_ms {
        return Err(WebError::bad("the approval took too long; start again"));
    }
    let result = app
        .webauthn
        .finish_passkey_authentication(&body.credential, &pending.state)
        .map_err(|e| WebError::forbidden(format!("assertion rejected: {e}")))?;
    if !result.user_verified() {
        return Err(WebError::forbidden(
            "assertion rejected: the authenticator did not verify its user",
        ));
    }
    let device_id = passkey::device_id_of(result.cred_id());
    let subject = pending.challenge.action_digest.clone();
    let approval = Approval {
        subject_hash: subject.clone(),
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: device_id.clone(),
        },
        challenge: Some(pending.challenge),
        signature_hex: Some(hex::encode(body.credential.response.signature.as_ref())),
    };
    let node_id = app.node_id.clone();
    let (id, dev) = (task_id.clone(), device_id.clone());
    let status = with_kernel(&app, move |k| {
        // The counter the verifier saw, kept: a replayed or cloned
        // authenticator shows up as a counter that did not move.
        let rows = k.passkeys()?;
        let (_, mut stored) = passkey::load(rows)
            .into_iter()
            .find(|(d, _)| *d == dev)
            .ok_or_else(|| {
                KernelError::I1("assertion by a passkey that is not enrolled".into())
            })?;
        if stored.update_credential(&result) == Some(true) {
            let credential = serde_json::to_value(&stored)
                .map_err(|e| KernelError::Store(format!("cannot serialise the passkey: {e}")))?;
            k.update_passkey(&dev, credential)?;
        }
        k.record_verified_human_approval(now, approval, PROOF)?;
        // The step that was waiting for exactly this: run it, so the task
        // leaves `waiting_human` and whoever is watching it sees the approval
        // land. One step, as `vk task step` runs one; nothing after it.
        let ctx = machine_ctx(&node_id, now);
        let stepped = k.run_task_step(&ctx, &id);
        if let Err(e) = &stepped {
            tracing::warn!(task = %id, error = %e, "approval recorded; the waiting step did not run");
        }
        Ok(k.task(&ctx, &id).map(|t| t.status))
    })
    .await?;
    app.links.spend(&body.t);
    tracing::info!(task = %task_id, device = %device_id, "human approval recorded (webauthn)");
    Ok(Json(json!({
        "ok": true,
        "task_id": task_id,
        "subject_hash": subject,
        "device_id": device_id,
        "status": status,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_opens_its_page_for_its_task_until_spent_or_expired() {
        let links = Links::new("http://localhost:1".into());
        let url = links.approve_link("task-1", 1_000);
        let t = url.rsplit("?t=").next().unwrap().to_string();
        assert!(url.starts_with("http://localhost:1/approve/task-1?t="));
        assert!(links.admits(&t, Page::Approve, Some("task-1"), 1_001));
        assert!(!links.admits(&t, Page::Approve, Some("task-2"), 1_001));
        assert!(!links.admits(&t, Page::Enroll, None, 1_001));
        assert!(!links.admits("other", Page::Approve, Some("task-1"), 1_001));
        assert!(!links.admits(&t, Page::Approve, Some("task-1"), 1_000 + LINK_TTL_MS));
        links.spend(&t);
        assert!(!links.admits(&t, Page::Approve, Some("task-1"), 1_001));

        let e = links.enroll_link(2_000);
        let t = e.rsplit("?t=").next().unwrap().to_string();
        assert!(links.admits(&t, Page::Enroll, None, 2_001));
        assert!(!links.admits(&t, Page::Approve, None, 2_001));
    }

    #[test]
    fn open_links_are_bounded_and_expired_ones_swept() {
        let links = Links::new("http://localhost:1".into());
        for i in 0..(MAX_OPEN as u64 + 10) {
            links.enroll_link(i);
        }
        assert!(links.open_count(0) <= MAX_OPEN);
        links.enroll_link(LINK_TTL_MS + MAX_OPEN as u64 + 100);
        assert_eq!(links.open_count(LINK_TTL_MS + MAX_OPEN as u64 + 100), 1);
    }

    #[test]
    fn markup_values_are_escaped() {
        assert_eq!(
            escape("<b>\"x\" & 'y'</b>"),
            "&lt;b&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/b&gt;"
        );
    }
}
