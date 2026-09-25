//! The human ceremony's web surface (SP1b Task 5): passkey enrolment and
//! approval pages, served by `vkd` on loopback — `127.0.0.1:<port>` **and**
//! `[::1]:<port>`, never a routable address — and verified in this process
//! with `webauthn-rs`. Windows Hello today, a phone's passkey later, the same
//! page.
//!
//! What this crate is and is not, for invariant I1:
//!
//! - **The kernel mints every challenge, and the authenticator signs it.**
//!   `POST /approve/<task>/start` has the verifier generate the WebAuthn
//!   challenge and then asks the kernel to mint the task's approval
//!   `Challenge` with that value as its nonce: one value, bound by the kernel
//!   to the task's subject, resource and expiry, signed by the authenticator
//!   inside `clientDataJSON`, spent by the kernel on first use. `finish`
//!   hands the kernel that challenge back with the verified assertion — the
//!   bytes the authenticator signed go onto the record beside the approval,
//!   so the recorded signature can be checked again by anyone with the
//!   record and the enrolled public key. No request field ever carries a
//!   challenge in, and no request field ever names a principal: the approver
//!   is the passkey the verifier identified.
//! - **What protects the pages, and from whom.** Loopback HTTP has no ACL:
//!   any local process, of any user, can connect to the port. So (1) `vkd`
//!   holds *both* loopback addresses and refuses to start if either is taken
//!   — a browser asked for `localhost` may connect to `::1` first, and an
//!   address this daemon did not hold was one a rogue local listener could
//!   receive the link on (review Critical 1); (2) every page and every call
//!   carries a link token minted only over the kernel's endpoint (`web.link`),
//!   short-lived, bound to a page and a task, spent by the ceremony it served
//!   — there is no cookie and no session, and ceremony state ids are random
//!   and single-use; (3) every request's `Host` must be this server's own
//!   name on its own port. A request without a live token is told `404` and
//!   nothing else.
//! - **What is verified, and by whom.** `webauthn-rs` checks the origin, the
//!   relying-party id, the challenge, the signature over the authenticator
//!   data with the enrolled public key, the user-verification flag
//!   (required) and the signature counter. This crate checks the link, the
//!   state, the task and that the signed challenge is the minted nonce; the
//!   kernel checks the minted challenge and records. Nothing about the
//!   *attestation* of the authenticator is claimed (`attestation: none`): a
//!   passkey is trusted because it was enrolled under an existing human
//!   ceremony (`web.link enroll` takes a presence proof), not because of
//!   what made it.
pub mod passkey;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, Request, State},
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
use std::future::IntoFuture;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use vk_contracts::labels::{Clearance, Scope};
use vk_contracts::principal::{Approval, ApprovalKind, Challenge, Principal};
use vk_contracts::syscalls::{Ctx, KernelError};
use vk_kernel::tasks::TaskStatus;
use vk_kernel::{now_ms, AssertionRecord, RealKernel};
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
/// How many OS-chosen ports `bind(0)` tries before giving up on finding one
/// free on both loopback addresses.
const EPHEMERAL_TRIES: usize = 32;

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

/// An approval under way: the verifier's authentication state and the
/// challenge the kernel minted for the task **with the verifier's challenge
/// as its nonce** — one value in two records, stored server-side under one
/// single-use id, so the assertion that answers the first is the assertion
/// that spends the second.
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
    /// The `Host` values this server answers to: its own three names on its
    /// own port, nothing else.
    hosts: [String; 3],
    enrolments: Mutex<BTreeMap<String, Enrolment>>,
    approvals: Mutex<BTreeMap<String, PendingAuth>>,
}

/// What `build` returns: the router to serve and the links the transport
/// mints into.
pub struct Web {
    pub router: Router,
    pub links: Arc<Links>,
}

/// The pages' listeners: one per loopback family, on one port. Both, because
/// a browser asked for `localhost` may connect to either, and the family this
/// daemon does not hold is the one anybody else may (review Critical 1).
pub struct Listeners {
    v4: TcpListener,
    /// `None` only on a host with no IPv6 loopback at all, where `localhost`
    /// cannot resolve to `::1` and nobody can bind it either.
    v6: Option<TcpListener>,
    port: u16,
}

impl Listeners {
    /// The port both listeners hold.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Is `[::1]` held too?
    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    /// What is bound, for the log: `127.0.0.1:<p>, [::1]:<p>`.
    pub fn bound(&self) -> String {
        match self.v6 {
            Some(_) => format!("127.0.0.1:{0}, [::1]:{0}", self.port),
            None => format!("127.0.0.1:{} (this host has no IPv6 loopback)", self.port),
        }
    }
}

/// The OS says there is no IPv6 loopback to bind: `EADDRNOTAVAIL`, or the
/// family is unsupported (`EAFNOSUPPORT` / `WSAEAFNOSUPPORT`).
fn ipv6_unavailable(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::AddrNotAvailable | ErrorKind::Unsupported
    ) || matches!(e.raw_os_error(), Some(97) | Some(10047))
}

/// Bind the pages on **both** loopback addresses, `127.0.0.1:<port>` and
/// `[::1]:<port>`, or refuse: a port that is taken on either family is not
/// served on the other, because a family this daemon leaves free is a
/// family a rogue local listener can take and receive the link token on.
/// `port` 0 asks the OS for one — for tests, and for a daemon that will
/// report the port it got — and a number the OS picks on IPv4 that IPv6
/// cannot follow on is given back and another asked for.
pub async fn bind(port: u16) -> Result<Listeners> {
    for _ in 0..EPHEMERAL_TRIES {
        let v4 = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(l) => l,
            Err(e) if e.kind() == ErrorKind::AddrInUse => anyhow::bail!(
                "127.0.0.1:{port} is already taken: another daemon, or another process, holds \
                 the passkey pages' port; refusing to serve them on one loopback address only"
            ),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("bind 127.0.0.1:{port} for the passkey pages"))
            }
        };
        let got = v4
            .local_addr()
            .context("the passkey pages' IPv4 address")?
            .port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, got)).await {
            Ok(v6) => {
                return Ok(Listeners {
                    v4,
                    v6: Some(v6),
                    port: got,
                })
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                if port != 0 {
                    anyhow::bail!(
                        "[::1]:{got} is already taken while 127.0.0.1:{got} is free: a browser \
                         asked for localhost may connect to it first, so refusing to serve the \
                         passkey pages on one loopback address only; find what holds it, or \
                         pick another --web-port"
                    );
                }
                // The OS's choice on IPv4 is held on IPv6: give it back and
                // ask for another.
                drop(v4);
                continue;
            }
            Err(e) if ipv6_unavailable(&e) => {
                tracing::warn!(
                    port = got,
                    error = %e,
                    "no IPv6 loopback on this host; the passkey pages are served on 127.0.0.1 only"
                );
                return Ok(Listeners {
                    v4,
                    v6: None,
                    port: got,
                });
            }
            Err(e) => {
                return Err(e).with_context(|| format!("bind [::1]:{got} for the passkey pages"))
            }
        }
    }
    anyhow::bail!(
        "no OS-chosen port was free on both loopback addresses after {EPHEMERAL_TRIES} tries"
    )
}

/// The pages over `kernel`, for the listeners bound on `port`.
pub fn build(kernel: Shared, node_id: &str, port: u16) -> Result<Web> {
    let origin = passkey::origin(port);
    let links = Arc::new(Links::new(origin));
    let app = Arc::new(App {
        kernel,
        node_id: node_id.into(),
        webauthn: passkey::webauthn(port)?,
        links: links.clone(),
        hosts: [
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
        ],
        enrolments: Mutex::new(BTreeMap::new()),
        approvals: Mutex::new(BTreeMap::new()),
    });
    // Layers wrap outward: the `Host` check runs first on the way in, and
    // the security headers are added last on the way out — to its `400` too.
    let router = Router::new()
        .route("/", get(index))
        .route("/vk.js", get(script))
        .route("/enroll", get(enroll_page))
        .route("/enroll/start", post(enroll_start))
        .route("/enroll/finish", post(enroll_finish))
        .route("/approve/{task_id}", get(approve_page))
        .route("/approve/{task_id}/start", post(approve_start))
        .route("/approve/{task_id}/finish", post(approve_finish))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            require_local_host,
        ))
        .layer(middleware::from_fn(secure_headers))
        .with_state(app);
    Ok(Web { router, links })
}

/// Serve on both listeners until either fails.
pub async fn serve(listeners: Listeners, router: Router) -> Result<()> {
    let Listeners { v4, v6, .. } = listeners;
    let on_v4 = axum::serve(v4, router.clone()).into_future();
    match v6 {
        Some(v6) => {
            let on_v6 = axum::serve(v6, router).into_future();
            tokio::try_join!(on_v4, on_v6).context("serve the passkey pages")?;
        }
        None => on_v4.await.context("serve the passkey pages")?,
    }
    Ok(())
}

/// Every request must name this server — `localhost`, `127.0.0.1` or `[::1]`
/// on its own port — or it is refused before any route sees it: a page on
/// another origin whose name is rebound to loopback reaches nothing (review
/// Minor 3). The port is part of it: a name on another port is another
/// server.
async fn require_local_host(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let named = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.trim().to_ascii_lowercase())
        .is_some_and(|h| app.hosts.contains(&h));
    if !named {
        return WebError::bad(
            "this server answers only as localhost, 127.0.0.1 or [::1] on its own port",
        )
        .into_response();
    }
    next.run(req).await
}

/// Every response, whatever it is: no framing (a Windows Hello prompt must
/// not be raised from inside somebody else's page), no scripts but this
/// origin's own, no referrer (the link token is in the URL), nothing cached.
async fn secure_headers(req: Request, next: Next) -> Response {
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

/// The five characters HTML needs escaped, for the values the pages carry in
/// their markup.
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

/// Fill a page's `{{name}}` slots in one pass, escaping each value as it goes
/// in. One pass, so a value is never scanned for slots: a goal that happens
/// to contain the text `{{subject}}` stays that text (review Minor 4). An
/// unknown slot is left as it was.
fn render(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let name = &after[..end];
                match values.iter().find(|(n, _)| *n == name) {
                    Some((_, value)) => out.push_str(&escape(value)),
                    None => {
                        out.push_str("{{");
                        out.push_str(name);
                        out.push_str("}}");
                    }
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn page(html: String) -> Response {
    Html(html).into_response()
}

/// base64url, unpadded — how WebAuthn spells bytes on the wire and how the
/// kernel's nonce and the record spell them.
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes a base64url string names, padded or not; `None` if it is not
/// base64url at all.
fn from_b64url(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
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
    Ok(page(render(ENROLL_HTML, &[("node_id", &app.node_id)])))
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
    Ok(page(render(
        APPROVE_HTML,
        &[
            ("task_id", &task_id),
            ("goal", &goal),
            ("artefact", &artefact_type),
            ("subject", &subject),
        ],
    )))
}

/// Start an approval. The verifier makes its request options — and its
/// challenge — over every enrolled passkey; the kernel then mints the task's
/// approval challenge **with that challenge as its nonce**, so what the
/// authenticator will sign inside `clientDataJSON` is the minted nonce, bound
/// by the kernel to the subject, the resource and an expiry. The two are
/// kept together under one single-use state id; the challenge's own expiry
/// bounds the state. The nonce goes to the browser as the WebAuthn challenge
/// — it must — and nothing else of the minted challenge does (review Minor
/// 1): the page is told what it is approving and until when.
async fn approve_start(
    State(app): State<Arc<App>>,
    Path(task_id): Path<String>,
    Json(body): Json<TokenBody>,
) -> Result<Json<Value>, WebError> {
    let now = now_ms();
    require_link(&app, &body.t, Page::Approve, Some(&task_id), now)?;
    let rows = with_kernel(&app, |k| {
        let rows = k.passkeys()?;
        if rows.is_empty() {
            // Before anything is minted: a challenge nobody could answer is
            // a challenge that should not exist.
            return Err(KernelError::Gate(
                "no passkey is enrolled on this node; run `vk passkey enroll` first".into(),
            ));
        }
        Ok(rows)
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
    let nonce = b64url(options.public_key.challenge.as_ref());
    let node_id = app.node_id.clone();
    let id = task_id.clone();
    let challenge = with_kernel(&app, move |k| {
        k.mint_approval_challenge_with_nonce(&machine_ctx(&node_id, now), &id, nonce)
    })
    .await?;
    let state_id = random_token();
    let (subject, expires_at_ms) = (challenge.action_digest.clone(), challenge.expires_at_ms);
    {
        let mut open = app.approvals.lock().unwrap_or_else(|e| e.into_inner());
        sweep(&mut open, now, |p| p.challenge.expires_at_ms);
        open.insert(
            state_id.clone(),
            PendingAuth {
                state,
                task_id,
                challenge,
            },
        );
    }
    Ok(Json(json!({
        "state_id": state_id,
        "options": options,
        "subject_hash": subject,
        "expires_at_ms": expires_at_ms,
    })))
}

/// Finish an approval.
///
/// **I1 argument.** This handler is the only path to a human approval that
/// involves no ed25519 device key. Its verification is `webauthn-rs`'s,
/// against a passkey enrolled under an existing human ceremony; the
/// *approver* is the credential the verifier identified, and the *challenge*
/// is the one the kernel minted at `start` — whose nonce is the very value
/// the authenticator signed inside `clientDataJSON`, checked again here — and
/// kept beside the request state. The client supplied neither, and could
/// not: there is no request field for either. The state is taken before it
/// is looked at, so an assertion is recorded at most once; an assertion for
/// another state's challenge fails the verifier's challenge check; the bytes
/// the authenticator signed go onto the record beside the approval, so the
/// recorded signature is re-verifiable; and the kernel's own spend of the
/// minted challenge is the last word, in-process, through
/// `record_verified_human_approval`, which no syscall reaches. Afterwards the
/// step that was waiting for exactly this approval is run — and only that
/// one: a task that has moved on since `start` is not stepped (review Minor
/// 2).
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
    // The verifier has just checked the signed challenge against its state;
    // the state's challenge is the minted nonce by construction. Checked once
    // more, against the record that is about to be written, so the binding
    // the record claims is the binding this handler saw.
    let client_data_json = body.credential.response.client_data_json.as_ref();
    let signed: Value = serde_json::from_slice(client_data_json)
        .map_err(|e| WebError::forbidden(format!("assertion rejected: client data: {e}")))?;
    let signed_challenge = signed["challenge"].as_str().and_then(from_b64url);
    if signed_challenge.is_none() || signed_challenge != from_b64url(&pending.challenge.nonce) {
        return Err(WebError::forbidden(
            "assertion rejected: it does not sign the challenge this node minted",
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
    let assertion = AssertionRecord {
        credential_id: b64url(result.cred_id().as_ref()),
        authenticator_data: b64url(body.credential.response.authenticator_data.as_ref()),
        client_data_json: b64url(client_data_json),
    };
    let node_id = app.node_id.clone();
    let (id, dev, expected) = (task_id.clone(), device_id.clone(), subject.clone());
    let (status, stepped) = with_kernel(&app, move |k| {
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
        k.record_verified_human_approval(now, approval, PROOF, Some(assertion))?;
        // The step that was waiting for exactly this: run it, so the task
        // leaves `waiting_human` and whoever is watching it sees the approval
        // land. Only if it is still that step, waiting for that subject —
        // a task that moved on since `start` (approved by the node key and
        // stepped, say) is not pushed into its next step by this page.
        let ctx = machine_ctx(&node_id, now);
        let waiting_for_this = k
            .task(&ctx, &id)
            .is_some_and(|t| t.status == TaskStatus::WaitingHuman)
            && k.approval_subject(&ctx, &id).ok().as_deref() == Some(expected.as_str());
        let stepped = waiting_for_this
            && match k.run_task_step(&ctx, &id) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(task = %id, error = %e, "approval recorded; the waiting step did not run");
                    false
                }
            };
        Ok((k.task(&ctx, &id).map(|t| t.status), stepped))
    })
    .await?;
    app.links.spend(&body.t);
    tracing::info!(task = %task_id, device = %device_id, stepped, "human approval recorded (webauthn)");
    Ok(Json(json!({
        "ok": true,
        "task_id": task_id,
        "subject_hash": subject,
        "device_id": device_id,
        "status": status,
        "stepped": stepped,
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

    /// Review Minor 4: one pass over the template, values escaped as they go
    /// in and never scanned for slots themselves.
    #[test]
    fn a_page_is_rendered_in_one_pass_and_values_are_never_templated() {
        let html = render(
            "<p>{{goal}}</p><code>{{subject}}</code>{{unknown}}{{",
            &[
                ("goal", "see {{subject}} & <b>this</b>"),
                ("subject", "sha256:abc"),
            ],
        );
        assert_eq!(
            html,
            "<p>see {{subject}} &amp; &lt;b&gt;this&lt;/b&gt;</p><code>sha256:abc</code>{{unknown}}{{"
        );
    }

    #[test]
    fn base64url_is_unpadded_on_the_way_out_and_lenient_on_the_way_in() {
        assert_eq!(b64url(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(from_b64url("-__-"), Some(vec![0xfb, 0xff, 0xfe]));
        assert_eq!(from_b64url("-__-=="), Some(vec![0xfb, 0xff, 0xfe]));
        assert_eq!(from_b64url("not base64!"), None);
    }
}
