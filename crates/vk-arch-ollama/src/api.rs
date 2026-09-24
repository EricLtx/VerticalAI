//! The Ollama HTTP API, as spike 1a measured it on 0.33.3 — the wire types
//! and the five calls this adapter makes.
//!
//! Every field name here was read off a real response on 2026-09-24 and is
//! pinned by `tests/api.rs`; the pinned server version is part of the arch
//! identity, so a newer Ollama that renames one of them mints a different arch
//! rather than quietly changing what this one means.
//!
//! The client is blocking on purpose: `ArchAdapter::complete` is synchronous,
//! and the kernel calls it holding its own lock. Each call carries its own
//! timeout, because they are not the same kind of wait — a version probe that
//! takes five seconds is a server that is not up, while a pull legitimately
//! takes minutes and a CPU completion takes as long as the tokens do.
use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// A version probe: the server is either listening or it is not.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Metadata calls — `/api/tags`, `/api/show`, `/api/tokenize`.
const META_TIMEOUT: Duration = Duration::from_secs(30);
/// A pull is a download: the 1B is 815 MB and the demo model 9.6 GB, over
/// whatever line this node has.
const PULL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// One completion. Generous, because this is a model on a CPU: spike 1a
/// measured 10.1 tokens/s for the demo model, so a long answer is minutes, and
/// a cold load adds 25 s in front of it. It is a backstop against a server
/// that has stopped answering, not a budget.
const CHAT_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// How often the mount wait re-probes a server that is still starting.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// The request `/api/chat` is sent, exactly as spike 1a pinned it.
///
/// `stream: false` so one request is one answer; `think: false` at the top
/// level — not inside `options` — because the demo model is a thinking model
/// and without it the answer goes to `message.thinking` and `message.content`
/// comes back empty.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub stream: bool,
    pub think: bool,
    pub options: Options,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// The sampling options this adapter sets, and only those.
///
/// `num_ctx`, `seed` and `temperature` are in the arch identity, so a call can
/// never be sampled differently from the arch it was made on. `num_predict` is
/// not: it is the caller's bound on this one answer (Ruling 9a), and it is
/// always sent — without it a local model generates until it decides to stop,
/// which on a CPU at ten tokens a second is a wait nobody asked for.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Options {
    pub num_ctx: u32,
    pub num_predict: u32,
    pub seed: u64,
    pub temperature: f32,
}

/// What `/api/chat` answers with. Everything but the message is a measurement
/// of the call, and all of it is optional: a field this version does not send
/// must not turn a good answer into a parse failure.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ChatResponse {
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub done_reason: Option<String>,
    /// Prompt tokens the server actually read. The one number that says
    /// whether it truncated: spike 1a measured a cut at `num_ctx / 2 + 3`,
    /// reported with HTTP 200 and `done_reason: "stop"` over the top of it.
    #[serde(default)]
    pub prompt_eval_count: u32,
    #[serde(default)]
    pub eval_count: u32,
    /// Nanoseconds, as Ollama reports them.
    #[serde(default)]
    pub eval_duration: u64,
    #[serde(default)]
    pub load_duration: u64,
    /// Some failures come back inside a 200. If this is set, the call failed.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionResponse {
    pub version: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TagsResponse {
    #[serde(default)]
    pub models: Vec<TagModel>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TagModel {
    #[serde(default)]
    pub name: String,
    /// The content address of the weights — what the arch id is built on.
    #[serde(default)]
    pub digest: String,
}

/// `/api/show`. `model_info` is keyed by family (`gemma4.context_length`),
/// which is why `details.family` has to be read before the window can be.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ShowResponse {
    #[serde(default)]
    pub details: Details,
    #[serde(default)]
    pub model_info: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Details {
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub parameter_size: String,
    #[serde(default)]
    pub quantization_level: String,
}

impl ShowResponse {
    /// The model's own context window, from `model_info["<family>.context_length"]`.
    pub fn context_length(&self) -> Option<u32> {
        self.model_info
            .get(&format!("{}.context_length", self.details.family))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenizeResponse {
    #[serde(default)]
    pub tokens: Vec<i64>,
}

/// The blocking client every call here goes through. No global timeout: the
/// calls set their own, and a pull and a version probe do not deserve the same
/// one.
///
/// **`no_proxy` is the load-bearing line.** `reqwest`'s builder consults the
/// machine's proxy configuration by default — `HTTP_PROXY`, `http_proxy`,
/// `ALL_PROXY`, and on Windows the WinINET registry settings — and applies no
/// loopback bypass to the environment ones. That would send the whole prompt
/// of the only arch cleared to `Scope::Personal` to whatever host a corporate
/// agent, a leftover mitmproxy or a stray variable names, while its manifest
/// went on claiming `locality: Local`, `retention_days: 0` and `governed:
/// true`, with no ledger record of the third party (SP1b Task 1 review,
/// Critical 1). On a machine whose proxy is merely unreachable it is only a
/// 60-second mount failure. A model on this machine's loopback has no business
/// consulting a proxy for any reason, so it never does.
pub fn client() -> Result<Client> {
    Client::builder()
        .no_proxy()
        .user_agent("verticalai-vk-arch-ollama")
        .build()
        .context("build the HTTP client for Ollama")
}

fn url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// A response's body, or a refusal naming the status and what the server said.
fn body(what: &str, r: Response) -> Result<String> {
    let status = r.status();
    let text = r.text().unwrap_or_default();
    if !status.is_success() {
        bail!("{what}: Ollama answered {status}: {}", text.trim());
    }
    Ok(text)
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, text: &str) -> Result<T> {
    serde_json::from_str(text)
        .with_context(|| format!("{what}: cannot read Ollama's answer: {}", head(text, 300)))
}

/// The first `n` characters of `s`, marked when something was cut — a server
/// that answers with a whole HTML error page must not put it in a log line.
fn head(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.trim().to_string();
    }
    format!("{}…", s.chars().take(n).collect::<String>())
}

pub fn version(client: &Client, base: &str) -> Result<String> {
    let r = client
        .get(url(base, "/api/version"))
        .timeout(PROBE_TIMEOUT)
        .send()
        .context("GET /api/version")?;
    Ok(parse::<VersionResponse>("/api/version", &body("/api/version", r)?)?.version)
}

/// Wait for the server to answer, for up to `deadline`. A container that has
/// just been started is not listening yet, and mounting must not fail because
/// it was asked a second too early.
pub fn wait_for_version(client: &Client, base: &str, deadline: Duration) -> Result<String> {
    let until = Instant::now() + deadline;
    loop {
        // Kept, so the refusal at the deadline says what the last attempt
        // actually failed on rather than only that it timed out.
        let last = match version(client, base) {
            Ok(v) => return Ok(v),
            Err(e) => format!("{e:#}"),
        };
        if Instant::now() >= until {
            bail!("no Ollama answered at {base} within {deadline:?}: {last}");
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

pub fn tags(client: &Client, base: &str) -> Result<TagsResponse> {
    let r = client
        .get(url(base, "/api/tags"))
        .timeout(META_TIMEOUT)
        .send()
        .context("GET /api/tags")?;
    parse("/api/tags", &body("/api/tags", r)?)
}

/// The digest of `model` as the server lists it, matching the tag exactly:
/// `gemma3:1b` and `gemma3:1b-it-q4_K_M` are two rows with (here) one digest,
/// and the arch is named after the one that was asked for.
pub fn digest_of(tags: &TagsResponse, model: &str) -> Option<String> {
    tags.models
        .iter()
        .find(|m| m.name == model)
        .map(|m| m.digest.clone())
        .filter(|d| !d.is_empty())
}

/// Download `model` into the server's volume. Not streamed: this is a mount,
/// nobody is watching a progress bar, and the answer is one object at the end.
pub fn pull(client: &Client, base: &str, model: &str) -> Result<()> {
    let r = client
        .post(url(base, "/api/pull"))
        .json(&serde_json::json!({ "name": model, "stream": false }))
        .timeout(PULL_TIMEOUT)
        .send()
        .with_context(|| format!("POST /api/pull {model}"))?;
    let text = body("/api/pull", r)?;
    let status: serde_json::Value = parse("/api/pull", &text)?;
    // A pull can fail inside a 200 — `{"error": "pull model manifest: ..."}`.
    if let Some(e) = status.get("error").and_then(serde_json::Value::as_str) {
        bail!("cannot pull {model}: {e}");
    }
    Ok(())
}

pub fn show(client: &Client, base: &str, model: &str) -> Result<ShowResponse> {
    let r = client
        .post(url(base, "/api/show"))
        .json(&serde_json::json!({ "model": model }))
        .timeout(META_TIMEOUT)
        .send()
        .with_context(|| format!("POST /api/show {model}"))?;
    parse("/api/show", &body("/api/show", r)?)
}

/// The server's own token count for `text`. `Err` when the endpoint is not
/// there — which is every 0.33.3, where it 404s (spike 1a).
pub fn tokenize(client: &Client, base: &str, model: &str, text: &str) -> Result<u32> {
    let r = client
        .post(url(base, "/api/tokenize"))
        .json(&serde_json::json!({ "model": model, "prompt": text }))
        .timeout(META_TIMEOUT)
        .send()
        .context("POST /api/tokenize")?;
    let parsed: TokenizeResponse = parse("/api/tokenize", &body("/api/tokenize", r)?)?;
    u32::try_from(parsed.tokens.len()).map_err(|_| anyhow!("/api/tokenize: absurd token count"))
}

/// Does this server tokenize at all? Asked once, at mount, so that no call
/// pays for the 404 — and so that the answer cannot change under a mounted
/// arch.
pub fn tokenize_available(client: &Client, base: &str, model: &str) -> bool {
    tokenize(client, base, model, "probe").is_ok()
}

pub fn chat(client: &Client, base: &str, req: &ChatRequest) -> Result<ChatResponse> {
    let r = client
        .post(url(base, "/api/chat"))
        .json(req)
        .timeout(CHAT_TIMEOUT)
        .send()
        .context("POST /api/chat")?;
    let parsed: ChatResponse = parse("/api/chat", &body("/api/chat", r)?)?;
    if let Some(e) = &parsed.error {
        bail!("Ollama refused the call: {e}");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_window_is_read_under_the_family_the_model_declares() {
        let show: ShowResponse = serde_json::from_str(
            r#"{"details":{"family":"gemma4","parameter_size":"8.0B","quantization_level":"Q4_K_M"},
                "model_info":{"gemma4.context_length":131072,"general.architecture":"gemma4"}}"#,
        )
        .expect("the shape spike 1a measured");
        assert_eq!(show.context_length(), Some(131_072));
        assert_eq!(show.details.parameter_size, "8.0B");
        // A response whose family does not match the key names no window at
        // all, rather than a number from some other model's row.
        let mismatched = ShowResponse {
            details: Details {
                family: "gemma3".into(),
                ..show.details.clone()
            },
            ..show
        };
        assert_eq!(mismatched.context_length(), None);
    }

    #[test]
    fn a_digest_is_taken_from_the_exact_tag_that_was_asked_for() {
        let tags: TagsResponse = serde_json::from_str(
            r#"{"models":[{"name":"gemma3:1b","digest":"8648f3"},{"name":"gemma4:e4b","digest":"c6eb39"}]}"#,
        )
        .expect("the shape spike 1a measured");
        assert_eq!(digest_of(&tags, "gemma4:e4b").as_deref(), Some("c6eb39"));
        assert_eq!(digest_of(&tags, "gemma4"), None);
    }

    #[test]
    fn a_url_is_joined_the_same_way_with_or_without_a_trailing_slash() {
        assert_eq!(
            url("http://127.0.0.1:11434/", "/api/chat"),
            "http://127.0.0.1:11434/api/chat"
        );
        assert_eq!(
            url("http://127.0.0.1:11434", "/api/chat"),
            "http://127.0.0.1:11434/api/chat"
        );
    }
}
