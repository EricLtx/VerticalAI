//! Claude through the **API** as an arch: first-party over raw HTTPS (US), and
//! EU-hosted through Amazon Bedrock ([`bedrock`]).
//!
//! This is the arch a *customer* node mounts. The Claude Code arch
//! (`vk-arch-claude-code`) drives the founder's own claude.ai subscription,
//! and a subscription is a person's and not a product's; these two carry a
//! key, a per-token price and — for `bedrock` — a different host and a
//! different jurisdiction.
//!
//! ## What is honest about them
//!
//! Neither is **governed**: the inference runs on somebody else's machine, so
//! `locality: Cloud`, `governed: false`, clearance stops at `Business` and
//! third-party data is refused. What differs is where, and for how long:
//!
//! | | first-party | Bedrock |
//! |---|---|---|
//! | `jurisdiction` | `US` | `EU` (`eu-central-1`, `eu-west-1`) |
//! | `retention_days` | `Some(30)` | `None` |
//! | `identity.backend` | `anthropic-first-party` | `aws-bedrock` |
//!
//! `Some(30)` is Anthropic's standard API retention window; `None` on Bedrock
//! is not "unknown" but "there is no window to name" — AWS does not store
//! model inputs or outputs for Bedrock `Converse`. Both numbers are claims
//! about a third party, which is exactly why they are in the manifest where
//! I2 can read them rather than in a comment.
//!
//! ## The key
//!
//! The API key lives in the OS keyring, service `vk`, user `anthropic`, put
//! there by `vk secret set anthropic`. It is **never** in the mount spec — a
//! spec is stored unencrypted in the metadata database, and
//! [`vk_kernel::arch::MountSpec::new`] refuses a config carrying anything
//! credential-shaped — never in a manifest, never in a log line, and never in
//! an error: every message this crate produces is passed through
//! [`SecretString::scrub`] on the way out. The only file it may come from is
//! the `--anthropic-key-file` seam, which exists for tests and for a headless
//! node with no keyring.
//!
//! ## I4′
//!
//! The ceiling is the model's documented context window (see [`MODELS`]), and
//! a prompt past nine tenths of it is refused before anything is sent. The
//! count is the API's own — `POST /v1/messages/count_tokens`, which is free
//! and is the only tokenizer there is for these models — falling back to the
//! `bytes/3 + 64` estimate when that call fails, because a rate-limited
//! counter should cost accuracy and not the inference. Afterwards the answer's
//! own `usage.input_tokens` is checked against the ceiling: the API refuses an
//! oversize prompt rather than truncating it, so this is a belt to that
//! suspender rather than the load-bearing check Ollama needs.

pub mod bedrock;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use std::path::PathBuf;
use std::time::Duration;
use vk_contracts::arch::{ArchIdentity, ArchManifest, Capability, Determinism, Locality};
use vk_contracts::labels::{Clearance, Scope};
use vk_kernel::arch::{AdapterError, ArchAdapter, Completion};
use zeroize::Zeroize;

/// The API version header every request carries. It is in the arch identity:
/// a different version of the wire contract is a different arch.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The model an API arch runs on unless told otherwise.
pub const DEFAULT_MODEL: &str = "claude-opus-5";

/// The first-party endpoint, and the only one an ordinary node ever uses.
///
/// **Not a request field.** A client that could name the origin could name a
/// collector, and the daemon would put its own key on the wire to it — over
/// plaintext, persistently, at every boot, from a service account whose
/// keyring that client cannot otherwise read (fix round 1, Critical 1). The
/// origin is daemon configuration (`vkd --anthropic-base-url`, for tests) and
/// [`check_base_url`] bounds even that.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// The longest answer one call may produce. The plan's cap, not the API's:
/// these models take far more, and an arch driven as a completion engine has
/// no business generating a book because nobody bounded it.
pub const MAX_OUTPUT_TOKENS: u32 = 4096;

/// The ceiling for a model that is not in [`MODELS`]. Deliberately the
/// smallest window any current Claude model has, because the failure of
/// guessing high is a refused call at the far end and the failure of guessing
/// low is only a prompt this node projects further than it had to.
pub const FALLBACK_CONTEXT: u32 = 200_000;

/// The keyring service every VerticalAI secret lives under.
pub const KEYRING_SERVICE: &str = "vk";

/// The keyring user the first-party key lives under: `vk`/`anthropic`.
pub const KEYRING_USER: &str = "anthropic";

/// How much of the ceiling a prompt may take before the call is refused (I4′).
const CONTEXT_HEADROOM: f64 = 0.9;

/// Euros to the dollar, **pinned** on 2026-09-25 and not a live rate.
///
/// `ArchManifest::cost_per_1k_tokens_eur` is a price tag on the arch, read by
/// `vk top` to say what a node's calls are costing it in the currency it is
/// billed in. Anthropic and AWS both publish in USD, so one conversion has to
/// happen somewhere; doing it here, from a constant with a date on it, is
/// visibly a pinned figure. The exact per-call number never goes through it:
/// `Completion::cost_list_usd` is USD as the provider prices it, and that is
/// what the ledger records.
pub const EUR_PER_USD: f64 = 0.92;

// ---------------------------------------------------------------- the table

/// One model, as its provider documents it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Model {
    /// The API model id, exactly as it is sent.
    pub id: &'static str,
    /// The documented context window, in tokens — the I4′ ceiling.
    pub context_window: u32,
    /// List price for input tokens, USD per million.
    pub input_usd_per_mtok: f64,
    /// List price for output tokens, USD per million.
    pub output_usd_per_mtok: f64,
    /// Order-of-magnitude p50 latency for a ~500-token answer, in
    /// milliseconds. Outside `ArchIdentity`, so re-measuring it does not mint
    /// a new arch id.
    pub latency_ms_p50: u32,
    /// Does this model take `thinking: {"type": "adaptive"}`?
    ///
    /// Adaptive thinking arrived with the 4.6/5 generation. A 4.5-generation
    /// model — `claude-haiku-4-5` is the one in this table — takes
    /// `{"type": "enabled", "budget_tokens": N}` instead and **400s** on
    /// `adaptive`, so sending it unconditionally would let an operator mount
    /// a healthy-looking cheap arch whose every call then failed at the far
    /// end (fix round 1, Important 2). This adapter does not implement the
    /// older form; it simply sends no `thinking` block for such a model,
    /// which is a valid request on every model here.
    pub thinking_supported: bool,
}

/// Every model this node will price, with its window and its list price.
///
/// **Source:** Anthropic's published model and pricing tables, as carried by
/// the `claude-api` reference, snapshot **2026-06-24**, re-read 2026-09-25.
/// Prices are first-party API list prices in USD per million tokens; Bedrock
/// and Vertex are partner-operated and priced separately by AWS and Google
/// (see [`bedrock`], which says so rather than pretending otherwise).
///
/// **The windows are the documented ones.** The Claude 5 family is documented
/// at 1 000 000 tokens and Haiku 4.5 at 200 000. The SP1b plan's Task 2b
/// paragraph says "200 000 for the Claude 5 family"; that was the window of
/// the previous generation, and the rule the same sentence states — "the
/// model's documented context window" — is the one followed here. Guessing
/// high is safe on this provider in a way it is not on Ollama: the API
/// **refuses** an oversize prompt with a 400 rather than silently truncating
/// it, so a ceiling that is too generous costs a failed call and never a
/// confident answer to half a question. `--ctx` pins a smaller one for a
/// node that wants the old number back.
///
/// The latencies are carried over from spike 2a's measurements of the same
/// models through the Claude Code CLI, less its ~3 s of process start-up;
/// Haiku and Fable were not measured and are estimates. Nothing in this
/// column is in the arch id.
///
/// `thinking_supported` is `false` for `claude-haiku-4-5` alone: adaptive
/// thinking is a 4.6-and-later parameter and the 4.5 generation rejects it
/// with a 400 (fix round 1, Important 2). Not verifiable from here — there is
/// no key — so it is taken from the same published reference as the rest of
/// the row; `GET /v1/models/claude-haiku-4-5` settles it the day one exists.
pub const MODELS: &[Model] = &[
    Model {
        id: "claude-opus-5",
        context_window: 1_000_000,
        input_usd_per_mtok: 5.00,
        output_usd_per_mtok: 25.00,
        latency_ms_p50: 11_000,
        thinking_supported: true,
    },
    Model {
        id: "claude-opus-4-8",
        context_window: 1_000_000,
        input_usd_per_mtok: 5.00,
        output_usd_per_mtok: 25.00,
        latency_ms_p50: 11_000,
        thinking_supported: true,
    },
    Model {
        id: "claude-sonnet-5",
        context_window: 1_000_000,
        input_usd_per_mtok: 2.00,
        output_usd_per_mtok: 10.00,
        latency_ms_p50: 7_000,
        thinking_supported: true,
    },
    Model {
        id: "claude-haiku-4-5",
        context_window: 200_000,
        input_usd_per_mtok: 1.00,
        output_usd_per_mtok: 5.00,
        latency_ms_p50: 4_000,
        thinking_supported: false,
    },
    Model {
        id: "claude-fable-5-1",
        context_window: 1_000_000,
        input_usd_per_mtok: 10.00,
        output_usd_per_mtok: 50.00,
        latency_ms_p50: 20_000,
        thinking_supported: true,
    },
];

/// The table's row for `id`, or `None` for a model this node has no numbers
/// for. `None` is not a refusal: an arch on an unlisted model mounts, and
/// reports no price rather than an invented one.
pub fn model(id: &str) -> Option<&'static Model> {
    MODELS.iter().find(|m| m.id == id)
}

/// The documented window for `id`, or [`FALLBACK_CONTEXT`].
pub fn context_window(id: &str) -> u32 {
    model(id).map_or(FALLBACK_CONTEXT, |m| m.context_window)
}

/// The manifest's price tag: input tokens, per thousand, in euros, or `None`
/// for a model with no row.
///
/// `None`, emphatically not `0.0` (Ruling 30). Zero is a claim that the calls
/// are free, which is what a local model and a subscription arch say; an
/// unlisted model on a metered API is billed at a rate this node does not
/// know, and `vk top` prints `?` for it rather than a figure that would read
/// as free.
pub fn cost_per_1k_tokens_eur(id: &str) -> Option<f64> {
    model(id).map(|m| m.input_usd_per_mtok / 1_000.0 * EUR_PER_USD)
}

// --------------------------------------------------------------- the secret

/// An API key that does not print itself and is wiped when it is dropped.
///
/// The whole point of the type is the two `impl`s below: `Debug` renders
/// `SecretString(redacted)`, so a `#[derive(Debug)]` anywhere upstream cannot
/// put a key in a log line, and `Drop` zeroes the bytes rather than leaving
/// them in a freed allocation. [`SecretString::scrub`] is the third leg: every
/// message this crate hands back to a caller goes through it, so a provider
/// that echoes the key into an error cannot make this node repeat it.
pub struct SecretString(Vec<u8>);

impl SecretString {
    pub fn new(key: &str) -> SecretString {
        SecretString(key.as_bytes().to_vec())
    }

    /// The key itself. Private on purpose: the only caller is the header this
    /// crate sets.
    fn expose(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// `text` with every occurrence of the key replaced. Applied to every
    /// error and every log line that could have come from the far end.
    pub fn scrub(&self, text: &str) -> String {
        let key = self.expose();
        if key.is_empty() {
            return text.to_string();
        }
        text.replace(key, "[redacted]")
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(redacted)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Where the API key comes from. The keyring in every ordinary run; a file
/// only for tests, CI and a headless node whose OS has no credential store —
/// the same shape, and the same reasoning, as
/// [`vk_store::keys::KeySource`](https://docs.rs/) in the store.
#[derive(Debug, Clone, Default)]
pub enum KeySource {
    /// Service `vk`, user `<name>`.
    #[default]
    Keyring,
    /// One line in a file. Never a default.
    File(PathBuf),
}

/// Read the secret called `name` — `anthropic`, for this arch.
///
/// Every failure names `vk secret set <name>`, because every one of them has
/// the same remedy and the person reading it is at a terminal: a missing
/// entry, a keyring this OS does not have, a file that is not there. The
/// value itself is never in the error, whatever went wrong.
pub fn load_key(source: &KeySource, name: &str) -> Result<SecretString> {
    let remedy = format!("set it with: vk secret set {name}");
    match source {
        KeySource::Keyring => {
            let entry = keyring::Entry::new(KEYRING_SERVICE, name)
                .with_context(|| format!("no keyring on this machine; {remedy}"))?;
            match entry.get_password().map(zeroize::Zeroizing::new) {
                Ok(secret) if secret.trim().is_empty() => {
                    bail!("the keyring entry {KEYRING_SERVICE}/{name} is empty; {remedy}")
                }
                // Wrapped on the way out of `keyring`, so the copy this
                // function made is wiped rather than left in freed heap when
                // it goes (fix round 1, Minor 5).
                Ok(secret) => Ok(SecretString::new(secret.trim())),
                Err(keyring::Error::NoEntry) => {
                    bail!("no {KEYRING_SERVICE}/{name} in this account's keyring; {remedy}")
                }
                Err(e) => Err(anyhow!(e))
                    .with_context(|| format!("cannot read {KEYRING_SERVICE}/{name}; {remedy}")),
            }
        }
        KeySource::File(path) => {
            let text = zeroize::Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read {}; {remedy}", path.display()))?,
            );
            let line = text.lines().next().unwrap_or_default().trim();
            if line.is_empty() {
                bail!("{} is empty; {remedy}", path.display());
            }
            Ok(SecretString::new(line))
        }
    }
}

// --------------------------------------------------------------- the config

/// Everything `arch.mount { kind: "anthropic" }` may say. Note what is not
/// here: the key.
#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicConfig {
    pub model: String,
    /// The API's origin. `https://api.anthropic.com` in every real mount; the
    /// field exists so the tests can point at a stand-in on loopback, and it
    /// is in the arch identity so that an arch answered by something else is
    /// visibly not the same arch.
    pub base_url: String,
    /// The mount's own bound on one answer, capped at [`MAX_OUTPUT_TOKENS`].
    pub max_tokens: u32,
    /// The I4′ ceiling. `0` means "the model's documented window"
    /// ([`context_window`]), which is what every ordinary mount wants.
    pub context_ceiling: u32,
    /// How long one `/v1/messages` call may take.
    pub timeout: Duration,
}

impl Default for AnthropicConfig {
    fn default() -> AnthropicConfig {
        AnthropicConfig {
            model: DEFAULT_MODEL.into(),
            base_url: DEFAULT_BASE_URL.into(),
            max_tokens: MAX_OUTPUT_TOKENS,
            context_ceiling: 0,
            // Generous: these are thinking models, and a hard task can run
            // minutes. It is a backstop against a call that has stopped
            // answering, not a budget.
            timeout: Duration::from_secs(600),
        }
    }
}

impl AnthropicConfig {
    /// The ceiling this config actually uses.
    fn ceiling(&self) -> u32 {
        if self.context_ceiling > 0 {
            self.context_ceiling
        } else {
            context_window(&self.model)
        }
    }

    /// The mount's answer cap, never past the API arch's own.
    fn cap(&self) -> u32 {
        self.max_tokens.clamp(1, MAX_OUTPUT_TOKENS)
    }
}

// -------------------------------------------------------------- the adapter

pub struct AnthropicAdapter {
    cfg: AnthropicConfig,
    manifest: ArchManifest,
    key: SecretString,
    /// Built once, at mount. `Err` is kept rather than panicked on: a TLS
    /// stack that will not initialise is a broken arch, not a dead daemon,
    /// and every call says so.
    client: std::result::Result<Client, String>,
}

impl AnthropicAdapter {
    /// The plan's constructor: a key, a model and an origin.
    pub fn new(api_key: SecretString, model: &str, base_url: &str) -> AnthropicAdapter {
        Self::with_config(
            api_key,
            AnthropicConfig {
                model: model.to_string(),
                base_url: base_url.to_string(),
                ..Default::default()
            },
        )
    }

    /// The same, for `vkd`, which has a whole config to hand.
    pub fn with_config(api_key: SecretString, cfg: AnthropicConfig) -> AnthropicAdapter {
        let manifest = Self::manifest_for(&cfg);
        // The origin is checked here as well as where it is configured: this
        // is the last place before the key goes on a wire, and a refusal that
        // reaches every call is better than one that depended on which door
        // the configuration came in by (fix round 1, Critical 1).
        let client = check_base_url(&cfg.base_url)
            .and_then(|()| build_client())
            .map_err(|e| format!("{e:#}"));
        AnthropicAdapter {
            cfg,
            manifest,
            key: api_key,
            client,
        }
    }

    /// The manifest for this configuration.
    ///
    /// Only `ArchIdentity` is hashed into the arch id, so what goes in there
    /// is everything that changes what the model does: the model, the wire
    /// version it is addressed by, the origin it is addressed at, and the
    /// thinking mode. Price and latency sit outside it and can be re-read off
    /// a new price list without minting a new arch.
    pub fn manifest_for(cfg: &AnthropicConfig) -> ArchManifest {
        ArchManifest {
            name: format!("anthropic/{}", cfg.model),
            capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
            locality: Locality::Cloud,
            // Anthropic's first-party API serves from the United States.
            jurisdiction: "US".into(),
            // The standard API retention window.
            retention_days: Some(30),
            cost_per_1k_tokens_eur: cost_per_1k_tokens_eur(&cfg.model),
            latency_ms_p50: model(&cfg.model).map_or(12_000, |m| m.latency_ms_p50),
            context_ceiling: cfg.ceiling(),
            determinism: Determinism::NonDeterministic,
            identity: ArchIdentity {
                // No weights to hash: the model id is all the provider gives
                // us to name what is on the other end.
                weights_sha256: format!("model:{}", cfg.model),
                engine: "anthropic-api".into(),
                engine_version: ANTHROPIC_VERSION.into(),
                backend: "anthropic-first-party".into(),
                quant: "-".into(),
                kv_cache: "-".into(),
                threads: 1,
                batch: 1,
                sampling: [
                    // Which of the two requests this arch sends. A model that
                    // takes no `thinking` block is answering a different
                    // question from one that does, so the two must not be
                    // able to share an arch id.
                    (
                        "thinking".to_string(),
                        if model(&cfg.model).is_some_and(|m| m.thinking_supported) {
                            "adaptive".to_string()
                        } else {
                            "off".to_string()
                        },
                    ),
                    // Where the call is addressed. A mount pointed at a proxy
                    // or a stand-in is not the arch a mount pointed at
                    // Anthropic is, and the id should not pretend it is.
                    ("base_url".to_string(), cfg.base_url.clone()),
                ]
                .into_iter()
                .collect(),
                // Nothing we set makes a hosted model reproducible.
                seed: None,
            },
            clearance: Clearance {
                max_scope: Scope::Business,
                third_party_allowed: false,
            },
            // Anthropic's servers are not a process this kernel launched and
            // contains (spec §3.3).
            governed: false,
        }
    }

    /// The request this adapter puts on the wire, and the only one it does.
    ///
    /// `max_tokens` is the caller's bound on this one answer; `0` means "no
    /// opinion" and the mount's cap is used. Whichever is smaller wins, so
    /// neither the kernel's per-call bound nor the mount's can be talked past.
    ///
    /// No `stream`: one request, one answer, and there is no caller here to
    /// stream to. `thinking: {"type": "adaptive"}` is the only thinking
    /// configuration the Claude 5 family accepts — `budget_tokens` is a 400 on
    /// those models — and its `display` defaults to `omitted`, which is why
    /// [`text_of`] concatenates the `text` blocks and skips the rest. It is
    /// sent **only** for a model the table marks as taking it: the 4.5
    /// generation 400s on `adaptive`, and an unlisted model is not something
    /// to guess about (fix round 1, Important 2).
    pub fn messages_request(
        cfg: &AnthropicConfig,
        prompt: &str,
        max_tokens: u32,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": answer_tokens(cfg, max_tokens),
            "messages": [{ "role": "user", "content": prompt }],
        });
        if model(&cfg.model).is_some_and(|m| m.thinking_supported) {
            body["thinking"] = serde_json::json!({ "type": "adaptive" });
        }
        body
    }

    /// A deliberately crude token estimate, for when the API's counter cannot
    /// be reached: three bytes to the token plus a fixed margin, the same
    /// heuristic the other two adapters use, so a prompt projected for one
    /// arch is projected the same way for this one.
    ///
    /// It **over**-counts. Prose runs nearer four bytes to the token, so
    /// `len / 3` is high by about a quarter on it and by more on short
    /// prompts (spike 1a measured 1.25× and 1.9×); code, being denser in
    /// punctuation, narrows the gap without closing it. Erring high is the
    /// direction a refusal should err in, and it is what the argument at
    /// [`AnthropicAdapter::count_tokens`] rests on.
    pub fn estimate_tokens(text: &str) -> u32 {
        u32::try_from(text.len() / 3 + 64).unwrap_or(u32::MAX)
    }

    /// What this call would cost at list price, in USD, or `None` for a model
    /// with no row in [`MODELS`]. `None` rather than `0.0`: a call that was
    /// certainly billed must not be recorded as free.
    pub fn cost_list_usd(model_id: &str, tokens_in: u32, tokens_out: u32) -> Option<f64> {
        let m = model(model_id)?;
        Some(
            f64::from(tokens_in) * m.input_usd_per_mtok / 1e6
                + f64::from(tokens_out) * m.output_usd_per_mtok / 1e6,
        )
    }

    /// The largest prompt this arch accepts: the ceiling less the margin the
    /// count may be wrong by. One number, used both as the budget the kernel
    /// is told and as the limit `complete` enforces, so the kernel can never
    /// fit a prompt to a size this adapter then refuses.
    fn usable_ceiling(&self) -> u32 {
        (f64::from(self.manifest.context_ceiling) * CONTEXT_HEADROOM) as u32
    }

    fn client(&self) -> std::result::Result<&Client, AdapterError> {
        self.client
            .as_ref()
            .map_err(|e| AdapterError::Other(anyhow!("no HTTPS client for this arch: {e}")))
    }

    /// The API's own count of `text`, or `Err` when the counter could not be
    /// reached. Free, and the only tokenizer these models have.
    fn api_count_tokens(&self, text: &str) -> Result<u32> {
        let client = self.client.as_ref().map_err(|e| anyhow!("{e}"))?;
        let body = serde_json::json!({
            "model": self.cfg.model,
            "messages": [{ "role": "user", "content": text }],
        });
        let r = self
            .post(client, "/v1/messages/count_tokens", &body, COUNT_TIMEOUT)
            .context("POST /v1/messages/count_tokens")?;
        let answer = self.read("/v1/messages/count_tokens", r)?;
        answer["input_tokens"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| anyhow!("/v1/messages/count_tokens: no input_tokens in the answer"))
    }

    fn post(
        &self,
        client: &Client,
        path: &str,
        body: &serde_json::Value,
        timeout: Duration,
    ) -> Result<Response> {
        client
            .post(format!("{}{path}", self.cfg.base_url.trim_end_matches('/')))
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("x-api-key", self.key.expose())
            .header("content-type", "application/json")
            .timeout(timeout)
            .json(body)
            .send()
            // A transport error can name the URL; it cannot be allowed to
            // name anything else this node put on the request.
            .map_err(|e| anyhow!(self.key.scrub(&format!("{e}"))))
    }

    /// A successful response's body as JSON, or a refusal carrying the API's
    /// own error — its `type` and its `message`, which is what the person
    /// reading the failure needs — and never the key.
    fn read(&self, what: &str, r: Response) -> Result<serde_json::Value> {
        let status = r.status();
        let text = r.text().unwrap_or_default();
        let parsed: serde_json::Value =
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            // Scrubbed like every other string out of the far end: a hostile
            // one that echoed the key into `error.type` must not get it
            // printed back out of this daemon (fix round 1, Minor 2).
            let kind = self
                .key
                .scrub(parsed["error"]["type"].as_str().unwrap_or("error"));
            let message = parsed["error"]["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| head(&text, 300));
            bail!(
                "{what}: the Anthropic API answered {status} ({kind}): {}",
                self.key.scrub(&message)
            );
        }
        if parsed.is_null() {
            bail!(
                "{what}: cannot read the API's answer: {}",
                self.key.scrub(&head(&text, 300))
            );
        }
        Ok(parsed)
    }
}

/// A version probe has no place here — there is nothing to probe — so the only
/// timeouts are the two calls. Counting is metadata and must not hang a
/// projection loop.
const COUNT_TIMEOUT: Duration = Duration::from_secs(30);

/// The bound on one answer: the smaller of what the caller asked for and what
/// this arch was mounted with, and the mount's cap when the caller says `0`.
fn answer_tokens(cfg: &AnthropicConfig, max_tokens: u32) -> u32 {
    let cap = cfg.cap();
    if max_tokens == 0 {
        cap
    } else {
        max_tokens.min(cap)
    }
}

/// Is this an origin this node will send its API key to?
///
/// `https://` anywhere, or `http://` to a loopback **address** — which is the
/// test stand-in and nothing else. Plaintext to another host would put the key
/// on the wire in the clear, and there is no configuration worth having that
/// wants it (fix round 1, Critical 1). An address and not `localhost`: a name
/// resolves to whatever `hosts` says today (fix round 2, Minor A).
pub fn check_base_url(raw: &str) -> Result<()> {
    // Parsed by the same crate `reqwest` parses it with, rather than scanned
    // by hand. WHATWG ends the authority of a special scheme at a backslash
    // as well as at `/`, `?` and `#`, so a hand-rolled scan reads
    // `http://evil.example\@127.0.0.1` as loopback while the client posts to
    // `evil.example` (fix round 2, Minor A). One parser, one answer.
    let url = url::Url::parse(raw).with_context(|| format!("{raw} is not a URL"))?;
    match url.scheme() {
        "https" => {
            anyhow::ensure!(url.host().is_some(), "{raw} has no host in it");
            Ok(())
        }
        // Plaintext only to an address on this machine — and an *address*:
        // `localhost` is a name, and a name is whatever `hosts` says it is
        // today, which is not something to put an API key on.
        "http" => {
            let loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            anyhow::ensure!(
                loopback,
                "{raw} is plaintext http:// to {}: this node will not put an API key on the wire in the clear to anywhere but a loopback address",
                url.host_str().unwrap_or("nowhere")
            );
            Ok(())
        }
        other => bail!("{raw} is {other}://, not https://"),
    }
}

/// The blocking client every call goes through.
///
/// **`no_proxy()` is deliberately absent**, which is the opposite of the
/// choice the Ollama adapter makes and for the opposite reason: that one talks
/// to loopback, where a proxy could only ever be an interception, while this
/// one talks to the public internet from inside whatever network the node is
/// on, where a proxy is how a great many companies reach it at all. The arch
/// says `locality: Cloud` and `governed: false`, so a proxy in the path
/// changes nothing it claims.
///
/// rustls rather than the platform's TLS, so the same build works on all three
/// CI runners, and a connect timeout so a black-holed route fails in ten
/// seconds rather than at the call's own timeout.
///
/// **`Policy::none()` is the other load-bearing line.** reqwest follows up to
/// ten redirects by default and, on a host change, strips only `authorization`,
/// `cookie`, `cookie2`, `proxy-authorization` and `www-authenticate` —
/// `x-api-key` is a custom header and is on none of those lists, so it would
/// be re-sent verbatim to wherever a `307` pointed, body and all (fix round 1,
/// Important 1). The Messages API does not redirect; a redirect here is an
/// interception or a misconfiguration, and either is a failed call rather than
/// a hop to follow.
fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent("verticalai-vk-arch-anthropic")
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build the HTTPS client for the Anthropic API")
}

/// The first `n` characters of `s`, marked when something was cut — a far end
/// that answers with a whole HTML error page must not put it in a log line.
fn head(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.trim().to_string();
    }
    format!("{}…", s.chars().take(n).collect::<String>())
}

/// The answer: every `text` block, in order, and nothing else.
///
/// Not `content[0].text`. A response carries `thinking` blocks as well —
/// empty ones, since `display` defaults to `omitted` — and on a model that
/// used a server tool it would carry those too. Concatenating the `text`
/// blocks is the documented way to read the reply, and skipping the rest is
/// what keeps an empty thinking block out of the register.
fn text_of(content: &serde_json::Value) -> String {
    content
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<String>()
        })
        .unwrap_or_default()
}

impl ArchAdapter for AnthropicAdapter {
    fn manifest(&self) -> &ArchManifest {
        &self.manifest
    }

    /// What `complete` will actually accept, not the manifest's ceiling: the
    /// kernel projects a long prompt *into* this number, so reporting the full
    /// ceiling would have it fit a prompt the adapter then refuses.
    fn context_budget(&self) -> u32 {
        self.usable_ceiling()
    }

    /// The estimate, not the API.
    ///
    /// The kernel calls this once per candidate line while it fits a prompt,
    /// and each of those would be an HTTPS round trip to another continent.
    /// The measured count is taken once, in `complete`, where it is worth the
    /// trip. The two cannot disagree in the dangerous direction: the estimate
    /// runs high (spike 1a measured 1.25× the real count on prose and 1.9× on
    /// a short prompt), so a prompt the kernel fitted by this ruler is one the
    /// API's own count also fits — and in the rare case it is not, refusing is
    /// the correct I4′ answer rather than a truncation at the far end.
    fn count_tokens(&self, text: &str) -> u32 {
        Self::estimate_tokens(text)
    }

    fn complete(&self, prompt: &str, max_tokens: u32) -> Result<Completion, AdapterError> {
        let ceiling = self.usable_ceiling();
        // I4′, before anything is sent, from the API's own tokenizer — and
        // from the estimate when that call fails, because a rate-limited
        // counter should cost accuracy and not the inference.
        let (needed, counted) = match self.api_count_tokens(prompt) {
            Ok(n) => (n, true),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "the Anthropic token counter did not answer; falling back to the estimate"
                );
                (Self::estimate_tokens(prompt), false)
            }
        };
        if needed > ceiling {
            return Err(AdapterError::I4Prime { needed, ceiling });
        }

        let client = self.client()?;
        let req = Self::messages_request(&self.cfg, prompt, max_tokens);
        let answer = self
            .post(client, "/v1/messages", &req, self.cfg.timeout)
            .and_then(|r| self.read("/v1/messages", r))
            .map_err(AdapterError::Other)?;

        let usage = &answer["usage"];
        let tokens_in = usage["input_tokens"].as_u64().unwrap_or(0);
        let tokens_in = u32::try_from(tokens_in).unwrap_or(u32::MAX);
        let tokens_out =
            u32::try_from(usage["output_tokens"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);

        // I4′ again, from the provider's own count of what it read. The API
        // refuses an oversize prompt rather than truncating it, so reaching
        // this is a surprise — but a surprise about the size of the prompt is
        // exactly the surprise this invariant exists to catch.
        //
        // Against the **full** window, and the refusal says so: comparing the
        // measured count against `0.9 ×` would be tautological on the path
        // where the pre-check already measured it, and a refusal reporting a
        // ceiling it did not compare against is one no operator can reconcile
        // with a single number (fix round 1, Minor 1).
        if tokens_in >= self.manifest.context_ceiling {
            return Err(AdapterError::I4Prime {
                needed: tokens_in,
                ceiling: self.manifest.context_ceiling,
            });
        }

        let stop_reason = answer["stop_reason"].as_str().unwrap_or("").to_string();
        // A safety classifier declined the request: HTTP 200, no content, a
        // `refusal` stop reason and a category beside it. That is a failed
        // call, not an empty draft to raise into a register.
        if stop_reason == "refusal" {
            let category = answer["stop_details"]["category"]
                .as_str()
                .unwrap_or("unspecified");
            return Err(AdapterError::Other(anyhow!(
                "the model declined this prompt (stop_reason refusal, category {category})"
            )));
        }

        let text = text_of(&answer["content"]);
        if text.trim().is_empty() {
            return Err(AdapterError::Other(anyhow!(
                "the Anthropic API answered {tokens_in} prompt tokens with no text at all \
                 (stop_reason {}, {tokens_out} output tokens)",
                if stop_reason.is_empty() {
                    "none"
                } else {
                    &stop_reason
                },
            )));
        }

        Ok(Completion {
            text,
            // The provider counted the prompt; the pre-check above only had
            // to decide whether to make the call.
            tokens_in_measured: Some(tokens_in),
            tokens_out: Some(tokens_out),
            cost_list_usd: Self::cost_list_usd(&self.cfg.model, tokens_in, tokens_out),
            details: Some(serde_json::json!({
                "input_tokens": tokens_in,
                "output_tokens": tokens_out,
                // Always zero: this adapter sets no `cache_control`, so there
                // is no cached prefix and `input_tokens` is the whole prompt.
                // Recorded anyway, so the day one is set the record says so.
                "cache_creation": usage["cache_creation_input_tokens"].as_u64().unwrap_or(0),
                "cache_read": usage["cache_read_input_tokens"].as_u64().unwrap_or(0),
                "stop_reason": stop_reason,
                "message_id": answer["id"].as_str().unwrap_or("-"),
                "model": answer["model"].as_str().unwrap_or(&self.cfg.model),
                // Whether the pre-check was a measurement or a guess. The
                // difference matters to anyone auditing an I4′ refusal.
                "prompt_counted_by_api": counted,
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_price_tag_is_the_input_rate_per_thousand_tokens_in_euros() {
        // $5 per million in, at the pinned rate: €0.0046 per 1 000.
        let opus = cost_per_1k_tokens_eur("claude-opus-5").expect("a listed model is priced");
        assert!((opus - 0.0046).abs() < 1e-12);
        // And a model with no row claims nothing — `None`, never `0.0`, which
        // would read as free (Ruling 30).
        assert_eq!(cost_per_1k_tokens_eur("claude-imaginary-9"), None);
    }

    #[test]
    fn the_default_ceiling_is_the_model_s_documented_window() {
        let cfg = AnthropicConfig::default();
        assert_eq!(cfg.ceiling(), 1_000_000);
        // And `--ctx` pins a smaller one.
        assert_eq!(
            AnthropicConfig {
                context_ceiling: 200_000,
                ..Default::default()
            }
            .ceiling(),
            200_000
        );
    }

    #[test]
    fn the_answer_cap_is_never_past_the_arch_s_own() {
        let cfg = AnthropicConfig {
            max_tokens: 100_000,
            ..Default::default()
        };
        assert_eq!(answer_tokens(&cfg, 0), MAX_OUTPUT_TOKENS);
        assert_eq!(answer_tokens(&cfg, 10), 10);
    }

    #[test]
    fn only_the_text_blocks_are_the_answer() {
        let content = serde_json::json!([
            {"type": "thinking", "thinking": ""},
            {"type": "text", "text": "a"},
            {"type": "tool_use", "name": "x"},
            {"type": "text", "text": "b"},
        ]);
        assert_eq!(text_of(&content), "ab");
        assert_eq!(text_of(&serde_json::Value::Null), "");
    }

    #[test]
    fn an_origin_is_https_anywhere_or_plaintext_only_on_this_machine() {
        for good in [
            "https://api.anthropic.com",
            "https://gateway.example.com/v1",
            "http://127.0.0.1:8080",
            "http://127.0.0.2:9999/base",
            "http://[::1]:9000",
        ] {
            assert!(check_base_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://collector.example",
            "http://10.0.0.5:80",
            // Starts with `127.` and is somebody else's machine.
            "http://127.example.com",
            // A name, not an address: `hosts` decides where it goes.
            "http://localhost:3000/base",
            // WHATWG ends the authority at the backslash, so the host is
            // `evil.example` and the rest is a path. A scan that took
            // everything after the last `@` read this as loopback.
            r"http://evil.example\@127.0.0.1",
            "ftp://api.anthropic.com",
            "api.anthropic.com",
        ] {
            assert!(check_base_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn thinking_is_sent_only_to_a_model_that_takes_it() {
        let adaptive = AnthropicAdapter::messages_request(&AnthropicConfig::default(), "hi", 0);
        assert_eq!(
            adaptive["thinking"],
            serde_json::json!({"type": "adaptive"})
        );
        // Haiku 4.5 is a 4.5-generation model: `adaptive` is a 400 there, so
        // the block is left out rather than sent and refused.
        let haiku = AnthropicAdapter::messages_request(
            &AnthropicConfig {
                model: "claude-haiku-4-5".into(),
                ..Default::default()
            },
            "hi",
            0,
        );
        assert!(haiku.get("thinking").is_none(), "{haiku}");
        // And an unlisted model is not guessed about.
        let unknown = AnthropicAdapter::messages_request(
            &AnthropicConfig {
                model: "claude-imaginary-9".into(),
                ..Default::default()
            },
            "hi",
            0,
        );
        assert!(unknown.get("thinking").is_none(), "{unknown}");
    }
}
