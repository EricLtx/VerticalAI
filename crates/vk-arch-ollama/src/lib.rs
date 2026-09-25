//! A Gemma-class model as an arch: Ollama in a container this kernel starts,
//! caps and can stop, behind SP1a's `ArchAdapter` boundary.
//!
//! What makes this one different from the Claude Code arch is that it is
//! *governed*. The inference runs in a process this node launched, under a
//! memory cap and a CPU cap it imposed, on loopback, with the weights in a
//! volume it owns — so the manifest says `governed: true`, `locality: Local`
//! and `jurisdiction: "local"`, and nothing about the call leaves the machine.
//! Three things keep that from being a slogan: the HTTP client never consults
//! a proxy ([`api::client`]), an existing container is adopted only when it is
//! exactly the one being asked for ([`container::ensure`]), and the caps that
//! go in the manifest are the ones [`container::governor`] read back off the
//! running container. An uncapped container is not a governor, and
//! `--external` (an Ollama someone else is running, on this machine's loopback
//! and nowhere else until SP4) is never governed at all.
//!
//! Identity is content-addressed. The arch id is built from the digest
//! `/api/tags` reports for the tag, not from the tag — `gemma4:e4b` is a name
//! that can be re-pointed, `c6eb396d…` is the weights — together with the
//! family, the parameter size, the quantisation, the Ollama version, `num_ctx`
//! and the seed. Change any of them and it is a different arch.
//!
//! ## The context ceiling is half of what the server advertises (I4′)
//!
//! Spike 1a measured Ollama 0.33.3 silently cutting an oversize prompt to
//! `num_ctx / 2 + 3` tokens: HTTP 200, `done_reason: "stop"`, no error field,
//! nothing but a `WARN` in the container's log. An arch that lets that happen
//! reports a confident answer to half a question, which is exactly what I4′
//! exists to prevent. So this adapter:
//!
//! * puts the ceiling at `min(num_ctx, context_length) / 2` — what the server
//!   will really read, not what it advertises;
//! * refuses, before the call, any prompt whose count is past nine tenths of
//!   that (the tenth is the margin the estimate is allowed to be wrong by);
//! * refuses, after the call, any answer whose `prompt_eval_count` reached
//!   that same ceiling — the signature of a truncation that happened anyway.
//!
//! There is no tokenizer to ask on 0.33.3 (`/api/tokenize` 404s), so the count
//! before the call is the same three-bytes-a-token estimate the Claude Code
//! arch uses; spike 1a measured it at 1.25× the real count on prose, which is
//! the right direction for a refusal to err in.
pub mod api;
pub mod container;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use std::time::Duration;
use vk_contracts::arch::{ArchIdentity, ArchManifest, Capability, Determinism, Locality};
use vk_contracts::labels::{Clearance, Scope};
use vk_kernel::arch::{AdapterError, ArchAdapter, Completion};

pub use container::{ContainerSpec, Governor, State};

/// The model the demo runs on (spike 1a's `VK_DEMO_MODEL`): Gemma 4 E4B,
/// measured at 10.1 tokens/s on this machine's CPU.
pub const DEFAULT_MODEL: &str = "gemma4:e4b";
/// The model the tests run on (`VK_TEST_MODEL`): 815 MB and 22.5 tokens/s, so
/// CI can pull it every run. Gemma 4 has no 1B-class tag.
pub const TEST_MODEL: &str = "gemma3:1b";
/// The Ollama image, pinned to the version spike 1a measured. The version is
/// in the arch identity, so moving this mints new arch ids — deliberately.
pub const DEFAULT_IMAGE: &str = "ollama/ollama:0.33.3";
/// The digest of that image as it was pulled on 2026-09-24.
pub const PINNED_IMAGE_DIGEST: &str =
    "sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2";
/// Where a container mount's server listens. Loopback, always.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";
pub const DEFAULT_NUM_CTX: u32 = 8192;
pub const DEFAULT_SEED: u64 = 7;
/// Low, not zero: zero is not more deterministic than this on a model that is
/// also given a seed, and it makes short answers repeat themselves.
pub const DEFAULT_TEMPERATURE: f32 = 0.2;
/// The longest answer this arch will produce unless the caller asks for less
/// (Ruling 9a). Sent as `num_predict` on every call: without it a local model
/// runs until it decides to stop, and at ten tokens a second on a CPU that is
/// a wait with no end anybody chose. 2048 is roughly three minutes of the demo
/// model, and half the usable context of the default mount.
pub const DEFAULT_MAX_TOKENS: u32 = 2048;

/// How much of the ceiling a prompt may take before the call is refused — the
/// margin the estimate is allowed to be wrong by (I4′).
const CONTEXT_HEADROOM: f64 = 0.9;
/// How long a just-started container is given to answer `/api/version`.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// Everything a mount needs to know. `container: None` is `--external`: an
/// Ollama somebody else is running, which this node cannot cap and therefore
/// cannot call governed.
#[derive(Debug, Clone, PartialEq)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
    pub num_ctx: u32,
    /// The cap on one answer, sent as `num_predict` (Ruling 9a). Not part of
    /// the arch identity: how long an answer may run does not change what the
    /// model is.
    pub max_tokens: u32,
    pub seed: u64,
    pub temperature: f32,
    pub container: Option<ContainerSpec>,
    /// Throw an existing container away and make it again from the pinned
    /// line, keeping the volume (Ruling 10). The remedy the refusal names
    /// when the container that is there is not the one being asked for; an
    /// action, not a property of the container, which is why it sits here and
    /// not on [`ContainerSpec`].
    pub recreate: bool,
}

impl Default for OllamaConfig {
    fn default() -> OllamaConfig {
        OllamaConfig {
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            num_ctx: DEFAULT_NUM_CTX,
            max_tokens: DEFAULT_MAX_TOKENS,
            seed: DEFAULT_SEED,
            temperature: DEFAULT_TEMPERATURE,
            container: None,
            recreate: false,
        }
    }
}

impl OllamaConfig {
    /// The same defaults, in a container this kernel starts and caps.
    pub fn governed(model: &str) -> OllamaConfig {
        OllamaConfig {
            model: model.into(),
            container: Some(ContainerSpec::default()),
            ..Default::default()
        }
    }
}

/// What the server says the weights are. Read once, at mount: two calls of one
/// mount must be the same model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    /// The content address from `/api/tags`, as the server spells it.
    pub digest: String,
    pub family: String,
    pub parameter_size: String,
    pub quantization: String,
    /// The model's own window, from `/api/show`. Not what will be read — see
    /// the ceiling — but what the weights were trained to hold.
    pub context_length: u32,
}

pub struct OllamaAdapter {
    cfg: OllamaConfig,
    client: Client,
    identity: ModelIdentity,
    ollama_version: String,
    /// Does this server have `/api/tokenize`? Probed once, at mount: 0.33.3
    /// does not, and no call should pay for a 404 to find out again.
    tokenize_available: bool,
    /// What the container was actually running under, read off it at mount —
    /// `None` for an external server, which this node governs not at all.
    governor: Option<Governor>,
    /// Did this mount start the container? Only then is it this arch's to stop
    /// when it is unmounted.
    started_here: bool,
    /// Docker's id for the container this mount handled — not its name. A
    /// `--recreate` puts a *different* container behind the same name, so the
    /// arch it replaced must be able to tell that the thing now called
    /// `vk-ollama` is not the one it started (Ruling 13).
    container_id: String,
    governed: bool,
    manifest: ArchManifest,
}

/// Stop the container when the arch that started it goes away.
///
/// `vk umount` drops the adapter, and a governed arch that leaves a model
/// resident in a container nobody is using is not a kernel that "can stop it"
/// (SP1b Task 1 review, Minor 3). Only a container *this mount started* is
/// stopped: one that was already running when we arrived belongs to whoever
/// started it — another mount of another model, or a person — and stopping it
/// would be this arch reaching outside itself.
///
/// It is also the *same* container: a `--recreate` mount replaces the arch
/// and puts a new container behind the same name, and stopping that would
/// break the mount that replaced this one, so the id is checked first
/// (Ruling 13).
///
/// Best effort, as every `Drop` must be: the error has nowhere to go but the
/// log, and a failed stop must not panic a daemon that is unmounting.
impl Drop for OllamaAdapter {
    fn drop(&mut self) {
        let Some(spec) = self.cfg.container.as_ref().filter(|_| self.started_here) else {
            return;
        };
        match container::inspected(spec) {
            Ok(Some(now)) if now.id == self.container_id => {
                if let Err(e) = container::stop(spec) {
                    tracing::warn!(container = %spec.name, "could not stop the container this arch started: {e:#}");
                }
            }
            Ok(_) => tracing::debug!(
                container = %spec.name,
                "not stopping it: the container there is not the one this arch started"
            ),
            Err(e) => {
                tracing::warn!(container = %spec.name, "could not check the container before stopping it: {e:#}");
            }
        }
    }
}

impl OllamaAdapter {
    /// Bring the arch up: the container if one was asked for, the server, the
    /// model, and the identity of what is actually loaded.
    ///
    /// Everything slow is here rather than in `complete`: starting a container
    /// takes seconds, a cold pull takes minutes, and the caller mounting is
    /// the one who should wait for it. `vkd` calls this before it takes the
    /// kernel lock, so a pull does not wedge every other syscall on the node.
    pub fn mount(cfg: OllamaConfig) -> Result<OllamaAdapter> {
        // An ungoverned arch may be somebody else's server, but it may not be
        // somebody else's *machine*: a prompt crossing the network is a
        // different product with a different contract (Ruling 9c).
        if cfg.container.is_none() {
            check_loopback(&cfg.base_url)?;
        }
        // Governed means: this node started the process, and the caps it is
        // actually running under are the ones asked for. `ensure` refuses to
        // adopt a container that is not the one asked for (Ruling 10), and
        // what is claimed afterwards is read off the container — never taken
        // from the request.
        let (governor, started_here, container_id) = match &cfg.container {
            Some(spec) => {
                // Before anything is started or adopted: if somebody else is
                // already on the published port, this mount would either fail
                // to publish it or read its identity off their server
                // (Ruling 12).
                container::check_port_free(spec)?;
                let state = if cfg.recreate {
                    container::recreate(spec)?
                } else {
                    container::ensure(spec)?
                };
                // One inspect for all three: the caps that decide `governed`,
                // and the id that decides, later, whether the container still
                // there is the one this mount handled.
                let now = container::inspected(spec)?
                    .with_context(|| format!("no container {} to read the caps off", spec.name))?;
                (Some(now.governor), container::started_here(state), now.id)
            }
            None => (None, false, String::new()),
        };
        let governed = governor.as_ref().is_some_and(Governor::capped);
        let client = api::client()?;
        let ollama_version = api::wait_for_version(&client, &cfg.base_url, START_TIMEOUT)?;

        // The tag, or a pull of it. Asked of `/api/tags` rather than of
        // `/api/show`, because the digest has to come from there anyway.
        let mut tags = api::tags(&client, &cfg.base_url)?;
        if api::digest_of(&tags, &cfg.model).is_none() {
            api::pull(&client, &cfg.base_url, &cfg.model)
                .with_context(|| format!("{} is not on this server", cfg.model))?;
            tags = api::tags(&client, &cfg.base_url)?;
        }
        let digest = api::digest_of(&tags, &cfg.model).ok_or_else(|| {
            anyhow::anyhow!(
                "Ollama reports no digest for {} even after pulling it; \
                 the arch id would name no particular weights",
                cfg.model
            )
        })?;

        let shown = api::show(&client, &cfg.base_url, &cfg.model)?;
        let context_length = shown.context_length().ok_or_else(|| {
            anyhow::anyhow!(
                "Ollama does not say how much context {} holds \
                 (no model_info[\"{}.context_length\"]); refusing to guess it",
                cfg.model,
                shown.details.family
            )
        })?;
        let identity = ModelIdentity {
            digest,
            family: shown.details.family,
            parameter_size: shown.details.parameter_size,
            quantization: shown.details.quantization_level,
            context_length,
        };
        if ceiling_of(&cfg, &identity) == 0 {
            bail!(
                "num_ctx {} leaves no usable context: Ollama reads at most half of it",
                cfg.num_ctx
            );
        }
        let tokenize_available = api::tokenize_available(&client, &cfg.base_url, &cfg.model);
        let manifest = Self::manifest_for(&cfg, &identity, &ollama_version, governor.as_ref());
        Ok(OllamaAdapter {
            cfg,
            client,
            identity,
            ollama_version,
            tokenize_available,
            governor,
            started_here,
            container_id,
            governed,
            manifest,
        })
    }

    /// The manifest for this model under this configuration.
    ///
    /// Only [`ArchIdentity`] is hashed into the arch id, and everything in it
    /// changes what the model does: the weights (by digest), what they are
    /// (family, size, quantisation), the engine version driving them, the
    /// window they are run in, the seed, and whether the process is one this
    /// node contains. Latency and the ceiling sit outside it, so re-measuring
    /// a throughput does not mint a new arch.
    ///
    /// `sampling` carries what has no field of its own — this manifest's only
    /// free-form identity map, as `max_turns` is on the Claude Code arch. The
    /// governor goes in there too (Ruling 10): the image the container
    /// actually runs and the caps actually in force, so that `governed: true`
    /// is a claim the manifest itself spells out rather than a bare boolean,
    /// and so that the same weights under a 4 GiB cap and under a 12 GiB cap
    /// are visibly not the same arch.
    ///
    /// `governor` is `None` for an external server and `Some` for a container
    /// this node handled; `governed` is `capped()` on it and is never taken
    /// from what the request asked for.
    pub fn manifest_for(
        cfg: &OllamaConfig,
        id: &ModelIdentity,
        ollama_version: &str,
        governor: Option<&Governor>,
    ) -> ArchManifest {
        let governed = governor.is_some_and(Governor::capped);
        ArchManifest {
            name: format!("ollama/{}", cfg.model),
            capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
            // The process runs on this machine either way; `governed` is what
            // says whether this kernel is the one containing it.
            locality: Locality::Local,
            // Not a country: the data never reaches one. The register stays in
            // this node's own store and the prompt stays on loopback.
            jurisdiction: "local".into(),
            retention_days: if governed { Some(0) } else { None },
            // Local compute is not metered. The cost of a call is the CPU it
            // takes, and `vk top` reports the tokens rather than a price.
            cost_per_1k_tokens_eur: Some(0.0),
            latency_ms_p50: latency_p50_ms(&cfg.model),
            context_ceiling: ceiling_of(cfg, id),
            // A seed, a temperature and a fixed engine version: the same
            // prompt on the same build of llama.cpp gives the same answer.
            determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity {
                weights_sha256: normalise_digest(&id.digest),
                engine: "ollama".into(),
                engine_version: ollama_version.into(),
                // Where the engine runs, not which accelerator it found: a
                // container this node caps and a server somebody else runs are
                // not the same arch even on the same weights.
                backend: if cfg.container.is_some() {
                    "docker".into()
                } else {
                    "external".into()
                },
                quant: id.quantization.clone(),
                // Not something the API reports; the default is f16 and this
                // adapter never sets it.
                kv_cache: "-".into(),
                // Ollama picks both from what it finds in the container. What
                // bounds what it finds is the cap — which is *not* here: see
                // `governed` below.
                threads: 1,
                batch: 1,
                sampling: [
                    ("family".to_string(), id.family.clone()),
                    ("parameter_size".to_string(), id.parameter_size.clone()),
                    ("num_ctx".to_string(), cfg.num_ctx.to_string()),
                    ("temperature".to_string(), cfg.temperature.to_string()),
                    ("think".to_string(), "false".to_string()),
                    // Whether this node contains the process, in the one map
                    // the arch id is hashed from (Ruling 11). `ArchManifest`
                    // has a `governed` field, but it is outside `ArchIdentity`
                    // and so outside the id — and a capped container and an
                    // uncapped one carry different clearances
                    // (Personal/Business) and different retention. Two
                    // manifests that disagree about that must never be able to
                    // share an id.
                    ("governed".to_string(), governed.to_string()),
                ]
                .into_iter()
                // The image the container actually runs, by digest: a
                // different Ollama build is a different arch even under the
                // same tag. The cap *values* are deliberately not here — the
                // same model under 12 GiB and under 14 GiB is the same model,
                // only slower — and they are recorded in the mount spec and on
                // every call's `details` instead (Ruling 11).
                .chain(governor.map(|g| ("container_image".to_string(), g.image.clone())))
                .collect(),
                seed: Some(cfg.seed),
            },
            clearance: if governed {
                // Nothing leaves the node and nothing is kept: the one arch
                // this system can hand personal data to.
                Clearance {
                    max_scope: Scope::Personal,
                    third_party_allowed: true,
                }
            } else {
                // Somebody else's server. It may well be on this machine, but
                // this node cannot say what it does with a prompt.
                Clearance {
                    max_scope: Scope::Business,
                    third_party_allowed: false,
                }
            },
            governed,
        }
    }

    /// The prompt token estimate, when there is no tokenizer to ask: three
    /// bytes to the token plus a fixed margin, the same heuristic the Claude
    /// Code arch uses. Spike 1a measured it at 1.25× the real count on prose
    /// and 1.9× on a short prompt — high, which is the direction a refusal
    /// should err in.
    pub fn estimate_tokens(text: &str) -> u32 {
        u32::try_from(text.len() / 3 + 64).unwrap_or(u32::MAX)
    }

    /// The request this adapter puts on the wire, and the only one it does.
    ///
    /// `max_tokens` is the caller's bound on this one answer; `0` means "no
    /// opinion", and the mount's own cap is used. Whichever is smaller wins,
    /// so neither the kernel's per-call bound nor the `--max-tokens` the arch
    /// was mounted with can be talked past (Ruling 9a).
    pub fn chat_request(cfg: &OllamaConfig, prompt: &str, max_tokens: u32) -> api::ChatRequest {
        api::ChatRequest {
            model: cfg.model.clone(),
            messages: vec![api::Message {
                role: "user".into(),
                content: prompt.into(),
            }],
            // One request, one answer: there is no caller here to stream to.
            stream: false,
            // Top level, not in `options`. The demo model is a thinking model,
            // and without this the answer arrives in `message.thinking` and
            // `message.content` comes back empty (spike 1a).
            think: false,
            options: api::Options {
                num_ctx: cfg.num_ctx,
                num_predict: predict_tokens(cfg, max_tokens),
                seed: cfg.seed,
                temperature: cfg.temperature,
            },
        }
    }

    /// What the server said the weights are.
    pub fn identity(&self) -> &ModelIdentity {
        &self.identity
    }

    /// What the container is actually running under — the image it was made
    /// from and the caps in force — or `None` for an external server.
    pub fn governor(&self) -> Option<&Governor> {
        self.governor.as_ref()
    }

    /// Did this mount start the container? Then it is this arch's to stop.
    pub fn started_here(&self) -> bool {
        self.started_here
    }

    /// The Ollama version this arch is pinned to.
    pub fn ollama_version(&self) -> &str {
        &self.ollama_version
    }

    /// Is the inference process one this kernel started and capped?
    pub fn governed(&self) -> bool {
        self.governed
    }

    /// The largest prompt this arch accepts: the ceiling less the margin the
    /// count may be wrong by. One number, used both as the budget the kernel
    /// is told and as the limit `complete` enforces, so the kernel can never
    /// fit a prompt to a size this adapter then refuses.
    fn usable_ceiling(&self) -> u32 {
        (f64::from(self.manifest.context_ceiling) * CONTEXT_HEADROOM) as u32
    }
}

/// The ceiling: half of the smaller of the window asked for and the window the
/// model has. Half, because that is what Ollama 0.33.3 actually reads before
/// it starts cutting (spike 1a) — the advertised window is not a promise.
fn ceiling_of(cfg: &OllamaConfig, id: &ModelIdentity) -> u32 {
    cfg.num_ctx.min(id.context_length) / 2
}

/// The bound on one answer: the smaller of what the caller asked for and what
/// this arch was mounted with, and the mount's cap when the caller says `0`.
fn predict_tokens(cfg: &OllamaConfig, max_tokens: u32) -> u32 {
    if max_tokens == 0 {
        cfg.max_tokens
    } else {
        max_tokens.min(cfg.max_tokens)
    }
}

/// Is this base URL on this machine's own loopback?
///
/// `--external` exists so a person can point the kernel at an Ollama they are
/// already running — on *this* machine. A prompt crossing the network to
/// another host is a different product with a different contract: the arch
/// would still be claiming `locality: Local` while the register left the node,
/// and nothing here could say what the far end does with it. That arrives with
/// SP4; until then it is refused at mount (Ruling 9c).
fn check_loopback(base_url: &str) -> Result<()> {
    let host = host_of(base_url)
        .with_context(|| format!("--external {base_url} is not a URL with a host in it"))?;
    if is_loopback(&host) {
        return Ok(());
    }
    bail!(
        "--external {base_url} names {host}, which is not this machine: a prompt sent there \
         leaves the node, and the arch would still be claiming locality Local. LAN arches arrive \
         with SP4; until then point --external at 127.0.0.1, ::1 or localhost, or mount the \
         governed container instead"
    )
}

/// The host out of `scheme://[user@]host[:port]/…`, lowercased, with the
/// brackets of an IPv6 literal removed.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match authority.strip_prefix('[') {
        // `[::1]:11434` — the colons inside the brackets are the address.
        Some(rest) => rest.split_once(']').map(|(h, _)| h)?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// 127.0.0.0/8, `::1` however it is spelled, and the name every platform
/// resolves to one of them.
fn is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// `sha256:`-prefixed, whichever way the server spelled it, so two mounts of
/// one model cannot mint two arch ids over a punctuation difference.
fn normalise_digest(digest: &str) -> String {
    if digest.contains(':') {
        digest.to_string()
    } else {
        format!("sha256:{digest}")
    }
}

/// p50 for a ~400-token answer on this machine's CPU, from spike 1a's measured
/// generation rate: 10.1 tokens/s for the demo model, 22.5 for the 1B. Outside
/// `ArchIdentity`, so re-measuring it on other hardware mints no new arch.
fn latency_p50_ms(model: &str) -> u32 {
    if model.contains(":1b") || model.contains(":270m") {
        18_000
    } else {
        40_000
    }
}

impl ArchAdapter for OllamaAdapter {
    fn manifest(&self) -> &ArchManifest {
        &self.manifest
    }

    fn context_budget(&self) -> u32 {
        self.usable_ceiling()
    }

    /// The server's count when it has a tokenizer, the estimate when it does
    /// not (every 0.33.3). A failed tokenize falls back rather than failing
    /// the call: this is the kernel's projection loop, and a server that
    /// hiccups mid-projection should cost accuracy, not the inference.
    ///
    /// The kernel calls this once per candidate line while it fits a prompt,
    /// so on a server that does tokenize this is a loopback round trip per
    /// line. That is the price of not guessing.
    fn count_tokens(&self, text: &str) -> u32 {
        if !self.tokenize_available {
            return Self::estimate_tokens(text);
        }
        api::tokenize(&self.client, &self.cfg.base_url, &self.cfg.model, text)
            .unwrap_or_else(|_| Self::estimate_tokens(text))
    }

    fn complete(&self, prompt: &str, max_tokens: u32) -> Result<Completion, AdapterError> {
        // I4′, before anything is sent. `count_tokens`, not the estimate
        // directly: it is the same ruler `context_budget` hands the kernel, so
        // a prompt the kernel fitted is never one this refuses (they are the
        // same number on 0.33.3, which has no tokenizer to disagree with).
        let needed = self.count_tokens(prompt);
        let ceiling = self.usable_ceiling();
        if needed > ceiling {
            return Err(AdapterError::I4Prime { needed, ceiling });
        }

        let req = Self::chat_request(&self.cfg, prompt, max_tokens);
        let answer =
            api::chat(&self.client, &self.cfg.base_url, &req).map_err(AdapterError::Other)?;

        // I4′ again, from the server's own count. Ollama cuts an oversize
        // prompt to `num_ctx / 2 + 3` and reports success; reaching that line
        // means what came back is an answer to a prompt nobody wrote, and it
        // must not be raised into a register as though it were.
        //
        // Against the manifest's ceiling, which is the same
        // `min(num_ctx, context_length) / 2` the pre-check is measured
        // against — not against `num_ctx / 2`, which is the wrong number
        // whenever the model's own window is the binding half and would leave
        // `--ctx 65536` on a 32768-token model with no post-check at all
        // (SP1b Task 1 review, Minor 4).
        if answer.prompt_eval_count >= self.manifest.context_ceiling {
            return Err(AdapterError::I4Prime {
                needed: answer.prompt_eval_count,
                ceiling,
            });
        }

        // An answer with nothing in it is not an answer. The way this happens
        // in practice is a thinking model that ignored `think: false` and put
        // the whole reply in `message.thinking` (spike 1a) — which would reach
        // the register as a confident empty draft. Better a failed call.
        let text = answer.message.map(|m| m.content).unwrap_or_default();
        if text.trim().is_empty() {
            return Err(AdapterError::Other(anyhow::anyhow!(
                "Ollama answered {} prompt tokens with no content at all \
                 (done_reason {:?}, {} output tokens)",
                answer.prompt_eval_count,
                answer.done_reason.unwrap_or_else(|| "none".into()),
                answer.eval_count,
            )));
        }
        Ok(Completion {
            text,
            // The server counted the prompt; the estimate above was only ever
            // a stand-in for this.
            tokens_in_measured: Some(answer.prompt_eval_count),
            // A model on this machine has no list price. Zero would be a
            // number; `None` is the truth.
            cost_list_usd: None,
            details: Some(serde_json::json!({
                "prompt_eval_count": answer.prompt_eval_count,
                "eval_count": answer.eval_count,
                "eval_duration_ns": answer.eval_duration,
                "load_duration_ns": answer.load_duration,
                "done_reason": answer.done_reason,
                // What was governing this call, as it was read off the
                // container at mount: the ledger stores the hash of this
                // payload, so an auditor recomputing it can say not only which
                // weights answered but under which image and which caps
                // (Ruling 10). Null for an external server, which this node
                // governs not at all.
                "container_image": self.governor.as_ref().map(|g| g.image.clone()),
                "container_memory_bytes": self.governor.as_ref().map(|g| g.memory_bytes),
                "container_nano_cpus": self.governor.as_ref().map(|g| g.nano_cpus),
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ModelIdentity {
        ModelIdentity {
            digest: "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb".into(),
            family: "gemma4".into(),
            parameter_size: "8.0B".into(),
            quantization: "Q4_K_M".into(),
            context_length: 131_072,
        }
    }

    #[test]
    fn the_estimate_is_three_bytes_a_token_plus_a_fixed_margin() {
        assert_eq!(OllamaAdapter::estimate_tokens(""), 64);
        assert_eq!(OllamaAdapter::estimate_tokens(&"x".repeat(300)), 164);
    }

    #[test]
    fn the_ceiling_is_half_of_the_smaller_window() {
        let cfg = OllamaConfig::default();
        assert_eq!(ceiling_of(&cfg, &identity()), 4096);
        assert_eq!(
            ceiling_of(
                &OllamaConfig {
                    num_ctx: 262_144,
                    ..cfg.clone()
                },
                &identity()
            ),
            65_536,
            "the model's own window is the other half of the minimum"
        );
    }

    #[test]
    fn a_digest_is_prefixed_once_however_the_server_spelled_it() {
        assert_eq!(normalise_digest("abc"), "sha256:abc");
        assert_eq!(normalise_digest("sha256:abc"), "sha256:abc");
    }

    /// The caps as a container would report them back: 12 GiB and 6 CPUs.
    fn governor() -> Governor {
        Governor {
            image: PINNED_IMAGE_DIGEST.into(),
            memory_bytes: 12_884_901_888,
            nano_cpus: 6_000_000_000,
        }
    }

    #[test]
    fn a_governed_arch_and_an_external_one_are_not_the_same_arch() {
        let contained = OllamaConfig::governed(DEFAULT_MODEL);
        let external = OllamaConfig {
            container: None,
            ..contained.clone()
        };
        let g = governor();
        let a = OllamaAdapter::manifest_for(&contained, &identity(), "0.33.3", Some(&g));
        let b = OllamaAdapter::manifest_for(&external, &identity(), "0.33.3", None);
        assert_ne!(
            a.arch_id(),
            b.arch_id(),
            "the same weights behind a governor and behind somebody else's \
             server must not share an id, or one mount would answer for the other"
        );
        assert_eq!(a.clearance.max_scope, Scope::Personal);
        assert_eq!(b.clearance.max_scope, Scope::Business);
        assert_eq!(a.retention_days, Some(0));
        assert_eq!(b.retention_days, None);
    }

    /// Ruling 11: what the arch id hashes about the container is the image it
    /// runs and *whether* it is governed — never the size of the cap. The same
    /// model under 12 GiB and under 14 GiB is the same model, only slower; a
    /// capped container and an uncapped one carry different clearances and so
    /// must never be able to share an id.
    #[test]
    fn the_cap_size_is_not_the_arch_but_being_capped_at_all_is() {
        let cfg = OllamaConfig::governed(DEFAULT_MODEL);
        let g = governor();
        let capped = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", Some(&g));
        assert!(capped.governed);
        let s = &capped.identity.sampling;
        assert_eq!(s["container_image"], PINNED_IMAGE_DIGEST);
        assert_eq!(s["governed"], "true");
        assert!(
            !s.contains_key("container_memory_bytes") && !s.contains_key("container_nano_cpus"),
            "cap values do not belong in the identity: {s:?}"
        );

        // 12 GiB and 14 GiB on the same image: the same arch.
        let roomier = OllamaAdapter::manifest_for(
            &cfg,
            &identity(),
            "0.33.3",
            Some(&Governor {
                memory_bytes: 15_032_385_536,
                ..g.clone()
            }),
        );
        assert_eq!(
            capped.arch_id(),
            roomier.arch_id(),
            "--memory 12g and --memory 14g are one arch"
        );

        // `--memory 0 --cpus 0` is a container Docker accepts and this node
        // does not govern. Different clearance, different retention, and —
        // because `governed` is in the identity — a different id, so the two
        // manifests can never be mistaken for one another.
        let uncapped = OllamaAdapter::manifest_for(
            &cfg,
            &identity(),
            "0.33.3",
            Some(&Governor {
                memory_bytes: 0,
                nano_cpus: 0,
                ..g
            }),
        );
        assert!(!uncapped.governed);
        assert_eq!(uncapped.identity.sampling["governed"], "false");
        assert_eq!(uncapped.clearance.max_scope, Scope::Business);
        assert_eq!(uncapped.retention_days, None);
        assert_ne!(
            capped.arch_id(),
            uncapped.arch_id(),
            "a governed arch and an ungoverned one must not share an id"
        );
    }

    #[test]
    fn the_smaller_model_is_the_faster_one_and_neither_changes_the_arch_id() {
        assert!(latency_p50_ms(TEST_MODEL) < latency_p50_ms(DEFAULT_MODEL));
        let cfg = OllamaConfig::default();
        let a = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", None);
        let mut b = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", None);
        b.latency_ms_p50 = 1;
        b.context_ceiling = 1;
        assert_eq!(a.arch_id(), b.arch_id());
    }

    /// Ruling 9a: an answer is always bounded, by the smaller of the two
    /// bounds, and `max_tokens` is not part of what the arch *is*.
    #[test]
    fn an_answer_is_bounded_by_the_smaller_of_the_two_caps() {
        let cfg = OllamaConfig::default();
        assert_eq!(
            predict_tokens(&cfg, 1024),
            1024,
            "the caller asked for less"
        );
        assert_eq!(
            predict_tokens(&cfg, 99_999),
            DEFAULT_MAX_TOKENS,
            "the mount's cap is not something a call can talk past"
        );
        assert_eq!(
            predict_tokens(&cfg, 0),
            DEFAULT_MAX_TOKENS,
            "no opinion from the caller means the mount's cap"
        );
        let tight = OllamaConfig {
            max_tokens: 64,
            ..cfg.clone()
        };
        assert_eq!(predict_tokens(&tight, 1024), 64);
        assert_eq!(
            OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", None).arch_id(),
            OllamaAdapter::manifest_for(&tight, &identity(), "0.33.3", None).arch_id(),
            "how long an answer may run does not change which model answers"
        );
    }

    /// Ruling 9c: `--external` is for an engine on this machine. Anything else
    /// would put the register on the network under a manifest still claiming
    /// `locality: Local`.
    #[test]
    fn external_is_loopback_only_until_sp4() {
        for ok in [
            "http://127.0.0.1:11434",
            "http://127.0.0.1:11434/",
            "http://localhost:11434",
            "http://LOCALHOST:11434",
            "http://127.9.9.9:11434",
            "http://[::1]:11434",
            "http://user:pass@127.0.0.1:11434",
        ] {
            check_loopback(ok).unwrap_or_else(|e| panic!("{ok} should be loopback: {e:#}"));
        }
        for refused in [
            "http://192.168.1.10:11434",
            "http://ollama.example.com:11434",
            "http://[2001:db8::1]:11434",
            "http://10.0.0.1",
        ] {
            let e = check_loopback(refused).unwrap_err().to_string();
            assert!(e.contains("LAN arches arrive with SP4"), "{refused}: {e}");
        }
        assert!(check_loopback("not a url at all").is_err());
    }
}
