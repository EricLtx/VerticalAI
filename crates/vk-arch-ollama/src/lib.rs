//! A Gemma-class model as an arch: Ollama in a container this kernel starts,
//! caps and can stop, behind SP1a's `ArchAdapter` boundary.
//!
//! What makes this one different from the Claude Code arch is that it is
//! *governed*. The inference runs in a process this node launched, under a
//! memory cap and a CPU cap it imposed, on loopback, with the weights in a
//! volume it owns — so the manifest says `governed: true`, `locality: Local`
//! and `jurisdiction: "local"`, and nothing about the call leaves the machine.
//! [`container::caps_applied`] reads the caps back off the running container
//! before that claim is made: an uncapped container is not a governor, and
//! `--external` (an Ollama someone else is running) is never governed at all.
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
//!   `num_ctx / 2` — the signature of a truncation that happened anyway.
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

pub use container::{ContainerSpec, State};

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
    pub seed: u64,
    pub temperature: f32,
    pub container: Option<ContainerSpec>,
}

impl Default for OllamaConfig {
    fn default() -> OllamaConfig {
        OllamaConfig {
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            num_ctx: DEFAULT_NUM_CTX,
            seed: DEFAULT_SEED,
            temperature: DEFAULT_TEMPERATURE,
            container: None,
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
    governed: bool,
    manifest: ArchManifest,
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
        // Governed means: this node started the process *and* the caps it
        // asked for are the caps it is running under. Both are read back, not
        // assumed — an uncapped container would be a claim we cannot support.
        let governed = match &cfg.container {
            Some(spec) => {
                container::ensure(spec)?;
                container::caps_applied(spec).unwrap_or(false)
            }
            None => false,
        };
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
        let manifest = Self::manifest_for(&cfg, &identity, &ollama_version, governed);
        Ok(OllamaAdapter {
            cfg,
            client,
            identity,
            ollama_version,
            tokenize_available,
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
    /// free-form identity map, as `max_turns` is on the Claude Code arch.
    pub fn manifest_for(
        cfg: &OllamaConfig,
        id: &ModelIdentity,
        ollama_version: &str,
        governed: bool,
    ) -> ArchManifest {
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
            cost_per_1k_tokens_eur: 0.0,
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
                // Ollama picks both from what it finds in the container. The
                // cap that bounds them is `ContainerSpec`, which is not an
                // identity: the same model under a tighter cap is the same
                // model, only slower.
                threads: 1,
                batch: 1,
                sampling: [
                    ("family".to_string(), id.family.clone()),
                    ("parameter_size".to_string(), id.parameter_size.clone()),
                    ("num_ctx".to_string(), cfg.num_ctx.to_string()),
                    ("temperature".to_string(), cfg.temperature.to_string()),
                    ("think".to_string(), "false".to_string()),
                ]
                .into_iter()
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
    pub fn chat_request(cfg: &OllamaConfig, prompt: &str) -> api::ChatRequest {
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
                seed: cfg.seed,
                temperature: cfg.temperature,
            },
        }
    }

    /// What the server said the weights are.
    pub fn identity(&self) -> &ModelIdentity {
        &self.identity
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

    fn complete(&self, prompt: &str, _max_tokens: u32) -> Result<Completion, AdapterError> {
        // I4′, before anything is sent. `count_tokens`, not the estimate
        // directly: it is the same ruler `context_budget` hands the kernel, so
        // a prompt the kernel fitted is never one this refuses (they are the
        // same number on 0.33.3, which has no tokenizer to disagree with).
        let needed = self.count_tokens(prompt);
        let ceiling = self.usable_ceiling();
        if needed > ceiling {
            return Err(AdapterError::I4Prime { needed, ceiling });
        }

        let req = Self::chat_request(&self.cfg, prompt);
        let answer =
            api::chat(&self.client, &self.cfg.base_url, &req).map_err(AdapterError::Other)?;

        // I4′ again, from the server's own count. Ollama cuts an oversize
        // prompt to `num_ctx / 2 + 3` and reports success; reaching that line
        // means what came back is an answer to a prompt nobody wrote, and it
        // must not be raised into a register as though it were.
        if answer.prompt_eval_count >= self.cfg.num_ctx / 2 {
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

    #[test]
    fn a_governed_arch_and_an_external_one_are_not_the_same_arch() {
        let contained = OllamaConfig::governed(DEFAULT_MODEL);
        let external = OllamaConfig {
            container: None,
            ..contained.clone()
        };
        let a = OllamaAdapter::manifest_for(&contained, &identity(), "0.33.3", true);
        let b = OllamaAdapter::manifest_for(&external, &identity(), "0.33.3", false);
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

    #[test]
    fn the_smaller_model_is_the_faster_one_and_neither_changes_the_arch_id() {
        assert!(latency_p50_ms(TEST_MODEL) < latency_p50_ms(DEFAULT_MODEL));
        let cfg = OllamaConfig::default();
        let a = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", true);
        let mut b = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", true);
        b.latency_ms_p50 = 1;
        b.context_ceiling = 1;
        assert_eq!(a.arch_id(), b.arch_id());
    }
}
