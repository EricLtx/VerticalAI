//! Claude **hosted in the EU**, through Amazon Bedrock's `Converse` API.
//!
//! The same models as the first-party arch, reached in `eu-central-1`
//! (Frankfurt) or `eu-west-1` (Ireland), which is the whole point: a register
//! that may not leave the Union has one arch it can be lowered into, and the
//! manifest says so where I2 can read it — `jurisdiction: "EU"`,
//! `retention_days: None`, because AWS does not store model inputs or outputs
//! for Bedrock inference.
//!
//! ## What is compiled, and what is behind the feature
//!
//! Everything a test can reach is unconditional: [`manifest_for`],
//! [`converse_input`], [`check_region`] and [`model_id`]. The transport —
//! [`BedrockAdapter`], the AWS SDK, the runtime — is behind the `bedrock`
//! cargo feature, which is **on by default** because the measurement allowed
//! it: 83 extra crates and about a minute on a clean Windows build of this
//! crate (15 s to 1 m 15 s), well inside the budget that would have made it
//! default-off. A node that wants neither the SDK nor those 83 crates in its
//! supply chain builds `--no-default-features`, and `vk mount bedrock` is
//! then refused by name and says how to get a build that has it.
//!
//! ## What is not pinned here
//!
//! There are no AWS credentials on the machine this was written on, so the
//! request shape below is pinned by [`converse_input`] against the documented
//! `Converse` body and **has never been sent**. Two things in particular are
//! unverified against a live endpoint and are flagged in the Task 2b report:
//! the `eu.` cross-region inference-profile prefix [`model_id`] puts on a bare
//! model name, and Bedrock's own price list, which is AWS's and not
//! Anthropic's — so this manifest carries **no** price rather than the
//! first-party one (see [`cost_per_1k_tokens_eur`] below).

use vk_contracts::arch::{ArchIdentity, ArchManifest, Capability, Determinism, Locality};
use vk_contracts::labels::{Clearance, Scope};

use crate::{context_window, DEFAULT_MODEL, MAX_OUTPUT_TOKENS};

/// The regions this adapter will claim `jurisdiction: "EU"` for. Not a
/// filter on what Bedrock serves — it serves Claude in many places — but on
/// what this node is willing to call European.
pub const EU_REGIONS: &[&str] = &["eu-central-1", "eu-west-1"];

/// Everything `arch.mount { kind: "bedrock" }` may say.
#[derive(Debug, Clone, PartialEq)]
pub struct BedrockConfig {
    /// One of [`EU_REGIONS`].
    pub region: String,
    /// A bare model name (`claude-opus-5`), which [`model_id`] qualifies, or
    /// a full Bedrock model id or inference-profile ARN, which it passes
    /// through untouched.
    pub model: String,
    pub max_tokens: u32,
    /// `0` means "the model's documented window".
    pub context_ceiling: u32,
}

impl Default for BedrockConfig {
    fn default() -> BedrockConfig {
        BedrockConfig {
            region: "eu-central-1".into(),
            model: DEFAULT_MODEL.into(),
            max_tokens: MAX_OUTPUT_TOKENS,
            context_ceiling: 0,
        }
    }
}

impl BedrockConfig {
    fn ceiling(&self) -> u32 {
        if self.context_ceiling > 0 {
            self.context_ceiling
        } else {
            context_window(&self.model)
        }
    }
}

/// Refuse a region this node will not call European.
///
/// The manifest's `jurisdiction: "EU"` is the reason this arch exists. A
/// mount in `us-east-1` that still carried it would be the manifest lying
/// about the only thing it was mounted for, so the region is checked at the
/// door rather than trusted.
pub fn check_region(region: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        EU_REGIONS.contains(&region),
        "{region} is not an EU region: this arch mounts in {} only, because its \
         manifest claims jurisdiction EU and that claim is the region",
        EU_REGIONS.join(" or ")
    );
    Ok(())
}

/// The id Bedrock is asked for.
///
/// A name with a `.` in it is already qualified — a Bedrock model id
/// (`anthropic.claude-sonnet-5`), a cross-region inference profile
/// (`eu.anthropic.claude-opus-5`) or an ARN — and is passed through exactly as
/// given: a caller who names a profile means that profile. A bare name is
/// qualified for the region: Claude on Bedrock in Europe is reached through
/// the `eu.` cross-region inference profile, which is what routes a call
/// between the European regions and never out of them.
pub fn model_id(region: &str, model: &str) -> String {
    if model.contains('.') {
        return model.to_string();
    }
    let prefix = region.split('-').next().unwrap_or_default();
    if EU_REGIONS.contains(&region) {
        format!("{prefix}.anthropic.{model}")
    } else {
        format!("anthropic.{model}")
    }
}

/// The manifest for this configuration.
///
/// The region is inside `ArchIdentity`: the same model in Frankfurt and in
/// Dublin are two arches, because where the inference happened is part of
/// what an auditor is being told. `backend` is `aws-bedrock` rather than
/// `anthropic-first-party`, so the two hosts can never share an arch id even
/// on the same model.
pub fn manifest_for(cfg: &BedrockConfig) -> ArchManifest {
    ArchManifest {
        name: format!("bedrock/{}/{}", cfg.region, cfg.model),
        capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
        locality: Locality::Cloud,
        // The whole reason for this arch.
        jurisdiction: "EU".into(),
        // Not "unknown": AWS does not retain model inputs or outputs for
        // Bedrock inference, so there is no window to name.
        retention_days: None,
        // Bedrock is partner-operated and priced by AWS, not by Anthropic.
        // This node has not read that price list, so it claims no price at
        // all: `None`, which `vk top` prints as `?`. Not `0.0`, which would
        // tell an operator their EU calls were free (Ruling 30).
        cost_per_1k_tokens_eur: None,
        latency_ms_p50: crate::model(&cfg.model).map_or(12_000, |m| m.latency_ms_p50),
        context_ceiling: cfg.ceiling(),
        determinism: Determinism::NonDeterministic,
        identity: ArchIdentity {
            weights_sha256: format!("model:{}", cfg.model),
            engine: "bedrock-converse".into(),
            engine_version: "converse-2023-09-30".into(),
            backend: "aws-bedrock".into(),
            quant: "-".into(),
            kv_cache: "-".into(),
            threads: 1,
            batch: 1,
            sampling: [
                ("region".to_string(), cfg.region.clone()),
                ("model_id".to_string(), model_id(&cfg.region, &cfg.model)),
            ]
            .into_iter()
            .collect(),
            seed: None,
        },
        clearance: Clearance {
            max_scope: Scope::Business,
            third_party_allowed: false,
        },
        governed: false,
    }
}

/// The body of the one `Converse` call this adapter makes, as JSON.
///
/// JSON rather than the SDK's builders on purpose: this is the shape the
/// request must have, and it has to be assertable in a build that does not
/// compile the AWS SDK at all. [`BedrockAdapter::complete`] builds the typed
/// request from the same two numbers, so the two cannot drift without a test
/// noticing.
///
/// `max_tokens` is the caller's bound on this one answer; `0` means "no
/// opinion" and [`MAX_OUTPUT_TOKENS`] is used. Note what is not in it: no
/// `thinking` block. Adaptive thinking is a first-party Messages API
/// parameter and `Converse` has its own `additionalModelRequestFields` route
/// to it, which this adapter does not take — an EU arch that has never been
/// exercised should send the smallest request that works.
pub fn converse_input(prompt: &str, max_tokens: u32) -> serde_json::Value {
    let bounded = if max_tokens == 0 {
        MAX_OUTPUT_TOKENS
    } else {
        max_tokens.min(MAX_OUTPUT_TOKENS)
    };
    serde_json::json!({
        "messages": [{ "role": "user", "content": [{ "text": prompt }] }],
        "inferenceConfig": { "maxTokens": bounded },
    })
}

// --------------------------------------------------------------- the client

/// The transport. Compiled only with the `bedrock` feature; see the module
/// documentation for why it is off by default.
#[cfg(feature = "bedrock")]
mod client {
    use super::*;
    use anyhow::{anyhow, Context, Result};
    use aws_sdk_bedrockruntime::types::{
        ContentBlock, ConversationRole, ConverseOutput, InferenceConfiguration, Message,
    };
    use std::sync::Arc;
    use vk_kernel::arch::{AdapterError, ArchAdapter, Completion};

    pub struct BedrockAdapter {
        cfg: BedrockConfig,
        manifest: ArchManifest,
        model_id: String,
        client: aws_sdk_bedrockruntime::Client,
        /// One runtime for the adapter's lifetime, driven from a thread of
        /// its own — see [`block_on`].
        runtime: Arc<tokio::runtime::Runtime>,
    }

    /// Drive a future to completion from a synchronous caller, safely.
    ///
    /// `Runtime::block_on` panics when the calling thread is already inside a
    /// runtime, and `ArchAdapter::complete` is called from the daemon's
    /// blocking pool, where that is exactly the case. A freshly spawned OS
    /// thread is in no runtime at all, so the block happens there and the
    /// caller waits on the join.
    fn block_on<F>(rt: &tokio::runtime::Runtime, future: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        std::thread::scope(|scope| {
            scope
                .spawn(|| rt.block_on(future))
                .join()
                .unwrap_or_else(|_| panic!("the Bedrock call's thread panicked"))
        })
    }

    impl BedrockAdapter {
        /// A client for `region`, or a refusal.
        ///
        /// Refused when the region is not European, and when the AWS
        /// credential chain resolves nothing: an arch that cannot
        /// authenticate is not an arch that is merely idle, and finding that
        /// out at mount is much better than finding it out at the first
        /// inference of a task somebody is waiting on.
        pub fn new(region: &str, model: &str) -> Result<BedrockAdapter> {
            Self::with_config(BedrockConfig {
                region: region.to_string(),
                model: model.to_string(),
                ..Default::default()
            })
        }

        pub fn with_config(cfg: BedrockConfig) -> Result<BedrockAdapter> {
            check_region(&cfg.region)?;
            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(1)
                    .thread_name("vk-bedrock")
                    .build()
                    .context("start the runtime the AWS SDK needs")?,
            );
            let region = aws_config::Region::new(cfg.region.clone());
            let sdk = block_on(
                &runtime,
                aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(region)
                    .load(),
            );
            // Resolve once, here, rather than letting the first inference
            // discover there is nothing to sign with.
            let provider = sdk
                .credentials_provider()
                .ok_or_else(|| anyhow!("no AWS credential provider is configured"))?;
            block_on(&runtime, async {
                use aws_sdk_bedrockruntime::config::ProvideCredentials;
                provider.provide_credentials().await
            })
            .context(
                "no AWS credentials resolved for this node: set them the way the AWS CLI does \
                 (a profile, the environment, or an instance role) and mount again",
            )?;
            let manifest = manifest_for(&cfg);
            let model_id = model_id(&cfg.region, &cfg.model);
            Ok(BedrockAdapter {
                client: aws_sdk_bedrockruntime::Client::new(&sdk),
                cfg,
                manifest,
                model_id,
                runtime,
            })
        }

        fn usable_ceiling(&self) -> u32 {
            (f64::from(self.manifest.context_ceiling) * crate::CONTEXT_HEADROOM) as u32
        }
    }

    impl ArchAdapter for BedrockAdapter {
        fn manifest(&self) -> &ArchManifest {
            &self.manifest
        }

        fn context_budget(&self) -> u32 {
            self.usable_ceiling()
        }

        /// The estimate. `Converse` has no counting endpoint, so unlike the
        /// first-party arch there is nothing better to ask.
        fn count_tokens(&self, text: &str) -> u32 {
            crate::AnthropicAdapter::estimate_tokens(text)
        }

        fn complete(&self, prompt: &str, max_tokens: u32) -> Result<Completion, AdapterError> {
            // I4′ from the estimate: it is the same ruler `context_budget`
            // hands the kernel, so a prompt the kernel fitted is never one
            // this refuses.
            let needed = crate::AnthropicAdapter::estimate_tokens(prompt);
            let ceiling = self.usable_ceiling();
            if needed > ceiling {
                return Err(AdapterError::I4Prime { needed, ceiling });
            }
            // The same two numbers `converse_input` pins, in the SDK's types:
            // the smaller of what the caller asked for and what this arch was
            // mounted with, and the mount's cap when the caller says `0`.
            let cap = self.cfg.max_tokens.clamp(1, MAX_OUTPUT_TOKENS);
            let asked = if max_tokens == 0 {
                cap
            } else {
                max_tokens.min(cap)
            };
            // Read back out of `converse_input` so the typed request and the
            // JSON one this crate pins can never bound an answer
            // differently — and `expect`, not a fallback: a shape change
            // must fail the build's tests, not silently halve the caller's
            // bound (fix round 1, nit).
            let bounded = converse_input(prompt, asked)["inferenceConfig"]["maxTokens"]
                .as_u64()
                .and_then(|n| i32::try_from(n).ok())
                .expect("converse_input always writes inferenceConfig.maxTokens");
            let message = Message::builder()
                .role(ConversationRole::User)
                .content(ContentBlock::Text(prompt.to_string()))
                .build()
                .map_err(|e| AdapterError::Other(anyhow!("build the Converse message: {e}")))?;
            let call = self
                .client
                .converse()
                .model_id(&self.model_id)
                .messages(message)
                .inference_config(
                    InferenceConfiguration::builder()
                        .max_tokens(bounded)
                        .build(),
                )
                .send();
            let answer = block_on(&self.runtime, call).map_err(|e| {
                AdapterError::Other(anyhow!(
                    "Bedrock Converse refused the call in {}: {}",
                    self.cfg.region,
                    aws_message(&e)
                ))
            })?;

            let text = match answer.output() {
                Some(ConverseOutput::Message(m)) => m
                    .content()
                    .iter()
                    .filter_map(|b| b.as_text().ok())
                    .cloned()
                    .collect::<String>(),
                _ => String::new(),
            };
            let (tokens_in, tokens_out) = answer.usage().map_or((0, 0), |u| {
                (
                    u32::try_from(u.input_tokens()).unwrap_or(0),
                    u32::try_from(u.output_tokens()).unwrap_or(0),
                )
            });
            // I4′ from the provider's own count, as on the first-party arch.
            if tokens_in >= self.manifest.context_ceiling {
                return Err(AdapterError::I4Prime {
                    needed: tokens_in,
                    ceiling,
                });
            }
            if text.trim().is_empty() {
                return Err(AdapterError::Other(anyhow!(
                    "Bedrock answered {tokens_in} prompt tokens with no text at all \
                     (stop reason {:?})",
                    answer.stop_reason()
                )));
            }
            Ok(Completion {
                text,
                tokens_in_measured: Some(tokens_in),
                tokens_out: Some(tokens_out),
                // AWS prices Bedrock, not Anthropic, and this node has not
                // read that list. `None` rather than a figure from the wrong
                // table.
                cost_list_usd: None,
                details: Some(serde_json::json!({
                    "input_tokens": tokens_in,
                    "output_tokens": tokens_out,
                    "stop_reason": format!("{:?}", answer.stop_reason()),
                    "region": self.cfg.region,
                    "model_id": self.model_id,
                })),
            })
        }
    }

    /// The service's own message out of an SDK error.
    ///
    /// `SdkError`'s own `Display` is the category ("service error"); the
    /// sentence a person can act on is on the error inside it. The other arms
    /// — a timeout, a failure to construct the request, a response that would
    /// not parse — have no service error to unwrap and say what they are.
    fn aws_message<E, R>(e: &aws_sdk_bedrockruntime::error::SdkError<E, R>) -> String
    where
        E: std::error::Error,
    {
        match e {
            aws_sdk_bedrockruntime::error::SdkError::ServiceError(inner) => inner.err().to_string(),
            other => other.to_string(),
        }
    }
}

#[cfg(feature = "bedrock")]
pub use client::BedrockAdapter;
