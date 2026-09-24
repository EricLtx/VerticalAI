//! The adapter against a stand-in Ollama (`tests/fake`): what it puts on the
//! wire, what it refuses, and what it reports having spent.
//!
//! What this pins is the half of the adapter no canned-JSON test can reach:
//! that the request actually sent is the one spike 1a measured — no streaming,
//! no thinking, a bounded answer, the `num_ctx` and `seed` this arch's
//! identity names — that a prompt the model would silently truncate is refused
//! *before* the server is called at all, that a server which truncated anyway
//! is caught afterwards from its own `prompt_eval_count`, and that the usage on
//! the completion is the server's measurement rather than this node's estimate.
mod fake;

use fake::{Canned, Fake, PULLED_DIGEST};
use vk_arch_ollama::{Governor, ModelIdentity, OllamaAdapter, OllamaConfig};
use vk_kernel::arch::{AdapterError, ArchAdapter};

/// A config pointing at the stand-in: no container, so nothing here needs
/// Docker, and `governed` is false for the same reason.
fn config(fake: &Fake, model: &str, num_ctx: u32) -> OllamaConfig {
    OllamaConfig {
        base_url: fake.base_url.clone(),
        model: model.into(),
        num_ctx,
        ..Default::default()
    }
}

fn identity() -> ModelIdentity {
    ModelIdentity {
        digest: "8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc".into(),
        family: "gemma3".into(),
        parameter_size: "999.89M".into(),
        quantization: "Q4_K_M".into(),
        context_length: 32768,
    }
}

/// A container as it would read back: this mount's image, 12 GiB, 6 CPUs.
fn governor() -> Governor {
    Governor {
        image: "sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2".into(),
        memory_bytes: 12_884_901_888,
        nano_cpus: 6_000_000_000,
    }
}

#[test]
fn chat_request_pins_num_ctx_seed_no_streaming_and_no_thinking() {
    let cfg = OllamaConfig {
        model: "gemma4:e4b".into(),
        num_ctx: 8192,
        seed: 7,
        ..Default::default()
    };
    let wire =
        serde_json::to_string(&OllamaAdapter::chat_request(&cfg, "hello", 1024)).expect("json");
    for pinned in [
        r#""stream":false"#,
        r#""think":false"#,
        r#""num_ctx":8192"#,
        r#""seed":7"#,
        r#""role":"user""#,
        r#""content":"hello""#,
    ] {
        assert!(wire.contains(pinned), "{pinned} missing from {wire}");
    }
}

#[test]
fn manifest_identity_changes_with_digest_num_ctx_or_seed() {
    let cfg = OllamaConfig {
        model: "gemma3:1b".into(),
        num_ctx: 8192,
        seed: 7,
        ..Default::default()
    };
    let base = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", Some(&governor()));

    // The ceiling is half of the smaller of the two windows: spike 1a measured
    // Ollama silently cutting a prompt to `num_ctx / 2 + 3`.
    assert_eq!(base.context_ceiling, 4096);
    assert_eq!(
        OllamaAdapter::manifest_for(
            &OllamaConfig {
                num_ctx: 131_072,
                ..cfg.clone()
            },
            &identity(),
            "0.33.3",
            Some(&governor())
        )
        .context_ceiling,
        32768 / 2,
        "a num_ctx past the model's own window does not widen it"
    );

    let other_digest = OllamaAdapter::manifest_for(
        &cfg,
        &ModelIdentity {
            digest: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ..identity()
        },
        "0.33.3",
        Some(&governor()),
    );
    let other_ctx = OllamaAdapter::manifest_for(
        &OllamaConfig {
            num_ctx: 4096,
            ..cfg.clone()
        },
        &identity(),
        "0.33.3",
        Some(&governor()),
    );
    let other_seed = OllamaAdapter::manifest_for(
        &OllamaConfig {
            seed: 8,
            ..cfg.clone()
        },
        &identity(),
        "0.33.3",
        Some(&governor()),
    );
    let other_version = OllamaAdapter::manifest_for(&cfg, &identity(), "0.34.3", Some(&governor()));
    let ids: Vec<String> = [
        &base,
        &other_digest,
        &other_ctx,
        &other_seed,
        &other_version,
    ]
    .iter()
    .map(|m| m.arch_id())
    .collect();
    for (i, a) in ids.iter().enumerate() {
        for b in ids.iter().skip(i + 1) {
            assert_ne!(a, b, "two of these manifests share an arch id: {ids:?}");
        }
    }
    assert_eq!(
        base.arch_id(),
        OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", Some(&governor())).arch_id(),
        "the same configuration is the same arch"
    );

    // `governed` is what the container was read to be, never what the request
    // asked for: a governor with caps in force, or no governor at all.
    assert!(base.governed);
    assert!(!OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", None).governed);
}

#[test]
fn refuses_a_prompt_the_model_would_truncate() {
    let fake = Fake::start(Canned::default());
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");

    // min(8192, 32768) / 2 = 4096, less the tenth the estimate may be wrong by.
    let ceiling = adapter.manifest().context_ceiling;
    assert_eq!(ceiling, 4096);
    assert_eq!(adapter.context_budget(), 3686);

    // A prompt whose estimate is 0.95 of the ceiling: under it, over the
    // budget, and exactly the prompt Ollama would have cut in half in silence.
    let prompt = "x".repeat(((f64::from(ceiling) * 0.95) as usize - 64) * 3);
    let needed = OllamaAdapter::estimate_tokens(&prompt);
    assert!(needed < ceiling && needed > adapter.context_budget());

    match adapter.complete(&prompt, 256) {
        Err(AdapterError::I4Prime {
            needed: n,
            ceiling: c,
        }) => {
            assert_eq!(n, needed);
            assert_eq!(
                c,
                adapter.context_budget(),
                "the refusal and the budget are one number"
            );
        }
        other => panic!("expected an I4' refusal, got {other:?}"),
    }
    assert!(
        fake.calls("/api/chat").is_empty(),
        "the refusal must happen before the model is called"
    );
}

#[test]
fn fails_when_the_server_reports_a_truncated_prompt() {
    // The server claims to have read `num_ctx / 2 + 3` tokens of the prompt —
    // spike 1a's signature of a silent truncation, with HTTP 200 and
    // `done_reason: "stop"` over the top of it.
    let fake = Fake::start(Canned {
        prompt_eval_count: Some(8192 / 2 + 3),
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    match adapter.complete("a short prompt", 256) {
        Err(AdapterError::I4Prime { needed, .. }) => assert_eq!(needed, 4099),
        other => panic!("expected an I4' refusal, got {other:?}"),
    }
    assert_eq!(fake.calls("/api/chat").len(), 1, "the call did happen");
}

#[test]
fn estimate_is_conservative() {
    // A stand-in that *does* tokenize, so the estimate can be measured against
    // a count rather than against another guess.
    let fake = Fake::start(Canned {
        tokenize: true,
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    let sentences = [
        "The kernel refuses a prompt it cannot honestly fit.",
        "Ollama truncates an oversize prompt without saying so.",
        "A governed arch is one this node started and capped.",
        "Every mount writes the model digest into the arch id.",
        "The ledger records what was sent before it is sent.",
        "A local model bills nothing and leaks nothing.",
        "Half the window is all the server will really read.",
        "The estimate is three bytes to the token, plus a margin.",
        "A container without caps is not a governor.",
        "Measured usage beats an estimate of the same thing.",
        "The seed is part of what makes this arch this arch.",
        "Thinking is off, so the answer is in the content.",
        "Streaming is off, so one request is one answer.",
        "The digest comes from the tag list, not from the name.",
        "A pull at mount time is not a pull at call time.",
        "Docker Desktop must be running for a container arch.",
        "The volume keeps the weights between runs.",
        "An external server is not governed, and says so.",
        "The context ceiling is measured, not advertised.",
        "Refusing is better than sending half a prompt.",
    ];
    for s in sentences {
        let counted = adapter.count_tokens(s);
        let estimated = OllamaAdapter::estimate_tokens(s);
        assert!(
            f64::from(estimated) >= 1.2 * f64::from(counted),
            "estimate {estimated} is not conservative against {counted} for {s:?}"
        );
    }
    assert_eq!(
        fake.calls("/api/tokenize").len(),
        sentences.len() + 1,
        "one probe at mount, then one count per sentence"
    );
}

#[test]
fn usage_is_measured_not_guessed() {
    let fake = Fake::start(Canned {
        prompt_eval_count: Some(311),
        reply: "the stand-in's answer".into(),
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    let out = adapter
        .complete("say something", 256)
        .expect("a completion");
    assert_eq!(out.text, "the stand-in's answer");
    assert_eq!(
        out.tokens_in_measured,
        Some(311),
        "the server counted the prompt; the estimate was only a stand-in for it"
    );
    assert_eq!(
        out.cost_list_usd, None,
        "a model on this machine has no list price"
    );
    let details = out
        .details
        .expect("a local call still reports its own numbers");
    assert_eq!(details["prompt_eval_count"], 311);
    assert_eq!(details["eval_count"], 5);
    assert_eq!(details["eval_duration_ns"], 900_000_000u64);
    assert_eq!(details["load_duration_ns"], 250_000_000u64);
    assert_eq!(details["done_reason"], "stop");
}

#[test]
fn mount_pulls_a_model_the_server_does_not_have_and_leaves_one_it_does() {
    let fake = Fake::start(Canned::default());
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    assert!(fake.pulls().is_empty(), "the server already had that tag");
    assert_eq!(
        adapter.manifest().identity.weights_sha256,
        "sha256:8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc",
        "the arch is addressed by the weights, not by the tag"
    );
    assert_eq!(adapter.manifest().name, "ollama/gemma3:1b");
    assert_eq!(adapter.manifest().identity.engine_version, "0.33.3");
    assert!(
        !adapter.manifest().governed,
        "no container was asked for, so nothing here is contained"
    );

    let other = Fake::start(Canned::default());
    let pulled = OllamaAdapter::mount(config(&other, "gemma3:270m", 8192))
        .expect("a tag the server does not have is pulled, once, at mount");
    assert_eq!(other.pulls(), vec!["gemma3:270m"]);
    assert_eq!(
        pulled.manifest().identity.weights_sha256,
        format!("sha256:{PULLED_DIGEST}"),
        "the digest is read back after the pull, not assumed before it"
    );
}
