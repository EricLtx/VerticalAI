//! The real thing: a real Ollama in a real container, under the caps this
//! kernel imposes.
//!
//! `#[ignore]` and gated on `VK_OLLAMA=1`: it needs Docker Desktop running, it
//! pulls a model the first time, and it spends a minute of CPU. It is the only
//! evidence that the endpoints spike 1a measured are the endpoints this
//! adapter drives, that the digest in the arch id is the digest the server
//! reports, and that the caps the kernel asked for are the caps the container
//! actually runs under — which is the whole of what `governed: true` claims.
//!
//! ```text
//! VK_OLLAMA=1 VK_TEST_MODEL=gemma3:1b cargo test -p vk-arch-ollama --test container -- --ignored --nocapture
//! ```
use std::time::Instant;
use vk_arch_ollama::{
    container, ContainerSpec, OllamaAdapter, OllamaConfig, PINNED_IMAGE_DIGEST, TEST_MODEL,
};
use vk_kernel::arch::ArchAdapter;

/// The model this test runs on: the 1B, unless `VK_TEST_MODEL` says otherwise.
/// Never the demo model — CI would pull 9.6 GB per run.
fn test_model() -> String {
    std::env::var("VK_TEST_MODEL").unwrap_or_else(|_| TEST_MODEL.to_string())
}

#[test]
#[ignore = "needs Docker and a model pull; set VK_OLLAMA=1 and run with --ignored"]
fn the_real_container_answers_under_the_caps_the_kernel_gave_it() {
    if std::env::var("VK_OLLAMA").as_deref() != Ok("1") {
        eprintln!("skipped: set VK_OLLAMA=1 to drive a real container");
        return;
    }
    let spec = ContainerSpec::default();
    let model = test_model();

    // From a known state: a container left running by an earlier run would
    // make `Started` unreachable and the first half of this test vacuous.
    let _ = container::stop(&spec);
    // Adoption is the path this normally takes. A machine whose `vk-ollama`
    // was built with other caps — or from an image it no longer has — is
    // refused rather than adopted (Ruling 10), and the remedy is the one the
    // refusal names; taking it here is what makes this test runnable anywhere
    // rather than only where the container already happens to match.
    let state = match container::ensure(&spec) {
        Ok(state) => state,
        Err(refused) => {
            eprintln!("not the container this spec asks for, re-creating it: {refused:#}");
            container::recreate(&spec).expect("re-create it")
        }
    };
    assert!(
        container::started_here(state),
        "a stopped container is started, not left alone: {state:?}"
    );
    assert!(
        matches!(
            container::ensure(&spec).expect("the second ensure"),
            container::State::AlreadyRunning
        ),
        "ensure is idempotent: a running container is not restarted under a live call"
    );
    assert!(
        container::caps_applied(&spec).expect("read the caps back"),
        "a container without a memory and CPU cap is not a governor"
    );
    // Printed rather than asserted: an image that has drifted from the pinned
    // one is something the person running this should see, but it is not this
    // test's business to refuse it — the Ollama *version* is what the arch id
    // is built on, and the adapter reads that off the server itself.
    eprintln!(
        "container image: {} (pinned: {PINNED_IMAGE_DIGEST})",
        container::image_digest(&spec).expect("the image digest")
    );

    let mounted = Instant::now();
    // `governed`, not the bare default: the default config is the external
    // one, and what this test is about is the container.
    let adapter = OllamaAdapter::mount(OllamaConfig::governed(&model))
        .expect("mount against the real container");
    let manifest = adapter.manifest().clone();
    eprintln!(
        "mounted {} in {:?} as {} (ceiling {}, budget {})",
        manifest.name,
        mounted.elapsed(),
        manifest.arch_id(),
        manifest.context_ceiling,
        adapter.context_budget(),
    );
    assert!(
        manifest.governed,
        "a capped container this node started is governed"
    );
    assert_eq!(manifest.name, format!("ollama/{model}"));

    // What the arch id says about the container: the image it runs, and that
    // it is governed — not the size of the caps (Ruling 11). The cap values
    // were read off the container and belong to the call record below.
    let governor = adapter
        .governor()
        .expect("a container mount has a governor");
    assert_eq!(
        manifest.identity.sampling["container_image"],
        governor.image
    );
    assert_eq!(manifest.identity.sampling["governed"], "true");
    assert!(
        !manifest
            .identity
            .sampling
            .contains_key("container_memory_bytes"),
        "cap values are not part of the arch: {:?}",
        manifest.identity.sampling
    );
    assert_eq!(governor.memory_bytes, 12_884_901_888, "--memory 12g");
    assert_eq!(governor.nano_cpus, 6_000_000_000, "--cpus 6");
    assert!(
        !adapter.started_here(),
        "this test started the container itself, above, so the mount adopted a running one"
    );

    // The arch id names these weights, and the server agrees about which they
    // are: content-addressed identity, not a tag anyone can move.
    let digest = &adapter.identity().digest;
    assert_eq!(manifest.identity.weights_sha256, format!("sha256:{digest}"));
    assert_eq!(manifest.identity.engine, "ollama");
    assert!(
        !manifest.identity.engine_version.is_empty(),
        "the Ollama version is part of the arch identity"
    );

    let started = Instant::now();
    let out = adapter
        .complete("Reply with the single word ok", 64)
        .expect("the real model answers");
    let elapsed = started.elapsed();
    assert!(!out.text.trim().is_empty(), "an empty answer: {out:?}");
    assert_eq!(out.cost_list_usd, None, "nothing local is billed");

    let details = out
        .details
        .clone()
        .expect("a real call reports its numbers");
    let eval = details["eval_count"].as_u64().unwrap_or(0);
    let ns = details["eval_duration_ns"].as_u64().unwrap_or(1).max(1);
    eprintln!(
        "live: {model} on Ollama {} answered {:?} in {elapsed:?}; \
         prompt_eval_count={} eval_count={eval} at {:.1} tokens/s; details={details}",
        manifest.identity.engine_version,
        out.text.trim(),
        out.tokens_in_measured.unwrap_or(0),
        eval as f64 * 1e9 / ns as f64,
    );
    assert!(eval > 0, "an answer with no output tokens: {details}");
    assert!(
        out.tokens_in_measured.unwrap_or(0) > 0,
        "the server counts the prompt; we do not have to guess it"
    );
    // What was governing the call is in the record, not only in the manifest:
    // the ledger stores the hash of these details (Ruling 10).
    assert_eq!(details["container_image"], governor.image);
    assert_eq!(details["container_memory_bytes"], governor.memory_bytes);
    assert_eq!(details["container_nano_cpus"], governor.nano_cpus);
    // Ruling 9a: an answer is bounded, and 64 tokens is what was asked for.
    assert!(
        eval <= 64,
        "the answer ran past the {} tokens the caller allowed: {details}",
        64
    );

    // Unmounting an arch that *adopted* a running container leaves it running:
    // it belongs to whoever started it — here, to this test.
    drop(adapter);
    assert!(
        running(&spec),
        "an arch must not stop a container it only borrowed"
    );

    // And the other half: a mount that starts the container itself owns it,
    // and stops it again when it goes. No model is loaded by a mount, so this
    // second one costs a container start and four HTTP calls.
    container::stop(&spec).expect("stop it, so the next mount is the one that starts it");
    let owner = OllamaAdapter::mount(OllamaConfig::governed(&model)).expect("mount again");
    assert!(
        owner.started_here(),
        "nothing was running, so this mount is what started it"
    );
    drop(owner);
    assert!(
        !running(&spec),
        "the arch that started the container stops it again when it goes"
    );
}

/// Is the container up right now?
fn running(spec: &ContainerSpec) -> bool {
    container::inspected(spec)
        .expect("look at the container")
        .expect("it is still there, running or not")
        .running
}
