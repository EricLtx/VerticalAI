//! A proxy in the environment must never touch a model on this machine.
//!
//! `reqwest` consults `HTTP_PROXY`, `http_proxy`, `ALL_PROXY` and the
//! platform's own proxy settings by default, and applies no loopback bypass to
//! the environment ones. On a machine where the proxy is merely unreachable
//! that turns every mount into a 60-second failure; on one where it *is*
//! reachable — a corporate agent, a forgotten mitmproxy — it sends the whole
//! prompt of the only arch cleared to `Scope::Personal` to a third party,
//! while the manifest goes on claiming `locality: Local`, `retention_days: 0`
//! and `governed: true` (SP1b Task 1 review, Critical 1).
//!
//! This test is a binary of its own because it sets process-wide environment
//! variables: with one test in it, nothing else can be building a client while
//! they are set. `127.0.0.1:9` is the discard port — nothing listens there, so
//! a client that consulted the proxy could not possibly succeed.
mod fake;

use fake::{Canned, Fake};
use vk_arch_ollama::{OllamaAdapter, OllamaConfig};
use vk_kernel::arch::ArchAdapter;

const DEAD_PROXY: &str = "http://127.0.0.1:9";

#[test]
fn a_proxy_in_the_environment_is_never_consulted_for_a_model_on_this_machine() {
    // Set before anything in this process builds a client, and left set for
    // the whole test: the point is that the adapter works with them in place.
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(name, DEAD_PROXY);
    }
    // Belt and braces: even `NO_PROXY` is not what is doing the work here.
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    let fake = Fake::start(Canned::default());
    let started = std::time::Instant::now();
    let adapter = OllamaAdapter::mount(OllamaConfig {
        base_url: fake.base_url.clone(),
        model: "gemma3:1b".into(),
        ..Default::default()
    })
    .unwrap_or_else(|e| {
        panic!(
            "a loopback mount must not go through {DEAD_PROXY} (after {:?}): {e:#}",
            started.elapsed()
        )
    });

    let out = adapter
        .complete("say something", 64)
        .expect("and neither must the call");
    assert_eq!(out.text, "ok");
    assert_eq!(
        fake.calls("/api/chat").len(),
        1,
        "the stand-in, not the proxy, is what answered"
    );
    // The 60 s `START_TIMEOUT` is what a proxied mount burns before failing;
    // a direct one is milliseconds. This is a smoke alarm, not a benchmark.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the mount took {:?}, which is a proxy being waited on",
        started.elapsed()
    );
}
