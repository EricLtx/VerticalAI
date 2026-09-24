//! The real Claude Code, under the founder's own subscription.
//!
//! `#[ignore]` and gated on `VK_CLAUDE=1`: it costs a real call, needs a logged
//! -in CLI on `PATH`, and is the only evidence that the pinned launch line and
//! the pinned JSON field names are still the ones this version prints. Run it
//! deliberately:
//!
//! ```text
//! VK_CLAUDE=1 cargo test -p vk-arch-claude-code --test live -- --ignored --nocapture
//! ```
//!
//! It runs from one fixed directory (`<temp>/vk-claude-code-live`) rather than
//! a fresh one per call: `--no-session-persistence` writes no transcript but
//! still creates `~/.claude/projects/<mangled-cwd>/memory/`, and a temp
//! directory per call would litter one of those each time.
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vk_arch_claude_code::{ClaudeCodeAdapter, ClaudeCodeConfig};
use vk_kernel::arch::ArchAdapter;

/// The working directory, removed however the test ends. Not a `TempDir`,
/// because the point of the fixed path is that repeated runs reuse one
/// `~/.claude/projects/<mangled-cwd>` entry instead of minting a new one.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "spends a real Claude Code call; set VK_CLAUDE=1 and run with --ignored"]
fn the_real_claude_completes_a_prompt_and_reports_what_it_spent() {
    if std::env::var("VK_CLAUDE").as_deref() != Ok("1") {
        eprintln!("skipped: set VK_CLAUDE=1 to spend a real call");
        return;
    }
    let cwd = std::env::temp_dir().join("vk-claude-code-live");
    std::fs::create_dir_all(&cwd).expect("the fixed working directory");
    // Removed however this test leaves: a failed assertion unwinds through the
    // drop, so a run that spends a call does not also leave a directory behind.
    let _leave_nothing = Cleanup(cwd.clone());
    let adapter = ClaudeCodeAdapter::new(ClaudeCodeConfig {
        cwd,
        timeout: Duration::from_secs(120),
        ..Default::default()
    });

    // The version is part of the arch identity, so a version the adapter could
    // not read is an arch it cannot honestly name.
    let version = adapter.manifest().identity.engine_version.clone();
    assert!(!version.is_empty(), "no claude version");
    assert_ne!(
        version,
        ClaudeCodeAdapter::UNKNOWN_VERSION,
        "claude --version failed"
    );

    let started = Instant::now();
    let out = adapter
        .complete("Reply with the single word ok", 64)
        .expect("the real claude answers");
    let elapsed = started.elapsed();

    let text = out.text.trim().to_lowercase();
    assert!(text.contains("ok"), "claude answered {:?}", out.text);

    let details = out.details.expect("a real call reports its usage");
    eprintln!(
        "live: claude {version} in {elapsed:?}; cost_list_usd={:?}; details={details}",
        out.cost_list_usd
    );
    for field in [
        "input_uncached",
        "cache_creation",
        "cache_read",
        "output",
        "duration_api_ms",
        "session_id",
    ] {
        assert!(!details[field].is_null(), "no {field} in {details}");
    }
    assert!(out.cost_list_usd.is_some(), "no list-price cost reported");
    assert!(
        details["output"].as_u64().unwrap_or(0) > 0,
        "an answer with no output tokens: {details}"
    );
}
