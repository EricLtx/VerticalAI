//! The adapter against a stand-in `claude`: a script this test writes, which
//! records the argv, the stdin and the working directory it was launched with
//! and then prints a canned result object.
//!
//! What it pins is the half of the adapter that no canned-JSON test can reach:
//! that the launch line spike 2a measured is the launch line that is actually
//! executed — tools off, MCP off, one turn, no session on disk — that the
//! prompt goes in on stdin rather than as an argument a process list would
//! show, that the call runs in the one fixed directory it is configured with,
//! and that a stand-in which never answers is killed rather than waited on.
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vk_arch_claude_code::{output, ClaudeCodeAdapter, ClaudeCodeConfig};
use vk_kernel::arch::ArchAdapter;

/// The canned result object the stand-in prints: spike 2a's field set, with
/// distinct token figures so a test can tell which of them was read.
const REPLY: &str = r#"{
  "type": "result", "subtype": "success", "is_error": false,
  "duration_ms": 9861, "duration_api_ms": 6702, "ttft_ms": 1204, "num_turns": 1,
  "result": "the stand-in's answer",
  "session_id": "fake-session-1",
  "total_cost_usd": 0.0148193,
  "usage": {
    "input_tokens": 12,
    "cache_creation_input_tokens": 3421,
    "cache_read_input_tokens": 11002,
    "output_tokens": 517
  },
  "modelUsage": {
    "claude-sonnet-5": {
      "inputTokens": 12, "outputTokens": 517,
      "cacheReadInputTokens": 11002, "cacheCreationInputTokens": 3421,
      "costUSD": 0.0148193, "contextWindow": 200000, "costBasis": "list"
    }
  }
}"#;

/// A scripted `claude` plus the files it writes down what it was asked.
struct Standin {
    _home: tempfile::TempDir,
    bin: PathBuf,
    cwd: PathBuf,
    argv: PathBuf,
    stdin: PathBuf,
    child_cwd: PathBuf,
}

/// How the stand-in should misbehave. The default is a well-behaved `claude`.
#[derive(Default, Clone, Copy)]
struct How {
    /// Wait ten seconds before answering, so a test can watch the adapter give
    /// up on it.
    slow: bool,
    /// Exit with this code after printing the (perfectly good) reply.
    exit: i32,
}

impl Standin {
    fn new() -> Standin {
        Standin::behaving(How::default())
    }

    fn behaving(how: How) -> Standin {
        let How { slow, exit } = how;
        let home = tempfile::tempdir().expect("temp dir");
        let at = |name: &str| home.path().join(name);
        let (bin, cwd) = (
            at(&format!(
                "fake-claude.{}",
                if cfg!(windows) { "cmd" } else { "sh" }
            )),
            at("cwd"),
        );
        let (argv, stdin, child_cwd, reply) = (
            at("argv.txt"),
            at("stdin.txt"),
            at("child-cwd.txt"),
            at("reply.json"),
        );
        fs::create_dir_all(&cwd).expect("the arch's fixed working directory");
        fs::write(&reply, REPLY).expect("write the canned reply");

        let p = |path: &Path| path.display().to_string();
        let script = if cfg!(windows) {
            format!(
                "@echo off\r\n\
                 if \"%~1\"==\"--version\" (\r\n  echo 9.9.9-fake\r\n  exit /b 0\r\n)\r\n\
                 >\"{cwd_f}\" echo %CD%\r\n\
                 break>\"{argv_f}\"\r\n\
                 :vk_next\r\n\
                 if [%1]==[] goto vk_done\r\n\
                 >>\"{argv_f}\" echo.%~1\r\n\
                 shift\r\n\
                 goto vk_next\r\n\
                 :vk_done\r\n\
                 findstr \"^\" >\"{stdin_f}\"\r\n\
                 {delay}\r\n\
                 type \"{reply_f}\"\r\n\
                 echo the stand-in complains 1>&2\r\n\
                 exit /b {exit}\r\n",
                cwd_f = p(&child_cwd),
                argv_f = p(&argv),
                stdin_f = p(&stdin),
                reply_f = p(&reply),
                delay = if slow {
                    "ping -n 11 127.0.0.1 >nul"
                } else {
                    ""
                },
            )
        } else {
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"--version\" ]; then echo 9.9.9-fake; exit 0; fi\n\
                 pwd -P > '{cwd_f}'\n\
                 : > '{argv_f}'\n\
                 for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{argv_f}'; done\n\
                 cat > '{stdin_f}'\n\
                 {delay}\n\
                 cat '{reply_f}'\n\
                 echo 'the stand-in complains' 1>&2\n\
                 exit {exit}\n",
                cwd_f = p(&child_cwd),
                argv_f = p(&argv),
                stdin_f = p(&stdin),
                reply_f = p(&reply),
                delay = if slow { "sleep 10" } else { ":" },
            )
        };
        fs::write(&bin, script).expect("write the stand-in");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("chmod +x");
        }
        Standin {
            _home: home,
            bin,
            cwd,
            argv,
            stdin,
            child_cwd,
        }
    }

    fn config(&self) -> ClaudeCodeConfig {
        ClaudeCodeConfig {
            binary: self.bin.clone(),
            cwd: self.cwd.clone(),
            timeout: Duration::from_secs(2),
            ..Default::default()
        }
    }

    /// The arguments the stand-in was launched with, argv[0] aside.
    fn recorded_argv(&self) -> Vec<String> {
        fs::read_to_string(&self.argv)
            .expect("the stand-in recorded no argv — it was never launched")
            .lines()
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect()
    }

    fn recorded_stdin(&self) -> String {
        fs::read_to_string(&self.stdin).expect("the stand-in recorded no stdin")
    }

    fn recorded_cwd(&self) -> PathBuf {
        let raw = fs::read_to_string(&self.child_cwd).expect("the stand-in recorded no cwd");
        PathBuf::from(raw.trim())
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[test]
fn the_pinned_launch_line_is_what_actually_runs() {
    let fake = Standin::new();
    let cfg = fake.config();
    let expected = ClaudeCodeAdapter::launch_line(&cfg);
    let adapter = ClaudeCodeAdapter::new(cfg);

    let out = adapter
        .complete("ROLE: draft\nGOAL: say something\n", 256)
        .expect("complete");
    assert_eq!(out.text, "the stand-in's answer");

    // argv[0] is the binary itself; the stand-in only sees what follows it.
    assert_eq!(expected[0], fake.bin.display().to_string());
    assert_eq!(
        fake.recorded_argv(),
        expected[1..].to_vec(),
        "the launch line spike 2a pinned is not the one that ran"
    );
    // The four flags the TCB note rests on, named rather than only positional.
    for flag in [
        "-p",
        "--output-format",
        "json",
        "--max-turns",
        "--tools",
        "--safe-mode",
        "--strict-mcp-config",
        "--no-session-persistence",
        "--system-prompt",
    ] {
        assert!(
            expected.iter().any(|a| a == flag),
            "{flag} missing from {expected:?}"
        );
    }
    // `--tools` takes the empty string: every built-in tool off.
    let tools = expected
        .iter()
        .position(|a| a == "--tools")
        .expect("--tools");
    assert_eq!(expected[tools + 1], "", "--tools must be given \"\"");
    // Never `--bare`: it drops the subscription login.
    assert!(!expected.iter().any(|a| a == "--bare"), "{expected:?}");
    // The prompt is not an argument: a process list must not show it.
    assert!(
        !expected.iter().any(|a| a.contains("GOAL: say something")),
        "the prompt leaked into argv: {expected:?}"
    );
}

#[test]
fn the_prompt_goes_in_on_stdin_and_the_call_runs_in_the_configured_directory() {
    let fake = Standin::new();
    let adapter = ClaudeCodeAdapter::new(fake.config());
    adapter
        .complete(
            "ROLE: draft\nGOAL: say something\nCONSTRAINTS:\n- be brief\n",
            256,
        )
        .expect("complete");

    let on_stdin = fake.recorded_stdin();
    assert!(on_stdin.contains("ROLE: draft"), "{on_stdin:?}");
    assert!(on_stdin.contains("GOAL: say something"), "{on_stdin:?}");
    assert!(on_stdin.contains("- be brief"), "{on_stdin:?}");

    assert!(
        same_dir(&fake.recorded_cwd(), &fake.cwd),
        "the child ran in {:?}, not the configured {:?}",
        fake.recorded_cwd(),
        fake.cwd
    );
}

#[test]
fn what_the_call_measured_comes_back_with_it() {
    let fake = Standin::new();
    let adapter = ClaudeCodeAdapter::new(fake.config());
    let out = adapter
        .complete("ROLE: draft\nGOAL: g\n", 256)
        .expect("complete");

    // List price, never guessed: exactly what the CLI reported.
    assert_eq!(out.cost_list_usd, Some(0.0148193));

    let d = out.details.expect("a real arch reports what it spent");
    assert_eq!(d["input_uncached"], 12);
    assert_eq!(d["cache_creation"], 3421);
    assert_eq!(d["cache_read"], 11002);
    assert_eq!(d["output"], 517);
    assert_eq!(d["duration_api_ms"], 6702);
    assert_eq!(d["session_id"], "fake-session-1");

    // tokens_in = uncached + cache_creation + cache_read, which is what the
    // whole prompt cost — `usage.input_tokens` alone is only the remainder.
    let tokens_in = output::parse(REPLY)
        .expect("the canned reply parses")
        .tokens_in();
    assert_eq!(tokens_in, 12 + 3421 + 11002);
    assert_eq!(
        tokens_in,
        d["input_uncached"].as_u64().unwrap()
            + d["cache_creation"].as_u64().unwrap()
            + d["cache_read"].as_u64().unwrap()
    );

    // And that is the number the kernel is handed, so it accounts the call by
    // what it cost rather than by this adapter's three-bytes-a-token guess
    // (ruling 7). The estimate for this short prompt is nowhere near it.
    assert_eq!(out.tokens_in_measured, Some(14_435));
    assert!(
        ClaudeCodeAdapter::estimate_tokens("ROLE: draft\nGOAL: g\n") < 100,
        "the estimate and the measurement must be visibly different numbers"
    );
}

/// Review finding (SP1b, Minor 6): a non-zero exit is a failed call even when
/// what it printed parses as a clean success. Reading the object and ignoring
/// the exit code would let a future CLI fail in a way this parser does not
/// recognise and still be taken for an answer.
#[test]
fn a_non_zero_exit_is_a_failure_even_with_a_well_formed_result_object() {
    let fake = Standin::behaving(How {
        exit: 3,
        ..Default::default()
    });
    let adapter = ClaudeCodeAdapter::new(fake.config());
    let msg = adapter
        .complete("ROLE: draft\nGOAL: g\n", 256)
        .expect_err("a non-zero exit is not a completion")
        .to_string();
    assert!(
        msg.contains("exited 3"),
        "the exit code belongs in it: {msg}"
    );
    assert!(
        msg.contains("claims success"),
        "and what the object said about itself: {msg}"
    );
    assert!(
        msg.contains("the stand-in complains"),
        "and the tail of stderr, which is where the reason usually is: {msg}"
    );
}

/// Review finding (SP1b, Important 2): the budget the kernel is told must be
/// the budget `complete` honours. Told 200 000 while refusing above 180 000,
/// the kernel would fit a long prompt to 200 000, log an `infer.projected`
/// event for it, and then be refused — an inference that never happened, with
/// a projection in the ledger saying it did.
#[test]
fn the_advertised_budget_is_the_one_complete_actually_accepts() {
    let fake = Standin::new();
    // The shipped numbers first: 200 000 of ceiling, 180 000 of budget.
    let shipped = ClaudeCodeAdapter::new(fake.config());
    assert_eq!(shipped.manifest().context_ceiling, 200_000);
    assert_eq!(shipped.context_budget(), 180_000);

    // Then the same relationship at a size a stand-in can actually be fed: a
    // prompt at exactly the advertised budget is sent, one token past it is
    // refused — so there is no band the kernel would project into and this
    // adapter would then reject.
    let adapter = ClaudeCodeAdapter::new(ClaudeCodeConfig {
        context_ceiling: 1_000,
        ..fake.config()
    });
    assert_eq!(adapter.context_budget(), 900);
    let at_budget = "x".repeat((900 - 64) * 3);
    assert_eq!(ClaudeCodeAdapter::estimate_tokens(&at_budget), 900);
    adapter
        .complete(&at_budget, 256)
        .expect("a prompt the advertised budget allows must be sent");
    let past = "x".repeat((901 - 64) * 3);
    let msg = adapter
        .complete(&past, 256)
        .expect_err("one token past it must not be")
        .to_string();
    assert!(msg.contains("901") && msg.contains("900"), "{msg}");
}

#[test]
fn a_stand_in_that_never_answers_is_killed_at_the_timeout() {
    let fake = Standin::behaving(How {
        slow: true,
        ..Default::default()
    });
    let adapter = ClaudeCodeAdapter::new(fake.config()); // 2 s
    let start = Instant::now();
    let err = adapter
        .complete("ROLE: draft\nGOAL: g\n", 256)
        .expect_err("a claude that never answers must not be waited on");
    let waited = start.elapsed();

    let msg = err.to_string();
    assert!(
        msg.contains("2s") || msg.contains("2 s"),
        "the refusal must name the timeout it hit: {msg}"
    );
    assert!(
        waited < Duration::from_secs(8),
        "gave up after {waited:?}, which is not a 2 s timeout"
    );
}

/// I4': the prompt is measured against the arch's real ceiling *before*
/// anything is spawned, so an over-long prompt is refused rather than sent and
/// silently truncated at the other end.
#[test]
fn an_over_long_prompt_is_refused_without_launching_anything() {
    let fake = Standin::new();
    let cfg = ClaudeCodeConfig {
        context_ceiling: 1_000,
        ..fake.config()
    };
    let adapter = ClaudeCodeAdapter::new(cfg);
    let huge = "x".repeat(4_000); // 4000/3 + 64 = 1397 > 0.9 * 1000
    let msg = adapter
        .complete(&huge, 256)
        .expect_err("an over-long prompt is an I4' refusal")
        .to_string();
    assert!(msg.contains("I4"), "{msg}");
    assert!(
        !fake.argv.exists(),
        "nothing may be launched for a prompt that cannot fit"
    );
}

/// The manifest is what the kernel labels the call with, and its identity is
/// what the arch id hashes: the model, the CLI version and the turn limit.
#[test]
fn the_manifest_says_what_this_arch_is() {
    let fake = Standin::new();
    let cfg = fake.config();
    let adapter = ClaudeCodeAdapter::new(cfg);
    let m = adapter.manifest();

    assert_eq!(m.name, "claude-code/claude-sonnet-5");
    assert_eq!(m.locality, vk_contracts::arch::Locality::Cloud);
    assert_eq!(m.jurisdiction, "US");
    assert_eq!(m.retention_days, Some(30));
    assert_eq!(m.clearance.max_scope, vk_contracts::labels::Scope::Business);
    assert!(!m.clearance.third_party_allowed);
    assert!(!m.governed, "the kernel did not launch Anthropic's servers");
    // Subscription: the call is not billed per token (ruling 3).
    assert_eq!(m.cost_per_1k_tokens_eur, 0.0);
    assert_eq!(m.identity.engine, "claude-code");
    assert_eq!(m.identity.engine_version, "9.9.9-fake");
    assert!(m.identity.weights_sha256.contains("claude-sonnet-5"));
    assert_eq!(
        m.identity.sampling.get("max_turns").map(String::as_str),
        Some("1")
    );
    assert!(m.validate().is_ok());

    // Identity, so a different model or turn limit is a different arch.
    let other = ClaudeCodeAdapter::manifest_for(
        &ClaudeCodeConfig {
            model: "claude-opus-5".into(),
            ..fake.config()
        },
        "9.9.9-fake",
    );
    assert_ne!(m.arch_id(), other.arch_id());
}
