//! Claude Code as an arch: the founder's own subscription behind SP1a's
//! `ArchAdapter` boundary, driven as a pure completion engine.
//!
//! The installed `claude` binary is launched once per call with every tool
//! removed, MCP off, one turn allowed and no session written to disk — see
//! [`ClaudeCodeAdapter::launch_line`], which is the launch line spike 2a
//! measured and `tests/fake_claude.rs` pins. The prompt goes in on stdin, so a
//! process list on this machine never shows it, and the answer comes back as
//! the single JSON object [`output::parse`] reads.
//!
//! What this arch is *not*: governed. The kernel launches the CLI, but the
//! inference happens on Anthropic's servers, where no interceptor of ours
//! runs — so the manifest says `governed: false`, `locality: Cloud`,
//! `jurisdiction: "US"`, and its clearance stops at Business with
//! third-party data refused. `contracts/tcb.md` says the same in prose.
//!
//! Cost: nothing is billed per call under a subscription, so the manifest's
//! `cost_per_1k_tokens_eur` is 0 and the *list-price equivalent* the CLI
//! reports rides along on the completion instead (SP1b ruling 3), where it is
//! visibly a comparison and not a charge.

pub mod output;

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vk_contracts::arch::{ArchIdentity, ArchManifest, Capability, Determinism, Locality};
use vk_contracts::labels::{Clearance, Scope};
use vk_kernel::arch::{AdapterError, ArchAdapter, Completion};

/// The model the draft arch runs on unless told otherwise.
pub const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// What the CLI is told it is. It has no tools and one turn, so the only thing
/// it can do with a prompt is answer it.
const SYSTEM_PROMPT: &str =
    "You are a text completion engine with no tools. Answer the prompt directly in plain text.";

/// How much of the ceiling a prompt may take before the call is refused. The
/// estimate below is a heuristic, not a tokenizer, so the last tenth is left
/// as the margin it is wrong by (I4').
const CONTEXT_HEADROOM: f64 = 0.9;

/// How often the wait loop looks at the child. Small enough that a 2 s
/// timeout is a 2 s timeout, large enough not to spin.
const POLL: Duration = Duration::from_millis(25);

/// How long `claude --version` is given to answer at mount time.
const VERSION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ClaudeCodeConfig {
    /// The `claude` binary: a name to find on `PATH`, or a path to one.
    pub binary: PathBuf,
    pub model: String,
    pub max_turns: u32,
    pub timeout: Duration,
    pub context_ceiling: u32,
    /// The one fixed directory every call runs in.
    ///
    /// Not a fresh temp directory per call: `--no-session-persistence` writes
    /// no transcript, but the CLI still creates
    /// `~/.claude/projects/<mangled-cwd>/memory/` for wherever it was run
    /// from, so a directory per call would leave one of those behind every
    /// time (spike 2a). `vkd` hands it `<state_dir>/claude-code-cwd`, which it
    /// creates empty and keeps empty.
    pub cwd: PathBuf,
}

impl Default for ClaudeCodeConfig {
    fn default() -> Self {
        ClaudeCodeConfig {
            binary: PathBuf::from("claude"),
            model: DEFAULT_MODEL.into(),
            max_turns: 1,
            timeout: Duration::from_secs(180),
            context_ceiling: 200_000,
            // The temp directory, not the caller's working directory: a
            // default-constructed adapter must not end up running `claude` in
            // somebody's repository. Every real mount overrides it anyway.
            cwd: std::env::temp_dir(),
        }
    }
}

pub struct ClaudeCodeAdapter {
    cfg: ClaudeCodeConfig,
    manifest: ArchManifest,
}

impl ClaudeCodeAdapter {
    /// What the version reads as when the binary could not be asked. It is in
    /// the arch identity, so a mount that lands on it is a mount whose arch id
    /// names no particular version of Claude Code — `vkd` refuses it.
    pub const UNKNOWN_VERSION: &'static str = "unknown";

    /// Mount-time construction. The CLI's version is part of the arch
    /// identity, so it is asked for once, here, rather than per call: two
    /// calls of one mount must be the same arch.
    pub fn new(cfg: ClaudeCodeConfig) -> ClaudeCodeAdapter {
        let version = probe_version(&cfg.binary).unwrap_or_else(|| Self::UNKNOWN_VERSION.into());
        Self::with_version(cfg, &version)
    }

    /// The same, for a caller that has already asked the binary its version —
    /// `vkd` does, before it takes the kernel lock, so a binary that is slow to
    /// answer delays one mount and not every other syscall (SP1b review).
    pub fn with_version(cfg: ClaudeCodeConfig, claude_version: &str) -> ClaudeCodeAdapter {
        let manifest = Self::manifest_for(&cfg, claude_version);
        ClaudeCodeAdapter { cfg, manifest }
    }

    /// The manifest for this configuration under that CLI version.
    ///
    /// Only `ArchIdentity` is hashed into the arch id, so what goes in there is
    /// everything that changes what the model does: which model, which CLI
    /// version drives it, and how many turns it is allowed. Latency and cost
    /// sit outside it and can be re-measured without minting a new arch.
    pub fn manifest_for(cfg: &ClaudeCodeConfig, claude_version: &str) -> ArchManifest {
        ArchManifest {
            name: format!("claude-code/{}", cfg.model),
            capabilities: [Capability::Generate, Capability::Plan, Capability::Judge].into(),
            locality: Locality::Cloud,
            jurisdiction: "US".into(),
            retention_days: Some(30),
            // A subscription call is not billed per token; what it would have
            // cost rides on the completion as `cost_list_usd` (ruling 3).
            cost_per_1k_tokens_eur: Some(0.0),
            latency_ms_p50: latency_p50_ms(&cfg.model),
            context_ceiling: cfg.context_ceiling,
            determinism: Determinism::NonDeterministic,
            identity: ArchIdentity {
                // No weights to hash: the model id is all the provider gives
                // us to name what is on the other end.
                weights_sha256: format!("model:{}", cfg.model),
                engine: "claude-code".into(),
                engine_version: claude_version.into(),
                backend: "anthropic-cloud".into(),
                quant: "-".into(),
                kv_cache: "-".into(),
                threads: 1,
                batch: 1,
                sampling: [("max_turns".to_string(), cfg.max_turns.to_string())]
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
            // contains (spec §3.3), whatever the CLI in front of them is.
            governed: false,
        }
    }

    /// The launch line, argv[0] first. Pinned by spike 2a against Claude Code
    /// 2.1.281 and asserted in `tests/fake_claude.rs`:
    ///
    /// * `-p --output-format json` — one non-interactive call, one JSON object.
    /// * `--tools ""` — every built-in tool removed. `--allowedTools ""` is a
    ///   no-op here and does not do this.
    /// * `--safe-mode --strict-mcp-config` — no MCP connector, no hook, no
    ///   skill, no CLAUDE.md: nothing but the model.
    /// * `--max-turns` — enforced; the CLI exits 1 with `error_max_turns`.
    /// * `--no-session-persistence` — no transcript on disk.
    /// * never `--bare`, which would drop the subscription login and ask for
    ///   an API key instead.
    ///
    /// The prompt is not here: it goes in on stdin, so it is not in any
    /// process list, and there is no positional argument.
    pub fn launch_line(cfg: &ClaudeCodeConfig) -> Vec<String> {
        vec![
            cfg.binary.display().to_string(),
            "-p".into(),
            "--output-format".into(),
            "json".into(),
            "--model".into(),
            cfg.model.clone(),
            "--max-turns".into(),
            cfg.max_turns.to_string(),
            "--tools".into(),
            String::new(),
            "--safe-mode".into(),
            "--strict-mcp-config".into(),
            "--no-session-persistence".into(),
            "--system-prompt".into(),
            SYSTEM_PROMPT.into(),
        ]
    }

    /// A deliberately crude token estimate: there is no tokenizer endpoint to
    /// ask before the call, and the measured usage only arrives with the
    /// answer. Three bytes per token errs low for prose and high for code, and
    /// [`CONTEXT_HEADROOM`] is the margin it is allowed to be wrong by.
    pub fn estimate_tokens(text: &str) -> u32 {
        u32::try_from(text.len() / 3 + 64).unwrap_or(u32::MAX)
    }

    /// The largest prompt this arch accepts: the ceiling less the margin the
    /// estimate above is allowed to be wrong by. One number, used both as the
    /// budget the kernel is told and as the limit `complete` enforces, so the
    /// two can never drift apart.
    fn usable_ceiling(&self) -> u32 {
        (f64::from(self.cfg.context_ceiling) * CONTEXT_HEADROOM) as u32
    }
}

impl ArchAdapter for ClaudeCodeAdapter {
    fn manifest(&self) -> &ArchManifest {
        &self.manifest
    }

    /// What `complete` will actually accept, not the manifest's ceiling: the
    /// kernel projects a long prompt *into* this number, so reporting the full
    /// ceiling would have it fit a prompt to 200 000 tokens and then hand it to
    /// a `complete` that refuses anything over 180 000 — a call that was
    /// servable, refused, with an `infer.projected` event already in the ledger
    /// for an inference that never happened (SP1b review, Important 2).
    fn context_budget(&self) -> u32 {
        self.usable_ceiling()
    }

    fn count_tokens(&self, text: &str) -> u32 {
        Self::estimate_tokens(text)
    }

    fn complete(&self, prompt: &str, _max_tokens: u32) -> Result<Completion, AdapterError> {
        // I4': measured against the real ceiling before anything is spawned.
        // Sending a prompt that cannot fit means letting the far end decide
        // what to drop, which is exactly the silent truncation the kernel
        // projects prompts to avoid.
        let needed = Self::estimate_tokens(prompt);
        let ceiling = self.usable_ceiling();
        if needed > ceiling {
            return Err(AdapterError::I4Prime { needed, ceiling });
        }

        let argv = Self::launch_line(&self.cfg);
        let printed = run(&argv, &self.cfg.cwd, prompt, self.cfg.timeout)?;
        let j = output::parse(&printed)?;
        // The provider counted the prompt; this node only estimated it.
        let measured = u32::try_from(j.tokens_in()).unwrap_or(u32::MAX);
        Ok(Completion {
            text: j.result,
            tokens_in_measured: Some(measured),
            tokens_out: Some(u32::try_from(j.output_tokens).unwrap_or(u32::MAX)),
            cost_list_usd: Some(j.total_cost_usd),
            details: Some(serde_json::json!({
                "input_uncached": j.input_tokens,
                "cache_creation": j.cache_creation_input_tokens,
                "cache_read": j.cache_read_input_tokens,
                "output": j.output_tokens,
                "duration_api_ms": j.duration_api_ms,
                "session_id": j.session_id,
            })),
        })
    }
}

/// p50 latency from spike 2a, for ~500 output tokens including ~3 s of process
/// start-up. Outside `ArchIdentity`, so re-measuring it does not mint a new
/// arch id.
fn latency_p50_ms(model: &str) -> u32 {
    if model.contains("opus") {
        14_000
    } else {
        10_000
    }
}

/// `claude --version` prints `2.1.281 (Claude Code)`; the version is the first
/// token. `None` when the binary is not there, fails, or does not answer —
/// bounded, because this runs inside `vkd`'s mount call and a binary that
/// never returns must not wedge the daemon.
pub fn probe_version(binary: &Path) -> Option<String> {
    let mut child = spawn(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let printed = drain(child.stdout.take()?);
    let status = wait_or_kill(&mut child, VERSION_TIMEOUT, "claude --version", "").ok()?;
    if !status.success() {
        return None;
    }
    String::from_utf8_lossy(&printed.join().unwrap_or_default())
        .split_whitespace()
        .next()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// Wait for `child`, killing it once `timeout` has passed. A poll rather than
/// a blocking `wait`, because a child that never answers has to be given up on
/// rather than waited for. `advice` is appended to the refusal.
fn wait_or_kill(
    child: &mut std::process::Child,
    timeout: Duration,
    what: &str,
    advice: &str,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .with_context(|| format!("wait for {what}"))?
        {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                kill_tree(child);
                bail!("{what} did not answer within {timeout:?} and was killed{advice}");
            }
            None => std::thread::sleep(POLL),
        }
    }
}

/// Kill the child *and everything it started*, then reap it.
///
/// Killing the process alone is not enough: an engine that spawns a helper
/// leaves it holding the pipes and the machine, and on Windows a killed
/// process never takes its children with it. So: `taskkill /T` there, and on
/// Unix one signal to the process group the child leads — which is why
/// [`spawn`] puts it in a group of its own.
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    if let Ok(pgid) = i32::try_from(child.id()) {
        // Safety: `kill(2)` with a negative pid signals the process group, and
        // the group is this child's own — nothing else can be in it.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A `Command` for a child this module may have to kill wholesale. On Unix it
/// leads its own process group, so [`kill_tree`] can signal the group without
/// reaching this process or its siblings; on Windows the tree is found from
/// the pid at kill time instead.
fn spawn(program: &Path) -> Command {
    let cmd = Command::new(program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = cmd;
        cmd.process_group(0);
        cmd
    }
    #[cfg(not(unix))]
    cmd
}

/// Launch the CLI, feed it the prompt on stdin and hand back what it printed.
///
/// stdin, stdout and stderr are each worked by their own thread: a prompt
/// larger than a pipe buffer and an answer larger than a pipe buffer would
/// otherwise deadlock against each other, and spike 2a's 6 KB prompt is not
/// the largest a register will lower to. The wait is a poll rather than a
/// blocking `wait`, because a `claude` that never answers has to be killed at
/// the timeout rather than waited on forever.
fn run(argv: &[String], cwd: &Path, prompt: &str, timeout: Duration) -> Result<String> {
    let mut child = spawn(Path::new(&argv[0]))
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("launch {} in {}", argv[0], cwd.display()))?;

    let mut stdin = child.stdin.take().context("no stdin pipe")?;
    let written = prompt.to_string();
    // A child that exits before reading the whole prompt is not an error here:
    // whatever it printed is still the answer, and the refusal (if any) is in
    // it. The broken pipe is dropped on purpose.
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(written.as_bytes());
        drop(stdin);
    });
    let out_t = drain(child.stdout.take().context("no stdout pipe")?);
    let err_t = drain(child.stderr.take().context("no stderr pipe")?);

    // On the timeout the drain threads are left to end with the pipes rather
    // than joined: a grandchild of the process just killed can hold the write
    // end open, and waiting on it would undo the timeout.
    let status = wait_or_kill(
        &mut child,
        timeout,
        "claude",
        "; raise the arch's timeout or shorten the prompt",
    )?;
    let _ = feeder.join();
    let printed = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let complained = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();

    // A non-zero exit is a failed call, full stop. The CLI does print the
    // object saying why (spike 2a: exit 1 ⇔ `is_error`), and `output::parse`
    // turns that into the better message, so the object is tried first — but
    // if it reads as a clean success the exit code wins, because a future CLI
    // that fails in a way this parser does not recognise must not be read as
    // an answer (SP1b review, Minor 6).
    if !status.success() {
        let how = status
            .code()
            .map_or_else(|| "on a signal".into(), |c| format!("{c}"));
        let said = complained.trim();
        let tail = if said.is_empty() {
            "nothing on stderr".to_string()
        } else {
            last_chars(said, 400)
        };
        // The object's own reason if there is one; otherwise the exit code.
        let why = output::parse(&printed).err().map_or_else(
            || "and printed a result that claims success".into(),
            |e| e.to_string(),
        );
        bail!("claude exited {how}: {why} [stderr: {tail}]");
    }
    Ok(printed)
}

/// The last `n` characters of `s`, marked when something was cut. Used on
/// stderr, which can be a whole stack trace and whose interesting end is the
/// last line.
fn last_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        return s.to_string();
    }
    format!("…{}", s.chars().skip(count - n).collect::<String>())
}

/// Read one of the child's pipes to the end on a thread of its own.
fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_estimate_is_three_bytes_a_token_plus_a_fixed_margin() {
        assert_eq!(ClaudeCodeAdapter::estimate_tokens(""), 64);
        assert_eq!(ClaudeCodeAdapter::estimate_tokens(&"x".repeat(300)), 164);
    }

    #[test]
    fn the_prompt_is_never_an_argument() {
        let argv = ClaudeCodeAdapter::launch_line(&ClaudeCodeConfig::default());
        assert_eq!(argv[1], "-p");
        // `-p` takes no positional prompt here: the last argument is the
        // system prompt, and nothing follows it.
        assert_eq!(argv.last().map(String::as_str), Some(SYSTEM_PROMPT));
    }

    #[test]
    fn opus_is_slower_than_sonnet_and_neither_changes_the_arch_id() {
        let sonnet = ClaudeCodeConfig::default();
        let opus = ClaudeCodeConfig {
            model: "claude-opus-5".into(),
            ..Default::default()
        };
        assert!(latency_p50_ms(&opus.model) > latency_p50_ms(&sonnet.model));
        let a = ClaudeCodeAdapter::manifest_for(&sonnet, "2.1.281");
        let mut b = ClaudeCodeAdapter::manifest_for(&sonnet, "2.1.281");
        b.latency_ms_p50 = 1;
        assert_eq!(a.arch_id(), b.arch_id());
    }

    #[test]
    fn the_cli_version_is_part_of_the_arch_identity() {
        let cfg = ClaudeCodeConfig::default();
        assert_ne!(
            ClaudeCodeAdapter::manifest_for(&cfg, "2.1.281").arch_id(),
            ClaudeCodeAdapter::manifest_for(&cfg, "2.1.282").arch_id(),
        );
    }
}
