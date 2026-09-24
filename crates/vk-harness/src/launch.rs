//! The confined launch of Claude Code as a harness.
//!
//! [`launch_claude_code`] writes the workspace's `.mcp.json` (the one channel
//! back to the kernel, carrying the lease token that authenticates every
//! `harness.*` syscall), spawns the CLI under the [`Governor`](crate::confine)
//! it is handed, samples the child's egress every 500 ms, and waits — killing
//! the tree on a timeout or a STOP. It hands back what the run was: the exit,
//! whether the process was contained, the endpoints it reached, and the JSON
//! Claude printed.
//!
//! **The kernel drives this with its lock released.** The launched harness calls
//! back over MCP (`harness.read_register`, `harness.attach_artefact`, …) while
//! it runs, and those are ordinary syscalls that take the kernel lock; a lock
//! held across the wait would deadlock the harness against itself. So the kernel
//! leases and materialises under its lock, drops it, runs this, then re-takes
//! the lock to attach the artefact and record the telemetry.
use crate::confine::Governor;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The tools the harness is allowed: the kernel's own, plus the file tools it
/// needs to read the brief and write the proposal. Pinned here because it is
/// half of what confines the harness — nothing runs a shell.
pub const ALLOWED_TOOLS: &str = "mcp__vk__*,Read,Write,Edit,Glob,Grep";

/// The MCP server name the kernel answers as. Claude Code exposes its tools as
/// `mcp__<name>__<tool>`, so this is the `vk` in `mcp__vk__*`.
pub const MCP_SERVER_NAME: &str = "vk";

/// How often the child's egress is sampled into the run record.
pub const SAMPLE_EVERY: Duration = Duration::from_millis(500);

/// What the token reads as in a `--dry-run`'s printed `.mcp.json`: the real one
/// is a live capability and does not belong in a log or a terminal.
pub const REDACTED_TOKEN: &str = "<redacted>";

/// Everything a launch needs. The kernel builds it; a `--dry-run` builds it with
/// [`REDACTED_TOKEN`] to print the launch line and the `.mcp.json` without
/// running anything.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// The Claude Code binary. The real one is `claude.exe`, launched directly
    /// (never a `.cmd` shim, so no grandchild is spawned before the governor can
    /// contain the tree); a test passes a stand-in.
    pub binary: PathBuf,
    /// The materialised workspace, which is also the child's working directory.
    pub workspace: PathBuf,
    /// The lease id that authenticates every `harness.*` call the child makes.
    pub lease_token: String,
    /// The kernel endpoint the child's `vk-mcp` connects back to.
    pub endpoint: String,
    /// The `vk-mcp` binary `.mcp.json` names as the server command.
    pub mcp_server: PathBuf,
    /// The instruction handed to `claude -p`.
    pub prompt: String,
    /// The model, if one is pinned; `None` lets the CLI choose its default.
    pub model: Option<String>,
    /// How long the whole run may take before the tree is killed.
    pub timeout: Duration,
}

/// Why a run ended, told rather than guessed. A Job Object kill leaves the
/// child's exit status `0` (spike 3a), so a run this harness cut short is
/// recorded from what the harness did, not from the code the OS reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// The process exited on its own with this code.
    Exited(i32),
    /// It was killed for exceeding the run's time budget.
    Timeout,
    /// A STOP arrived while it ran; the governor was dropped and the tree
    /// killed.
    KilledByGovernor,
    /// It died on a signal (Unix), no code.
    Signal,
}

impl ExitReason {
    /// The `exit` field of the `harness.connections` ledger event and of the
    /// harness `task.step` payload: `code N`, `timeout`, `killed by governor`,
    /// or `signal`.
    pub fn label(&self) -> String {
        match self {
            ExitReason::Exited(c) => format!("code {c}"),
            ExitReason::Timeout => "timeout".into(),
            ExitReason::KilledByGovernor => "killed by governor".into(),
            ExitReason::Signal => "signal".into(),
        }
    }

    /// Did the harness finish its work? Only a clean `code 0` counts: a killed
    /// or timed-out run has left whatever it left, and the step fails.
    pub fn is_success(&self) -> bool {
        matches!(self, ExitReason::Exited(0))
    }
}

/// What one harness run was.
#[derive(Debug, Clone)]
pub struct HarnessRun {
    pub exit_code: Option<i32>,
    pub exit_reason: ExitReason,
    /// What `claude -p --output-format json` printed on stdout, verbatim.
    pub stdout_json: String,
    /// The remote `ip:port` the child talked to over the run, deduplicated and
    /// sorted.
    pub connections: Vec<String>,
    /// How many times egress was sampled.
    pub samples: usize,
    pub duration_ms: u64,
    /// Whether the kernel contained the process: `contain` succeeded and the OS
    /// read back that the child is in the job (spike 3a, Ruling 18).
    pub governed: bool,
}

/// The `.mcp.json` a launch writes into the workspace: one stdio MCP server,
/// `vk`, run as the `vk-mcp` binary with the endpoint and lease token in its
/// environment. `token` is [`REDACTED_TOKEN`] for a `--dry-run`.
pub fn mcp_json(cfg: &HarnessConfig, token: &str) -> String {
    let value = serde_json::json!({
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": cfg.mcp_server.display().to_string(),
                "env": {
                    "VK_ENDPOINT": cfg.endpoint,
                    "VK_LEASE_TOKEN": token,
                }
            }
        }
    });
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

/// Where a launch writes its `.mcp.json`.
pub fn mcp_config_path(cfg: &HarnessConfig) -> PathBuf {
    cfg.workspace.join(".mcp.json")
}

/// The launch line, argv[0] first — the pinned line (plan Global Constraints)
/// plus `--strict-mcp-config`, so only the `vk` server declared in `.mcp.json`
/// is loaded and no user MCP config, hook or skill reaches the harness.
///
/// The prompt is an argument, not stdin: it is a fixed instruction, not data,
/// and the data the harness may read is in the workspace, projected under the
/// harness clearance. The sensitive material never rides the command line.
pub fn launch_line(cfg: &HarnessConfig) -> Vec<String> {
    let mut argv = vec![
        cfg.binary.display().to_string(),
        "-p".into(),
        cfg.prompt.clone(),
        "--mcp-config".into(),
        mcp_config_path(cfg).display().to_string(),
        "--allowedTools".into(),
        ALLOWED_TOOLS.into(),
        "--permission-mode".into(),
        "acceptEdits".into(),
        "--output-format".into(),
        "json".into(),
        "--strict-mcp-config".into(),
    ];
    if let Some(model) = &cfg.model {
        argv.push("--model".into());
        argv.push(model.clone());
    }
    argv
}

/// Launch Claude Code under `governor`, sample its egress, and wait.
///
/// `should_stop` is polled between samples: when it answers true a STOP has
/// arrived, so the governor is dropped — which on Windows closes the job and
/// kills the tree — the process group is signalled as well (for the platforms
/// with no governor), and the run is recorded as `killed by governor`. The
/// governor is taken by value so this can drop it; it is dropped at the end
/// either way, killing anything the child left running.
pub fn launch_claude_code(
    cfg: &HarnessConfig,
    governor: Box<dyn Governor>,
    should_stop: &(dyn Fn() -> bool + Sync),
) -> Result<HarnessRun> {
    std::fs::create_dir_all(&cfg.workspace)
        .with_context(|| format!("create workspace {}", cfg.workspace.display()))?;
    std::fs::write(mcp_config_path(cfg), mcp_json(cfg, &cfg.lease_token))
        .with_context(|| format!("write {}", mcp_config_path(cfg).display()))?;

    let argv = launch_line(cfg);
    let started = Instant::now();
    let mut child = spawn(Path::new(&argv[0]))
        .args(&argv[1..])
        .current_dir(&cfg.workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("launch {} in {}", argv[0], cfg.workspace.display()))?;

    // Immediately after spawn, before the child can do much: contain the tree,
    // and remember whether the OS confirmed it (Ruling 18). A refusal is not
    // fatal — an ungoverned run is honestly recorded as such — but it is logged.
    let governed = match governor.contain(&child) {
        Ok(()) => governor.governed(),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "harness launched ungoverned: contain refused");
            false
        }
    };

    let pid = child.id();
    let out_t = drain(child.stdout.take().context("no stdout pipe")?);
    let err_t = drain(child.stderr.take().context("no stderr pipe")?);

    let mut connections: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut samples = 0usize;
    let deadline = started + cfg.timeout;
    let exit_reason = loop {
        if let Some(status) = child.try_wait().context("wait for claude")? {
            break reason_from(status);
        }
        if should_stop() {
            // A STOP: kill the tree now, and let the governor close the job
            // when it drops below — both terminate the tree, on every platform.
            kill_tree(&mut child);
            let _ = child.wait();
            break ExitReason::KilledByGovernor;
        }
        if Instant::now() >= deadline {
            kill_tree(&mut child);
            let _ = child.wait();
            break ExitReason::Timeout;
        }
        // Sample egress, then sleep the interval. The child's own pid owns the
        // TLS sockets of the native binary; a helper it spawns is missed
        // (`netwatch`, `contracts/tcb.md`).
        for c in crate::netwatch::sample(pid) {
            connections.insert(c);
        }
        samples += 1;
        std::thread::sleep(SAMPLE_EVERY);
    };

    let stdout_json = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
    if !exit_reason.is_success() {
        let tail = last_chars(stderr.trim(), 300);
        tracing::warn!(reason = %exit_reason.label(), stderr = %tail, "harness run did not finish cleanly");
    }
    // The governor drops here, killing anything the child left in the job.
    drop(governor);

    Ok(HarnessRun {
        exit_code: match &exit_reason {
            ExitReason::Exited(c) => Some(*c),
            _ => None,
        },
        exit_reason,
        stdout_json,
        connections: connections.into_iter().collect(),
        samples,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        governed,
    })
}

fn reason_from(status: std::process::ExitStatus) -> ExitReason {
    match status.code() {
        Some(c) => ExitReason::Exited(c),
        None => ExitReason::Signal,
    }
}

/// A `Command` for a child this module may have to kill wholesale. On Unix it
/// leads its own process group, so [`kill_tree`] can signal the group; on
/// Windows the Job Object kills the tree and the pid tree is found at kill time.
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

/// Kill the child and everything it started. The governor's Job Object already
/// does this on Windows when dropped; this is the belt-and-braces path, and the
/// only kill on platforms with no governor.
fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    // On Unix there is no governor yet (the Noop confines nothing), so this is
    // the only kill; the harness there is a test stand-in with no descendants,
    // so killing the process itself is enough.
    let _ = child.kill();
}

fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

fn last_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        return s.to_string();
    }
    format!("…{}", s.chars().skip(count - n).collect::<String>())
}
