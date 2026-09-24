//! The confined launch of Claude Code as a harness.
//!
//! [`launch_claude_code`] writes the run's configuration **outside** the
//! workspace — `mcp.json` (the one channel back to the kernel, carrying the
//! lease token that authenticates every `harness.*` syscall) and a
//! `settings.json` holding the permission fence — spawns the CLI under the
//! [`Governor`](crate::confine) it is handed, samples the child's egress every
//! 500 ms, and waits, killing the tree on a timeout or a STOP. It hands back
//! what the run was: the exit, whether the process was contained, the endpoints
//! it reached, and what Claude reported (cost, turns, permission denials).
//!
//! **The fence (Rulings 19 and 22).** Claude Code's own permission system is
//! what keeps the harness inside its workspace: the session runs in `dontAsk`
//! mode with `--permission-prompts none`, so anything not covered by an allow
//! rule is denied and never retried; the allow rules are `Read(./**)` and
//! `Edit(./**)` — the two rule kinds Claude Code consults for every file tool
//! (a `Write`, `Glob` or `Grep` path rule is accepted and ignored, per the
//! permissions documentation) — plus `mcp__vk__*`; the deny rules remove every
//! other built-in tool by name ([`DENIED_TOOLS`], which a test diffs against
//! the documented list [`BUILTIN_TOOLS`]), keep the harness's own inputs
//! read-only, and name the state directory, the run's configuration directory
//! and the usual sensitive trees explicitly. Two controls of the CLI itself
//! back the rules without depending on the mode: `--restricted` (the command-
//! and code-running tools and `WebFetch` removed, the file tools confined to
//! the working directories, only managed settings and `--settings` loaded,
//! `bypassPermissions` and cloud sessions refused) and
//! `permissions.blockReadsOutsideWorkingDirectories` (`Read`, `Grep`, `Glob`
//! and `LSP` refuse a path outside the working directories in every mode).
//! `--setting-sources ""` keeps the user's own settings out of the session,
//! `--strict-mcp-config` keeps every MCP server but `vk` out. What this is
//! not: OS-level isolation — a helper process the model cannot launch would
//! not be bound by it. That arrives with the restricted token (plan, Task 10
//! group G); `contracts/tcb.md` says so.
//!
//! **The kernel drives this with its lock released.** The launched harness calls
//! back over MCP (`harness.read_register`, `harness.attach_artefact`, …) while
//! it runs, and those are ordinary syscalls that take the kernel lock; a lock
//! held across the wait would deadlock the harness against itself. So the kernel
//! leases and materialises under its lock, drops it, runs this, then re-takes
//! the lock to attach the artefact and record the telemetry.
use crate::confine::Governor;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The MCP server name the kernel answers as. Claude Code exposes its tools as
/// `mcp__<name>__<tool>`, so this is the `vk` in `mcp__vk__*`.
pub const MCP_SERVER_NAME: &str = "vk";

/// How often the child's egress is sampled into the run record.
pub const SAMPLE_EVERY: Duration = Duration::from_millis(500);

/// What the token reads as in a `--dry-run`'s printed `mcp.json`: the real one
/// is a live capability and does not belong in a log or a terminal.
pub const REDACTED_TOKEN: &str = "<redacted>";

/// The permission mode the harness runs in. `dontAsk` is Claude Code's
/// documented mode for locked-down unattended runs: every call that would
/// otherwise prompt is denied, and only what an allow rule covers runs. (The
/// installed 2.1.281 lists `acceptEdits, auto, bypassPermissions, manual,
/// dontAsk, plan`; `-p` starts in `manual`, whose prompts a hostless run also
/// denies — `dontAsk` says so explicitly.)
pub const PERMISSION_MODE: &str = "dontAsk";

/// Every built-in tool of the Claude Code this fence is written against: the 46
/// names of the tools reference (`code.claude.com/docs/en/tools-reference`,
/// read 2026-09-24 against the installed 2.1.281) and the two `claude --help`
/// names that table lacks — `REPL`, a code-running tool `--restricted` removes,
/// and `SendUserMessage`, behind `--brief`. This is the list the fence is
/// diffed against: `the_fence_partitions_every_documented_built_in` fails until
/// every name here is either kept ([`KEPT_TOOLS`]) or denied
/// ([`DENIED_TOOLS`]), so a tool the CLI grows is a failing test the moment it
/// is added here, not a hole in the fence. Keep it in step with the reference.
pub const BUILTIN_TOOLS: &[&str] = &[
    "Agent",
    "Artifact",
    "AskUserQuestion",
    "Bash",
    "CronCreate",
    "CronDelete",
    "CronList",
    "Edit",
    "EndConversation",
    "EnterPlanMode",
    "EnterWorktree",
    "ExitPlanMode",
    "ExitWorktree",
    "Glob",
    "Grep",
    "ListAgents",
    "ListMcpResourcesTool",
    "LSP",
    "Monitor",
    "NotebookEdit",
    "PowerShell",
    "PushNotification",
    "Read",
    "ReadMcpResourceTool",
    "RemoteTrigger",
    "ReportFindings",
    "ScheduleWakeup",
    "SendFeedback",
    "SendMessage",
    "SendUserFile",
    "ShareOnboardingGuide",
    "Skill",
    "SubagentHandback",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "TodoWrite",
    "ToolSearch",
    "WaitForMcpServers",
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
    // `claude --help` on 2.1.281, not in the table.
    "REPL",
    "SendUserMessage",
];

/// The built-ins the fence keeps, by name: the five file tools the `Read(./**)`
/// and `Edit(./**)` rules govern — `Edit` rules cover `Write`, `Read` rules
/// cover `Glob` and `Grep`, and all five are confined to the working directory
/// by `--restricted` and `blockReadsOutsideWorkingDirectories` — and the two
/// that reach only the session's MCP servers, of which `--strict-mcp-config`
/// leaves exactly `vk`: `ToolSearch`, which loads the kernel's tools when the
/// CLI defers them (the real runs did that), and `WaitForMcpServers`.
/// Everything else a built-in can reach — a shell, the web, another agent, the
/// user's claude.ai account, device or inbox, a language server — is outside
/// the workspace, and is denied.
pub const KEPT_TOOLS: &[&str] = &[
    "Read",
    "Edit",
    "Write",
    "Glob",
    "Grep",
    "ToolSearch",
    "WaitForMcpServers",
];

/// Older spellings the CLI still accepts and the fence still denies: `Task`
/// (the subagent tool before `Agent`), `KillShell` and `BashOutput` (before
/// `TaskStop` and `TaskOutput`), `Cd`. Not in the documented list, so the
/// partition test accounts for them separately.
pub const LEGACY_TOOL_NAMES: &[&str] = &["Task", "KillShell", "BashOutput", "Cd"];

/// The tools the fence removes outright, whatever any allow rule says: every
/// built-in but [`KEPT_TOOLS`] (Ruling 22, I9), by bare name, which removes the
/// tool from the model's context. Grouped by what each reaches. Unknown names
/// are harmless — a bare tool-name deny matches at the tool level and warns
/// about nothing — so the older spellings stay.
pub const DENIED_TOOLS: &[&str] = &[
    // Commands and code.
    "Bash",
    "PowerShell",
    "REPL",
    "Monitor",
    "NotebookEdit",
    // The web.
    "WebFetch",
    "WebSearch",
    // Other agents, sessions and workflows.
    "Agent",
    "Workflow",
    "SendMessage",
    "ListAgents",
    "SubagentHandback",
    "Skill",
    // The user's claude.ai account, device and inbox — past every fence on
    // this machine, and past netwatch, with no prompt (I9).
    "RemoteTrigger",
    "SendUserFile",
    "SendUserMessage",
    "PushNotification",
    "Artifact",
    "ShareOnboardingGuide",
    "SendFeedback",
    "AskUserQuestion",
    // Code intelligence: a file reader the `Read` rules do not see.
    "LSP",
    // MCP resources: the kernel exposes none.
    "ListMcpResourcesTool",
    "ReadMcpResourceTool",
    // Scheduling and session control.
    "CronCreate",
    "CronDelete",
    "CronList",
    "ScheduleWakeup",
    "EnterPlanMode",
    "ExitPlanMode",
    "EnterWorktree",
    "ExitWorktree",
    // Documented as not removable while any other tool remains; denied so
    // the list says what it means.
    "EndConversation",
    // The session's own task list and checklist: nothing the run needs.
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "TodoWrite",
    "ReportFindings",
    // Older spellings (`LEGACY_TOOL_NAMES`).
    "Task",
    "KillShell",
    "BashOutput",
    "Cd",
];

/// Everything a launch needs. The kernel builds it; a `--dry-run` builds it with
/// [`REDACTED_TOKEN`] to print the launch line and the configuration without
/// running anything.
#[derive(Clone)]
pub struct HarnessConfig {
    /// The Claude Code binary — daemon configuration (`vkd --harness-bin`),
    /// never a request field. The real one is `claude.exe`, launched directly
    /// (never a `.cmd` shim, so no grandchild is spawned before the governor can
    /// contain the tree); a test's daemon is started with a stand-in.
    pub binary: PathBuf,
    /// The materialised workspace, which is also the child's working directory
    /// and the only place its file tools may reach.
    pub workspace: PathBuf,
    /// Where this run's `mcp.json` and `settings.json` are written: outside the
    /// workspace, so no allow rule reaches them, and denied by name as well.
    pub config_dir: PathBuf,
    /// The daemon's state directory, so the fence can deny its store, keys,
    /// ledger and exports by their real paths.
    pub state_dir: PathBuf,
    /// The lease token that authenticates every `harness.*` call the child
    /// makes. A secret: it goes into `mcp.json` and nowhere else.
    pub lease_token: String,
    /// The kernel endpoint the child's `vk-mcp` connects back to.
    pub endpoint: String,
    /// The `vk-mcp` binary `mcp.json` names as the server command.
    pub mcp_server: PathBuf,
    /// The instruction handed to `claude -p`.
    pub prompt: String,
    /// The model, if one is pinned; `None` lets the CLI choose its default.
    pub model: Option<String>,
    /// How long the whole run may take before the tree is killed.
    pub timeout: Duration,
    /// An operator addendum to Claude Code's *system* prompt
    /// (`--append-system-prompt`), from the daemon's own environment only
    /// (`VK_HARNESS_SYSTEM_SUFFIX`). The channel a confinement diagnostic has to
    /// use: the model treats a "try to read `C:\Windows\win.ini`" placed in a
    /// task file or in the user turn as an injection and refuses to act on it —
    /// it said so, twice — so a proof of the fence has to come from the one
    /// channel it holds as the operator's. `None` in every ordinary run.
    pub system_suffix: Option<String>,
}

/// Hand-written, so the token never rides a `{cfg:?}` into a log line or an
/// error context: it prints as [`REDACTED_TOKEN`], as it does in a `--dry-run`
/// (Ruling 22, M15).
impl std::fmt::Debug for HarnessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HarnessConfig")
            .field("binary", &self.binary)
            .field("workspace", &self.workspace)
            .field("config_dir", &self.config_dir)
            .field("state_dir", &self.state_dir)
            .field("lease_token", &REDACTED_TOKEN)
            .field("endpoint", &self.endpoint)
            .field("mcp_server", &self.mcp_server)
            .field("prompt", &self.prompt)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .field("system_suffix", &self.system_suffix)
            .finish()
    }
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
    /// A STOP arrived while it ran; the tree was killed and the governor
    /// dropped.
    KilledByGovernor,
    /// It died on a signal (Unix), no code.
    Signal,
    /// The governor could not contain it, so it was killed before it ran
    /// (Windows only: fail closed — Ruling 21.8).
    NotContained,
    /// It never started: the binary could not be spawned.
    NotStarted,
}

impl ExitReason {
    /// The `exit` field of the `harness.connections` ledger event and of the
    /// harness `task.step` payload: `code N`, `timeout`, `killed by governor`,
    /// `signal`, `not contained` or `not started`.
    pub fn label(&self) -> String {
        match self {
            ExitReason::Exited(c) => format!("code {c}"),
            ExitReason::Timeout => "timeout".into(),
            ExitReason::KilledByGovernor => "killed by governor".into(),
            ExitReason::Signal => "signal".into(),
            ExitReason::NotContained => "not contained".into(),
            ExitReason::NotStarted => "not started".into(),
        }
    }

    /// Did the harness finish its work? Only a clean `code 0` counts: a killed
    /// or timed-out run has left whatever it left, and the step fails.
    pub fn is_success(&self) -> bool {
        matches!(self, ExitReason::Exited(0))
    }
}

/// What Claude Code itself reported about the run, read off the one JSON object
/// `claude -p --output-format json` prints. Best effort: a run that printed no
/// object (killed, timed out) has none.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaudeOutcome {
    pub is_error: bool,
    pub num_turns: u64,
    /// List-price equivalent, as the CLI reports it — a comparison under a
    /// subscription, not a charge (SP1b ruling 3).
    pub total_cost_usd: f64,
    /// Every tool call the fence refused, as `Tool(what)` — the evidence that
    /// the confinement held for this run.
    pub permission_denials: Vec<String>,
}

/// What one harness run was.
#[derive(Debug, Clone)]
pub struct HarnessRun {
    pub exit_code: Option<i32>,
    pub exit_reason: ExitReason,
    /// What `claude -p --output-format json` printed on stdout, verbatim.
    pub stdout_json: String,
    /// The same, read: cost, turns and the denials the fence recorded.
    pub outcome: Option<ClaudeOutcome>,
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

/// The `mcp.json` a launch writes: one stdio MCP server, `vk`, run as the
/// `vk-mcp` binary with the endpoint and lease token in its environment.
/// `token` is [`REDACTED_TOKEN`] for a `--dry-run`.
pub fn mcp_json(cfg: &HarnessConfig, token: &str) -> String {
    let value = json!({
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

/// Where a launch writes its `mcp.json`: in the configuration directory, outside
/// the workspace.
pub fn mcp_config_path(cfg: &HarnessConfig) -> PathBuf {
    cfg.config_dir.join("mcp.json")
}

/// Where a launch writes its permission `settings.json`.
pub fn settings_path(cfg: &HarnessConfig) -> PathBuf {
    cfg.config_dir.join("settings.json")
}

/// A path as a Claude Code absolute permission pattern: POSIX form, `//`
/// anchored at the filesystem root, drive letter lowercased, `/**` for the
/// whole tree (`C:\Users\a\x` → `//c/Users/a/x/**`; `/tmp/x` → `//tmp/x/**`).
pub fn tree_pattern(path: &Path) -> String {
    format!("//{}/**", posix_abs(path))
}

/// The same for one file (`C:\x\vk.sqlite` → `//c/x/vk.sqlite`).
pub fn file_pattern(path: &Path) -> String {
    format!("//{}", posix_abs(path))
}

/// `C:\Users\a` → `c/Users/a`; `/tmp/x` → `tmp/x` (no leading slash; the
/// caller adds the `//` anchor).
fn posix_abs(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    let s = if s.len() >= 2 && s.as_bytes()[1] == b':' {
        format!("{}{}", s[..1].to_ascii_lowercase(), &s[2..])
    } else {
        s
    };
    s.trim_start_matches('/').trim_end_matches('/').to_string()
}

/// The permission rules of the fence: what the harness may touch, and what it
/// may not whatever else says so.
///
/// Allow: the workspace, for reading and for editing, and the kernel's tools.
/// Deny (deny beats allow, in every scope): every built-in tool but the file
/// tools and the MCP loaders ([`DENIED_TOOLS`]); the run's configuration
/// directory (the token lives there); the daemon's store, keys, ledger and
/// exports by their real paths; the usual sensitive trees under the home
/// directory and the OS directories; the harness's own inputs (`TASK.md`,
/// `PLAN.md`, `BRIEF/`) for editing, so the projection stays what the kernel
/// wrote; and any settings, MCP or `CLAUDE.md` file, so a run cannot widen its
/// own fence or plant one for the next.
///
/// Not denied by pattern: the home directory as a whole. The workspace lives
/// under it (`%LOCALAPPDATA%`), and Claude Code's `!` carve-outs cannot reach
/// past a `~/` anchor; the fence against everything else outside the workspace
/// is the default deny of `dontAsk` — a read or edit outside the working
/// directory needs a prompt, and nothing answers one — backed, since Ruling
/// 22, by `permissions.blockReadsOutsideWorkingDirectories` (a read outside is
/// refused in every mode) and by `--restricted` (the file tools are confined
/// to the working directories), neither of which depends on the mode.
pub fn permission_rules(cfg: &HarnessConfig) -> (Vec<String>, Vec<String>) {
    let allow = vec![
        "Read(./**)".to_string(),
        "Edit(./**)".to_string(),
        format!("mcp__{MCP_SERVER_NAME}__*"),
    ];

    let mut deny: Vec<String> = DENIED_TOOLS.iter().map(|t| t.to_string()).collect();
    // The run's own configuration — the token — and the daemon's state, by
    // their real paths (outside the workspace, so already unreachable by the
    // allow rules; named so the refusal is explicit and auditable).
    let mut trees: Vec<PathBuf> = vec![
        cfg.config_dir.clone(),
        cfg.state_dir.join("blobs"),
        cfg.state_dir.join("ledger"),
        cfg.state_dir.join("exports"),
        cfg.state_dir.join("claude-code-cwd"),
    ];
    let mut files: Vec<PathBuf> = vec![
        cfg.state_dir.join("vk.sqlite"),
        cfg.state_dir.join("vk.sqlite-wal"),
        cfg.state_dir.join("vk.sqlite-shm"),
        cfg.state_dir.join("master.key"),
        cfg.state_dir.join("node.key"),
        cfg.state_dir.join("lock"),
        cfg.state_dir.join("vkd.log"),
    ];
    // The OS and program directories, where the platform names them.
    for var in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            trees.push(PathBuf::from(dir));
        }
    }
    if cfg!(unix) {
        for dir in [
            "/etc", "/root", "/proc", "/sys", "/var", "/usr", "/opt", "/boot",
        ] {
            trees.push(PathBuf::from(dir));
        }
    }
    for tree in &trees {
        deny.push(format!("Read({})", tree_pattern(tree)));
        deny.push(format!("Edit({})", tree_pattern(tree)));
    }
    for file in &files {
        deny.push(format!("Read({})", file_pattern(file)));
        deny.push(format!("Edit({})", file_pattern(file)));
    }
    files.clear();
    // Sensitive trees under the home directory, by their well-known names.
    for home in [
        ".ssh/**",
        ".aws/**",
        ".gnupg/**",
        ".azure/**",
        ".kube/**",
        ".docker/**",
        ".config/**",
        ".claude/**",
        ".claude.json",
        ".credentials.json",
        ".netrc",
        ".git-credentials",
        "AppData/Roaming/**",
    ] {
        deny.push(format!("Read(~/{home})"));
        deny.push(format!("Edit(~/{home})"));
    }
    // Inside the workspace: the inputs stay the kernel's, and nothing that could
    // configure Claude Code — this run or the next — may be written.
    for path in ["TASK.md", "PLAN.md", "BRIEF/**"] {
        deny.push(format!("Edit({path})"));
    }
    for path in [
        ".claude/**",
        "settings.json",
        "settings.local.json",
        ".mcp.json",
        ".claude.json",
        "CLAUDE.md",
        "CLAUDE.local.md",
        ".env",
        ".env.*",
    ] {
        deny.push(format!("Edit({path})"));
    }
    // And a secrets file that somehow landed in reach is not for reading.
    for path in [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519"] {
        deny.push(format!("Read({path})"));
    }
    (allow, deny)
}

/// The `settings.json` a launch writes: the fence as Claude Code's
/// `permissions` block — the rules, and `blockReadsOutsideWorkingDirectories`
/// (v2.1.257+; Ruling 22), under which `Read`, `Grep`, `Glob` and `LSP` refuse
/// a path outside the working directories in every permission mode, so a read
/// the fence does not name is refused by the CLI and not only by the mode's
/// unanswered prompt.
pub fn settings_json(cfg: &HarnessConfig) -> String {
    let (allow, deny) = permission_rules(cfg);
    let value = json!({
        "permissions": {
            "allow": allow,
            "deny": deny,
            "blockReadsOutsideWorkingDirectories": true,
        }
    });
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

/// The launch line, argv[0] first.
///
/// `-p <prompt>`; `--restricted` (v2.1.248+; Ruling 22: the command- and
/// code-running tools and `WebFetch` removed, the file tools confined to the
/// working directories, only managed settings and `--settings` loaded,
/// `bypassPermissions` and cloud sessions refused — the documented form of
/// what `--setting-sources ""` is relied on for); the run's `mcp.json` with
/// `--strict-mcp-config` (no other MCP server, hook or skill reaches the
/// session); the run's `settings.json` with `--setting-sources ""` (the user's
/// own settings do not); `dontAsk` with `--permission-prompts none` (anything
/// the fence does not allow is denied and not retried); JSON output; and the
/// model the daemon pins.
///
/// The prompt is an argument, not stdin: it is a fixed instruction, not data,
/// and the data the harness may read is in the workspace, projected under the
/// harness clearance. The sensitive material never rides the command line.
pub fn launch_line(cfg: &HarnessConfig) -> Vec<String> {
    let mut argv = vec![
        cfg.binary.display().to_string(),
        "-p".into(),
        cfg.prompt.clone(),
        "--restricted".into(),
        "--mcp-config".into(),
        mcp_config_path(cfg).display().to_string(),
        "--strict-mcp-config".into(),
        "--settings".into(),
        settings_path(cfg).display().to_string(),
        "--setting-sources".into(),
        String::new(),
        "--permission-mode".into(),
        PERMISSION_MODE.into(),
        "--permission-prompts".into(),
        "none".into(),
        "--output-format".into(),
        "json".into(),
        // No transcript on disk: a session file would copy the projected
        // workspace — Business-labelled brief included — into the user's
        // `~/.claude/projects`, outside every fence above.
        "--no-session-persistence".into(),
    ];
    if let Some(model) = &cfg.model {
        argv.push("--model".into());
        argv.push(model.clone());
    }
    if let Some(suffix) = cfg
        .system_suffix
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        argv.push("--append-system-prompt".into());
        argv.push(suffix.trim().to_string());
    }
    argv
}

/// Read what Claude reported off its result object. `None` when there is no
/// object to read (a killed run prints none), never an error: the run record
/// is about what happened, and a missing report is one of the things that can.
pub fn parse_outcome(stdout: &str) -> Option<ClaudeOutcome> {
    let v: Value = serde_json::from_str(stdout.trim()).ok()?;
    let obj = v.as_object()?;
    let denials = obj
        .get("permission_denials")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(render_denial).collect())
        .unwrap_or_default();
    Some(ClaudeOutcome {
        is_error: obj
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        num_turns: obj.get("num_turns").and_then(Value::as_u64).unwrap_or(0),
        total_cost_usd: obj
            .get("total_cost_usd")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        permission_denials: denials,
    })
}

/// One denial as `Tool(what)`: the tool name and the one input that says what it
/// was reaching for, so an auditor can read the record without the raw object.
fn render_denial(d: &Value) -> String {
    let tool = d
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let input = d.get("tool_input").cloned().unwrap_or(Value::Null);
    let what = [
        "file_path",
        "path",
        "command",
        "url",
        "notebook_path",
        "pattern",
    ]
    .iter()
    .find_map(|k| input.get(k).and_then(Value::as_str).map(str::to_owned))
    .unwrap_or_else(|| {
        let s = input.to_string();
        s.chars().take(160).collect()
    });
    format!("{tool}({what})")
}

/// Launch Claude Code under `governor`, sample its egress, and wait.
///
/// `should_stop` is polled between samples: when it answers true a STOP has
/// arrived, the tree is killed, and the run is recorded as `killed by
/// governor`. The governor is taken by value and dropped at the end, killing
/// anything the child left running.
///
/// Fail closed on Windows (Ruling 21.8): a child the governor cannot contain is
/// killed before it does anything and the run is `not contained`. Elsewhere
/// the governor is the documented Noop and the run proceeds `governed: false`.
pub fn launch_claude_code(
    cfg: &HarnessConfig,
    governor: Box<dyn Governor>,
    should_stop: &(dyn Fn() -> bool + Sync),
) -> Result<HarnessRun> {
    write_config(cfg)?;

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
    // and remember whether the OS confirmed it (Ruling 18).
    let governed = match governor.contain(&child) {
        Ok(()) => governor.governed(),
        Err(e) => {
            if cfg!(windows) {
                // Fail closed: the platform has a governor and it refused, so
                // the harness does not run at all.
                tracing::error!(error = %format!("{e:#}"), "harness not contained: killed before it ran");
                kill_tree(&mut child);
                let _ = child.wait();
                drop(governor);
                return Ok(HarnessRun {
                    exit_code: None,
                    exit_reason: ExitReason::NotContained,
                    stdout_json: String::new(),
                    outcome: None,
                    connections: Vec::new(),
                    samples: 0,
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    governed: false,
                });
            }
            tracing::warn!(error = %format!("{e:#}"), "harness launched ungoverned: no governor on this platform");
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
        // TLS sockets of the native binary; a helper it spawns, a connection
        // shorter than the interval, and UDP are not seen (`netwatch`,
        // `contracts/tcb.md`).
        for c in crate::netwatch::sample(pid) {
            connections.insert(c);
        }
        samples += 1;
        std::thread::sleep(SAMPLE_EVERY);
    };

    // The child is gone; what it left running in its process group is not
    // (Unix — on Windows the Job Object does this when the governor drops):
    // TERM the group, give it a moment, then KILL what remains, so no helper
    // outlives the settle and the removal of the workspace (Ruling 22, M16).
    #[cfg(unix)]
    if matches!(exit_reason, ExitReason::Exited(_) | ExitReason::Signal) {
        settle_group(pid);
    }

    let stdout_json = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
    if !exit_reason.is_success() {
        let tail = last_chars(stderr.trim(), 300);
        tracing::warn!(reason = %exit_reason.label(), stderr = %tail, "harness run did not finish cleanly");
    }
    // The governor drops here, killing anything the child left in the job.
    drop(governor);

    let outcome = parse_outcome(&stdout_json);
    Ok(HarnessRun {
        exit_code: match &exit_reason {
            ExitReason::Exited(c) => Some(*c),
            _ => None,
        },
        exit_reason,
        stdout_json,
        outcome,
        connections: connections.into_iter().collect(),
        samples,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        governed,
    })
}

/// Write the run's `mcp.json` and `settings.json` into the configuration
/// directory (created `0700` on Unix), and make sure the workspace is there.
fn write_config(cfg: &HarnessConfig) -> Result<()> {
    private_dir(&cfg.config_dir)?;
    std::fs::create_dir_all(&cfg.workspace)
        .with_context(|| format!("create workspace {}", cfg.workspace.display()))?;
    std::fs::write(mcp_config_path(cfg), mcp_json(cfg, &cfg.lease_token))
        .with_context(|| format!("write {}", mcp_config_path(cfg).display()))?;
    std::fs::write(settings_path(cfg), settings_json(cfg))
        .with_context(|| format!("write {}", settings_path(cfg).display()))?;
    Ok(())
}

fn private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    Ok(())
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
/// only kill on platforms with no governor — where the child leads its own
/// process group, which is signalled whole.
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
    #[cfg(unix)]
    {
        if let Ok(pgid) = i32::try_from(child.id()) {
            // SAFETY: `kill(2)` with a negative pid signals the process group,
            // which is this child's own — `spawn` made it lead one — so nothing
            // of ours or anyone else's is in it.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

/// How long what the child left behind gets between `SIGTERM` and `SIGKILL`
/// once the child itself has exited.
#[cfg(unix)]
const GROUP_GRACE: Duration = Duration::from_secs(2);

/// Signal what is left of the child's process group after the child has exited
/// on its own: `SIGTERM`, up to [`GROUP_GRACE`] for it to go, then `SIGKILL`.
/// The group is the child's own (`spawn` made it lead one), so nothing else is
/// in it; a group with no member left answers `ESRCH`, and there is nothing to
/// do.
#[cfg(unix)]
fn settle_group(pid: u32) {
    let Ok(pgid) = i32::try_from(pid) else {
        return;
    };
    // SAFETY: `kill(2)` with a negative pid addresses the process group, which
    // is the child's own; signal 0 delivers nothing and only asks whether any
    // member is left.
    let alive = || unsafe { libc::kill(-pgid, 0) == 0 };
    if !alive() {
        return;
    }
    // SAFETY: as above; SIGTERM to the child's own group.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = Instant::now() + GROUP_GRACE;
    while alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if alive() {
        tracing::warn!(
            pgid,
            "a process the harness left running ignored SIGTERM; killing it"
        );
        // SAFETY: as above; SIGKILL to the child's own group.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HarnessConfig {
        HarnessConfig {
            binary: PathBuf::from("claude.exe"),
            workspace: PathBuf::from(r"C:\st\harness\task-1"),
            config_dir: PathBuf::from(r"C:\st\harness\task-1.mcp"),
            state_dir: PathBuf::from(r"C:\st"),
            lease_token: "secret".into(),
            endpoint: "ep".into(),
            mcp_server: PathBuf::from("vk-mcp.exe"),
            prompt: "do".into(),
            model: None,
            timeout: Duration::from_secs(1),
            system_suffix: None,
        }
    }

    #[test]
    fn a_system_suffix_rides_the_system_prompt_flag_and_only_then() {
        let plain = launch_line(&cfg());
        assert!(!plain.iter().any(|a| a == "--append-system-prompt"));
        let mut with = cfg();
        with.system_suffix = Some("  diagnostic  ".into());
        let line = launch_line(&with);
        let i = line
            .iter()
            .position(|a| a == "--append-system-prompt")
            .expect("the flag");
        assert_eq!(line[i + 1], "diagnostic");
    }

    #[test]
    fn absolute_patterns_take_claude_codes_posix_form() {
        assert_eq!(tree_pattern(Path::new(r"C:\Users\a\x")), "//c/Users/a/x/**");
        assert_eq!(
            file_pattern(Path::new(r"C:\st\vk.sqlite")),
            "//c/st/vk.sqlite"
        );
        assert_eq!(tree_pattern(Path::new("/tmp/x")), "//tmp/x/**");
    }

    #[test]
    fn the_config_debug_redacts_the_token() {
        let s = format!("{:?}", cfg());
        assert!(!s.contains("secret"), "the token leaked into Debug: {s}");
        assert!(
            s.contains("lease_token") && s.contains(REDACTED_TOKEN),
            "{s}"
        );
    }

    /// Ruling 22 (I9): the deny list is every documented built-in but the kept
    /// ones. `BUILTIN_TOOLS` is the documented list; a tool added there without
    /// a deny entry, a kept tool that is also denied, or a denied name that is
    /// neither documented nor a known older spelling, fails here.
    #[test]
    fn the_fence_partitions_every_documented_built_in() {
        use std::collections::BTreeSet;
        let builtin: BTreeSet<&str> = BUILTIN_TOOLS.iter().copied().collect();
        let kept: BTreeSet<&str> = KEPT_TOOLS.iter().copied().collect();
        let denied: BTreeSet<&str> = DENIED_TOOLS.iter().copied().collect();
        let legacy: BTreeSet<&str> = LEGACY_TOOL_NAMES.iter().copied().collect();
        assert_eq!(
            builtin.len(),
            BUILTIN_TOOLS.len(),
            "a duplicate in BUILTIN_TOOLS"
        );
        assert_eq!(
            denied.len(),
            DENIED_TOOLS.len(),
            "a duplicate in DENIED_TOOLS"
        );
        assert!(
            kept.is_subset(&builtin),
            "a kept tool must be a documented one"
        );
        assert!(
            kept.is_disjoint(&denied),
            "a tool cannot be both kept and denied"
        );
        assert!(
            legacy.is_disjoint(&builtin),
            "a legacy name is one the documented list lacks"
        );
        let expected: BTreeSet<&str> = builtin
            .difference(&kept)
            .copied()
            .chain(legacy.iter().copied())
            .collect();
        let missing: Vec<&str> = expected.difference(&denied).copied().collect();
        assert!(
            missing.is_empty(),
            "documented built-ins the fence neither keeps nor denies: {missing:?}"
        );
        let stray: Vec<&str> = denied.difference(&expected).copied().collect();
        assert!(
            stray.is_empty(),
            "denied names that are neither documented nor legacy: {stray:?}"
        );
        // The kept set is exactly the file tools the two rule families govern
        // and the two MCP loaders — nothing with reach past the workspace.
        assert_eq!(
            KEPT_TOOLS,
            &[
                "Read",
                "Edit",
                "Write",
                "Glob",
                "Grep",
                "ToolSearch",
                "WaitForMcpServers"
            ]
        );
        // The names the re-review named are denied, by name.
        for tool in [
            "RemoteTrigger",
            "SendUserFile",
            "LSP",
            "Artifact",
            "Workflow",
            "CronCreate",
            "REPL",
        ] {
            assert!(denied.contains(tool), "{tool} must be denied");
        }
        // And every denied name is in the rendered fence.
        let (_, deny) = permission_rules(&cfg());
        for tool in DENIED_TOOLS {
            assert!(deny.iter().any(|d| d == tool), "{tool} not in the fence");
        }
    }

    #[test]
    fn the_settings_block_reads_outside_the_working_directories_in_every_mode() {
        let v: Value = serde_json::from_str(&settings_json(&cfg())).unwrap();
        assert_eq!(
            v["permissions"]["blockReadsOutsideWorkingDirectories"],
            json!(true)
        );
        assert_eq!(v["permissions"]["allow"].as_array().unwrap().len(), 3);
        // Only the permissions block: no hook, no MCP server, no env.
        assert_eq!(v.as_object().unwrap().len(), 1, "{v}");
    }

    #[test]
    fn the_fence_allows_only_the_workspace_and_the_kernel_tools() {
        let (allow, deny) = permission_rules(&cfg());
        assert_eq!(allow, vec!["Read(./**)", "Edit(./**)", "mcp__vk__*"]);
        for tool in [
            "Bash",
            "WebFetch",
            "WebSearch",
            "Task",
            "NotebookEdit",
            "RemoteTrigger",
            "SendUserFile",
            "LSP",
            "REPL",
        ] {
            assert!(deny.iter().any(|d| d == tool), "{tool} must be denied");
        }
        // The token's directory, the store and the keys are denied by real path.
        assert!(deny.contains(&"Read(//c/st/harness/task-1.mcp/**)".to_string()));
        assert!(deny.contains(&"Read(//c/st/vk.sqlite)".to_string()));
        assert!(deny.contains(&"Read(//c/st/master.key)".to_string()));
        // The inputs are read-only and no settings file may be written.
        assert!(deny.contains(&"Edit(TASK.md)".to_string()));
        assert!(deny.contains(&"Edit(BRIEF/**)".to_string()));
        assert!(deny.contains(&"Edit(.claude/**)".to_string()));
        assert!(deny.contains(&"Edit(settings.json)".to_string()));
        assert!(deny.contains(&"Read(~/.claude/**)".to_string()));
        // Nothing in the fence is a Write/Glob/Grep path rule, which Claude Code
        // accepts and ignores.
        assert!(!allow.iter().chain(deny.iter()).any(|r| {
            r.starts_with("Write(") || r.starts_with("Glob(") || r.starts_with("Grep(")
        }));
    }

    /// The deterministic guard on the fence, independent of any model: every
    /// tree and file the confinement rests on is denied by its real path, for
    /// reading and for editing, and the allow list is exactly the workspace and
    /// the kernel's tools. Loosen the fence and this fails.
    #[test]
    fn the_fence_denies_every_required_tree_and_file_by_real_path() {
        let cfg = cfg();
        let (allow, deny) = permission_rules(&cfg);
        assert_eq!(allow, vec!["Read(./**)", "Edit(./**)", "mcp__vk__*"]);
        let has = |rule: String| assert!(deny.contains(&rule), "missing deny rule {rule}");

        // The run's configuration (the token) and the daemon's state, as trees.
        for tree in [
            cfg.config_dir.clone(),
            cfg.state_dir.join("blobs"),
            cfg.state_dir.join("ledger"),
            cfg.state_dir.join("exports"),
            cfg.state_dir.join("claude-code-cwd"),
        ] {
            has(format!("Read({})", tree_pattern(&tree)));
            has(format!("Edit({})", tree_pattern(&tree)));
        }
        // The store, the keys, the lock and the log, as files.
        for file in [
            "vk.sqlite",
            "vk.sqlite-wal",
            "vk.sqlite-shm",
            "master.key",
            "node.key",
            "lock",
            "vkd.log",
        ] {
            has(format!("Read({})", file_pattern(&cfg.state_dir.join(file))));
            has(format!("Edit({})", file_pattern(&cfg.state_dir.join(file))));
        }
        // The OS and program directories, wherever this platform keeps them.
        let os_dirs: Vec<PathBuf> = if cfg!(unix) {
            [
                "/etc", "/root", "/proc", "/sys", "/var", "/usr", "/opt", "/boot",
            ]
            .iter()
            .map(PathBuf::from)
            .collect()
        } else {
            [
                "SystemRoot",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramData",
            ]
            .iter()
            .filter_map(|v| std::env::var_os(v).filter(|s| !s.is_empty()))
            .map(PathBuf::from)
            .collect()
        };
        assert!(!os_dirs.is_empty(), "this platform names no OS directories");
        for tree in os_dirs {
            has(format!("Read({})", tree_pattern(&tree)));
            has(format!("Edit({})", tree_pattern(&tree)));
        }
        // The home dotfiles and credential stores.
        for home in [
            ".ssh/**",
            ".aws/**",
            ".gnupg/**",
            ".azure/**",
            ".kube/**",
            ".docker/**",
            ".config/**",
            ".claude/**",
            ".claude.json",
            ".credentials.json",
            ".netrc",
            ".git-credentials",
            "AppData/Roaming/**",
        ] {
            has(format!("Read(~/{home})"));
            has(format!("Edit(~/{home})"));
        }
        // The tools that reach past the file rules.
        for tool in DENIED_TOOLS {
            has(tool.to_string());
        }
        // The inputs read-only; no settings, MCP or CLAUDE.md file writable.
        for path in ["TASK.md", "PLAN.md", "BRIEF/**"] {
            has(format!("Edit({path})"));
        }
        for path in [
            ".claude/**",
            "settings.json",
            "settings.local.json",
            ".mcp.json",
            ".claude.json",
            "CLAUDE.md",
            "CLAUDE.local.md",
        ] {
            has(format!("Edit({path})"));
        }
        // Every absolute rule is anchored at the filesystem root, so none can
        // silently become a settings-relative or cwd-relative pattern.
        for rule in deny.iter().filter(|r| r.contains("(/")) {
            assert!(
                rule.contains("(//"),
                "an absolute rule must use the `//` root anchor: {rule}"
            );
        }
    }

    #[test]
    fn the_launch_line_pins_the_locked_down_flags_and_no_bare_tool_allows() {
        let line = launch_line(&cfg());
        for flag in [
            "--restricted",
            "--strict-mcp-config",
            "--settings",
            "--setting-sources",
            "--permission-mode",
            "dontAsk",
            "--permission-prompts",
            "none",
            "--output-format",
            "json",
            "--no-session-persistence",
        ] {
            assert!(line.iter().any(|a| a == flag), "{flag} missing: {line:?}");
        }
        assert!(!line.iter().any(|a| a == "--allowedTools"), "{line:?}");
        assert!(!line.iter().any(|a| a == "acceptEdits"), "{line:?}");
        let i = line.iter().position(|a| a == "--setting-sources").unwrap();
        assert_eq!(line[i + 1], "", "no user, project or local settings");
    }

    #[test]
    fn the_outcome_reads_denials_cost_and_turns() {
        let o = parse_outcome(
            r#"{"is_error":false,"num_turns":5,"total_cost_usd":0.12,
                "permission_denials":[{"tool_name":"Read","tool_input":{"file_path":"C:\\Windows\\win.ini"}},
                                      {"tool_name":"Write","tool_input":{"file_path":"C:\\x\\escape.txt","content":"e"}}]}"#,
        )
        .unwrap();
        assert_eq!(o.num_turns, 5);
        assert!((o.total_cost_usd - 0.12).abs() < 1e-9);
        assert_eq!(
            o.permission_denials,
            vec!["Read(C:\\Windows\\win.ini)", "Write(C:\\x\\escape.txt)"]
        );
        assert!(parse_outcome("").is_none());
        assert!(parse_outcome("not json").is_none());
    }
}
