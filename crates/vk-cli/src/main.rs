//! `vk`: the VerticalAI command-line client — the shell of this OS.
//!
//! Every verb is one syscall over the local endpoint, printed as a table or,
//! with `--json`, as the daemon's own answer — plus, on the three verbs that
//! resolve something for the reader (`task show`'s release paths, `approve`'s
//! subject, `boot`'s pid), the field the client worked out, under its own
//! name. The three human verbs (`stop`,
//! `resume`, `approve`) are the exception: a connection is a machine
//! principal, so those carry a presence proof signed by this node's device
//! key over a nonce the daemon just issued (spec §3.6, invariant I1). In SP1a
//! the interactive machine *is* the enrolled device; SP1b replaces the key
//! file with a passkey.
mod render;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vk_contracts::principal::{Approval, ApprovalKind, Challenge, HumanKey, Principal};
use vk_ipc::client::Client;
use vk_ipc::transport::{default_endpoint, Endpoint};
use vk_ipc::PresenceProof;
use vk_kernel::presence::{KeySource, NodeDevice};

/// How long an approval challenge stays answerable — the daemon's own window.
const APPROVAL_TTL_MS: u64 = 60_000;
/// A `--all` run drives one step per call; this bounds it so a task that never
/// settles is reported rather than looped on forever.
const MAX_STEPS: usize = 256;
/// How long `vk boot` waits for the daemon it started to answer.
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(name = "vk", about = "VerticalAI kernel shell", version)]
struct Cli {
    /// Machine-readable output: the syscall's answer, unrendered.
    #[arg(long, global = true)]
    json: bool,
    /// Daemon endpoint (default: $VK_ENDPOINT, else this user's own).
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start vkd (Task 9 adds the full boot sequence).
    Boot(BootArgs),
    /// What this node is, and whether its ledger verifies.
    Status,
    /// List a namespace path.
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    /// Tasks and how far each has got.
    Ps,
    /// Per-arch calls and tokens, stopped scopes, liveness.
    Top,
    /// Mount an arch.
    Mount {
        #[command(subcommand)]
        what: MountCmd,
    },
    /// Unmount an arch by id.
    Umount { arch_id: String },
    /// Submit, step and inspect tasks.
    Task {
        #[command(subcommand)]
        what: TaskCmd,
    },
    /// STOP a scope. Human: signed with this node's device key.
    Stop {
        #[arg(default_value = "node")]
        scope: String,
    },
    /// Lift a STOP by its id. Human.
    Resume { stop_id: String },
    /// Approve a task's latest artefact. Human.
    Approve { task_id: String },
    /// The ledger tail.
    Dmesg {
        #[arg(short = 'n', long = "lines", default_value_t = 20)]
        n: u64,
    },
    /// The ledger itself.
    Ledger {
        #[command(subcommand)]
        what: LedgerCmd,
    },
}

/// Where the daemon's state and keys come from. The same flags `vkd` takes,
/// with the same meaning, because `vk boot` only hands them on.
#[derive(clap::Args)]
struct BootArgs {
    /// State directory to serve (default: this user's local app data).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = "node-1")]
    node_id: String,
    /// Master key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    master_key_file: Option<PathBuf>,
    /// Node device key file (default: $VK_NODE_KEY_FILE, else the keyring).
    #[arg(long)]
    node_key_file: Option<PathBuf>,
    /// Run the daemon in this terminal instead of detaching it.
    #[arg(long)]
    foreground: bool,
}

#[derive(Subcommand)]
enum MountCmd {
    /// A deterministic mock arch (SP1b mounts real engines).
    Mock {
        name: String,
        /// Context ceiling in tokens.
        #[arg(long, default_value_t = 4096)]
        ctx: u32,
    },
}

#[derive(Subcommand)]
enum TaskCmd {
    /// Submit a task: plan, draft, then optionally wait for a human and release.
    Submit {
        #[arg(long)]
        goal: String,
        /// The kind of artefact the draft produces (its file extension on release).
        #[arg(long, default_value = "note")]
        artefact: String,
        #[arg(long, value_name = "ARCH")]
        plan: String,
        #[arg(long, value_name = "ARCH")]
        draft: String,
        /// Wait for a human approval of the drafted artefact.
        #[arg(long)]
        approve: bool,
        /// Release the artefacts into this subpath of the kernel's export root.
        #[arg(long, value_name = "DIR")]
        release: Option<String>,
    },
    /// Run the next step, or with --all until the task waits or finishes.
    Step {
        task_id: String,
        #[arg(long)]
        all: bool,
    },
    /// One task in full, with where its release steps write.
    Show { task_id: String },
}

#[derive(Subcommand)]
enum LedgerCmd {
    /// Verify the hash chain.
    Verify,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        // One line, no backtrace and no panic: a refused syscall is an answer,
        // not a crash. Usage errors exit 2, and clap has already printed them.
        eprintln!("vk: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match &cli.cmd {
        Cmd::Boot(args) => boot(cli, &rt, args),
        _ => rt.block_on(call(cli)),
    }
}

/// `$VK_ENDPOINT` or `--endpoint`, when either says where the daemon is.
fn endpoint_override(cli: &Cli) -> Option<String> {
    cli.endpoint
        .clone()
        .or_else(|| std::env::var("VK_ENDPOINT").ok())
}

fn endpoint(cli: &Cli) -> Endpoint {
    endpoint_override(cli)
        .map(Endpoint)
        .unwrap_or_else(default_endpoint)
}

fn show(cli: &Cli, v: Value, render: fn(&Value) -> String) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{}", render(&v));
    }
    Ok(())
}

fn field(v: &Value, name: &str) -> Result<String> {
    v[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no {name} in the daemon's answer: {v}"))
}

async fn call(cli: &Cli) -> Result<()> {
    let ep = endpoint(cli);
    let c = Client::connect(&ep)
        .await
        .with_context(|| format!("no daemon on {} (start one with `vk boot`)", ep.0))?;
    match &cli.cmd {
        // Dispatched before the client connects: it starts a daemon rather
        // than calling one.
        Cmd::Boot(_) => unreachable!("boot does not go through the client"),
        Cmd::Status => show(
            cli,
            c.call("boot.info", json!({}), None).await?,
            render::status,
        ),
        Cmd::Ls { path } => show(
            cli,
            c.call("ns.ls", json!({ "path": path }), None).await?,
            render::ls,
        ),
        Cmd::Ps => show(cli, c.call("task.ls", json!({}), None).await?, render::ps),
        Cmd::Top => show(cli, c.call("top", json!({}), None).await?, render::top),
        Cmd::Mount {
            what: MountCmd::Mock { name, ctx },
        } => show(
            cli,
            c.call(
                "arch.mount_mock",
                json!({ "name": name, "context_ceiling": ctx }),
                None,
            )
            .await?,
            render::mounted,
        ),
        Cmd::Umount { arch_id } => show(
            cli,
            c.call("arch.unmount", json!({ "arch_id": arch_id }), None)
                .await?,
            render::ok,
        ),
        Cmd::Task { what } => task(cli, &c, what).await,
        Cmd::Stop { scope } => {
            let proof = presence(&c).await?;
            show(
                cli,
                c.call("stop", json!({ "scope": scope }), Some(proof))
                    .await?,
                render::stopped,
            )
        }
        Cmd::Resume { stop_id } => {
            let proof = presence(&c).await?;
            show(
                cli,
                c.call("resume", json!({ "stop_id": stop_id }), Some(proof))
                    .await?,
                render::ok,
            )
        }
        Cmd::Approve { task_id } => approve(cli, &c, task_id).await,
        Cmd::Dmesg { n } => show(
            cli,
            c.call("ledger.tail", json!({ "n": n }), None).await?,
            render::dmesg,
        ),
        Cmd::Ledger {
            what: LedgerCmd::Verify,
        } => show(
            cli,
            c.call("ledger.verify", json!({}), None).await?,
            render::verified,
        ),
    }
}

async fn task(cli: &Cli, c: &Client, what: &TaskCmd) -> Result<()> {
    match what {
        TaskCmd::Submit {
            goal,
            artefact,
            plan,
            draft,
            approve,
            release,
        } => {
            let mut steps = vec![
                json!({ "kind": "plan", "arch_id": plan }),
                json!({ "kind": "draft", "arch_id": draft }),
            ];
            if *approve {
                steps.push(json!({ "kind": "approve" }));
            }
            // A release destination is a subpath of the kernel's export root,
            // never a path of the caller's choosing: `vk task show` prints
            // where it resolved to.
            if let Some(dir) = release {
                steps.push(json!({ "kind": "release", "to_dir": dir }));
            }
            let created = c
                .call(
                    "task.create",
                    json!({ "goal": goal, "artefact_type": artefact, "steps": steps }),
                    None,
                )
                .await?;
            show(cli, created, render::task)
        }
        TaskCmd::Step { task_id, all } => {
            let step = || c.call("task.step", json!({ "task_id": task_id }), None);
            let mut t = step().await?;
            if *all {
                let mut runs = 1;
                while !settled(&t) {
                    if runs >= MAX_STEPS {
                        return Err(anyhow!(
                            "task {task_id} had not settled after {MAX_STEPS} steps"
                        ));
                    }
                    t = step().await?;
                    runs += 1;
                }
            }
            show(cli, t, render::task)
        }
        TaskCmd::Show { task_id } => {
            let mut t = c
                .call("task.show", json!({ "task_id": task_id }), None)
                .await?;
            let root = field(&c.call("boot.info", json!({}), None).await?, "export_root")?;
            let paths = render::release_paths(&t, &root);
            if let Some(o) = t.as_object_mut() {
                o.insert("release_paths".into(), json!(paths));
            }
            show(cli, t, render::task)
        }
    }
}

/// A task that will not move again without something else happening: a human,
/// a fix, or a resume.
fn settled(t: &Value) -> bool {
    matches!(
        t["status"].as_str(),
        Some("waiting_human") | Some("done") | Some("failed") | Some("stopped")
    )
}

/// This node's own device key, which in SP1a is the human's key: from
/// `$VK_NODE_KEY_FILE` if it names one, else the OS keyring. The daemon says
/// which node it is, so the key is the one enrolled as `node:<node_id>`.
async fn node_device(c: &Client) -> Result<NodeDevice> {
    let node_id = field(&c.call("boot.info", json!({}), None).await?, "node_id")?;
    let source = match std::env::var_os("VK_NODE_KEY_FILE") {
        Some(path) => KeySource::File(PathBuf::from(path)),
        None => KeySource::Keyring,
    };
    NodeDevice::load_or_create(source, &node_id).context("this node's device key")
}

/// A nonce this daemon issued: single use, and spent by the request that
/// carries it.
async fn challenge(c: &Client) -> Result<String> {
    field(
        &c.call("presence.challenge", json!({}), None).await?,
        "nonce",
    )
}

/// Proof that the device key was present for the next request.
async fn presence(c: &Client) -> Result<PresenceProof> {
    let device = node_device(c).await?;
    Ok(PresenceProof::sign(&device, &challenge(c).await?))
}

/// The approval ceremony: learn what the scheduler is waiting to have
/// approved, then sign it.
///
/// One challenge carries both signatures. They are in different domains — a
/// presence proof signs `sha256("presence|<nonce>")`, an approval signs
/// `H(resource|action|nonce|expiry)` — so neither can be replayed as the
/// other, and the approval is bound to a nonce this daemon issued a moment
/// ago rather than to one the client made up.
async fn approve(cli: &Cli, c: &Client, task_id: &str) -> Result<()> {
    let device = node_device(c).await?;
    let subject = field(
        &c.call("task.subject", json!({ "task_id": task_id }), None)
            .await?,
        "subject_hash",
    )?;
    let nonce = challenge(c).await?;
    let challenge = Challenge {
        resource: format!("task:{task_id}"),
        action_digest: subject.clone(),
        nonce: nonce.clone(),
        expires_at_ms: vk_kernel::now_ms() + APPROVAL_TTL_MS,
    };
    let approval = Approval {
        subject_hash: subject.clone(),
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: device.device_id(),
        },
        signature_hex: Some(hex::encode(device.sign(&challenge.digest()))),
        challenge: Some(challenge),
    };
    let proof = PresenceProof::sign(&device, &nonce);
    let mut answer = c
        .call("approve", json!({ "approval": approval }), Some(proof))
        .await?;
    // What was approved, named back to the person who just approved it — and
    // what has to happen next, because recording an approval does not run the
    // step that was waiting for it.
    if let Some(o) = answer.as_object_mut() {
        o.insert("task_id".into(), json!(task_id));
        o.insert("subject_hash".into(), json!(subject));
    }
    show(cli, answer, render::approved)
}

/// The `boot.info` of the daemon serving this endpoint, if one is. It carries
/// the state directory, which is what tells a second `vk boot` whether the
/// daemon already there is the one the caller asked for.
async fn serving(ep: &Endpoint) -> Option<Value> {
    let c = Client::connect(ep).await.ok()?;
    c.call("boot.info", json!({}), None).await.ok()
}

/// Two paths naming the same directory, canonicalised where the filesystem can
/// say so (`C:\X` against `c:\x`, a substituted drive, a symlinked `/tmp`).
fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// The node key file `vk boot` hands to the daemon: the flag, else the same
/// environment variable this shell signs with, so both ends use one key.
fn node_key_file(a: &BootArgs) -> Option<PathBuf> {
    a.node_key_file
        .clone()
        .or_else(|| std::env::var_os("VK_NODE_KEY_FILE").map(PathBuf::from))
}

/// Windows: take the inherit flag off *our own* standard handles before
/// starting the daemon.
///
/// `CreateProcess` hands a child every inheritable handle in the process, not
/// only the three it is given — and `vk`'s own stdout is an inheritable pipe
/// whenever something captured it, which is exactly what `out=$(vk boot
/// --json)` does. The daemon would hold that pipe for its whole life and the
/// capture would never see EOF, however carefully the child's own stdio was
/// redirected. `DETACHED_PROCESS` does not cover this; nothing but clearing
/// the flag does. (On Unix the redirect is enough: the child's `dup2` replaces
/// the inherited descriptor, and everything else is close-on-exec.)
#[cfg(windows)]
fn stop_inheriting_our_stdio() {
    use std::os::windows::io::AsRawHandle;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    extern "system" {
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }
    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        // A handle that cannot be told this (a console, a closed stream) was
        // not one a child could hold a pipe open with either.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
}

/// Cut the daemon loose from this terminal.
///
/// Inheriting the console would undo the whole point of starting it in the
/// background: on Windows a Ctrl+C or a closed window sends `CTRL_C_EVENT` /
/// `CTRL_CLOSE_EVENT` to everything attached to that console, and on Unix the
/// terminal's foreground group gets `SIGINT` and its session `SIGHUP` — so the
/// daemon, and every task in flight, would die with the shell that started it.
/// Inheriting stdout has a second cost: `out=$(vk boot --json)` would block for
/// the daemon's whole life waiting for a pipe the daemon still holds.
///
/// Its output is not lost, it is appended to `<state_dir>/vkd.log`.
fn detach(cmd: &mut Command, state_dir: &Path) -> Result<()> {
    let path = state_dir.join("vkd.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console to inherit,
        // and no console signals from this one.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
        stop_inheriting_our_stdio();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: outside the terminal's foreground group.
        cmd.process_group(0);
    }
    Ok(())
}

/// Start `vkd`, which lives next to this binary, and hand it the state
/// directory and keys this call named.
///
/// `--auto-enroll-node` goes with it: in SP1a the machine a person is sitting
/// at is the device that speaks for them, and without it this shell could
/// never stop, resume or approve anything.
fn boot(cli: &Cli, rt: &tokio::runtime::Runtime, a: &BootArgs) -> Result<()> {
    let exe =
        std::env::current_exe()?.with_file_name(format!("vkd{}", std::env::consts::EXE_SUFFIX));
    anyhow::ensure!(exe.exists(), "no vkd next to vk at {}", exe.display());
    // Resolved here, the way `vkd` itself would resolve it (and refusing a
    // synced folder here rather than in a daemon that is already detached), so
    // that it can be compared with what a daemon already on this endpoint
    // serves.
    let state_dir = vk_store::paths::state_dir(a.state_dir.clone())?;
    let ep = endpoint(cli);
    if let Some(info) = rt.block_on(serving(&ep)) {
        let served = field(&info, "state_dir")?;
        // One endpoint, one store. Reporting "already serving" for a daemon on
        // a *different* state directory would send every later `vk task
        // submit`, `vk approve` and `vk ledger verify` to a store the caller
        // did not ask for, with `vk status` the only clue.
        anyhow::ensure!(
            same_dir(Path::new(&served), &state_dir),
            "a daemon on {} is serving {served}, not {}; stop it, or pick another endpoint \
             with --endpoint",
            ep.0,
            state_dir.display()
        );
        return show(
            cli,
            json!({
                "endpoint": ep.0,
                "state_dir": state_dir.display().to_string(),
                "already_running": true,
            }),
            render::booted,
        );
    }
    let mut cmd = Command::new(&exe);
    cmd.arg("--auto-enroll-node")
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--node-id", &a.node_id])
        .args(["--endpoint", &ep.0]);
    if let Some(key) = &a.master_key_file {
        cmd.arg("--master-key-file").arg(key);
    }
    if let Some(key) = node_key_file(a) {
        cmd.arg("--node-key-file").arg(key);
    }
    if a.foreground {
        let status = cmd
            .status()
            .with_context(|| format!("run {}", exe.display()))?;
        anyhow::ensure!(status.success(), "vkd exited with {status}");
        return Ok(());
    }
    detach(&mut cmd, &state_dir)?;
    let mut child = cmd
        .spawn()
        .with_context(|| format!("start {}", exe.display()))?;
    let pid = child.id();
    // Started is not serving: the daemon is up when it answers.
    let start = Instant::now();
    let ready = rt.block_on(async {
        loop {
            if serving(&ep).await.is_some() {
                return true;
            }
            if start.elapsed() > BOOT_TIMEOUT {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    if !ready {
        // It is ours and nobody else knows its pid, so it does not outlive the
        // call that started it: otherwise it would sit on the endpoint and
        // every later `vk boot` would refuse, blaming a daemon the user never
        // sees.
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!(
            "vkd (pid {pid}) did not answer on {} within {BOOT_TIMEOUT:?}; see {}",
            ep.0,
            state_dir.join("vkd.log").display()
        );
    }
    show(
        cli,
        json!({
            "pid": pid,
            "endpoint": ep.0,
            "state_dir": state_dir.display().to_string(),
        }),
        render::booted,
    )
}
