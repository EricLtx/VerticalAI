//! `vk`: the VerticalAI command-line client — the shell of this OS.
//!
//! Every verb is one syscall over the local endpoint, printed as a table or,
//! with `--json`, as the syscall's own answer. The three human verbs (`stop`,
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
use std::process::Command;
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
    Boot {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Run the daemon in this terminal instead of in the background.
        #[arg(long)]
        foreground: bool,
    },
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
        Cmd::Boot {
            state_dir,
            foreground,
        } => boot(cli, &rt, state_dir.as_deref(), *foreground),
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
        // Handled before the runtime: it starts a daemon rather than calling one.
        Cmd::Boot { .. } => Ok(()),
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
        subject_hash: subject,
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: device.device_id(),
        },
        signature_hex: Some(hex::encode(device.sign(&challenge.digest()))),
        challenge: Some(challenge),
    };
    let proof = PresenceProof::sign(&device, &nonce);
    show(
        cli,
        c.call("approve", json!({ "approval": approval }), Some(proof))
            .await?,
        render::ok,
    )
}

/// Whether a daemon is serving on this endpoint.
async fn answers(ep: &Endpoint) -> bool {
    match Client::connect(ep).await {
        Ok(c) => c.call("boot.info", json!({}), None).await.is_ok(),
        Err(_) => false,
    }
}

/// Start `vkd`, which lives next to this binary.
///
/// `--auto-enroll-node` goes with it: in SP1a the machine a person is sitting
/// at is the device that speaks for them, and without it this shell could
/// never stop, resume or approve anything.
fn boot(
    cli: &Cli,
    rt: &tokio::runtime::Runtime,
    state_dir: Option<&Path>,
    foreground: bool,
) -> Result<()> {
    let exe =
        std::env::current_exe()?.with_file_name(format!("vkd{}", std::env::consts::EXE_SUFFIX));
    anyhow::ensure!(exe.exists(), "no vkd next to vk at {}", exe.display());
    let ep = endpoint(cli);
    // One daemon per endpoint: a second would fail to bind and die, and this
    // would then report the *first* one's readiness as the second one's pid.
    if rt.block_on(answers(&ep)) {
        return show(
            cli,
            json!({ "endpoint": ep.0, "already_running": true }),
            render::booted,
        );
    }
    let mut cmd = Command::new(&exe);
    cmd.arg("--auto-enroll-node");
    if let Some(dir) = state_dir {
        cmd.arg("--state-dir").arg(dir);
    }
    if let Some(ep) = endpoint_override(cli) {
        cmd.args(["--endpoint", &ep]);
    }
    if let Some(key) = std::env::var_os("VK_NODE_KEY_FILE") {
        cmd.arg("--node-key-file").arg(key);
    }
    if foreground {
        let status = cmd
            .status()
            .with_context(|| format!("run {}", exe.display()))?;
        anyhow::ensure!(status.success(), "vkd exited with {status}");
        return Ok(());
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("start {}", exe.display()))?;
    // Started is not serving: the daemon is up when it answers.
    let start = Instant::now();
    rt.block_on(async {
        loop {
            if answers(&ep).await {
                return Ok(());
            }
            if start.elapsed() > BOOT_TIMEOUT {
                return Err(anyhow!(
                    "vkd did not answer on {} within {BOOT_TIMEOUT:?}",
                    ep.0
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })?;
    show(
        cli,
        json!({ "pid": child.id(), "endpoint": ep.0 }),
        render::booted,
    )
}
