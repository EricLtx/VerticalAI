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
mod man;
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
use zeroize::Zeroizing;

/// `vkd --web-port`'s default, handed on by `vk boot`. A literal rather than
/// `vk_web::DEFAULT_PORT` so this shell does not link the verifier.
const DEFAULT_WEB_PORT: u16 = 7734;
/// How often `vk approve --passkey` asks whether the approval has landed.
const APPROVAL_POLL: Duration = Duration::from_millis(500);
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
    /// Start vkd over a state directory and wait until it answers.
    Boot(BootArgs),
    /// What this node is, and what its boot sequence found.
    Status,
    /// List a namespace path.
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    /// Tasks and how far each has got.
    Ps,
    /// Per-arch calls and tokens, stopped scopes, liveness.
    Top {
        /// Also list every call behind those totals: which arch, which task's
        /// which step, what came back and what it cost.
        #[arg(long)]
        calls: bool,
    },
    /// Mount an arch.
    Mount {
        #[command(subcommand)]
        what: MountCmd,
    },
    /// Unmount an arch by id.
    Umount { arch_id: String },
    /// One arch in full: its manifest, its identity tuple and its clearance.
    Arch {
        #[command(subcommand)]
        what: ArchCmd,
    },
    /// Submit, step and inspect tasks.
    Task {
        #[command(subcommand)]
        what: TaskCmd,
    },
    /// Run a confined agent harness (Claude Code) over a task.
    Harness {
        #[command(subcommand)]
        what: HarnessCmd,
    },
    /// STOP a scope. Human: signed with this node's device key.
    Stop {
        #[arg(default_value = "node")]
        scope: String,
    },
    /// Lift a STOP by its id. Human.
    Resume { stop_id: String },
    /// Approve a task's latest artefact. Human: signed with this node's
    /// device key, or — with --passkey — with a passkey in the browser.
    Approve {
        task_id: String,
        /// Approve with an enrolled passkey (Windows Hello, a phone): prints
        /// the approval page's link, then waits for the approval to land.
        #[arg(long)]
        passkey: bool,
        /// Open the link in the default browser as well as printing it.
        #[arg(long, requires = "passkey")]
        open: bool,
        /// How long to wait for the passkey approval, in seconds.
        #[arg(long, default_value_t = 300, requires = "passkey")]
        timeout: u64,
    },
    /// Secrets this node's daemon needs, in the OS keyring. Needs no daemon.
    Secret {
        #[command(subcommand)]
        what: SecretCmd,
    },
    /// Passkeys: the human's own device, enrolled through the browser.
    Passkey {
        #[command(subcommand)]
        what: PasskeyCmd,
    },
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
    /// Verify the whole store: the chain, the recorded head, every blob
    /// against its own address, every wrapped key, and the mounts.
    ///
    /// `vk ledger verify` answers one question — does the chain recompute.
    /// This answers whether the state this node says it has is the state it
    /// has. Exits non-zero if any tier fails, so a script can gate on it.
    ///
    /// A human act, like `stop` and `approve`: it reads every blob on the
    /// node, so it is signed with this node's device key.
    Fsck {
        /// Re-record the ledger head from the record as it is on disk.
        ///
        /// **The recovery path after a legitimate restore**, and nothing
        /// else. A restored backup is a shorter record than the one this
        /// store last wrote, which is the same shape as a tail somebody cut
        /// — the node cannot tell them apart and refuses to serve on either.
        /// This is a human saying which it was, and it goes on the record:
        /// the next `boot` event's report names both heads.
        ///
        /// Needs `--force` and the word `rebase` typed at the prompt.
        #[arg(long, requires = "force")]
        rebase_head: bool,
        /// Required beside `--rebase-head`. On its own it does nothing.
        #[arg(long)]
        force: bool,
        /// Take the typed confirmation as given, for scripts. The ceremony
        /// is still a presence proof by this node's device key.
        #[arg(long, requires = "rebase_head")]
        yes: bool,
    },
    /// The contracts this kernel speaks: no name lists them, a name renders
    /// one. Needs no daemon — the schemas are in this binary.
    Man { name: Option<String> },
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
    /// Start the daemon even though the ledger chain does not verify.
    #[arg(long)]
    force: bool,
    /// Loopback port for the passkey pages (`0`: one the OS picks).
    #[arg(long, default_value_t = DEFAULT_WEB_PORT)]
    web_port: u16,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Put a secret in this account's keyring, under service `vk`.
    ///
    /// `vk secret set anthropic` is the one an API arch needs: the daemon
    /// reads it at `vk mount anthropic` and again whenever it re-creates that
    /// arch at boot. The value is prompted for without echo and is never
    /// printed, never logged and never written to a file — it does not go
    /// into the mount spec either, which is stored in the clear and refuses
    /// anything credential-shaped.
    ///
    /// The keyring is **this account's**. A daemon running under the Windows
    /// service account (`vkd --as-service`) reads that account's keyring, not
    /// this one, and is given its key with `vkd --anthropic-key-file` or by
    /// running this verb as that account.
    Set {
        /// What it is called: `anthropic` for the first-party API arch.
        name: String,
        /// Read the value as one line on stdin instead of prompting, for
        /// scripts. Still never echoed and never printed back.
        #[arg(long)]
        stdin: bool,
        /// The keyring service. `vk` for everything this kernel reads; the
        /// flag exists so a test can use a throwaway name.
        #[arg(long, default_value = "vk")]
        service: String,
    },
}

#[derive(Subcommand)]
enum PasskeyCmd {
    /// Print the enrolment page's link (and open it with --open): the
    /// browser asks Windows Hello, or a phone, to make the passkey.
    Enroll {
        /// Open the link in the default browser as well as printing it.
        #[arg(long)]
        open: bool,
    },
    /// The passkeys enrolled on this node.
    Ls,
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
    /// Claude, through the installed Claude Code and this machine's own
    /// subscription: two arches, one to draft with and one to judge with.
    ///
    /// A cloud arch, so its clearance stops at Business and it refuses
    /// third-party data; see `contracts/tcb.md`. Customer nodes use API arches
    /// instead — a subscription is a person's, not a product's.
    ClaudeCode {
        #[arg(long, default_value = "claude-sonnet-5")]
        draft_model: String,
        #[arg(long, default_value = "claude-opus-5")]
        judge_model: String,
        /// The `claude` binary, if it is not on the daemon's PATH.
        #[arg(long, default_value = "claude")]
        bin: String,
        /// How long one call may take, in seconds.
        #[arg(long, default_value_t = 180)]
        timeout: u32,
    },
    /// Claude through the **Anthropic API**, on a key in this account's
    /// keyring (`vk secret set anthropic`). The arch a customer node mounts.
    ///
    /// A cloud arch in the United States: `jurisdiction: US`, 30-day
    /// retention, clearance capped at Business with third-party data refused,
    /// and metered — unlike `vk mount claude-code`, every call is billed, so
    /// the manifest carries a per-token price and `vk top` shows what the
    /// calls cost. For a register that may not leave the Union, mount
    /// `bedrock` instead.
    Anthropic {
        /// The model, as the API names it (`claude-opus-5`,
        /// `claude-sonnet-5`, `claude-haiku-4-5`).
        #[arg(long, default_value = "claude-opus-5")]
        model: String,
        /// Context ceiling in tokens. `0` is the model's documented window,
        /// which is what nearly every mount wants.
        #[arg(long, default_value_t = 0)]
        ctx: u32,
        /// The longest answer one call may produce. Capped at 4096.
        #[arg(long, default_value_t = 4096)]
        max_tokens: u32,
        /// How long one call may take, in seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u32,
    },
    /// Claude **hosted in the EU**, through Amazon Bedrock's `Converse` API
    /// in Frankfurt or Ireland, on this machine's AWS credentials.
    ///
    /// The EU jurisdiction: `jurisdiction: EU` and no retention window,
    /// because AWS keeps neither the inputs nor the outputs. Needs a build
    /// with the `bedrock` cargo feature; a daemon without it refuses the
    /// mount and says so.
    Bedrock {
        /// Which European region. Only these two: the manifest's
        /// `jurisdiction: EU` is the region, so a mount elsewhere is refused
        /// rather than mislabelled.
        #[arg(long, default_value = "eu-central-1",
              value_parser = ["eu-central-1", "eu-west-1"])]
        region: String,
        /// A model name (`claude-opus-5`), which is resolved to the region's
        /// cross-region inference profile, or a full Bedrock model id or
        /// profile ARN, which is used exactly as given.
        #[arg(long, default_value = "claude-opus-5")]
        model: String,
        /// Context ceiling in tokens. `0` is the model's documented window.
        #[arg(long, default_value_t = 0)]
        ctx: u32,
        /// The longest answer one call may produce. Capped at 4096.
        #[arg(long, default_value_t = 4096)]
        max_tokens: u32,
    },
    /// A Gemma-class model on this machine, served by Ollama in a container
    /// this kernel starts, caps and can stop.
    ///
    /// The governed arch: the inference is a process the kernel contains, on
    /// loopback, under a memory and CPU cap, so nothing about the call leaves
    /// this node. Its context ceiling is half the window asked for — Ollama
    /// silently truncates past that (spike 1a) and this node refuses instead.
    Ollama {
        /// The model tag, as Ollama names it (`gemma4:e4b`, `gemma3:1b`).
        #[arg(long)]
        model: String,
        /// Run it in a container this kernel starts and caps. The default.
        #[arg(long, conflicts_with = "external")]
        container: bool,
        /// Use an Ollama already serving at this URL instead. Not governed:
        /// this node did not start that process and cannot cap it.
        #[arg(long, value_name = "URL")]
        external: Option<String>,
        /// Context window asked of the server. Half of it is usable.
        #[arg(long, default_value_t = 8192)]
        ctx: u32,
        /// The longest answer one call may produce. Always sent: a local model
        /// with no bound runs until it decides to stop.
        #[arg(long, default_value_t = 2048)]
        max_tokens: u32,
        /// Replace an existing container that is not the one asked for. Stops
        /// it, removes it and makes it again under these caps; the volume, and
        /// the models in it, are kept.
        #[arg(long, conflicts_with = "external")]
        recreate: bool,
        // The three container flags are refused beside `--external`, rather
        // than ignored: a cap named for a server this node does not start is
        // a cap that would never be applied, and silently dropping it is how
        // somebody ends up believing an ungoverned arch is capped.
        /// Memory cap for the container, in Docker's syntax.
        #[arg(long, default_value = "12g", conflicts_with = "external")]
        memory: String,
        /// CPU cap for the container, in Docker's syntax.
        #[arg(long, default_value = "6", conflicts_with = "external")]
        cpus: String,
        /// The Ollama image. Pinned: the version is in the arch identity.
        #[arg(
            long,
            default_value = "ollama/ollama:0.33.3",
            conflicts_with = "external"
        )]
        image: String,
        /// Sampling seed. Part of the arch identity.
        #[arg(long, default_value_t = 7)]
        seed: u64,
    },
}

#[derive(Subcommand)]
enum TaskCmd {
    /// Submit a task: plan, then draft (or a harness), then optionally judge,
    /// wait for a human and release.
    Submit {
        #[arg(long)]
        goal: String,
        /// The kind of artefact the draft produces (its file extension on release).
        #[arg(long, default_value = "note")]
        artefact: String,
        #[arg(long, value_name = "ARCH")]
        plan: String,
        /// The arch that drafts the artefact. Either this or `--harness`: a
        /// task needs exactly one step that produces what is approved.
        #[arg(long, value_name = "ARCH", required_unless_present = "harness")]
        draft: Option<String>,
        /// Draft with a confined agent harness instead of an arch, by name
        /// (`claude-code`). The step is run by `vk harness run <TASK>`, not by
        /// `vk task step`, which says so when it reaches one.
        #[arg(long, value_name = "NAME", conflicts_with = "draft")]
        harness: Option<String>,
        /// Have this arch judge the draft. Its verdict is raised into the
        /// register's open questions, where a later step — or a reader — sees
        /// it beside the artefact it is about.
        #[arg(long, value_name = "ARCH")]
        judge: Option<String>,
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
enum HarnessCmd {
    /// Launch the confined harness over a task's harness step.
    ///
    /// Give an existing TASK whose next step is a harness step, or `--goal` to
    /// create a task (harness step, then a human approval) and run it.
    /// `--dry-run` prints the launch line, the `mcp.json` (token redacted) and
    /// the permission fence, and runs nothing. Which binary, model and timeout
    /// the harness runs with is the daemon's to set (`vkd --harness-bin`,
    /// `--harness-model`, `--harness-timeout-secs`), never this verb's.
    Run {
        /// The task to run. Omit it and pass `--goal` to create one.
        task: Option<String>,
        /// Create a fresh task with this goal — a harness step then an
        /// approval — and run its harness step.
        #[arg(long)]
        goal: Option<String>,
        /// Which harness. Only `claude-code` in SP1b.
        #[arg(long, default_value = "claude-code")]
        name: String,
        /// Print the launch line, `mcp.json` and `settings.json` and exit,
        /// without running.
        #[arg(long)]
        dry_run: bool,
        /// Keep the workspace after the run instead of removing it (it is
        /// swept at the daemon's next boot regardless).
        #[arg(long)]
        keep: bool,
    },
}

#[derive(Subcommand)]
enum ArchCmd {
    /// One arch in full, by id: what it is, whether it would answer a prompt,
    /// the identity tuple the arch id hashes, the clearance it may be handed,
    /// and what the next boot would make it from.
    Show { arch_id: String },
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
        Cmd::Man { name } => man(cli, name.as_deref()),
        // The keyring is this account's, not the daemon's to reach into: the
        // shell writes it directly and no syscall is involved.
        Cmd::Secret { what } => secret(cli, what),
        _ => rt.block_on(call(cli)),
    }
}

/// `vk man`, which answers out of the binary: a contract is readable on a
/// machine whose daemon will not start, which is exactly when somebody needs
/// to read one.
fn man(cli: &Cli, name: Option<&str>) -> Result<()> {
    match name {
        None if cli.json => println!("{}", serde_json::to_string_pretty(&man::names())?),
        None => println!("{}", man::list()),
        // `--json` is the schema itself, byte for byte: what a generator or a
        // validator wants, where the rendered page is what a person wants.
        Some(n) if cli.json => print!("{}", man::schema(n).ok_or_else(|| man::unknown(n))?),
        Some(n) => println!("{}", man::render(n)?),
    }
    Ok(())
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

/// `vk secret set NAME` — the one verb that writes a credential, and the only
/// place in this shell that handles one.
///
/// Three rules, all of them testable by reading this function: the value is
/// never echoed (the terminal's echo is off while it is typed), never printed
/// (what is reported back is the name, never the value) and never written
/// anywhere but the keyring. An empty value is refused rather than stored,
/// because an empty entry is worse than a missing one: `vk mount anthropic`
/// would find something and fail at the far end instead of here.
fn secret(cli: &Cli, what: &SecretCmd) -> Result<()> {
    let SecretCmd::Set {
        name,
        stdin,
        service,
    } = what;
    let name = name.trim();
    if name.is_empty() || name.split_whitespace().count() != 1 {
        return Err(anyhow!(
            "a secret's name is one word with no spaces in it; `anthropic` is the one an \
             API arch reads"
        ));
    }
    // Wrapped the moment it exists and never copied out of the wrapper: this
    // is the one process on this machine that sees the key as a human typed
    // it, and a plain `String` would leave it in freed heap (fix round 1,
    // Minor 5).
    let value: Zeroizing<String> = Zeroizing::new(if *stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .context("read the secret from stdin")?;
        line.to_string()
    } else {
        rpassword::prompt_password(format!("{service}/{name}: "))
            .context("read the secret from the terminal")?
    });
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!(
            "nothing was entered; the keyring was not touched. An empty entry is worse \
             than a missing one: the mount would find it and fail at the far end"
        ));
    }
    keyring::Entry::new(service, name)
        .and_then(|e| e.set_password(value))
        .with_context(|| format!("cannot write {service}/{name} to this account's keyring"))?;
    // The name, never the value.
    show(
        cli,
        json!({ "service": service, "name": name }),
        render::secret_set,
    )
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
        // Dispatched before the client connects: one starts a daemon rather
        // than calling one, the other needs none at all.
        Cmd::Boot(_) | Cmd::Man { .. } | Cmd::Secret { .. } => unreachable!("not a syscall"),
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
        Cmd::Top { calls } => show(
            cli,
            c.call("top", json!({ "calls": calls }), None).await?,
            render::top,
        ),
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
        // Two mounts, one verb: a role needs a model behind it, and one call
        // that leaves the node with a draft arch and no judge arch would be a
        // node whose tasks stall at their second step.
        Cmd::Mount {
            what:
                MountCmd::ClaudeCode {
                    draft_model,
                    judge_model,
                    bin,
                    timeout,
                },
        } => {
            // A proof per call: a nonce is spent by the request that shows
            // it, so the second mount asks for one of its own (fix round 1,
            // Critical 1 — a cloud arch is a human act).
            // `&Client` rather than the client, so the closure stays `Copy`
            // and can be called for each of the two roles.
            let client = &c;
            let mount = move |model: String| async move {
                let proof = presence(client).await?;
                client
                    .call(
                        "arch.mount",
                        json!({
                            "kind": "claude-code",
                            "config": {
                                "binary": bin,
                                "model": model,
                                "timeout_secs": timeout,
                            },
                        }),
                        Some(proof),
                    )
                    .await
            };
            let draft = mount(draft_model.clone()).await?;
            let judge = match mount(judge_model.clone()).await {
                Ok(v) => v,
                // All or nothing. A verb whose whole reason to exist is that a
                // node needs both arches must not leave one behind when the
                // second refuses — the unmount is best effort, and its own
                // failure is reported beside the one that caused it.
                Err(why) => {
                    let id = draft["arch_id"].as_str().unwrap_or_default();
                    let rolled_back = c
                        .call("arch.unmount", json!({ "arch_id": id }), None)
                        .await
                        .is_ok();
                    return Err(if rolled_back {
                        why.context(format!(
                            "mounting {judge_model} failed; unmounted {id} again"
                        ))
                    } else {
                        why.context(format!(
                            "mounting {judge_model} failed, and {id} could not be unmounted; \
                             remove it with: vk umount {id}"
                        ))
                    });
                }
            };
            show(
                cli,
                json!({ "draft": draft, "judge": judge }),
                render::mounted_roles,
            )
        }
        // One mount, one arch, and no key on the wire: the daemon reads it
        // out of its own keyring, so what travels is the model and the
        // numbers (Task 2b). It does travel with a **presence proof**, like
        // `stop` and `approve` do: mounting a cloud arch authorises this
        // node's registers to leave the machine for a third party, and it
        // persists across every restart, so the daemon refuses it from a bare
        // machine principal (fix round 1, Critical 1).
        Cmd::Mount {
            what:
                MountCmd::Anthropic {
                    model,
                    ctx,
                    max_tokens,
                    timeout,
                },
        } => {
            let proof = presence(&c).await?;
            show(
                cli,
                c.call(
                    "arch.mount",
                    json!({
                        "kind": "anthropic",
                        "config": {
                            "model": model,
                            "context_ceiling": ctx,
                            "max_tokens": max_tokens,
                            "timeout_secs": timeout,
                        },
                    }),
                    Some(proof),
                )
                .await?,
                render::mounted_arch,
            )
        }
        Cmd::Mount {
            what:
                MountCmd::Bedrock {
                    region,
                    model,
                    ctx,
                    max_tokens,
                },
        } => {
            let proof = presence(&c).await?;
            show(
                cli,
                c.call(
                    "arch.mount",
                    json!({
                        "kind": "bedrock",
                        "config": {
                            "region": region,
                            "model": model,
                            "context_ceiling": ctx,
                            "max_tokens": max_tokens,
                        },
                    }),
                    Some(proof),
                )
                .await?,
                render::mounted_arch,
            )
        }
        // One mount, one arch: a local model is one engine, and which role it
        // is given is the task's to say.
        Cmd::Mount {
            what:
                MountCmd::Ollama {
                    model,
                    container: _,
                    external,
                    ctx,
                    max_tokens,
                    recreate,
                    memory,
                    cpus,
                    image,
                    seed,
                },
        } => {
            // `--container` is the default, so it needs no branch of its own;
            // naming a server is what switches the mode, and the daemon reads
            // exactly that: a `base_url` means external, its absence means the
            // container this node governs.
            let mut config = json!({
                "model": model,
                "num_ctx": ctx,
                "max_tokens": max_tokens,
                "seed": seed,
            });
            match external {
                Some(url) => config["base_url"] = json!(url),
                None => {
                    config["image"] = json!(image);
                    config["memory"] = json!(memory);
                    config["cpus"] = json!(cpus);
                    config["recreate"] = json!(recreate);
                }
            }
            show(
                cli,
                c.call(
                    "arch.mount",
                    json!({ "kind": "ollama", "config": config }),
                    None,
                )
                .await?,
                render::mounted_arch,
            )
        }
        Cmd::Umount { arch_id } => show(
            cli,
            c.call("arch.unmount", json!({ "arch_id": arch_id }), None)
                .await?,
            render::unmounted,
        ),
        Cmd::Arch {
            what: ArchCmd::Show { arch_id },
        } => show(
            cli,
            c.call("arch.show", json!({ "arch_id": arch_id }), None)
                .await?,
            render::arch_show,
        ),
        Cmd::Task { what } => task(cli, &c, what).await,
        Cmd::Harness { what } => harness(cli, &c, what).await,
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
        Cmd::Approve {
            task_id,
            passkey: false,
            ..
        } => approve(cli, &c, task_id).await,
        Cmd::Approve {
            task_id,
            passkey: true,
            open,
            timeout,
        } => approve_with_passkey(cli, &c, task_id, *open, Duration::from_secs(*timeout)).await,
        Cmd::Passkey { what } => passkey(cli, &c, what).await,
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
        Cmd::Fsck {
            rebase_head,
            force: _,
            yes,
        } => fsck(cli, &c, *rebase_head, *yes).await,
    }
}

/// `vk fsck`, and the one write in it.
///
/// Three things happen here and nowhere else. The **typed confirmation**: a
/// rebase re-records where this node's record ends, and a flag is too easy to
/// pass by accident for that — so the word is typed, on this end, before a
/// syscall is made. The **presence proof**: reading every blob on the node,
/// and overriding its store's own refusal, are human acts (invariant I1), so
/// the call is signed with this node's device key like `stop` and `approve`.
/// And the **exit code**: the report is printed either way — a person running
/// `fsck` wants to see what failed — and then a store that does not verify
/// leaves by the error path, so `vk fsck && deploy` does what it looks like.
async fn fsck(cli: &Cli, c: &Client, rebase_head: bool, yes: bool) -> Result<()> {
    if rebase_head && !yes {
        confirm_rebase()?;
    }
    let proof = presence(c).await?;
    let answer = c
        .call(
            "store.fsck",
            json!({ "rebase_head": rebase_head }),
            Some(proof),
        )
        .await?;
    show(cli, answer.clone(), render::fsck)?;
    anyhow::ensure!(
        answer["ok"] == Value::Bool(true),
        "this store does not verify; the tiers above say which part of it"
    );
    Ok(())
}

/// The word, typed out. Refused on anything else, including an empty line and
/// a closed stdin — a confirmation nobody typed is not a confirmation.
fn confirm_rebase() -> Result<()> {
    // To stderr, so a `--json` run's stdout is still only the answer.
    eprint!(
        "This re-records where this node's record ends. Do it only if that record was \
         restored from a backup on purpose.\nType `rebase` to confirm: "
    );
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read the confirmation from stdin")?;
    anyhow::ensure!(
        line.trim() == "rebase",
        "not confirmed: the ledger head was not touched"
    );
    Ok(())
}

async fn task(cli: &Cli, c: &Client, what: &TaskCmd) -> Result<()> {
    match what {
        TaskCmd::Submit {
            goal,
            artefact,
            plan,
            draft,
            harness,
            judge,
            approve,
            release,
        } => {
            let mut steps = vec![json!({ "kind": "plan", "arch_id": plan })];
            // Exactly one of the two produces what is approved. Clap already
            // refuses both and refuses neither; this match is what turns the
            // one that was given into its step.
            match (draft, harness) {
                (Some(arch), _) => steps.push(json!({ "kind": "draft", "arch_id": arch })),
                (None, Some(name)) => steps.push(json!({ "kind": "harness", "name": name })),
                (None, None) => return Err(anyhow!("give --draft <ARCH> or --harness <NAME>")),
            }
            if let Some(arch) = judge {
                steps.push(json!({ "kind": "judge", "arch_id": arch }));
            }
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

/// `vk harness run`: the confined Claude Code harness over a task's harness step.
///
/// The launch, the containment, the workspace projection and the egress telemetry
/// all live in the daemon; this only names the task (or creates one from a goal),
/// hands over the options and prints what came back.
async fn harness(cli: &Cli, c: &Client, what: &HarnessCmd) -> Result<()> {
    let HarnessCmd::Run {
        task,
        goal,
        name,
        dry_run,
        keep,
    } = what;

    // An existing task, or a fresh one from a goal: a harness step, then the
    // approval the harness's last instruction (`vk_request_approval`) asks for
    // — so the request has a step to land on.
    let task_id = match (task, goal) {
        (Some(id), _) => id.clone(),
        (None, Some(g)) => {
            let created = c
                .call(
                    "task.create",
                    json!({
                        "goal": g,
                        "artefact_type": "proposal",
                        "steps": [ { "kind": "harness", "name": name }, { "kind": "approve" } ],
                    }),
                    None,
                )
                .await?;
            field(&created, "id")?
        }
        (None, None) => {
            return Err(anyhow!(
                "give a task id to run, or --goal to create one: vk harness run <TASK> | --goal \"...\""
            ))
        }
    };

    // Only what the request may carry (Ruling 20): the binary, the model and
    // the budget are the daemon's configuration.
    let params = json!({
        "task_id": task_id,
        "name": name,
        "dry_run": dry_run,
        "keep": keep,
    });
    let answer = c.call("harness.run", params, None).await?;
    if *dry_run {
        show(cli, answer, render::harness_dry_run)
    } else {
        show(cli, answer, render::harness_run)
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

/// The approval ceremony with this node's device key: ask the kernel for the
/// challenge it minted for the task — the subject, the resource, the nonce
/// and the expiry are all the kernel's, never this shell's (SP1b Task 5,
/// invariant I1) — sign its digest, and present it with a presence proof.
///
/// Two signatures, two domains: the presence proof signs
/// `sha256("presence|<nonce>")` over a nonce of its own, the approval signs
/// `H(resource|action|nonce|expiry)` over the minted challenge, so neither
/// can be replayed as the other, and `approve` accepts the approval only
/// while the minted challenge is unspent and unexpired.
async fn approve(cli: &Cli, c: &Client, task_id: &str) -> Result<()> {
    let device = node_device(c).await?;
    let challenge: Challenge = serde_json::from_value(
        c.call("approval.challenge", json!({ "task_id": task_id }), None)
            .await?,
    )
    .context("the daemon's approval challenge")?;
    let subject = challenge.action_digest.clone();
    let approval = Approval {
        subject_hash: subject.clone(),
        kind: ApprovalKind::Human,
        approver: Principal::Human {
            device_id: device.device_id(),
        },
        signature_hex: Some(hex::encode(device.sign(&challenge.digest()))),
        challenge: Some(challenge),
    };
    let proof = presence(c).await?;
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

/// The approval ceremony with a passkey: the daemon mints a link to the
/// task's approval page, this shell prints it (and opens it with `--open`),
/// and waits — polling `task.show` — for the task to leave `waiting_human`,
/// which is what the page's `finish` does once the passkey has signed and
/// the kernel has recorded. Nothing is signed here: the browser, the
/// authenticator and the daemon do the whole ceremony between them.
async fn approve_with_passkey(
    cli: &Cli,
    c: &Client,
    task_id: &str,
    open: bool,
    timeout: Duration,
) -> Result<()> {
    let linked = c
        .call(
            "web.link",
            json!({ "page": "approve", "task_id": task_id }),
            None,
        )
        .await?;
    let url = field(&linked, "url")?;
    let subject = field(&linked, "subject_hash")?;
    // The link goes to the person at once, before the wait: to stdout as the
    // answer of the moment, or — under `--json`, where stdout is the final
    // answer — to stderr, so a script capturing the answer still shows it.
    if cli.json {
        eprintln!("{url}");
    } else {
        println!("{}", render::link(&json!({ "url": url, "waiting": true })));
    }
    if open {
        open_browser(&url)?;
    }
    let start = Instant::now();
    let status = loop {
        let t = c
            .call("task.show", json!({ "task_id": task_id }), None)
            .await?;
        match t["status"].as_str() {
            Some("waiting_human") | None => {}
            // The approve step ran on the approval: the task finished, or
            // went on to its next step.
            Some(status @ ("done" | "running")) => break status.to_string(),
            // It left `waiting_human` some other way — a STOP, a failure —
            // and nothing says a passkey approved anything.
            Some(other) => {
                return Err(anyhow!(
                    "task {task_id} is {other}; no passkey approval landed on it"
                ))
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "no passkey approval of {task_id} arrived within {}s; the link stays open for \
                 a few minutes: {url}",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(APPROVAL_POLL).await;
    };
    show(
        cli,
        json!({
            "ok": true,
            "task_id": task_id,
            "subject_hash": subject,
            "status": status,
            "url": url,
        }),
        render::approved,
    )
}

/// `vk passkey enroll | ls`.
async fn passkey(cli: &Cli, c: &Client, what: &PasskeyCmd) -> Result<()> {
    match what {
        PasskeyCmd::Enroll { open } => {
            // Enrolling a passkey is a human act: the link is minted only
            // under a presence proof by this node's device key (review
            // Important 2), so a process with the pipe and no key gets none.
            let proof = presence(c).await?;
            let linked = c
                .call("web.link", json!({ "page": "enroll" }), Some(proof))
                .await?;
            let url = field(&linked, "url")?;
            if *open {
                open_browser(&url)?;
            }
            show(cli, json!({ "url": url, "opened": open }), render::link)
        }
        PasskeyCmd::Ls => show(
            cli,
            c.call("passkey.ls", json!({}), None).await?,
            render::passkeys,
        ),
    }
}

/// Hand `url` to the default browser: `start` on Windows, `open` on macOS,
/// `xdg-open` elsewhere. Detached, and only its launch is checked — what
/// the browser then does with the page is the person's, not this shell's.
fn open_browser(url: &str) -> Result<()> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        // `start` treats its first quoted argument as a window title.
        c.args(["/C", "start", "", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("open {url} in a browser"))?;
    Ok(())
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

/// How a daemon this shell started stopped being a daemon it is waiting for.
enum Started {
    /// It answered on the endpoint, with the `boot.info` it answered with —
    /// which says how many arches are still coming up behind it, so `vk boot`
    /// can tell the person who ran it (Task 1b review, Important 1).
    Serving(Box<Value>),
    /// It gave up before answering — a refused ledger, a key it could not
    /// read, an endpoint already taken.
    Exited(std::process::ExitStatus),
    /// The OS will not say whether it is still running.
    Lost(std::io::Error),
    /// Still running, still not answering, out of patience.
    Silent,
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
    // serves. Resolved only: this call may still refuse, and a refusal that
    // left a state directory behind would be a node the user never asked for.
    let state_dir = vk_store::paths::resolve_state_dir(a.state_dir.clone())?;
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
                "arches_starting": info["arches_starting"].as_u64().unwrap_or(0),
            }),
            render::booted,
        );
    }
    // Committed now: the daemon's log lands inside it before the daemon is
    // even started.
    let state_dir = vk_store::paths::state_dir(Some(state_dir))?;
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
    if a.force {
        cmd.arg("--force");
    }
    cmd.args(["--web-port", &a.web_port.to_string()]);
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
    // Started is not serving: the daemon is up when it answers. It is also not
    // *coming* up if it has already gone — a `vkd` that refuses its own ledger
    // exits in milliseconds, and waiting out the timeout would tell the one
    // person who can fix it that their endpoint is slow.
    let start = Instant::now();
    let outcome = rt.block_on(async {
        loop {
            if let Some(info) = serving(&ep).await {
                return Started::Serving(Box::new(info));
            }
            match child.try_wait() {
                Ok(Some(status)) => return Started::Exited(status),
                Err(e) => return Started::Lost(e),
                Ok(None) => {}
            }
            if start.elapsed() > BOOT_TIMEOUT {
                return Started::Silent;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let log = state_dir.join("vkd.log");
    let info = match outcome {
        Started::Serving(info) => *info,
        // It said why on its way out. The log is where a detached daemon
        // speaks, so its last lines are the answer — naming a file to go and
        // read is not.
        Started::Exited(status) => anyhow::bail!(
            "vkd (pid {pid}) exited with {status} before it answered on {}{}",
            ep.0,
            match std::fs::read_to_string(&log) {
                Ok(c) if !c.trim().is_empty() => format!(", saying:\n{}", render::log_tail(&c, 4)),
                _ => format!("; see {}", log.display()),
            }
        ),
        // The OS will not say whether it is still running, so assume it is:
        // a daemon nobody knows the pid of would sit on the endpoint and make
        // every later `vk boot` refuse, blaming a daemon the user never sees
        // — the same reason `Silent` kills (SP1b Task 8, deferred minor).
        Started::Lost(e) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("lost track of vkd (pid {pid}), and killed it: {e}")
        }
        Started::Silent => {
            // It is ours and nobody else knows its pid, so it does not outlive
            // the call that started it: otherwise it would sit on the endpoint
            // and every later `vk boot` would refuse, blaming a daemon the
            // user never sees.
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "vkd (pid {pid}) did not answer on {} within {BOOT_TIMEOUT:?}; see {}",
                ep.0,
                log.display()
            );
        }
    };
    show(
        cli,
        json!({
            "pid": pid,
            "endpoint": ep.0,
            "state_dir": state_dir.display().to_string(),
            // The node is serving; some of its arches may still be coming up.
            // Said here rather than left to be discovered by a task step that
            // asks to be retried (Task 1b review, Important 1).
            "arches_starting": info["arches_starting"].as_u64().unwrap_or(0),
        }),
        render::booted,
    )
}
