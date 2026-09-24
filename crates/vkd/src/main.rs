//! `vkd`: the VerticalAI kernel daemon. It opens the store, boots the kernel
//! and serves syscalls on the local endpoint — one daemon per user account.
//!
//! Everything that decides *who* a caller is lives behind the endpoint, in
//! `vk_ipc::server`: this binary only says where the state, the master key and
//! the node's device key come from.
use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "vkd", about = "VerticalAI kernel daemon", version)]
struct Args {
    /// State directory (default: this user's local app data; never a synced folder).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = "node-1")]
    node_id: String,
    /// Endpoint to listen on (default: this user's named pipe / socket).
    #[arg(long)]
    endpoint: Option<String>,
    /// Master key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    master_key_file: Option<PathBuf>,
    /// Node device key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    node_key_file: Option<PathBuf>,
    /// SP1a convenience: enroll this node's own device key at first start, so
    /// the interactive machine can be the human this node knows. SP1b replaces
    /// it with the passkey enrolment ceremony.
    #[arg(long)]
    auto_enroll_node: bool,
    /// Serve even though the ledger chain does not verify. For recovering a
    /// node whose record was damaged — everything it then appends is chained
    /// onto a record that is already known not to hold.
    #[arg(long)]
    force: bool,
    /// The Claude Code binary the harness runs (SP1b Task 4, Ruling 20): a
    /// name looked up on this daemon's PATH (`claude` → `claude.exe` on
    /// Windows, never a `.cmd` shim) or a path. Daemon configuration only —
    /// no pipe client can name it.
    #[arg(long, default_value = "claude")]
    harness_bin: PathBuf,
    /// The model the harness is pinned to.
    #[arg(long, default_value = "claude-sonnet-5")]
    harness_model: String,
    /// How long one harness run may take before its tree is killed.
    #[arg(long, default_value_t = 300)]
    harness_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Info by default, so the boot report is in `<state_dir>/vkd.log` without
    // anybody having had to know to ask for it; `$RUST_LOG` overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let a = Args::parse();
    // Settled before the store is opened: a `--harness-bin` path is made
    // absolute against this process's working directory and must be a file
    // (Ruling 22, M14); a bare name is pinned to what PATH holds now, or left
    // to refuse each run with a warning.
    let harness_bin = vk_ipc::server::harness_binary_at_start(&a.harness_bin)?;
    let state_dir = vk_store::paths::state_dir(a.state_dir)?;
    let key_source = match a.master_key_file {
        Some(p) => vk_store::keys::KeySource::File(p),
        None => vk_store::keys::KeySource::Keyring {
            service: "vk".into(),
            user: "master".into(),
        },
    };
    // Opening the store takes the single-writer lock on the state directory:
    // a second daemon over a store one is already serving stops here, before
    // it has read or written anything, and says which lock file it could not
    // take.
    // With the factory that knows this build's arch kinds (SP1b ruling 14):
    // the one thing the kernel cannot know is how to make a `claude-code`, an
    // `ollama` or a mock. Without it every persisted arch came back as a mock
    // under the real arch's id — the failure nothing downstream could detect.
    //
    // This takes the store's single-writer lock and reads what is mounted; it
    // builds **nothing**. The arches are re-created by `start_arches` below,
    // after the endpoint is answering, so the order is: lock → bind → boot →
    // serve, with re-creation alongside the serving (Task 1b review,
    // Important 1).
    let mut kernel = vk_kernel::RealKernel::open_with_factory(
        &state_dir,
        key_source,
        &a.node_id,
        vk_ipc::server::adapter_factory(state_dir.clone()),
    )?;
    // The endpoint before the record. Binding is the other way a start can be
    // refused — another daemon is serving this name — and a daemon that will
    // never serve must not have enrolled a device or appended its `boot`
    // event first: everything below writes to the ledger.
    let endpoint = a
        .endpoint
        .map(vk_ipc::transport::Endpoint)
        .unwrap_or_else(vk_ipc::transport::default_endpoint);
    let listener = vk_ipc::transport::os::bind(&endpoint)
        .await
        .with_context(|| format!("bind {}", endpoint.0))?;
    if a.auto_enroll_node {
        let source = match a.node_key_file {
            Some(p) => vk_kernel::presence::KeySource::File(p),
            None => vk_kernel::presence::KeySource::Keyring,
        };
        let device = vk_kernel::presence::NodeDevice::load_or_create(source, &a.node_id)?;
        kernel.enroll_node_device(&device)?;
    }
    let report = kernel.boot()?;
    tracing::info!(
        ledger_ok = report.ledger_ok,
        ledger_len = report.ledger_len,
        recovered_partial_line = report.recovered_partial_line,
        arches = report.arches.len(),
        arches_starting = report.starting_arches.len(),
        devices = report.devices.len(),
        stopped_scopes = ?report.stopped_scopes,
        policies_version = %report.policies_version,
        // Which master key the blobs are being opened with: a keyring entry
        // replaced since they were written is otherwise indistinguishable
        // from blobs that are not there.
        master_key = %kernel.store().blobs.master_fingerprint(),
        state_dir = %state_dir.display(),
        "vkd booted"
    );
    // One line per arch that did not come back, at warn: a node serving with
    // Gemma missing is serving, and the operator has to be able to find out
    // why from the log rather than from a task that failed an hour later.
    for id in &report.unavailable_arches {
        tracing::warn!(
            arch_id = %id,
            "this arch could not be re-created at boot and is unavailable; \
             `vk ls /arches` says why. Mount it again once its engine is back."
        );
    }
    if report.recovered_partial_line {
        tracing::warn!(
            "the last ledger line was unterminated and has been dropped: one event that a \
             previous run was appending when it stopped is not in the record"
        );
    }
    // A node whose record does not verify may still be looked at — `boot`
    // appended its event and `vk dmesg` reads the file — but it does not serve
    // syscalls, because everything it would append chains onto a record that is
    // already known not to hold.
    if !report.ledger_ok && !a.force {
        anyhow::bail!(
            "the ledger chain in {} does not verify ({} events): a line was rewritten, or the \
             tail this node last recorded is gone; refusing to serve. Inspect it, restore it \
             from a backup, or pass --force to serve anyway.",
            state_dir.join("ledger").display(),
            report.ledger_len
        );
    }
    if !report.ledger_ok {
        tracing::warn!("--force: serving on a ledger chain that does not verify");
        // The override is itself on the record: a `boot.forced` event naming
        // exactly the verdict just logged above, so `vk dmesg` and `vk
        // status` — not only this log line — say when and why.
        kernel.record_forced_boot(&report)?;
    }
    tracing::info!(endpoint = %endpoint.0, "vkd listening");
    let kernel = Arc::new(Mutex::new(kernel));
    // Alongside the serving, never in front of it (Task 1b review, Important
    // 1). The endpoint is bound and `boot()` has run, so `vk status` and
    // `vk ls /arches` answer from this moment on, while the arches come up one
    // by one behind them. Detached rather than awaited: a node with a cold
    // container to start would otherwise be dark for minutes, which is what
    // made `vk boot` kill the daemon it had just started.
    tokio::spawn(vk_ipc::server::start_arches(kernel.clone()));
    // The endpoint travels with the server so a harness run can write it into the
    // run's `mcp.json` for the harness's `vk-mcp` to dial back on; the harness
    // settings travel with it because they are this daemon's, never a request's.
    let config = vk_ipc::server::ServerConfig {
        endpoint: endpoint.0,
        harness: vk_ipc::server::HarnessSettings {
            binary: harness_bin,
            model: Some(a.harness_model),
            timeout: std::time::Duration::from_secs(a.harness_timeout_secs),
        },
    };
    vk_ipc::server::serve_on(kernel, listener, config).await
}
