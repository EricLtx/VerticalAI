//! `vkd`: the VerticalAI kernel daemon. It opens the store, boots the kernel
//! and serves syscalls on the local endpoint — one daemon per user account, or
//! one per machine when the Windows service runs it (SP1b Task 6).
//!
//! Everything that decides *who* a caller is lives behind the endpoint, in
//! `vk_ipc::server`: this crate only says where the state, the master key and
//! the node's device key come from, and — under `--as-service` — which
//! accounts the endpoint's own ACL admits.
//!
//! The daemon is a library as well as a binary because the service host
//! (`vkd-service run`, `crates/vk-service`) runs exactly this code in its own
//! process rather than spawning `vkd.exe`: one boot sequence, one place where
//! the order lock → bind → boot → serve is written down.
use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "vkd", about = "VerticalAI kernel daemon", version)]
pub struct Args {
    /// State directory (default: this user's local app data; never a synced folder).
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value = "node-1")]
    pub node_id: String,
    /// Endpoint to listen on (default: this user's named pipe / socket).
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Master key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    pub master_key_file: Option<PathBuf>,
    /// Node device key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    pub node_key_file: Option<PathBuf>,
    /// SP1a convenience: enroll this node's own device key at first start, so
    /// the interactive machine can be the human this node knows. SP1b replaces
    /// it with the passkey enrolment ceremony.
    #[arg(long)]
    pub auto_enroll_node: bool,
    /// Serve even though the ledger chain does not verify. For recovering a
    /// node whose record was damaged — everything it then appends is chained
    /// onto a record that is already known not to hold.
    #[arg(long)]
    pub force: bool,
    /// The Claude Code binary the harness runs (SP1b Task 4, Ruling 20): a
    /// name looked up on this daemon's PATH (`claude` → `claude.exe` on
    /// Windows, never a `.cmd` shim) or a path. Daemon configuration only —
    /// no pipe client can name it.
    #[arg(long, default_value = "claude")]
    pub harness_bin: PathBuf,
    /// The model the harness is pinned to.
    #[arg(long, default_value = "claude-sonnet-5")]
    pub harness_model: String,
    /// How long one harness run may take before its tree is killed.
    #[arg(long, default_value_t = 300)]
    pub harness_timeout_secs: u64,
    /// Loopback port for the passkey pages (`vk passkey enroll`, `vk approve
    /// --passkey`): `127.0.0.1:<port>`, never a routable address. `0` asks the
    /// OS for a port, for tests; `vk status` says which one was taken.
    #[arg(long, default_value_t = vk_web::DEFAULT_PORT)]
    pub web_port: u16,
    /// Run as the Windows service account (SP1b Task 6): the state directory
    /// is `%ProgramData%\VerticalAI\vk` rather than a user's app data, the
    /// keyring entries are the service account's own, and the pipe is created
    /// with a DACL that admits this account and `--user-sid` only.
    #[cfg(windows)]
    #[arg(long)]
    pub as_service: bool,
    /// The interactive user the service's pipe admits beside itself, as a
    /// string SID (`whoami /user`). Required by `--as-service`, and meaningless
    /// without it.
    #[cfg(windows)]
    #[arg(long)]
    pub user_sid: Option<String>,
}

/// What `--as-service` settles before the store is opened. Pure: it decides,
/// it does not create or bind anything, so the refusals below are the daemon's
/// first words rather than a half-started node's.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProfile {
    /// `%ProgramData%\VerticalAI\vk`, unless `--state-dir` named one.
    pub state_dir: PathBuf,
    /// The interactive user's SID, beside this process's own, in the DACL.
    pub user_sid: String,
    /// The endpoint, when the caller did not name one: the machine-wide pipe.
    pub endpoint: vk_ipc::transport::Endpoint,
}

/// `%ProgramData%\VerticalAI\vk` — the state directory of a daemon that is not
/// any one person's. `%ProgramData%` rather than the literal `C:\ProgramData`
/// because a machine may have moved it, and `vk_store::paths` still refuses it
/// if it turns out to be inside a synced folder.
#[cfg(windows)]
pub fn program_data_state_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("VerticalAI")
        .join("vk")
}

/// Read `--as-service`, `--user-sid` and `--state-dir` together, or refuse.
#[cfg(windows)]
pub fn service_profile(
    as_service: bool,
    user_sid: Option<&str>,
    state_dir: Option<&std::path::Path>,
) -> anyhow::Result<Option<ServiceProfile>> {
    if !as_service {
        anyhow::ensure!(
            user_sid.is_none(),
            "--user-sid is the account the service's pipe admits beside itself; it means nothing \
             without --as-service"
        );
        return Ok(None);
    }
    let user_sid = user_sid.context(
        "--as-service needs --user-sid: the pipe's DACL admits this service account and one \
         interactive user, and a service that did not know which user would serve nobody. \
         `whoami /user` prints it, and `vkd-service install` passes it.",
    )?;
    // Checked here, where the message can say which flag was wrong, rather
    // than at `bind` where it is an unexplained refusal from the OS.
    vk_ipc::transport::pipe_dacl(&[user_sid]).context("--user-sid")?;
    Ok(Some(ServiceProfile {
        state_dir: state_dir
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(program_data_state_dir),
        user_sid: user_sid.to_string(),
        endpoint: vk_ipc::transport::service_endpoint(),
    }))
}

/// Info by default, so the boot report is in `<state_dir>/vkd.log` without
/// anybody having had to know to ask for it; `$RUST_LOG` overrides. The
/// service host installs its own writer instead, because it has no stdout to
/// be redirected.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

/// The transport's view of the pages: `web.link` mints into the pages' own
/// link table. `vk-ipc` knows the trait, `vk-web` knows the pages, and this
/// crate is where the two meet.
struct LinkMinter(Arc<vk_web::Links>);

impl vk_ipc::server::WebLinks for LinkMinter {
    fn origin(&self) -> String {
        self.0.origin().to_string()
    }
    fn enroll_link(&self, now_ms: u64) -> String {
        self.0.enroll_link(now_ms)
    }
    fn approve_link(&self, task_id: &str, now_ms: u64) -> String {
        self.0.approve_link(task_id, now_ms)
    }
}

/// Lock → bind → boot → serve. Returns only when the endpoint stops serving.
pub async fn run(a: Args) -> anyhow::Result<()> {
    // Settled before the store is opened: a `--harness-bin` path is made
    // absolute against this process's working directory and must be a file
    // (Ruling 22, M14); a bare name is pinned to what PATH holds now, or left
    // to refuse each run with a warning.
    let harness_bin = vk_ipc::server::harness_binary_at_start(&a.harness_bin)?;
    // `--as-service` exists only on Windows, and so does everything it
    // settles: the ProgramData state directory, the machine-wide pipe and the
    // DACL on it. On Unix the daemon below reads exactly as it did before.
    #[cfg(windows)]
    let service = service_profile(a.as_service, a.user_sid.as_deref(), a.state_dir.as_deref())?;
    #[cfg(windows)]
    let state_dir_arg = service
        .as_ref()
        .map(|s| s.state_dir.clone())
        .or_else(|| a.state_dir.clone());
    #[cfg(not(windows))]
    let state_dir_arg = a.state_dir.clone();
    let state_dir = vk_store::paths::state_dir(state_dir_arg)?;
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
    let endpoint = match a.endpoint.map(vk_ipc::transport::Endpoint) {
        Some(named) => named,
        #[cfg(windows)]
        None => match &service {
            Some(s) => s.endpoint.clone(),
            None => vk_ipc::transport::default_endpoint(),
        },
        #[cfg(not(windows))]
        None => vk_ipc::transport::default_endpoint(),
    };
    // Under the service the pipe carries an explicit DACL: `GENERIC_ALL` to
    // the account this process runs as — read off its own token, so it is
    // right whatever the service is configured to use — and to the one
    // interactive user the installer named. Nobody else, not even the local
    // administrators the default DACL would have admitted.
    #[cfg(windows)]
    let pipe_dacl = match &service {
        Some(s) => {
            let own = vk_ipc::transport::os::current_process_sid()?;
            let dacl = vk_ipc::transport::pipe_dacl(&[&own, &s.user_sid])?;
            tracing::info!(
                account_sid = %own,
                user_sid = %s.user_sid,
                pipe_dacl = %dacl,
                "running as a service account; the endpoint admits these two accounts only"
            );
            Some(dacl)
        }
        None => None,
    };
    #[cfg(not(windows))]
    let pipe_dacl: Option<String> = None;
    let listener = vk_ipc::transport::os::bind_with_descriptor(&endpoint, pipe_dacl.as_deref())
        .await
        .with_context(|| format!("bind {}", endpoint.0))?;
    // The pages' port too, before the record, for the same reason: a port
    // another daemon holds is a start that is refused, not a node that
    // serves half of its ceremony. Both loopback families — a browser asked
    // for `localhost` may connect to `::1` first, and an address this daemon
    // does not hold is one anybody else may (review Critical 1).
    let web_listeners = vk_web::bind(a.web_port).await?;
    let web_port = web_listeners.port();
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
    // The passkey pages, on loopback beside the endpoint (SP1b Task 5). They
    // share the kernel mutex with the transport and take it the same way —
    // for a call, never across an await. A link into them is minted only
    // over the endpoint (`web.link`); what protects the pages is in
    // `contracts/tcb.md`.
    let web = vk_web::build(kernel.clone(), &a.node_id, web_port)?;
    tracing::info!(
        web = %web.links.origin(),
        bound = %web_listeners.bound(),
        "passkey pages listening"
    );
    tokio::spawn(async move {
        if let Err(e) = vk_web::serve(web_listeners, web.router).await {
            tracing::error!(error = %format!("{e:#}"), "the passkey pages stopped serving");
        }
    });
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
        web: Some(Arc::new(LinkMinter(web.links))),
    };
    vk_ipc::server::serve_on(kernel, listener, config).await
}

#[cfg(all(test, windows))]
mod service_tests {
    use super::*;

    const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(args).expect("these arguments parse")
    }

    #[test]
    fn as_service_puts_the_state_under_program_data_and_serves_the_machine_pipe() {
        let a = parse(&["vkd", "--as-service", "--user-sid", USER]);
        let p = service_profile(a.as_service, a.user_sid.as_deref(), a.state_dir.as_deref())
            .unwrap()
            .expect("--as-service yields a profile");
        assert_eq!(p.state_dir, program_data_state_dir());
        assert!(
            p.state_dir.ends_with(r"VerticalAI\vk"),
            "{}",
            p.state_dir.display()
        );
        assert_eq!(p.user_sid, USER);
        assert_eq!(p.endpoint.0, r"\\.\pipe\vk");
    }

    #[test]
    fn as_service_without_a_user_sid_is_refused_before_anything_is_opened() {
        let a = parse(&["vkd", "--as-service"]);
        let err = service_profile(a.as_service, a.user_sid.as_deref(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--user-sid"), "{err}");
    }

    #[test]
    fn a_user_sid_that_is_not_a_sid_is_refused_naming_the_flag() {
        let err = service_profile(true, Some("Administrators"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--user-sid"), "{err}");
    }

    #[test]
    fn a_user_sid_without_as_service_is_refused() {
        let err = service_profile(false, Some(USER), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--as-service"), "{err}");
    }

    #[test]
    fn an_explicit_state_dir_still_wins_under_as_service() {
        let chosen = std::path::Path::new(r"D:\vk-state");
        let p = service_profile(true, Some(USER), Some(chosen))
            .unwrap()
            .unwrap();
        assert_eq!(p.state_dir, chosen);
    }

    #[test]
    fn without_as_service_nothing_changes() {
        let a = parse(&["vkd"]);
        assert!(!a.as_service);
        assert!(
            service_profile(a.as_service, None, None).unwrap().is_none(),
            "an ordinary daemon has no service profile"
        );
    }
}
