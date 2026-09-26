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
    /// Anthropic API key file, for tests, CI and a headless node whose OS has
    /// no credential store; without it the key comes from this account's
    /// keyring, `vk`/`anthropic`, where `vk secret set anthropic` puts it.
    /// One line, the key and nothing else. Daemon configuration only — no
    /// pipe client can name it, because a client that could would be reading
    /// the daemon's files with the daemon's rights.
    #[arg(long)]
    pub anthropic_key_file: Option<PathBuf>,
    /// Where an `anthropic` arch's calls go. The first-party API unless this
    /// says otherwise, and this is the **only** way to say otherwise: no pipe
    /// client can name it, because a client that could would be choosing
    /// where this daemon sends its own key (SP1b Task 2b fix round 1). Must
    /// be `https://`, or `http://` on this machine's own loopback, which is
    /// what the tests use.
    #[arg(long)]
    pub anthropic_base_url: Option<String>,
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
    /// The interactive user's SID, beside this process's own, in the DACL —
    /// and, resolved to that account's name, the endpoint this daemon binds
    /// when `--endpoint` did not name one (`service_endpoint_for`).
    pub user_sid: String,
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

/// Who may reach a service's state directory: the `vkd` service account, SYSTEM,
/// the local administrators, and — when it is not one of those already — the
/// account making the call.
///
/// The service account is named **explicitly** rather than only being whoever
/// happens to be running (fix round 2, Minor 2). Without it, an elevated
/// `vkd --as-service` run by hand and the SCM-started service would make
/// mutually incompatible directories and each refuse the other's, with the
/// refusal pointing at `S-1-5-80-…` — the service's own account — as the
/// stranger, which reads as alarming and is not.
#[cfg(windows)]
pub fn service_dir_owners() -> anyhow::Result<Vec<String>> {
    let mut owners = vec![
        vk_ipc::transport::VKD_SERVICE_SID.to_string(),
        vk_store::win_acl::LOCAL_SYSTEM_SID.to_string(),
        vk_store::win_acl::ADMINISTRATORS_SID.to_string(),
    ];
    let own = vk_store::win_acl::current_process_sid()?;
    if !owners.iter().any(|s| s.eq_ignore_ascii_case(&own)) {
        owners.push(own);
    }
    Ok(owners)
}

/// The state directory of a daemon that is not any one person's, made private
/// before anything is written into it: Full Control to `service_dir_owners`,
/// protected so nothing is inherited from `%ProgramData%` and inheritable so
/// nothing underneath is reachable either (fix round 1, Critical 1). A
/// directory somebody else created first is refused rather than adopted.
///
/// The **parent** gets the same treatment when the directory is the
/// `%ProgramData%` default (fix round 2, Minor 1): a `VerticalAI` left on
/// `%ProgramData%`'s inherited ACL is one any local account can create first,
/// and the `CREATOR OWNER` entry it inherits carries `FILE_DELETE_CHILD` — so
/// they could rename the protected `vk` leaf out of the way without ever being
/// able to read it. Denial of service rather than disclosure, but a confusing
/// one. An explicit `--state-dir` is the operator's own path and only the leaf
/// is touched: this code has no business writing a descriptor onto `D:\`.
///
/// The service host calls this too, because it opens the log there before the
/// daemon runs — whichever of the two gets there first, the directory is born
/// private.
#[cfg(windows)]
pub fn protect_service_state_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    let owners = service_dir_owners()?;
    let allowed: Vec<&str> = owners.iter().map(String::as_str).collect();
    if dir == program_data_state_dir() {
        if let Some(parent) = dir.parent() {
            vk_store::win_acl::create_protected_dir(parent, &allowed)?;
        }
    }
    vk_store::win_acl::create_protected_dir(dir, &allowed)
}

/// Where a service installed for `user_sid` listens: that person's own
/// endpoint, derived from their account name through the one function
/// `default_endpoint` uses (founder decision, Task 6 follow-up).
///
/// The service used to bind a fixed machine-wide `\\.\pipe\vk`, which was
/// deterministic but meant every `vk` needed `$VK_ENDPOINT` set before it could
/// find the node — a wart in front of the demo and of every later shell. A
/// service account's own `%USERNAME%` is no use for this (it is not the human's
/// name and is not knowable in advance), so the name comes from the SID the
/// installer validated: `LookupAccountSid` gives the account, and
/// `transport::user_endpoint` turns it into exactly the name that person's
/// `vk` already dials.
#[cfg(windows)]
pub fn service_endpoint_for(user_sid: &str) -> anyhow::Result<vk_ipc::transport::Endpoint> {
    let account = vk_ipc::transport::os::user_account_name(user_sid)
        .with_context(|| format!("resolve the account of --user-sid {user_sid}"))?;
    Ok(vk_ipc::transport::user_endpoint(&account))
}

/// `%ProgramData%\VerticalAI\vk`, made private, for the service host.
#[cfg(windows)]
pub fn service_state_dir() -> anyhow::Result<PathBuf> {
    let dir = program_data_state_dir();
    protect_service_state_dir(&dir)?;
    Ok(dir)
}

/// The endpoint's access list. **Every** pipe this daemon creates carries an
/// explicit one (Ruling 26): under the service, the account it runs as and the
/// one interactive user the installer named; started by a person, the account
/// that started it and nobody else — including on an explicit `--endpoint`,
/// which is the name `vk boot` uses. The alternative is the OS default, which
/// grants Everyone and Anonymous read.
#[cfg(windows)]
pub fn pipe_descriptor(service: Option<&ServiceProfile>) -> anyhow::Result<String> {
    // Read off this process's own token, so it is right whatever account the
    // service is configured to run as.
    let own = vk_ipc::transport::os::current_process_sid()?;
    match service {
        Some(s) => vk_ipc::transport::pipe_dacl(&[&own, &s.user_sid]),
        None => vk_ipc::transport::pipe_dacl(&[&own]),
    }
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
    if let Some(s) = &service {
        // A SID's shape is not what it names: `S-1-1-0` is well-formed and is
        // Everyone. Resolved and required to be a user account before it
        // becomes an entry in the endpoint's DACL (fix round 1, Important 1).
        vk_ipc::transport::os::ensure_user_sid(&s.user_sid).context("--user-sid")?;
        // And the store's own directory is made private before the store
        // opens it — not after, by which time a directory somebody else
        // created would already be theirs (Critical 1).
        protect_service_state_dir(&s.state_dir)?;
    }
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
    // Where an `anthropic` arch's key comes from, at mount and again every
    // time a persisted one is re-created (SP1b Task 2b). The keyring unless
    // the operator named a file.
    let anthropic_keys = match &a.anthropic_key_file {
        Some(p) => {
            // A key in a file is a key anyone who can read the file has. The
            // store's master key file is held to the same rule, and for the
            // same reason (fix round 1, Ruling 30).
            // The same owner set the state directory is audited against
            // (`service_dir_owners`), so a key file an administrator put
            // there for the service account does not stop the service from
            // starting (fix round 2, Minor B).
            #[cfg(windows)]
            let owners = service_dir_owners()?;
            #[cfg(windows)]
            let owner_refs: Vec<&str> = owners.iter().map(String::as_str).collect();
            #[cfg(not(windows))]
            let owner_refs: Vec<&str> = Vec::new();
            vk_store::keys::check_private_file(p, &owner_refs).context("--anthropic-key-file")?;
            vk_arch_anthropic::KeySource::File(p.clone())
        }
        None => vk_arch_anthropic::KeySource::Keyring,
    };
    // Bounded here, once, rather than trusted: everything downstream of this
    // point puts an API key on whatever it names.
    let anthropic_base_url = a
        .anthropic_base_url
        .clone()
        .unwrap_or_else(|| vk_arch_anthropic::DEFAULT_BASE_URL.to_string());
    vk_arch_anthropic::check_base_url(&anthropic_base_url).context("--anthropic-base-url")?;
    let mut kernel = vk_kernel::RealKernel::open_with_factory(
        &state_dir,
        key_source,
        &a.node_id,
        vk_ipc::server::adapter_factory(
            state_dir.clone(),
            anthropic_keys.clone(),
            anthropic_base_url.clone(),
        ),
    )?;
    // The endpoint before the record. Binding is the other way a start can be
    // refused — another daemon is serving this name — and a daemon that will
    // never serve must not have enrolled a device or appended its `boot`
    // event first: everything below writes to the ledger.
    let endpoint = match a.endpoint.map(vk_ipc::transport::Endpoint) {
        Some(named) => named,
        #[cfg(windows)]
        None => match &service {
            // The interactive user's own endpoint, so their `vk` finds this
            // node with nothing set. `vkd-service install` writes the same
            // name into the `ImagePath`, from the same function, so the two
            // cannot drift — this is the fallback for a hand-run daemon.
            Some(s) => service_endpoint_for(&s.user_sid)?,
            None => vk_ipc::transport::default_endpoint(),
        },
        #[cfg(not(windows))]
        None => vk_ipc::transport::default_endpoint(),
    };
    // The pipe always carries an explicit DACL (Ruling 26): under the service
    // the account this process runs as plus the one interactive user the
    // installer named, and otherwise the account that started it alone.
    // Nobody else — not the local administrators, and not the Everyone and
    // Anonymous read the OS default hands out.
    #[cfg(windows)]
    let pipe_dacl = {
        let own = vk_ipc::transport::os::current_process_sid()?;
        let dacl = pipe_descriptor(service.as_ref())?;
        tracing::info!(
            account_sid = %own,
            user_sid = service.as_ref().map(|s| s.user_sid.as_str()).unwrap_or("-"),
            pipe_dacl = %dacl,
            "the endpoint admits these accounts and no others"
        );
        Some(dacl)
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
    // Somebody re-recorded where this node's record ends, by hand, since the
    // last boot (`vk fsck --rebase-head --force`). The `boot` event's payload
    // already commits to it — that is the durable half — and this is the line
    // an operator reading the log finds without being told to look for it.
    if let Some(r) = &report.fsck {
        tracing::warn!(
            rebased_from = ?r.rebased_from.as_ref().map(|h| h.seq),
            rebased_to = r.rebased_to.seq,
            at_ms = r.at,
            "the recorded ledger head was rebased by hand before this boot; this boot's event \
             names both heads"
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
        anthropic_keys,
        anthropic_base_url,
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
    fn as_service_puts_the_state_under_program_data() {
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
    }

    /// The founder's decision: a service installed for a person binds *that
    /// person's* endpoint, so their `vk` needs nothing set. Checked against
    /// this process's own SID, the only one a test can resolve.
    #[test]
    fn a_service_binds_the_endpoint_of_the_user_it_was_installed_for() {
        let me = vk_ipc::transport::os::current_process_sid().unwrap();
        assert_eq!(
            service_endpoint_for(&me).unwrap(),
            vk_ipc::transport::default_endpoint(),
            "installed for this account, the service must bind the pipe this account's vk dials"
        );
        // A SID that names nobody yields no endpoint, and says so naming the
        // flag's value rather than failing later at `bind`.
        let err = format!("{:#}", service_endpoint_for(USER).unwrap_err());
        assert!(err.contains(USER), "{err}");
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

    /// Ruling 26: a daemon a person started binds a pipe only that person may
    /// open — one entry, theirs — instead of the OS default, which grants
    /// Everyone and Anonymous read. This is the path `vk boot` takes, on the
    /// default endpoint and on an explicit `--endpoint` alike.
    #[test]
    fn an_interactive_daemon_admits_its_own_account_and_nobody_else() {
        let me = vk_ipc::transport::os::current_process_sid().unwrap();
        let dacl = pipe_descriptor(None).unwrap();
        assert_eq!(dacl, format!("D:(A;;GA;;;{me})"));
        assert_eq!(dacl.matches("(A;").count(), 1, "{dacl}");
    }

    /// The state directory's list names the service account whoever is
    /// running, so an elevated hand-run `vkd --as-service` and the SCM-started
    /// service accept each other's directory instead of each calling the other
    /// a stranger.
    #[test]
    fn the_state_directory_admits_the_service_account_by_name() {
        let owners = service_dir_owners().unwrap();
        let me = vk_store::win_acl::current_process_sid().unwrap();
        for expected in [
            vk_ipc::transport::VKD_SERVICE_SID,
            vk_store::win_acl::LOCAL_SYSTEM_SID,
            vk_store::win_acl::ADMINISTRATORS_SID,
            &me,
        ] {
            assert!(
                owners.iter().any(|o| o.eq_ignore_ascii_case(expected)),
                "{expected} must be on the list: {owners:?}"
            );
        }
        // No duplicate when the caller *is* one of the three — which is what
        // the service itself will be.
        let mut sorted = owners.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), owners.len(), "{owners:?}");
        // And the list is one the descriptor builder will take.
        vk_store::win_acl::protected_sddl(&owners.iter().map(String::as_str).collect::<Vec<_>>())
            .unwrap();
    }

    #[test]
    fn a_service_daemon_admits_itself_and_the_interactive_user() {
        let me = vk_ipc::transport::os::current_process_sid().unwrap();
        let profile = ServiceProfile {
            state_dir: program_data_state_dir(),
            user_sid: USER.to_string(),
        };
        let dacl = pipe_descriptor(Some(&profile)).unwrap();
        assert_eq!(dacl, format!("D:(A;;GA;;;{me})(A;;GA;;;{USER})"));
        assert_eq!(dacl.matches("(A;").count(), 2, "{dacl}");
    }
}
