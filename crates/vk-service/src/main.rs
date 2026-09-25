//! `vkd-service`: `vkd` as a Windows service under a virtual account.
//!
//! Five verbs. Four of them are the service control manager seen from a
//! terminal — `install`, `uninstall`, `start`, `stop` — and each needs an
//! elevated shell, because creating, deleting and controlling a service does.
//! The fifth, `run`, is the SCM's own entry point: it is what the `ImagePath`
//! points at, it answers the SCM's control requests, and it runs the daemon's
//! boot sequence **in this process** rather than spawning `vkd.exe`. One
//! process for the SCM to stop, one store lock, one thing to look at in Task
//! Manager.
//!
//! The account is a *virtual* one, `NT SERVICE\vkd`: created and managed by
//! Windows from the service's own name, with no password to store and a
//! Credential Manager of its own — which is where the master key and the
//! node's device key then live, separate from the founder's.
//!
//! What the account gains in isolation it loses in reach, and that is the
//! point of `pipe_acl`: the endpoint is created with a DACL that names this
//! service account and one interactive user, so `vk` from the founder's shell
//! connects and a second logon on the same machine does not.
//!
//! On anything but Windows this binary parses its arguments, says so, and
//! exits 2 — the workspace builds and tests on all three operating systems.

mod pipe_acl;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vkd-service",
    about = "Manage vkd as a Windows service under the NT SERVICE\\vkd virtual account",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum Cmd {
    /// Create the service (elevated). Prints the SIDs, the endpoint and the
    /// DACL the daemon will bind with.
    Install(InstallArgs),
    /// Stop the service if it is running and delete it (elevated).
    Uninstall,
    /// Start the installed service and wait for it to report running (elevated).
    Start,
    /// Stop the installed service and wait for it to report stopped (elevated).
    Stop,
    /// The service control manager's entry point. Not for a terminal.
    Run(RunArgs),
}

#[derive(Args, Debug, PartialEq, Eq)]
struct InstallArgs {
    /// The interactive user the endpoint admits beside the service account, as
    /// a string SID (`whoami /user`). Defaults to the account running this
    /// command — an elevated shell has the same user SID as the desktop that
    /// raised it.
    #[arg(long)]
    user_sid: Option<String>,
    /// The `vkd-service.exe` to register. Defaults to this executable.
    #[arg(long)]
    binary: Option<PathBuf>,
    /// Run `docker info` as the service account at every start and record the
    /// verdict in the log (spike 6a: is Docker Desktop's engine reachable from
    /// a virtual account at all?).
    #[arg(long)]
    probe_docker: bool,
    /// Everything after `--` is passed to the daemon, after `--as-service`.
    /// For the keys, mostly: `-- --master-key-file C:\ProgramData\...\master.key`.
    #[arg(last = true)]
    daemon_args: Vec<String>,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct RunArgs {
    /// The interactive user the endpoint admits beside this account.
    #[arg(long)]
    user_sid: String,
    /// Probe Docker before the daemon starts; see `install --probe-docker`.
    #[arg(long)]
    probe_docker: bool,
    /// Passed to the daemon after `--as-service`.
    #[arg(last = true)]
    daemon_args: Vec<String>,
}

impl RunArgs {
    /// The `vkd` command line this service host runs in-process. Written out
    /// rather than assembled from a struct so that what the service does is
    /// the same thing a person can type at a prompt.
    fn daemon_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "vkd".to_string(),
            "--as-service".to_string(),
            "--user-sid".to_string(),
            self.user_sid.clone(),
        ];
        argv.extend(self.daemon_args.iter().cloned());
        argv
    }
}

/// One line saying what this invocation will do. It is what the non-Windows
/// build prints instead of acting, what the service writes into its log as its
/// first line, and what the parse tests read back.
fn describe(cmd: &Cmd) -> String {
    match cmd {
        Cmd::Install(a) => format!(
            "install {} for user {} from {}{}{}, pipe DACL {}",
            pipe_acl::SERVICE_ACCOUNT,
            a.user_sid.as_deref().unwrap_or("<this account>"),
            a.binary
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<this executable>".into()),
            if a.probe_docker {
                ", probing docker"
            } else {
                ""
            },
            daemon_args_suffix(&a.daemon_args),
            predicted_dacl(a.user_sid.as_deref()),
        ),
        Cmd::Uninstall => format!("uninstall {}", pipe_acl::SERVICE_NAME),
        Cmd::Start => format!("start {}", pipe_acl::SERVICE_NAME),
        Cmd::Stop => format!("stop {}", pipe_acl::SERVICE_NAME),
        Cmd::Run(a) => format!(
            "run the daemon as {}{}: {}",
            pipe_acl::SERVICE_ACCOUNT,
            if a.probe_docker {
                ", probing docker"
            } else {
                ""
            },
            a.daemon_argv().join(" ")
        ),
    }
}

fn daemon_args_suffix(args: &[String]) -> String {
    if args.is_empty() {
        String::new()
    } else {
        format!(", daemon args: {}", args.join(" "))
    }
}

/// The DACL the installed service's pipe will carry, before the service
/// exists: the service account's SID is derived from the service's name, and
/// the other half is `--user-sid` (or, unnamed, whoever runs `install`).
fn predicted_dacl(user_sid: Option<&str>) -> String {
    match user_sid {
        Some(sid) => pipe_acl::pipe_sddl(pipe_acl::SERVICE_NAME, sid)
            .unwrap_or_else(|e| format!("<refused: {e}>")),
        None => format!(
            "D:(A;;GA;;;{})(A;;GA;;;<this account>)",
            pipe_acl::service_account_sid(pipe_acl::SERVICE_NAME)
        ),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dispatch(cli.cmd)
}

#[cfg(not(windows))]
fn dispatch(cmd: Cmd) -> anyhow::Result<()> {
    eprintln!(
        "vkd-service: Windows only. There is no service control manager here, so nothing was \
         done. It would have: {}",
        describe(&cmd)
    );
    std::process::exit(2)
}

#[cfg(windows)]
fn dispatch(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Install(a) => scm::install(a),
        Cmd::Uninstall => scm::uninstall(),
        Cmd::Start => scm::start(),
        Cmd::Stop => scm::stop(),
        Cmd::Run(a) => scm::run(a),
    }
}

#[cfg(windows)]
mod scm {
    use super::{describe, pipe_acl, InstallArgs, RunArgs};
    use anyhow::{Context, Result};
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    /// What `services.msc` shows.
    const DISPLAY_NAME: &str = "VerticalAI kernel daemon (vkd)";
    const DESCRIPTION: &str = "Opens the VerticalAI store, verifies the ledger chain and serves \
                               kernel syscalls on \\\\.\\pipe\\vk. The endpoint admits this \
                               service account and the interactive user named at install only.";

    /// `ERROR_SERVICE_DOES_NOT_EXIST`.
    const NO_SUCH_SERVICE: i32 = 1060;
    /// `ERROR_SERVICE_EXISTS`.
    const SERVICE_EXISTS: i32 = 1073;
    /// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: `run` outside the SCM.
    const NOT_THE_SCM: i32 = 1063;
    /// How long a control verb waits for the SCM to report the new state.
    const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
    /// How long `run` watches the daemon before it reports running. Long
    /// enough for the refusals a start really has — a store another daemon has
    /// locked, a ledger that does not verify, a port already taken — to come
    /// back as a failed start rather than as a service that is "running" and
    /// answers nothing.
    const DAEMON_SETTLE: Duration = Duration::from_secs(5);

    // ---------------------------------------------------------------- install

    pub fn install(a: InstallArgs) -> Result<()> {
        let user_sid = match a.user_sid {
            Some(s) => s,
            None => pipe_acl::interactive_user_sid()
                .context("read this account's SID for --user-sid")?,
        };
        // Both before the service exists, so a `--user-sid` that is not a user
        // account — `S-1-1-0` is Everyone and is perfectly well-formed — is
        // refused here rather than by a service that admits a whole group.
        vk_ipc::transport::os::ensure_user_sid(&user_sid).context("--user-sid")?;
        let dacl = pipe_acl::pipe_sddl(pipe_acl::SERVICE_NAME, &user_sid)?;
        let binary = match a.binary {
            Some(p) => p,
            None => std::env::current_exe().context("find this executable")?,
        };
        let binary = registrable_binary(&binary)?;
        let mut launch: Vec<OsString> =
            vec!["run".into(), "--user-sid".into(), OsString::from(&user_sid)];
        if a.probe_docker {
            launch.push("--probe-docker".into());
        }
        if !a.daemon_args.is_empty() {
            launch.push("--".into());
            launch.extend(a.daemon_args.iter().map(OsString::from));
        }
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context(
            "connect to the service control manager with permission to create a service — this \
             verb needs an elevated shell",
        )?;
        let info = ServiceInfo {
            name: OsString::from(pipe_acl::SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            // On demand, not automatic: SP1b installs the service to be
            // started deliberately. `sc config vkd start= auto` is the one
            // command that changes it, once the founder wants a node that is
            // up before anybody logs in.
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: binary.clone(),
            launch_arguments: launch.clone(),
            dependencies: vec![],
            // A virtual account: Windows creates and manages it from the
            // service's name, and a null password is what asks for one.
            account_name: Some(OsString::from(pipe_acl::SERVICE_ACCOUNT)),
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| {
                if is_winapi(&e, SERVICE_EXISTS) {
                    anyhow::anyhow!(
                        "a service called {} is already installed. `vkd-service uninstall` removes \
                         it — but look at it first (`sc qc {0}`): an existing one may have \
                         configuration of yours, and removing it takes that with it. The state \
                         directory is never touched either way.",
                        pipe_acl::SERVICE_NAME
                    )
                } else {
                    anyhow::Error::new(e).context("create the service")
                }
            })?;
        service
            .set_description(DESCRIPTION)
            .context("set the service description")?;
        let state_dir = vkd::program_data_state_dir();
        println!("service_name={}", pipe_acl::SERVICE_NAME);
        println!("service_account={}", pipe_acl::SERVICE_ACCOUNT);
        println!(
            "service_sid={}",
            pipe_acl::service_account_sid(pipe_acl::SERVICE_NAME)
        );
        println!("user_sid={user_sid}");
        println!("endpoint={}", vk_ipc::transport::service_endpoint().0);
        println!("pipe_dacl={dacl}");
        println!("state_dir={}", state_dir.display());
        println!("log={}", state_dir.join("vkd.log").display());
        println!(
            "image_path=\"{}\" {}",
            binary.display(),
            launch
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!("installed=ok");
        Ok(())
    }

    /// An absolute path to a file that is there, and that the service account
    /// can be asked to run.
    ///
    /// The SCM stores the `ImagePath` and runs it from `C:\Windows\System32`,
    /// so a relative path would start something else — or nothing. And the
    /// file itself runs as `NT SERVICE\vkd` at every start: registering one
    /// that lives under a user profile means anything running as that user can
    /// replace it and inherit the service account's Credential Manager on the
    /// next start, which makes the whole account separation nominal. A synced
    /// folder is refused for the same reason plus a duller one — OneDrive may
    /// replace the file, or leave a placeholder the SCM cannot start
    /// (fix round 1, Important 5). Put it somewhere only administrators may
    /// write: `%ProgramFiles%\VerticalAI\`.
    fn registrable_binary(p: &Path) -> Result<PathBuf> {
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()?.join(p)
        };
        anyhow::ensure!(
            abs.is_file(),
            "{} is not a file; --binary must name the vkd-service.exe to register",
            abs.display()
        );
        vk_store::paths::refuse_sync_folder(&abs).context("--binary")?;
        anyhow::ensure!(
            !under_a_user_profile(&abs),
            "{} is inside a user profile, and the service would run it as {} at every start: \
             anything running as that user could replace it and take the service account's \
             keyring with it. Copy the binaries somewhere only administrators may write — \
             `%ProgramFiles%\\VerticalAI\\` — and install from there.",
            abs.display(),
            pipe_acl::SERVICE_ACCOUNT
        );
        Ok(abs)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_binary_under_a_user_profile_is_not_registrable() {
            let home = std::env::var("USERPROFILE").expect("Windows has one");
            for inside in [
                format!(r"{home}\build\release\vkd-service.exe"),
                r"C:\Users\someone\.cargo-target\release\vkd-service.exe".into(),
                r"c:\users\someone\vkd-service.exe".into(),
                r"C:/Users/someone/vkd-service.exe".into(),
            ] {
                assert!(under_a_user_profile(Path::new(&inside)), "{inside}");
            }
            for outside in [
                r"C:\Program Files\VerticalAI\vkd-service.exe",
                r"C:\vk\vkd-service.exe",
                r"D:\opt\vk\vkd-service.exe",
                // Not a profile: a directory that merely starts the same way.
                r"C:\UsersBackup\vkd-service.exe",
            ] {
                assert!(!under_a_user_profile(Path::new(outside)), "{outside}");
            }
        }
    }

    /// `C:\Users\…`, by either name the machine knows it under.
    fn under_a_user_profile(p: &Path) -> bool {
        let lower = p.to_string_lossy().to_lowercase().replace('/', "\\");
        let roots = [
            std::env::var("USERPROFILE").ok(),
            std::env::var("PUBLIC").ok(),
            std::env::var("SystemDrive")
                .ok()
                .map(|d| format!("{d}\\Users")),
            Some(r"c:\users".into()),
        ];
        roots.into_iter().flatten().any(|root| {
            let root = root.to_lowercase().replace('/', "\\");
            !root.is_empty() && lower.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
        })
    }

    // -------------------------------------------------------------- uninstall

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context(
            "connect to the service control manager — this verb needs an elevated shell",
        )?;
        let service = match manager.open_service(
            pipe_acl::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            Ok(s) => s,
            Err(e) if is_winapi(&e, NO_SUCH_SERVICE) => {
                println!("uninstalled=already-absent");
                return Ok(());
            }
            Err(e) => return Err(e).context("open the service"),
        };
        if service.query_status()?.current_state != ServiceState::Stopped {
            service
                .stop()
                .context("stop the service before deleting it")?;
            wait_for(&service, ServiceState::Stopped)?;
        }
        service.delete().context("delete the service")?;
        drop(service);
        // Win32 offers no way to wait for a deletion, so it is polled: the
        // record goes only when the last handle to it closes.
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        while Instant::now() < deadline {
            match manager.open_service(pipe_acl::SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
                Err(e) if is_winapi(&e, NO_SUCH_SERVICE) => {
                    println!("uninstalled=ok");
                    return Ok(());
                }
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
        println!("uninstalled=marked-for-deletion");
        Ok(())
    }

    // ------------------------------------------------------------ start, stop

    pub fn start() -> Result<()> {
        let service = open(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        service
            .start(&[] as &[&OsStr])
            .context("start the service")?;
        let status = wait_for(&service, ServiceState::Running)?;
        println!("state={:?}", status.current_state);
        println!("exit_code={:?}", status.exit_code);
        println!("pid={:?}", status.process_id);
        anyhow::ensure!(
            status.current_state == ServiceState::Running,
            "the service did not reach running; its log is {}",
            vkd::program_data_state_dir().join("vkd.log").display()
        );
        println!("started=ok");
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let service = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            println!("state=Stopped");
            println!("stopped=already");
            return Ok(());
        }
        service.stop().context("stop the service")?;
        let status = wait_for(&service, ServiceState::Stopped)?;
        println!("state={:?}", status.current_state);
        println!("stopped=ok");
        Ok(())
    }

    fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("connect to the service control manager — this verb needs an elevated shell")?
            .open_service(pipe_acl::SERVICE_NAME, access)
            .with_context(|| {
                format!(
                    "open the service {} — `vkd-service install` creates it",
                    pipe_acl::SERVICE_NAME
                )
            })
    }

    fn wait_for(
        service: &windows_service::service::Service,
        wanted: ServiceState,
    ) -> Result<ServiceStatus> {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            let status = service.query_status()?;
            if status.current_state == wanted || Instant::now() >= deadline {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn is_winapi(e: &windows_service::Error, code: i32) -> bool {
        matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
    }

    // -------------------------------------------------------------------- run

    /// What `main` parsed, for the service entry point the SCM calls on its own
    /// thread. The arguments the SCM passes to `service_main` are the ones a
    /// `StartService` call supplied, not the `ImagePath`'s — so the
    /// `ImagePath`'s are read here, from this process's own command line.
    static RUN: OnceLock<RunArgs> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Why the host woke up: the SCM asked it to stop, or the daemon returned.
    enum Wake {
        Stop,
        Daemon(Box<Result<()>>),
    }

    pub fn run(a: RunArgs) -> Result<()> {
        // Nothing is created here, and the log is opened inside `service_main`
        // rather than now: a `vkd-service run` typed at a prompt must be a
        // refusal that leaves no `C:\ProgramData\VerticalAI\vk` behind —
        // least of all one owned by whoever typed it rather than by the
        // service account that will need to write in it.
        RUN.set(a).ok();
        match service_dispatcher::start(pipe_acl::SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            Err(e) if is_winapi(&e, NOT_THE_SCM) => anyhow::bail!(
                "`vkd-service run` is the service control manager's entry point, not a verb for a \
                 terminal: it can only be started by the SCM. Use `vkd-service start`, or run the \
                 daemon directly with `vkd --as-service --user-sid <SID>`."
            ),
            Err(e) => Err(e).context("hand this process to the service control manager"),
        }
    }

    /// Append to `<state_dir>\vkd.log`, the same file `vk boot` redirects a
    /// detached daemon into, so there is one log whoever started the node.
    fn log_to(path: &Path) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_ansi(false)
            .with_writer(std::sync::Arc::new(file))
            .init();
        Ok(())
    }

    /// The SCM has called us, so this really is the service: the state
    /// directory and the log are made now, by the service account, and the
    /// rest of the run has somewhere to speak.
    fn service_main(_scm_arguments: Vec<OsString>) {
        let state_dir = vkd::program_data_state_dir();
        // Made private as it is made, and refused if somebody else made it
        // first: this is the very first thing to touch `%ProgramData%`, before
        // even the log file goes in (fix round 1, Critical 1).
        let logging = vkd::protect_service_state_dir(&state_dir)
            .and_then(|()| log_to(&state_dir.join("vkd.log")));
        if let Err(e) = &logging {
            // Nowhere to write it; `serve` still reports the SCM statuses, so
            // `sc query vkd` remains the signal that something went wrong.
            eprintln!("vkd-service: no log: {e:#}");
        }
        if let Some(a) = RUN.get() {
            tracing::info!(
                command = %describe(&super::Cmd::Run(RunArgs {
                    user_sid: a.user_sid.clone(),
                    probe_docker: a.probe_docker,
                    daemon_args: a.daemon_args.clone(),
                })),
                log_ok = logging.is_ok(),
                "vkd-service starting"
            );
        }
        if let Err(e) = serve() {
            tracing::error!(error = %format!("{e:#}"), "the service host stopped");
        }
    }

    fn serve() -> Result<()> {
        let (tx, rx) = mpsc::channel::<Wake>();
        let from_scm = tx.clone();
        let handle = service_control_handler::register(pipe_acl::SERVICE_NAME, move |control| {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = from_scm.send(Wake::Stop);
                    ServiceControlHandlerResult::NoError
                }
                // Every service must answer Interrogate, even with nothing.
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        })
        .context("register the service control handler")?;
        let args = RUN.get().context("the run arguments were never parsed")?;
        handle.set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            Duration::from_secs(30),
        ))?;
        let argv = args.daemon_argv();
        tracing::info!(argv = %argv.join(" "), "starting the daemon in this process");
        std::thread::spawn(move || {
            let _ = tx.send(Wake::Daemon(Box::new(daemon(argv))));
        });
        // A start that is going to fail usually fails at once — the store is
        // locked, the ledger does not verify, the pipe or the port is taken —
        // and the SCM should hear about that as a failed start.
        if let Ok(Wake::Daemon(result)) = rx.recv_timeout(DAEMON_SETTLE) {
            return stopped(&handle, *result);
        }
        handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
            Duration::default(),
        ))?;
        tracing::info!("running");
        // The Docker probe runs **after** the service is running, on a thread
        // of its own (fix round 1, Important 4). It used to sit between
        // `StartPending` and `Running`, where its 30-second deadline could eat
        // the whole wait hint — and the case spike 6a exists to measure, an
        // engine the virtual account cannot reach, is exactly the slow one. A
        // measurement must not be able to make a healthy node look like a
        // failed start.
        if args.probe_docker {
            let dir = vkd::program_data_state_dir();
            std::thread::spawn(move || probe_docker(&dir));
        }
        match rx.recv() {
            Ok(Wake::Stop) => {
                tracing::info!("the service control manager asked this node to stop");
                handle.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::NO_ERROR,
                    Duration::from_secs(10),
                ))?;
                // The daemon has no shutdown of its own to call: what ends it
                // is this process ending, which is also what releases the
                // store's single-writer lock and the pipe. That is safe
                // because it is the same thing a kill is, and the store is
                // built to survive one — the ledger's last line is dropped if
                // it was unterminated and the head is re-verified at the next
                // boot (SP1a fix wave).
                handle.set_service_status(status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::NO_ERROR,
                    Duration::default(),
                ))?;
                Ok(())
            }
            Ok(Wake::Daemon(result)) => stopped(&handle, *result),
            Err(e) => {
                tracing::error!(error = %e, "the service host lost its own channel");
                stopped(&handle, Err(anyhow::anyhow!("{e}")))
            }
        }
    }

    /// Report Stopped, with a service-specific exit code when the daemon
    /// refused to serve, so `sc query vkd` says that the start failed rather
    /// than that the service is merely not running.
    fn stopped(
        handle: &service_control_handler::ServiceStatusHandle,
        result: Result<()>,
    ) -> Result<()> {
        let exit = match &result {
            Ok(()) => {
                tracing::info!("the daemon stopped serving");
                ServiceExitCode::NO_ERROR
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "the daemon refused to serve");
                ServiceExitCode::ServiceSpecific(1)
            }
        };
        handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit,
            Duration::default(),
        ))?;
        result
    }

    fn status(
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
        exit_code: ServiceExitCode,
        wait_hint: Duration,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        }
    }

    /// The daemon, on a runtime of its own. `vkd::Args` is parsed from a real
    /// command line rather than built field by field, so that what the service
    /// runs is exactly what `vkd --as-service --user-sid <SID>` runs.
    fn daemon(argv: Vec<String>) -> Result<()> {
        let args = <vkd::Args as clap::Parser>::try_parse_from(&argv)
            .with_context(|| format!("the daemon arguments {:?} are not valid", argv.join(" ")))?;
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build the daemon's runtime")?
            .block_on(vkd::run(args))
    }

    /// Spike 6a's Docker question, answered from inside the service account:
    /// `docker info`, with its output in `<state_dir>\docker-probe.log` and its
    /// verdict in the service log. A virtual account is not a member of
    /// `docker-users`, and Docker Desktop's engine pipe is ACL'd — so this is
    /// expected to be the finding that decides whether the Ollama container
    /// can be started by the node or must be started by the founder and
    /// mounted `--external`.
    fn probe_docker(state_dir: &Path) {
        // One word for the verdict and the rest in `detail`: the founder's
        // script reads `docker_probe=<word>` out of this line, and a value
        // with spaces in it would run into the fields after it.
        let (verdict, detail) = match run_docker_info(state_dir) {
            Ok((v, d)) => (v, d),
            Err(e) => ("error", format!("{e:#}")),
        };
        tracing::info!(
            // `%` so the value is printed bare: a `&str` recorded as itself
            // comes out quoted, and the script matches on the word.
            docker_probe = %verdict,
            detail = %detail,
            output = %state_dir.join("docker-probe.log").display(),
            "docker reachability from the service account"
        );
    }

    fn run_docker_info(state_dir: &Path) -> Result<(&'static str, String)> {
        let log = state_dir.join("docker-probe.log");
        let out =
            std::fs::File::create(&log).with_context(|| format!("create {}", log.display()))?;
        let mut child = std::process::Command::new("docker")
            .arg("info")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(out.try_clone()?))
            .stderr(std::process::Stdio::from(out))
            .spawn()
            .context("spawn `docker info` — the binary may not be on the service's PATH")?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait()? {
                Some(s) if s.success() => return Ok(("ok", "docker info answered".into())),
                Some(s) => return Ok(("failed", format!("exit {:?}", s.code()))),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    return Ok(("timed-out", "no answer in 30s; killed".into()));
                }
                None => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    fn parse(args: &[&str]) -> Cmd {
        Cli::try_parse_from(args)
            .expect("these arguments parse")
            .cmd
    }

    #[test]
    fn the_five_verbs_parse() {
        assert_eq!(
            parse(&["vkd-service", "install", "--user-sid", USER]),
            Cmd::Install(InstallArgs {
                user_sid: Some(USER.into()),
                binary: None,
                probe_docker: false,
                daemon_args: vec![],
            })
        );
        assert_eq!(parse(&["vkd-service", "uninstall"]), Cmd::Uninstall);
        assert_eq!(parse(&["vkd-service", "start"]), Cmd::Start);
        assert_eq!(parse(&["vkd-service", "stop"]), Cmd::Stop);
        assert_eq!(
            parse(&["vkd-service", "run", "--user-sid", USER]),
            Cmd::Run(RunArgs {
                user_sid: USER.into(),
                probe_docker: false,
                daemon_args: vec![],
            })
        );
    }

    #[test]
    fn install_takes_a_binary_a_docker_probe_and_daemon_arguments() {
        let Cmd::Install(a) = parse(&[
            "vkd-service",
            "install",
            "--user-sid",
            USER,
            "--binary",
            r"C:\vk\vkd-service.exe",
            "--probe-docker",
            "--",
            "--master-key-file",
            r"C:\vk\master.key",
        ]) else {
            panic!("that is an install");
        };
        assert_eq!(a.user_sid.as_deref(), Some(USER));
        assert_eq!(
            a.binary.unwrap().to_str().unwrap(),
            r"C:\vk\vkd-service.exe"
        );
        assert!(a.probe_docker);
        assert_eq!(a.daemon_args, ["--master-key-file", r"C:\vk\master.key"]);
    }

    /// `install` may default the user to whoever ran it; `run` may not — the
    /// SCM starts it with no session to ask.
    #[test]
    fn run_cannot_be_asked_to_serve_nobody() {
        assert!(Cli::try_parse_from(["vkd-service", "run"]).is_err());
        assert!(Cli::try_parse_from(["vkd-service", "install"]).is_ok());
    }

    #[test]
    fn a_verb_that_is_not_one_of_the_five_is_refused() {
        for bad in [
            vec!["vkd-service", "restart"],
            vec!["vkd-service", "boot"],
            vec!["vkd-service"],
        ] {
            assert!(Cli::try_parse_from(&bad).is_err(), "{bad:?}");
        }
    }

    /// What the service host runs is a `vkd` command line, and it is the one
    /// the plan and the README write down.
    #[test]
    fn the_daemon_command_line_is_vkd_as_service() {
        let Cmd::Run(a) = parse(&[
            "vkd-service",
            "run",
            "--user-sid",
            USER,
            "--",
            "--node-id",
            "node-1",
        ]) else {
            panic!("that is a run");
        };
        assert_eq!(
            a.daemon_argv(),
            [
                "vkd",
                "--as-service",
                "--user-sid",
                USER,
                "--node-id",
                "node-1"
            ]
        );
    }

    /// The DACL is in the sentence, so that `vkd-service install` on a machine
    /// that cannot install anything — a Linux CI runner, a dry read — still
    /// says exactly which two accounts the endpoint would admit.
    #[test]
    fn install_says_which_dacl_it_would_put_on_the_pipe() {
        let named = describe(&parse(&["vkd-service", "install", "--user-sid", USER]));
        assert!(
            named.contains(&pipe_acl::pipe_sddl(pipe_acl::SERVICE_NAME, USER).unwrap()),
            "{named}"
        );
        let unnamed = describe(&parse(&["vkd-service", "install"]));
        assert!(
            unnamed.contains(&pipe_acl::service_account_sid(pipe_acl::SERVICE_NAME)),
            "{unnamed}"
        );
        assert!(unnamed.contains("<this account>"), "{unnamed}");
        // A `--user-sid` that is not one says so here rather than producing an
        // ACE nobody meant.
        let bad = describe(&parse(&["vkd-service", "install", "--user-sid", "WD"]));
        assert!(bad.contains("<refused:"), "{bad}");
    }

    #[test]
    fn every_verb_says_what_it_would_do() {
        assert!(describe(&parse(&["vkd-service", "install"])).contains(r"NT SERVICE\vkd"));
        assert!(describe(&parse(&["vkd-service", "uninstall"])).contains("uninstall vkd"));
        assert!(describe(&parse(&["vkd-service", "start"])).contains("start vkd"));
        assert!(describe(&parse(&["vkd-service", "stop"])).contains("stop vkd"));
        let run = describe(&parse(&[
            "vkd-service",
            "run",
            "--user-sid",
            USER,
            "--probe-docker",
        ]));
        assert!(run.contains("--as-service"), "{run}");
        assert!(run.contains("probing docker"), "{run}");
    }
}
