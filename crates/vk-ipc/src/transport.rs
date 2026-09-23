//! Local endpoint: named pipe on Windows, Unix socket elsewhere. The OS ACL on
//! the endpoint is the first authentication factor — a `0600` socket inside a
//! `0700` directory on Unix; on Windows the default pipe DACL, which SP1b
//! hardens with an explicit one — and everything above this module assumes a
//! peer that could open it.
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(pub String);

/// Why an accept failed: one connection that could not be taken while the
/// listener is still fine (log it, back off, try again), or a listener that
/// can no longer be re-armed (give up).
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("connection not accepted: {0}")]
    Connection(std::io::Error),
    #[error("listener cannot be re-armed: {0}")]
    Listener(std::io::Error),
}

/// Where `vkd` listens for this user. One daemon per account, by name. The
/// Unix fallback is a directory of our own, which `bind` creates `0700`.
pub fn default_endpoint() -> Endpoint {
    #[cfg(windows)]
    {
        Endpoint(format!(r"\\.\pipe\vk-{}", whoami()))
    }
    #[cfg(not(windows))]
    {
        Endpoint(
            std::env::var("XDG_RUNTIME_DIR")
                .map(|d| format!("{d}/vk.sock"))
                .unwrap_or_else(|_| format!("/tmp/vk-{}/vk.sock", whoami())),
        )
    }
}

/// A fresh, unique endpoint: tests run in parallel and each needs its own.
pub fn test_endpoint() -> Endpoint {
    let id = uuid::Uuid::new_v4().simple().to_string();
    #[cfg(windows)]
    {
        Endpoint(format!(r"\\.\pipe\vk-test-{id}"))
    }
    #[cfg(not(windows))]
    {
        Endpoint(format!(
            "{}/vk-test-{id}/vk.sock",
            std::env::temp_dir().display()
        ))
    }
}

fn whoami() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "user".into())
}

/// A connected byte stream, whichever OS object it is underneath.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[cfg(windows)]
pub mod os {
    use super::*;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    /// `ERROR_PIPE_BUSY`: every instance is taken, try again shortly.
    const PIPE_BUSY: i32 = 231;

    pub struct Listener {
        name: String,
        /// The instance currently waiting for a client. Kept live between
        /// accepts so that a client arriving in the gap sees "busy" (and
        /// retries) rather than "no such pipe".
        next: Option<NamedPipeServer>,
        /// Consecutive failures to create an instance. One is a bad moment;
        /// two in a row means the name cannot be served any more.
        arm_failures: u32,
    }

    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&ep.0)?;
        Ok(Listener {
            name: ep.0.clone(),
            next: Some(first),
            arm_failures: 0,
        })
    }

    impl Listener {
        /// A fresh instance on the pipe name, counting consecutive failures.
        fn arm(&mut self) -> std::io::Result<NamedPipeServer> {
            match ServerOptions::new().create(&self.name) {
                Ok(s) => {
                    self.arm_failures = 0;
                    Ok(s)
                }
                Err(e) => {
                    self.arm_failures += 1;
                    Err(e)
                }
            }
        }

        pub async fn accept(&mut self) -> Result<Box<dyn Stream>, AcceptError> {
            let server = match self.next.take() {
                Some(s) => s,
                None => match self.arm() {
                    Ok(s) => s,
                    Err(e) if self.arm_failures >= 2 => return Err(AcceptError::Listener(e)),
                    Err(e) => return Err(AcceptError::Connection(e)),
                },
            };
            if let Err(e) = server.connect().await {
                // That instance went with the failed connection; have another
                // waiting if one can be had, and let the caller try again.
                self.next = self.arm().ok();
                return Err(AcceptError::Connection(e));
            }
            // Failing to pre-create the next instance is not a failed accept:
            // this client is connected, and the next accept arms one itself.
            self.next = match self.arm() {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "could not pre-create the next pipe instance");
                    None
                }
            };
            Ok(Box::new(server))
        }
    }

    pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Stream>> {
        for _ in 0..50 {
            match ClientOptions::new().open(&ep.0) {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await
                }
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("pipe {} busy", ep.0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn a_name_that_cannot_be_armed_twice_is_a_listener_error() {
            // Not a pipe name at all: every attempt to create an instance fails.
            let mut l = Listener {
                name: String::new(),
                next: None,
                arm_failures: 0,
            };
            assert!(matches!(l.accept().await, Err(AcceptError::Connection(_))));
            assert!(matches!(l.accept().await, Err(AcceptError::Listener(_))));
        }
    }
}

#[cfg(not(windows))]
pub mod os {
    use super::*;
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};

    pub struct Listener(UnixListener);

    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let path = Path::new(&ep.0);
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            anyhow::ensure!(
                meta.file_type().is_socket(),
                "{} exists and is not a socket",
                ep.0
            );
            // A live daemon answers on its socket; only a stale one is removed.
            if UnixStream::connect(path).await.is_ok() {
                anyhow::bail!("endpoint {} already in use", ep.0);
            }
            std::fs::remove_file(path)?;
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            private_dir(dir)?;
        }
        let l = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Listener(l))
    }

    /// The socket's directory is part of the ACL. It is created `0700` when
    /// missing (our `/tmp/vk-<user>` fallback, the test endpoints) and, when
    /// it already exists (`$XDG_RUNTIME_DIR`, a previous run), required to be
    /// closed to others: a pre-created world-writable directory of the same
    /// name would otherwise let another account swap the socket underneath
    /// us. The `0700` parent is also what closes the window between `bind`
    /// and the `0600` on the socket itself.
    fn private_dir(dir: &Path) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let mode = std::fs::metadata(dir)?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is accessible by others; refusing to listen there",
            dir.display()
        );
        Ok(())
    }

    impl Listener {
        pub async fn accept(&mut self) -> Result<Box<dyn Stream>, AcceptError> {
            match self.0.accept().await {
                Ok((s, _)) => Ok(Box::new(s)),
                Err(e) => Err(classify(e)),
            }
        }
    }

    /// `EBADF` and `EINVAL` mean the listening socket itself is gone; anything
    /// else (`EMFILE`, `ENFILE`, `ECONNABORTED`, `EAGAIN`, ...) is one
    /// connection that could not be taken.
    fn classify(e: std::io::Error) -> AcceptError {
        match e.raw_os_error() {
            Some(9) | Some(22) => AcceptError::Listener(e),
            _ => AcceptError::Connection(e),
        }
    }

    pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Stream>> {
        Ok(Box::new(UnixStream::connect(&ep.0).await?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn only_a_dead_listening_socket_is_fatal() {
            let emfile = std::io::Error::from_raw_os_error(24);
            // ECONNABORTED is 103 on Linux but 53 on macOS: naming the number
            // once per platform is what keeps this case about a lost
            // connection rather than about whatever 103 means over there.
            let econnaborted =
                std::io::Error::from_raw_os_error(if cfg!(target_os = "macos") { 53 } else { 103 });
            let ebadf = std::io::Error::from_raw_os_error(9);
            assert!(matches!(classify(emfile), AcceptError::Connection(_)));
            assert!(matches!(classify(econnaborted), AcceptError::Connection(_)));
            assert!(matches!(classify(ebadf), AcceptError::Listener(_)));
        }

        #[tokio::test]
        async fn a_live_endpoint_is_not_evicted_but_a_stale_one_is() {
            let ep = test_endpoint();
            let live = bind(&ep).await.unwrap();
            // `unwrap_err` would need `Listener: Debug`, which the Windows one
            // deliberately is not; let-else keeps the two ends of the cfg alike.
            let Err(err) = bind(&ep).await else {
                panic!("a live endpoint must not be taken from under its daemon");
            };
            assert!(err.to_string().contains("already in use"), "{err}");
            // Dropping the listener leaves the socket file behind: stale.
            drop(live);
            let _again = bind(&ep).await.unwrap();
            let dir = Path::new(&ep.0).parent().unwrap();
            let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode();
            let sock_mode = std::fs::metadata(&ep.0).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            assert_eq!(sock_mode & 0o777, 0o600);
        }

        #[tokio::test]
        async fn a_directory_open_to_others_is_refused() {
            let ep = test_endpoint();
            let dir = Path::new(&ep.0).parent().unwrap();
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let Err(err) = bind(&ep).await else {
                panic!("a directory others can reach must not be listened in");
            };
            assert!(err.to_string().contains("accessible by others"), "{err}");
        }

        #[tokio::test]
        async fn a_regular_file_at_the_endpoint_is_never_deleted() {
            let ep = test_endpoint();
            let dir = Path::new(&ep.0).parent().unwrap();
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(&ep.0, "not a socket").unwrap();
            let Err(err) = bind(&ep).await else {
                panic!("a regular file at the endpoint must not be bound over");
            };
            assert!(err.to_string().contains("not a socket"), "{err}");
            assert_eq!(std::fs::read_to_string(&ep.0).unwrap(), "not a socket");
        }
    }
}
