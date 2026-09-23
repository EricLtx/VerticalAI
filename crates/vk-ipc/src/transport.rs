//! Local endpoint: named pipe on Windows, Unix socket elsewhere. The OS ACL on
//! the endpoint is the first authentication factor (same user account only);
//! everything above this module assumes a peer that could open it.
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(pub String);

/// Where `vkd` listens for this user. One daemon per account, by name.
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
                .unwrap_or_else(|_| format!("/tmp/vk-{}.sock", whoami())),
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
            "{}/vk-test-{id}.sock",
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
    }

    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&ep.0)?;
        Ok(Listener {
            name: ep.0.clone(),
            next: Some(first),
        })
    }

    impl Listener {
        pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
            let server = match self.next.take() {
                Some(s) => s,
                None => ServerOptions::new().create(&self.name)?,
            };
            server.connect().await?;
            // Failing to pre-create the next instance is not a failed accept:
            // this client is connected, and the next accept creates one itself.
            self.next = match ServerOptions::new().create(&self.name) {
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
}

#[cfg(not(windows))]
pub mod os {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    pub struct Listener(UnixListener);

    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        let _ = std::fs::remove_file(&ep.0);
        let l = UnixListener::bind(&ep.0)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ep.0, std::fs::Permissions::from_mode(0o600))?;
        Ok(Listener(l))
    }

    impl Listener {
        pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
            let (s, _) = self.0.accept().await?;
            Ok(Box::new(s))
        }
    }

    pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Stream>> {
        Ok(Box::new(UnixStream::connect(&ep.0).await?))
    }
}
