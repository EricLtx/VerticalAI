//! Local endpoint: named pipe on Windows, Unix socket elsewhere. The OS ACL on
//! the endpoint is the first authentication factor — a `0600` socket inside a
//! `0700` directory on Unix; on Windows the default pipe DACL, which SP1b
//! hardens with an explicit one — and everything above this module assumes a
//! peer that could open it.
use anyhow::{Context, Result};
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

/// Where a `vkd` running as the Windows service listens (SP1b Task 6). Not
/// `vk-<user>`: the service account's name is not the name of the human it
/// serves, and a pipe whose name depended on whatever `%USERNAME%` a virtual
/// account reports could not be written down in advance — which is exactly
/// what the DACL and the documentation have to do. One machine-wide daemon,
/// one well-known name; `vk` reaches it with `$VK_ENDPOINT`.
pub fn service_endpoint() -> Endpoint {
    Endpoint(r"\\.\pipe\vk".into())
}

/// The pipe's DACL, as SDDL: `GENERIC_ALL` to each of `sids`, and — because a
/// DACL that is written out in full is the whole of the access check — to
/// nobody else. No `S:`, no owner, no group: what `CreateNamedPipe` is handed
/// is a discretionary list, and the object's owner is the account that creates
/// it.
///
/// The SIDs are checked here rather than left to
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, so that a typo in
/// `--user-sid` is refused by the daemon that was given it, naming the string,
/// instead of surfacing as an unexplained failure to bind.
pub fn pipe_dacl(sids: &[&str]) -> Result<String> {
    anyhow::ensure!(
        !sids.is_empty(),
        "a pipe DACL naming nobody would admit nobody; name at least one SID"
    );
    let mut sddl = String::from("D:");
    for sid in sids {
        ensure_string_sid(sid)?;
        sddl.push_str("(A;;GA;;;");
        sddl.push_str(sid);
        sddl.push(')');
    }
    Ok(sddl)
}

/// `S-1-<authority>-<sub>-…`, every part a decimal number. Deliberately
/// narrower than SDDL allows: no two-letter aliases (`BA`, `IU`), no hex
/// authorities. Everything this daemon puts in a DACL is a SID somebody read
/// off `whoami /user` or `sc showsid`, and a string that is not one is a
/// mistake worth refusing.
fn ensure_string_sid(sid: &str) -> Result<()> {
    let parts = sid
        .strip_prefix("S-1-")
        .with_context(|| format!("{sid:?} is not a string SID: it does not start with S-1-"))?;
    anyhow::ensure!(
        parts
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "{sid:?} is not a string SID: every part after S-1- must be a decimal number"
    );
    Ok(())
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

/// The DACL builder, which is the same string on every operating system —
/// only Windows can hand it to the kernel, but Linux and macOS CI still
/// check that what would be handed over is what Task 6 wrote down.
#[cfg(test)]
mod dacl_tests {
    use super::*;

    const SERVICE: &str = "S-1-5-80-2321736676-1855261038-2536180385-746309522-2788627728";
    const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn two_sids_become_the_task_6_dacl() {
        assert_eq!(
            pipe_dacl(&[SERVICE, USER]).unwrap(),
            format!("D:(A;;GA;;;{SERVICE})(A;;GA;;;{USER})")
        );
    }

    #[test]
    fn one_sid_is_a_pipe_only_that_account_may_open() {
        assert_eq!(pipe_dacl(&[USER]).unwrap(), format!("D:(A;;GA;;;{USER})"));
    }

    #[test]
    fn a_dacl_naming_nobody_is_refused() {
        let err = pipe_dacl(&[]).unwrap_err().to_string();
        assert!(err.contains("admit nobody"), "{err}");
    }

    #[test]
    fn anything_that_is_not_a_string_sid_is_refused() {
        // An SDDL alias, a truncated SID, an empty part, a name, and — the one
        // that matters — a string carrying SDDL punctuation, which would
        // otherwise let a `--user-sid` write its own ACEs.
        for bad in [
            "BA",
            "S-1-",
            "S-1-5--21",
            "Administrators",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD",
            "",
        ] {
            let err = pipe_dacl(&[bad]).unwrap_err().to_string();
            assert!(
                err.contains("not a string SID"),
                "{bad:?} must be refused as a SID, got {err}"
            );
        }
    }
}

/// A connected byte stream, whichever OS object it is underneath.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[cfg(windows)]
pub mod os {
    use super::*;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    /// `ERROR_PIPE_BUSY`: every instance is taken, try again shortly.
    const PIPE_BUSY: i32 = 231;

    pub struct Listener {
        name: String,
        /// The SDDL every instance of this pipe is created with, or `None` for
        /// the OS default. Kept as the text rather than as a descriptor: the
        /// descriptor is a raw `LocalAlloc` pointer, and a listener that is
        /// moved between threads by the runtime must not carry one.
        sddl: Option<String>,
        /// The instance currently waiting for a client. Kept live between
        /// accepts so that a client arriving in the gap sees "busy" (and
        /// retries) rather than "no such pipe".
        next: Option<NamedPipeServer>,
        /// Consecutive failures to create an instance. One is a bad moment;
        /// two in a row means the name cannot be served any more.
        arm_failures: u32,
    }

    pub async fn bind(ep: &Endpoint) -> Result<Listener> {
        bind_with_descriptor(ep, None).await
    }

    /// Bind, optionally with an explicit security descriptor in SDDL
    /// (`super::pipe_dacl` builds the one SP1b's service uses). Without one
    /// the pipe takes the default DACL, which on this Windows reads
    /// `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<creator>)(A;;FR;;;WD)(A;;FR;;;AN)`
    /// — SYSTEM, the administrators and the creator in full, **and Everyone
    /// and Anonymous with read**. For a daemon a person started in their own
    /// session that is a reasonable list; for one running as a service account
    /// on a machine with other logons it is not, which is why Task 6 writes
    /// the list out.
    ///
    /// The descriptor is applied to **every** instance, not only the first:
    /// each instance of a named pipe carries its own, and a client is checked
    /// against the instance it lands on.
    pub async fn bind_with_descriptor(ep: &Endpoint, sddl: Option<&str>) -> Result<Listener> {
        let mut first = ServerOptions::new();
        first.first_pipe_instance(true);
        let first = create_instance(&first, &ep.0, sddl)?;
        Ok(Listener {
            name: ep.0.clone(),
            sddl: sddl.map(str::to_owned),
            next: Some(first),
            arm_failures: 0,
        })
    }

    /// One pipe instance, with the descriptor when there is one.
    fn create_instance(
        opts: &ServerOptions,
        name: &str,
        sddl: Option<&str>,
    ) -> std::io::Result<NamedPipeServer> {
        let Some(sddl) = sddl else {
            return opts.create(name);
        };
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: `attrs` is a fully initialised `SECURITY_ATTRIBUTES` whose
        // descriptor `descriptor` owns and keeps alive across the call; the
        // pipe keeps a copy of the descriptor, not the pointer.
        unsafe {
            opts.create_with_security_attributes_raw(
                name,
                &mut attrs as *mut _ as *mut std::ffi::c_void,
            )
        }
    }

    /// A `LocalAlloc`-ed security descriptor, freed when it is dropped.
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> std::io::Result<SecurityDescriptor> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut psd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives
            // the call, and `psd` is a live out-parameter.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut psd,
                    None,
                )
            }
            .map_err(|e| {
                std::io::Error::other(format!("security descriptor {sddl:?} is not valid: {e}"))
            })?;
            Ok(SecurityDescriptor(psd))
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: the pointer came from
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents `LocalFree` as the way to release it, and it is
            // released exactly once.
            unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }

    /// The string SID of the account this process runs as — the service
    /// account when the SCM started it, the person's own when they did. It is
    /// half of the pipe's DACL, and it is read from the process token rather
    /// than derived from a service name, so it stays right whatever account
    /// the service is later configured to use.
    pub fn current_process_sid() -> Result<String> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        // SAFETY: each call below is given live out-parameters and a buffer
        // the OS itself sized; the token handle is closed on every path.
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .context("open this process's token")?;
            let mut needed = 0u32;
            // The first call is expected to fail with ERROR_INSUFFICIENT_BUFFER;
            // what is wanted from it is `needed`.
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            let mut buf = vec![0u8; needed as usize];
            let read = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                needed,
                &mut needed,
            );
            let _ = CloseHandle(token);
            read.context("read this process's token user")?;
            anyhow::ensure!(
                buf.len() >= std::mem::size_of::<TOKEN_USER>(),
                "the token user is shorter than a TOKEN_USER"
            );
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text = PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut text).context("format the token's SID")?;
            let sid = text.to_string().context("the token's SID is not UTF-16");
            LocalFree(Some(HLOCAL(text.0 as *mut std::ffi::c_void)));
            sid
        }
    }

    /// The DACL a pipe instance actually carries, as SDDL. Used by the tests
    /// to prove that what `bind_with_descriptor` was given is what the kernel
    /// put on the object — a descriptor silently ignored would otherwise look
    /// exactly like one that took.
    #[cfg(test)]
    fn dacl_of(pipe: &NamedPipeServer) -> Result<String> {
        use std::os::windows::io::AsRawHandle;
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
        };
        use windows::Win32::Security::DACL_SECURITY_INFORMATION;

        // SAFETY: `pipe` owns the handle for the whole call; the descriptor
        // `GetSecurityInfo` allocates is freed once, after it has been read.
        unsafe {
            let mut psd = PSECURITY_DESCRIPTOR::default();
            let rc = GetSecurityInfo(
                HANDLE(pipe.as_raw_handle()),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut psd),
            );
            anyhow::ensure!(rc.is_ok(), "GetSecurityInfo: {rc:?}");
            let mut text = PWSTR::null();
            let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                psd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            );
            let sddl = converted
                .map(|()| text.to_string().unwrap_or_default())
                .map_err(anyhow::Error::from);
            LocalFree(Some(HLOCAL(text.0 as *mut std::ffi::c_void)));
            LocalFree(Some(HLOCAL(psd.0)));
            sddl
        }
    }

    impl Listener {
        /// A fresh instance on the pipe name, counting consecutive failures.
        fn arm(&mut self) -> std::io::Result<NamedPipeServer> {
            match create_instance(&ServerOptions::new(), &self.name, self.sddl.as_deref()) {
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// The half of the Task 6 claim that one account can check: a pipe
        /// whose DACL names this user and nobody else is a pipe this user
        /// opens. The refusal of a *second* account cannot be shown from one
        /// logon — `scripts/spike-6a.ps1` is where that half is answered.
        #[tokio::test]
        async fn a_pipe_whose_dacl_names_only_this_user_admits_this_user() {
            let sid = current_process_sid().expect("this process has a token user");
            let sddl = pipe_dacl(&[&sid]).unwrap();
            let ep = test_endpoint();
            let mut listener = bind_with_descriptor(&ep, Some(&sddl)).await.unwrap();
            let dialling = tokio::spawn({
                let ep = ep.clone();
                async move { connect(&ep).await }
            });
            let mut server = listener.accept().await.unwrap();
            let mut client = dialling.await.unwrap().unwrap();
            client.write_all(b"vk").await.unwrap();
            let mut seen = [0u8; 2];
            server.read_exact(&mut seen).await.unwrap();
            assert_eq!(&seen, b"vk");
        }

        /// …and that the descriptor was not quietly dropped on the way: the
        /// DACL the object carries is read back off the handle and must name
        /// exactly the one SID that was asked for.
        #[tokio::test]
        async fn the_dacl_on_the_object_is_the_one_that_was_asked_for() {
            let sid = current_process_sid().unwrap();
            let sddl = pipe_dacl(&[&sid]).unwrap();
            let ep = test_endpoint();
            let listener = bind_with_descriptor(&ep, Some(&sddl)).await.unwrap();
            let on_the_object = dacl_of(listener.next.as_ref().unwrap()).unwrap();
            assert!(
                on_the_object.contains(&sid),
                "the DACL must name this account: {on_the_object}"
            );
            assert_eq!(
                on_the_object.matches("(A;").count(),
                1,
                "exactly one allow ACE was asked for, the object carries: {on_the_object}"
            );
            // A pipe bound the ordinary way carries the default DACL, which is
            // a different, longer list — so the assertion above is about this
            // descriptor, not about every pipe.
            let plain = bind(&test_endpoint()).await.unwrap();
            let default_dacl = dacl_of(plain.next.as_ref().unwrap()).unwrap();
            assert_ne!(default_dacl, on_the_object);
        }

        /// Every instance, not only the first: the second client on a pipe
        /// lands on an instance `arm` created, and it must be as closed as the
        /// one `bind` made.
        #[tokio::test]
        async fn a_re_armed_instance_carries_the_same_dacl() {
            let sid = current_process_sid().unwrap();
            let sddl = pipe_dacl(&[&sid]).unwrap();
            let ep = test_endpoint();
            let mut listener = bind_with_descriptor(&ep, Some(&sddl)).await.unwrap();
            let dialling = tokio::spawn({
                let ep = ep.clone();
                async move { connect(&ep).await }
            });
            let _first = listener.accept().await.unwrap();
            let _client = dialling.await.unwrap().unwrap();
            // `accept` pre-armed the next instance; that is the one to look at.
            let armed =
                dacl_of(listener.next.as_ref().expect("an instance was pre-armed")).unwrap();
            assert!(armed.contains(&sid), "{armed}");
            assert_eq!(armed.matches("(A;").count(), 1, "{armed}");
        }

        #[tokio::test]
        async fn a_descriptor_the_os_cannot_read_refuses_the_bind() {
            let ep = test_endpoint();
            let Err(err) = bind_with_descriptor(&ep, Some("D:(A;;GA;;;nonsense")).await else {
                panic!("a malformed SDDL must not bind a pipe");
            };
            assert!(err.to_string().contains("is not valid"), "{err}");
            // …and nothing was left listening on the name.
            assert!(
                ClientOptions::new().open(&ep.0).is_err(),
                "no pipe may exist after a refused bind"
            );
        }

        #[test]
        fn this_process_has_a_string_sid() {
            let sid = current_process_sid().unwrap();
            assert!(sid.starts_with("S-1-"), "{sid}");
            // It round-trips through the DACL builder's own validation.
            pipe_dacl(&[&sid]).unwrap();
        }

        #[tokio::test]
        async fn a_name_that_cannot_be_armed_twice_is_a_listener_error() {
            // Not a pipe name at all: every attempt to create an instance fails.
            let mut l = Listener {
                name: String::new(),
                sddl: None,
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

    /// The Windows signature, so that the daemon has one call site on every
    /// operating system. A Windows security descriptor is not something a
    /// Unix socket can carry, and silently ignoring one would turn a hardened
    /// endpoint into an open one, so `Some` is refused here rather than
    /// dropped. The daemon never passes one: `--as-service` is a Windows-only
    /// flag.
    pub async fn bind_with_descriptor(ep: &Endpoint, sddl: Option<&str>) -> Result<Listener> {
        anyhow::ensure!(
            sddl.is_none(),
            "a security descriptor is a Windows concept; this endpoint is a Unix socket, whose \
             ACL is its mode and its directory's"
        );
        bind(ep).await
    }

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
        async fn a_windows_descriptor_is_refused_rather_than_ignored() {
            let ep = test_endpoint();
            let Err(err) = bind_with_descriptor(&ep, Some("D:(A;;GA;;;S-1-5-18)")).await else {
                panic!("a security descriptor must not be silently dropped on Unix");
            };
            assert!(err.to_string().contains("Windows concept"), "{err}");
            bind_with_descriptor(&ep, None).await.unwrap();
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
