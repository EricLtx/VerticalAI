//! The restricted-token launch of the harness (SP1b Task 10 group G; founder
//! decision 2026-09-24).
//!
//! **Status: the mechanism is validated, the fence-meaningful restriction is
//! not shippable from here without a founder decision — see the "Measured
//! limit" note below. This module is the spike's result and the groundwork; it
//! is not yet wired into [`launch`](crate::launch).**
//!
//! Spike 4a(iii) showed `CreateRestrictedToken` on the daemon's own primary
//! token followed by `CreateProcessAsUserW` runs a restricted child from an
//! ordinary interactive session — the "restricted token of the caller's own
//! token" special case needs neither `SeAssignPrimaryToken` nor
//! `SeImpersonate`, which the session lacks. This module carries that mechanism.
//!
//! **The restricting SIDs.** The child's token carries a set of restricting
//! SIDs. With any restricting SID present every access check is made twice —
//! once against the token's ordinary SIDs (the interactive user, …) and once
//! against the restricting set — and access is granted only when **both** allow.
//! So the child reaches an object only when that object's DACL grants one of the
//! restricting SIDs *as well as* the user.
//!
//! The set is [`RESTRICTING_SIDS`]: the well-known `RESTRICTED` (`S-1-5-12`),
//! `BUILTIN\Users` (`S-1-5-32-545`), `Everyone` (`S-1-1-0`) and this logon
//! session's own logon SID (`S-1-5-5-x-y`, read from the token). `RESTRICTED`
//! alone cannot run the binary: `%SystemRoot%\System32` grants read/execute to
//! `Users`, not to `RESTRICTED`, so the restricting check on every system DLL
//! would fail and the child would die `0xC0000142` (`STATUS_DLL_INIT_FAILED`) —
//! measured on this machine. `Users`/`Everyone` in the set let the child reach
//! what the OS grants the world (System32, `%ProgramFiles%`, …, none of it
//! secret); the logon SID lets it reach the window station and desktop that
//! `user32`'s initialiser needs. What is **not** widened is the fence that
//! matters: the sensitive objects — the state directory, the keyring, the
//! user's profile, the daemon's pipe — grant only the *specific* user account
//! (and SYSTEM / the administrators / the service), never `Users`, `Everyone`,
//! `RESTRICTED` or the logon SID, so the restricting check fails on them and the
//! child is denied.
//!
//! * the **workspace** and the run's **config directory** are granted
//!   `RESTRICTED` ([`grant_restricting_sid`]), so the child can read its brief
//!   and write `OUT/` (and its captured stdout, which lives in the config
//!   directory, outside the workspace the model may read);
//! * the **state directory**, the **keyring** and the **user's profile** are
//!   not, so the child is denied them — and so is the **daemon's pipe**, whose
//!   DACL admits the interactive user and the service account and nobody else,
//!   which is what closes the pipe-as-same-user caveat: a restricted harness
//!   cannot open the endpoint and act as the operator.
//!
//! **Privileges.** Every privilege is deleted except `SeChangeNotify` — the
//! bypass-traverse right. Without it a token with `DISABLE_MAX_PRIVILEGE` must
//! be granted traverse on every ancestor of its workspace up from a
//! world-traversable root, which under the user profile it never has; keeping it
//! lets the child traverse to its workspace while the *object* checks above
//! still deny the sensitive leaves (bypass-traverse skips intermediate
//! directories, never the target's own read/write check).
//!
//! Were it shippable, the child would also lose the MCP callback to the kernel
//! (`vk-mcp` dials the same pipe and is denied): a restricted harness would be
//! file-in, file-out — it reads its projected workspace and writes `OUT/`, which
//! the unrestricted kernel collects at settle. A tighter posture than the Task 4
//! harness, not a weaker one.
//!
//! **Measured limit (2026-09-27, this machine, `windows` 0.62.2).** The
//! mechanism runs a *deprivileged* child (no restricting SIDs) with exit `0`.
//! The moment a restricting SID set that could deny the sensitive objects is
//! added — every set tried, up to `{RESTRICTED, Users, Everyone, Authenticated
//! Users, logon}`, and with `RESTRICTED` also granted on the window station and
//! desktop — a normal Win32 child (`cmd.exe`, and a bare Rust console `.exe`
//! alike) dies at initialisation with `0xC0000142` (`STATUS_DLL_INIT_FAILED`).
//! The cause is not the files above: process initialisation must also reach
//! session/global namespace objects (`\Sessions\N\BaseNamedObjects`,
//! `\KnownDlls`, the CSR port), whose DACLs grant the specific user and the
//! logon session but not, for the *restricting* check, any SID that is not also
//! on the sensitive objects. Granting a restricting SID on those namespaces is a
//! **session/machine-global** change, and the alternative that runs a process
//! while confining it — a LowBox/AppContainer token — is a **different
//! mechanism** from the spike's `CreateRestrictedToken`. Which of the two to
//! take is a founder decision (Task 10 reported it as `NEEDS_CONTEXT`); until
//! then, restricted-token launch stays the open TCB item and the harness runs
//! under the Job Object and Claude Code's own fence, as Task 4 shipped.
//!
//! Every `unsafe` block here carries the reason it is sound.
#![cfg(windows)]

use anyhow::{Context, Result};
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::process::Command;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, LUID, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, GetTokenInformation, LookupPrivilegeValueW, TokenGroups,
    TokenPrivileges, CREATE_RESTRICTED_TOKEN_FLAGS, LUID_AND_ATTRIBUTES, PSID, SID_AND_ATTRIBUTES,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

/// `SE_GROUP_LOGON_ID` (`0xC000_0000`): the attribute marking a token group as
/// the logon session's own logon SID. Defined here as `windows` 0.62 places the
/// constant under `System::SystemServices` as a signed `i32`.
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// The fixed restricting SIDs (the logon SID is added at build time): the
/// well-known `RESTRICTED`, `BUILTIN\Users` and `Everyone`. See the module doc
/// for why `Users`/`Everyone` are here and why they do not widen the fence that
/// matters.
pub const RESTRICTING_SIDS: &[&str] = &["S-1-5-12", "S-1-5-32-545", "S-1-1-0"];

/// The one restricting SID the workspace and config directory are granted, so
/// the child can reach them. `RESTRICTED` — granted to nothing else on this
/// machine, so a grant of it is unmistakably ours.
pub const WORKSPACE_GRANT_SID: &str = "S-1-5-12";

/// A primary token that is a restricted copy of this process's own: every
/// privilege but `SeChangeNotify` deleted, and the [`RESTRICTING_SIDS`] plus
/// this session's logon SID as restricting SIDs. Usable as the token argument
/// to `CreateProcessAsUserW`.
pub struct RestrictedToken(OwnedHandle);

impl RestrictedToken {
    /// Build it from the current process's primary token. Needs no privilege
    /// the interactive session lacks (spike 4a(iii)).
    pub fn for_this_process() -> Result<RestrictedToken> {
        Self::build(RESTRICTING_SIDS, true, true)
    }

    /// The flexible builder behind [`RestrictedToken::for_this_process`], for
    /// the group G spike to try SID sets and privilege modes. `extra` are the
    /// fixed restricting SIDs; `add_logon` appends this session's logon SID;
    /// `keep_traverse_only` deletes every privilege but `SeChangeNotify`
    /// (otherwise none are deleted). An empty `extra` with `add_logon = false`
    /// makes an ordinary deprivileged token — no restricting SIDs at all.
    #[doc(hidden)]
    pub fn build(
        extra: &[&str],
        add_logon: bool,
        keep_traverse_only: bool,
    ) -> Result<RestrictedToken> {
        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle needing no close;
        // `token` is a live out-parameter, owned and closed once below.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                &mut token,
            )
        }
        .context("open this process's token")?;
        // SAFETY: `token` was just opened and is valid; owned and closed once.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0 as RawHandle) };

        // The restricting SIDs: `extra` kept alive as owned `Sid`s, plus the
        // logon SID (which points into `groups`' buffer) when asked.
        let fixed: Vec<Sid> = extra.iter().map(|s| Sid::parse(s)).collect::<Result<_>>()?;
        let groups = token_groups(&token)?;
        let mut restrict: Vec<SID_AND_ATTRIBUTES> = fixed
            .iter()
            .map(|s| SID_AND_ATTRIBUTES {
                Sid: s.psid(),
                Attributes: 0,
            })
            .collect();
        if add_logon {
            let logon = logon_sid(&groups).context("this token has no logon SID")?;
            restrict.push(SID_AND_ATTRIBUTES {
                Sid: logon,
                Attributes: 0,
            });
        }

        let delete = if keep_traverse_only {
            privileges_to_delete_keeping_traverse(&token)?
        } else {
            Vec::new()
        };

        let mut new = HANDLE::default();
        // SAFETY: the existing token is live for the call; `restrict` and the
        // SIDs it names (`fixed`, `groups`) outlive the call, as does `delete`;
        // `new` is a live out-parameter.
        unsafe {
            CreateRestrictedToken(
                handle_of(&token),
                CREATE_RESTRICTED_TOKEN_FLAGS(0),
                None,
                if delete.is_empty() {
                    None
                } else {
                    Some(delete.as_slice())
                },
                if restrict.is_empty() {
                    None
                } else {
                    Some(restrict.as_slice())
                },
                &mut new,
            )
        }
        .context("CreateRestrictedToken on this process's own token")?;
        drop(groups);
        drop(fixed);
        // SAFETY: `new` is a valid primary token; owned and closed once.
        Ok(RestrictedToken(unsafe {
            OwnedHandle::from_raw_handle(new.0 as RawHandle)
        }))
    }
}

/// The token's group buffer (`TOKEN_GROUPS`), kept whole so the logon SID that
/// points into it stays valid.
fn token_groups(token: &OwnedHandle) -> Result<Vec<u8>> {
    let mut needed = 0u32;
    // SAFETY: the first call is expected to fail with insufficient buffer; what
    // is wanted is `needed`.
    unsafe {
        let _ = GetTokenInformation(handle_of(token), TokenGroups, None, 0, &mut needed);
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is `needed` bytes; `needed` is a live out-parameter.
    unsafe {
        GetTokenInformation(
            handle_of(token),
            TokenGroups,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .context("read the token groups")?;
    Ok(buf)
}

/// The logon SID (`SE_GROUP_LOGON_ID`) out of a token-groups buffer, or `None`.
/// The returned `PSID` points into `groups`, which must outlive it.
fn logon_sid(groups: &[u8]) -> Option<PSID> {
    // SAFETY: `groups` is a valid `TOKEN_GROUPS` from `GetTokenInformation`; the
    // group array follows the count and is `GroupCount` long.
    unsafe {
        let tg = &*(groups.as_ptr() as *const TOKEN_GROUPS);
        let slice = std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize);
        slice
            .iter()
            .find(|g| g.Attributes & SE_GROUP_LOGON_ID != 0)
            .map(|g| g.Sid)
    }
}

/// Every privilege the token holds except `SeChangeNotify`, as the
/// delete-list `CreateRestrictedToken` takes.
fn privileges_to_delete_keeping_traverse(token: &OwnedHandle) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let keep = lookup_privilege("SeChangeNotifyPrivilege")?;
    let mut needed = 0u32;
    // SAFETY: sizing call; `needed` is a live out-parameter.
    unsafe {
        let _ = GetTokenInformation(handle_of(token), TokenPrivileges, None, 0, &mut needed);
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is `needed` bytes; `needed` is live.
    unsafe {
        GetTokenInformation(
            handle_of(token),
            TokenPrivileges,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .context("read the token privileges")?;
    // SAFETY: `buf` is a valid `TOKEN_PRIVILEGES`; the array follows the count.
    let out = unsafe {
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let slice = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        slice
            .iter()
            .filter(|p| !(p.Luid.LowPart == keep.LowPart && p.Luid.HighPart == keep.HighPart))
            .copied()
            .collect()
    };
    Ok(out)
}

fn lookup_privilege(name: &str) -> Result<LUID> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = LUID::default();
    // SAFETY: the name is NUL-terminated and outlives the call; `luid` is live.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid) }
        .with_context(|| format!("look up the privilege {name}"))?;
    Ok(luid)
}

/// A `LocalAlloc`-ed binary SID from its string form, freed on drop.
struct Sid(PSID);

impl Sid {
    fn parse(s: &str) -> Result<Sid> {
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid = PSID::default();
        // SAFETY: the string is NUL-terminated and outlives the call; the SID
        // it allocates is freed in `Drop`.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid) }
            .with_context(|| format!("{s} is not a SID Windows can read"))?;
        Ok(Sid(psid))
    }
    fn psid(&self) -> PSID {
        self.0
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        // SAFETY: the pointer came from `ConvertStringSidToSidW`, released with
        // `LocalFree`, exactly once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

/// Grant `RESTRICTED` on this process's window station and its thread's
/// desktop, so a restricted child's `user32` initialiser can reach them —
/// without which even a console child dies `0xC0000142` (measured). Chromium's
/// approach. Idempotent: `SetEntriesInAclW` merges the entry.
///
/// This touches the daemon's own window station (`WinSta0` interactively,
/// `Service-0x0-…$` under the service). It grants only `RESTRICTED`, which
/// nothing else on the machine holds, so the widening is to this harness alone.
pub fn grant_restricted_on_winsta_desktop() -> Result<()> {
    use windows::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    // SAFETY: both return process/thread-scoped handles that need no close and
    // are valid for the calls below.
    let (winsta, desktop) = unsafe {
        (
            GetProcessWindowStation().context("GetProcessWindowStation")?,
            GetThreadDesktop(GetCurrentThreadId()).context("GetThreadDesktop")?,
        )
    };
    grant_restricted_on_object(HANDLE(winsta.0)).context("window station")?;
    grant_restricted_on_object(HANDLE(desktop.0)).context("desktop")?;
    Ok(())
}

/// Add an inheritable allow-all ACE for `RESTRICTED` to a kernel object's DACL.
fn grant_restricted_on_object(handle: HANDLE) -> Result<()> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SET_ACCESS, SE_WINDOW_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        PSECURITY_DESCRIPTOR,
    };

    let restricted = Sid::parse(WORKSPACE_GRANT_SID)?;
    // SAFETY: `handle` is a live window-object handle; the out-pointers are
    // live, and the descriptor `GetSecurityInfo` allocates is freed once below.
    unsafe {
        let mut old_dacl: *mut ACL = std::ptr::null_mut();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let rc = GetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_dacl),
            None,
            Some(&mut psd),
        );
        if rc.is_err() {
            anyhow::bail!("GetSecurityInfo on a window object: {rc:?}");
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x1000_0000, // GENERIC_ALL
            grfAccessMode: SET_ACCESS,
            grfInheritance: ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(restricted.psid().0 as *mut u16),
            },
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let set = SetEntriesInAclW(Some(&[ea]), Some(old_dacl as *const ACL), &mut new_dacl);
        if set.is_err() {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
            anyhow::bail!("SetEntriesInAclW for the window object: {set:?}");
        }
        let applied = SetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const ACL),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new_dacl as *mut c_void)));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        if applied.is_err() {
            anyhow::bail!("SetSecurityInfo on a window object: {applied:?}");
        }
    }
    Ok(())
}

/// Grant `RESTRICTED` inheritable Modify on `dir`, so the restricted child can
/// use it — its workspace, or the run's config directory. Applied with
/// `icacls`, the same tool `contracts/tcb.md` and the store's own audit name as
/// the remedy; it adds an entry rather than replacing the list, so the user's
/// own access is untouched.
pub fn grant_restricting_sid(dir: &Path) -> Result<()> {
    let out = Command::new("icacls")
        .arg(dir)
        .arg("/grant")
        .arg(format!("*{WORKSPACE_GRANT_SID}:(OI)(CI)M"))
        .arg("/Q")
        .output()
        .with_context(|| format!("run icacls /grant on {}", dir.display()))?;
    anyhow::ensure!(
        out.status.success(),
        "icacls could not grant the harness SID on {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// A child launched under a [`RestrictedToken`], its stdin from the null
/// device and its stdout and stderr redirected to files the caller names (in
/// the run's config directory, which the model may not read). A thin wrapper
/// over the raw process handle: it exposes the pid and the handle the Job
/// Object contains, polls without reaping, and terminates on a timeout or STOP.
pub struct RestrictedChild {
    process: OwnedHandle,
    _thread: OwnedHandle,
    pid: u32,
}

impl RestrictedChild {
    /// Launch `program args` under `token`, in `cwd`, stdin from `NUL`, stdout
    /// to `stdout_path`, stderr to `stderr_path`. The child inherits only those
    /// three handles (marked inheritable); every other handle stays private, so
    /// nothing of the daemon's leaks in.
    pub fn spawn(
        token: &RestrictedToken,
        program: &Path,
        args: &[String],
        cwd: &Path,
        stdout_path: &Path,
        stderr_path: &Path,
    ) -> Result<RestrictedChild> {
        let nul = inheritable_read("NUL".as_ref())?;
        let out = inheritable_write(stdout_path)?;
        let err = inheritable_write(stderr_path)?;

        let mut cmdline: Vec<u16> = command_line(program, args)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let cwd_wide: Vec<u16> = wide(cwd.as_os_str());

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: handle_of(&nul),
            hStdOutput: handle_of(&out),
            hStdError: handle_of(&err),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `token` is a live primary token; `cmdline`/`cwd_wide` are
        // NUL-terminated UTF-16 buffers that outlive the call; `si` names three
        // live inheritable handles; `pi` is a live out-parameter. Only those
        // three handles are inheritable, so the child inherits nothing else.
        let created = unsafe {
            CreateProcessAsUserW(
                Some(handle_of(&token.0)),
                PCWSTR::null(),
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW,
                None,
                PCWSTR(cwd_wide.as_ptr()),
                &si,
                &mut pi,
            )
        };
        // This process is done with the child's handles now, whatever happened.
        drop(nul);
        drop(out);
        drop(err);
        created.with_context(|| {
            format!(
                "CreateProcessAsUserW {} under a restricted token",
                program.display()
            )
        })?;
        // SAFETY: both handles came from a successful call; each closed once.
        Ok(RestrictedChild {
            process: unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0 as RawHandle) },
            _thread: unsafe { OwnedHandle::from_raw_handle(pi.hThread.0 as RawHandle) },
            pid: pi.dwProcessId,
        })
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    /// The process handle, for the Job Object to contain.
    pub fn process_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }

    /// Has it exited? `Some(code)` once it has, `None` while it runs. Never blocks.
    pub fn try_wait(&self) -> Result<Option<i32>> {
        // SAFETY: the process handle is live; a 0 timeout only polls.
        let w = unsafe { WaitForSingleObject(handle_of(&self.process), 0) };
        if w != WAIT_OBJECT_0 {
            return Ok(None);
        }
        let mut code = 0u32;
        // SAFETY: the handle is live; `code` is a live out-parameter.
        unsafe { GetExitCodeProcess(handle_of(&self.process), &mut code) }
            .context("GetExitCodeProcess")?;
        Ok(Some(code as i32))
    }

    /// Kill the process now. The Job Object closes the rest of the tree when
    /// the governor drops.
    pub fn kill(&self) {
        // SAFETY: the process handle is live; terminating a dead process is
        // harmless and its error is ignored.
        unsafe {
            let _ = TerminateProcess(handle_of(&self.process), 1);
        }
    }
}

fn handle_of(h: &OwnedHandle) -> HANDLE {
    HANDLE(h.as_raw_handle())
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Open a path for reading, shareable, as an inheritable handle (the child's stdin).
fn inheritable_read(path: &Path) -> Result<OwnedHandle> {
    use std::os::windows::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .open(path)
        .with_context(|| format!("open {} for the child's stdin", path.display()))?;
    make_inheritable(f.into())
}

/// Create/truncate a path for writing, shareable for reading, as an
/// inheritable handle (the child's stdout or stderr).
fn inheritable_write(path: &Path) -> Result<OwnedHandle> {
    use std::os::windows::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .open(path)
        .with_context(|| format!("create {} for the child's output", path.display()))?;
    make_inheritable(f.into())
}

fn make_inheritable(h: OwnedHandle) -> Result<OwnedHandle> {
    // SAFETY: `h` is a live handle; the flag makes exactly it inheritable.
    unsafe { SetHandleInformation(handle_of(&h), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .context("SetHandleInformation")?;
    Ok(h)
}

/// `program args`, quoted the way `CommandLineToArgvW` parses it back.
fn command_line(program: &Path, args: &[String]) -> String {
    let mut out = quote(&program.display().to_string());
    for a in args {
        out.push(' ');
        out.push_str(&quote(a));
    }
    out
}

fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\\']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..=backslashes {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// This process's token-user SID, as a string. The daemon's pipe grants
/// exactly this account (and the service); the group G test binds a pipe of
/// that shape to prove the restricted child cannot open it.
pub fn current_user_sid() -> Result<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    // SAFETY: the token handle is closed on every path; the buffer is sized by
    // the OS and its length checked before the cast; the string SID is freed once.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("open this process's token")?;
        let token = OwnedHandle::from_raw_handle(token.0 as RawHandle);
        let mut needed = 0u32;
        let _ = GetTokenInformation(handle_of(&token), TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        let read = GetTokenInformation(
            handle_of(&token),
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        );
        read.context("read the token user")?;
        anyhow::ensure!(
            buf.len() >= std::mem::size_of::<TOKEN_USER>(),
            "the token user is shorter than a TOKEN_USER"
        );
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text).context("format the token SID")?;
        let sid = text.to_string().context("the token SID is not UTF-16");
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
        sid
    }
}
