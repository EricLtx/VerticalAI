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
//! the System32 ACL was read on this machine (`Users` has read/execute, the two
//! AppContainer SIDs do too, no entry names `RESTRICTED`); the `RESTRICTED`-only
//! row itself was not run. `Users`/`Everyone` in the set let the child reach
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
//! alike) dies at initialisation with `0xC0000142` (`STATUS_DLL_INIT_FAILED`);
//! with `logon`, `Users` or `Authenticated Users` as the only restricting SID it
//! dies `0xC0000022` (`STATUS_ACCESS_DENIED`). **What was measured stops
//! there: the denying object was not isolated** — no Process Monitor or ETW
//! trace was taken, and the DACLs of the session and global namespace objects
//! were not read. What is *inferred* from the exit codes, the ACLs that were
//! read (System32 and the profile's ancestors) and the grants tried is that
//! process initialisation must also reach session/global namespace objects
//! (`\Sessions\N\BaseNamedObjects`, `\KnownDlls`, the CSR port) that grant
//! none of those SIDs for the *restricting* check. The conclusion does not
//! rest on that inference: no per-harness grant (workspace, config directory,
//! window station, desktop) let the child initialise, so every remaining
//! candidate is session- or machine-global — granting a restricting SID on
//! those namespaces is a **session/machine-global** change, and the alternative
//! that runs a process while confining it — a LowBox/AppContainer token — is a
//! **different mechanism** from the spike's `CreateRestrictedToken`. Which of
//! the two to take is a founder decision (Task 10 reported it as
//! `NEEDS_CONTEXT`); until then, restricted-token launch stays the open TCB
//! item and the harness runs under the Job Object and Claude Code's own fence,
//! as Task 4 shipped.
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
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SetSecurityInfo,
    SE_WINDOW_OBJECT,
};
use windows::Win32::Security::{
    CreateRestrictedToken, DeleteAce, EqualSid, GetAce, GetLengthSid, GetTokenInformation,
    LookupPrivilegeValueW, TokenGroups, TokenPrivileges, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    CONTAINER_INHERIT_ACE, CREATE_RESTRICTED_TOKEN_FLAGS, DACL_SECURITY_INFORMATION,
    LUID_AND_ATTRIBUTES, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES,
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

/// `ACCESS_ALLOWED_ACE_TYPE`: the type byte of an allow entry (`windows` 0.62
/// places it under `System::SystemServices` as a `u32`).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// What the window-object grant asks for: `GENERIC_ALL`, container- and
/// object-inheritable.
const GRANT_MASK: u32 = 0x1000_0000;
const GRANT_ACE_FLAGS: u8 = (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8;

/// How the object stores that request once set — read back on this machine
/// (Task 10 pre-review fix), in two shapes. Applied once to a clean object:
/// one entry, `OBJECT_INHERIT | CONTAINER_INHERIT` with the mask mapped to the
/// object's all-access — `WINSTA_ALL_ACCESS | STANDARD_RIGHTS_REQUIRED` =
/// `0x000F_037F` on a window station, `DESKTOP_ALL` = `0x000F_01FF` on a
/// desktop. Applied again over that entry (a run that could not restore,
/// then another): `SetEntriesInAclW` re-merges it into the canonical split the
/// logon SID's and SYSTEM's own entries beside it have — on a window station an
/// inherit-only part that keeps generic bits (`OBJECT_INHERIT |
/// CONTAINER_INHERIT | INHERIT_ONLY`, mask `0xF000_0000`) plus an effective
/// `NO_PROPAGATE_INHERIT` part with the mapped mask; on a desktop, which has no
/// children, one effective entry with no flags. These `(flags, mask)` pairs,
/// with the allow type and the `RESTRICTED` SID, are what the exact-match
/// removal looks for; nothing else on either object is touched.
const STORED_GRANT_WINSTA: [(u8, u32); 3] = [
    (0x03, 0x000F_037F),
    (0x0b, 0xF000_0000),
    (0x04, 0x000F_037F),
];
const STORED_GRANT_DESKTOP: [(u8, u32); 2] = [(0x03, 0x000F_01FF), (0x00, 0x000F_01FF)];

/// Which window object an entry was read from: the object manager stores
/// the same request differently on each (see the constants above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowObject {
    WindowStation,
    Desktop,
}

/// The window station and the desktop this process runs on.
fn winsta_and_desktop() -> Result<(HANDLE, HANDLE)> {
    use windows::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    // SAFETY: both return process/thread-scoped handles that need no close and
    // stay valid for the life of the process and thread.
    let (winsta, desktop) = unsafe {
        (
            GetProcessWindowStation().context("GetProcessWindowStation")?,
            GetThreadDesktop(GetCurrentThreadId()).context("GetThreadDesktop")?,
        )
    };
    Ok((HANDLE(winsta.0), HANDLE(desktop.0)))
}

/// One entry of a window object's DACL as read back — the tests' evidence and
/// the exact-match removal below. The SID is carried as bytes and compared as
/// bytes (Ruling 35); `sid` is its `S-1-…` rendering, for printing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AceView {
    /// `ACE_HEADER.AceType` (`0` allow, `1` deny).
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`: the inheritance bits.
    pub flags: u8,
    /// The access mask as the object stores it.
    pub mask: u32,
    /// The trustee, rendered; `?` for an ACE type this reader does not parse.
    pub sid: String,
    sid_bytes: Vec<u8>,
}

impl AceView {
    /// Does this entry's trustee equal `sid`, byte for byte?
    fn names(&self, sid: &Sid) -> bool {
        if self.sid_bytes.is_empty() {
            return false;
        }
        // SAFETY: both pointers address valid SIDs for the call's duration.
        unsafe { EqualSid(PSID(self.sid_bytes.as_ptr() as *mut c_void), sid.psid()) }.is_ok()
    }

    /// Does this entry name `RESTRICTED`?
    pub fn names_restricted(&self) -> bool {
        Sid::parse(WORKSPACE_GRANT_SID)
            .map(|r| self.names(&r))
            .unwrap_or(false)
    }

    /// Is this entry exactly what [`grant_restricted_on_winsta_desktop`] leaves
    /// on `on`: an allow for `RESTRICTED` with the flags and mask the object
    /// manager stores for the grant there (the `STORED_GRANT_*` pairs)?
    pub fn is_the_grant(&self, on: WindowObject) -> bool {
        let stored: &[(u8, u32)] = match on {
            WindowObject::WindowStation => &STORED_GRANT_WINSTA,
            WindowObject::Desktop => &STORED_GRANT_DESKTOP,
        };
        self.ace_type == ACCESS_ALLOWED_ACE_TYPE
            && stored.contains(&(self.flags, self.mask))
            && self.names_restricted()
    }

    fn render(&self) -> String {
        format!(
            "type={} flags=0x{:02x} mask=0x{:08x} sid={}",
            self.ace_type, self.flags, self.mask, self.sid
        )
    }
}

/// Render a list of entries, one per line, for the tests' evidence.
pub fn render_aces(aces: &[AceView]) -> String {
    if aces.is_empty() {
        return String::from("  (no DACL entries)");
    }
    aces.iter()
        .map(|a| format!("  {}", a.render()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn sid_string(bytes: &[u8]) -> String {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    if bytes.is_empty() {
        return String::from("?");
    }
    let mut s = PWSTR::null();
    // SAFETY: `bytes` holds a valid SID for the call; the string it allocates
    // is read once and freed with `LocalFree`.
    unsafe {
        if ConvertSidToStringSidW(PSID(bytes.as_ptr() as *mut c_void), &mut s).is_err() {
            return String::from("?");
        }
        let rendered = s.to_string().unwrap_or_else(|_| String::from("?"));
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
        rendered
    }
}

/// A window object's DACL, copied out of the descriptor `GetSecurityInfo`
/// allocates — DWORD-aligned, its `AclSize` capacity kept — so it can be
/// walked, edited and set back after the descriptor is freed. `None` is a NULL
/// DACL.
struct DaclCopy(Option<Vec<u32>>);

impl DaclCopy {
    fn read(handle: HANDLE) -> Result<DaclCopy> {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `handle` is a live window-object handle; the out-pointers are
        // live; the descriptor is copied from, then freed exactly once.
        unsafe {
            let rc = GetSecurityInfo(
                handle,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut psd),
            );
            if rc.is_err() {
                anyhow::bail!("GetSecurityInfo on a window object: {rc:?}");
            }
            let copy = if dacl.is_null() {
                None
            } else {
                let size = (*dacl).AclSize as usize;
                let mut words = vec![0u32; size.div_ceil(4)];
                std::ptr::copy_nonoverlapping(
                    dacl as *const u8,
                    words.as_mut_ptr() as *mut u8,
                    size,
                );
                Some(words)
            };
            let _ = LocalFree(Some(HLOCAL(psd.0)));
            Ok(DaclCopy(copy))
        }
    }

    fn ptr(&self) -> *const ACL {
        self.0
            .as_ref()
            .map_or(std::ptr::null(), |w| w.as_ptr() as *const ACL)
    }

    /// Set this DACL back on `handle`, byte for byte.
    fn apply(&self, handle: HANDLE) -> Result<()> {
        // SAFETY: the ACL (or null, a NULL DACL) stays valid for the call.
        let rc = unsafe {
            SetSecurityInfo(
                handle,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(self.ptr()),
                None,
            )
        };
        if rc.is_err() {
            anyhow::bail!("SetSecurityInfo on a window object: {rc:?}");
        }
        Ok(())
    }

    fn aces(&self) -> Result<Vec<AceView>> {
        let Some(words) = &self.0 else {
            return Ok(Vec::new());
        };
        let acl = words.as_ptr() as *const ACL;
        // SAFETY: `acl` is a whole, valid ACL we copied; `GetAce` hands back
        // pointers inside it, read within its bounds.
        unsafe {
            let count = u32::from((*acl).AceCount);
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                let mut ace: *mut c_void = std::ptr::null_mut();
                GetAce(acl, i, &mut ace).with_context(|| format!("GetAce {i}"))?;
                let header = *(ace as *const ACE_HEADER);
                let (mask, sid_bytes) = if header.AceType <= 1 {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    let psid = PSID(std::ptr::addr_of!((*a).SidStart) as *mut c_void);
                    let len = GetLengthSid(psid) as usize;
                    (
                        (*a).Mask,
                        std::slice::from_raw_parts(psid.0 as *const u8, len).to_vec(),
                    )
                } else {
                    (0, Vec::new())
                };
                out.push(AceView {
                    ace_type: header.AceType,
                    flags: header.AceFlags,
                    mask,
                    sid: sid_string(&sid_bytes),
                    sid_bytes,
                });
            }
            Ok(out)
        }
    }

    /// Delete every entry `ours` says is ours; how many were deleted.
    fn strip(&mut self, ours: impl Fn(&AceView) -> bool) -> Result<usize> {
        let views = self.aces()?;
        let Some(words) = &mut self.0 else {
            return Ok(0);
        };
        let acl = words.as_mut_ptr() as *mut ACL;
        let mut removed = 0;
        for (i, view) in views.iter().enumerate().rev() {
            if ours(view) {
                // SAFETY: `acl` is our own writable copy; walking from the end,
                // a deletion never shifts an index still to be visited.
                unsafe { DeleteAce(acl, i as u32) }.with_context(|| format!("DeleteAce {i}"))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// The DACL entries of this process's window station and of its thread's
/// desktop, as stored — read for the tests' before/after evidence.
pub fn winsta_desktop_aces() -> Result<(Vec<AceView>, Vec<AceView>)> {
    let (winsta, desktop) = winsta_and_desktop()?;
    Ok((
        DaclCopy::read(winsta).context("window station")?.aces()?,
        DaclCopy::read(desktop).context("desktop")?.aces()?,
    ))
}

/// The window-station and desktop grant, held: both DACLs were copied before
/// the entry was added and are set back, byte for byte, when this is dropped —
/// so a test that fails while holding it still leaves the session's window
/// station and desktop exactly as it found them.
pub struct WinstaDesktopGrant {
    winsta: HANDLE,
    desktop: HANDLE,
    saved_winsta: DaclCopy,
    saved_desktop: DaclCopy,
    restored: bool,
}

impl WinstaDesktopGrant {
    /// Put both DACLs back now, reporting a failure instead of swallowing it.
    pub fn restore(mut self) -> Result<()> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        let a = self
            .saved_winsta
            .apply(self.winsta)
            .context("restore the window station's DACL");
        let b = self
            .saved_desktop
            .apply(self.desktop)
            .context("restore the desktop's DACL");
        a.and(b)
    }
}

impl Drop for WinstaDesktopGrant {
    fn drop(&mut self) {
        if let Err(e) = self.restore_inner() {
            eprintln!("restricted-token grant: {e:#}");
        }
    }
}

/// Grant `RESTRICTED` on this process's window station and its thread's
/// desktop — the grant Chromium's sandbox makes so a restricted child's
/// `user32` initialiser can reach them. On this machine it did not change the
/// outcome: the child dies `0xC0000142` with the grant and without it
/// (measured, Task 10 group G). `SetEntriesInAclW` merges the entry, so the
/// grant is idempotent.
///
/// This touches the daemon's own window station (`WinSta0` interactively,
/// `Service-0x0-…$` under the service). It grants only `RESTRICTED`, which
/// nothing else on the machine holds, so the widening is to this harness alone
/// — and it is undone when the returned guard drops.
pub fn grant_restricted_on_winsta_desktop() -> Result<WinstaDesktopGrant> {
    let (winsta, desktop) = winsta_and_desktop()?;
    let guard = WinstaDesktopGrant {
        winsta,
        desktop,
        saved_winsta: DaclCopy::read(winsta).context("window station")?,
        saved_desktop: DaclCopy::read(desktop).context("desktop")?,
        restored: false,
    };
    // From here a failure drops `guard`, which puts back what was saved.
    grant_restricted_on_object(winsta).context("window station")?;
    grant_restricted_on_object(desktop).context("desktop")?;
    Ok(guard)
}

/// Remove, from this process's window station and desktop, every entry that
/// is exactly what the grant adds ([`AceView::is_the_grant`]) — the cleanup
/// for a run that ended before its guard could restore (a process killed
/// mid-test). Returns how many entries each object lost. Nothing else is
/// touched: an entry that differs in type, flags, mask or trustee stays.
pub fn strip_restricted_from_winsta_desktop() -> Result<(usize, usize)> {
    let (winsta, desktop) = winsta_and_desktop()?;
    let mut counts = (0, 0);
    for (handle, count, on, what) in [
        (
            winsta,
            &mut counts.0,
            WindowObject::WindowStation,
            "window station",
        ),
        (desktop, &mut counts.1, WindowObject::Desktop, "desktop"),
    ] {
        let mut dacl = DaclCopy::read(handle).context(what)?;
        *count = dacl.strip(|a| a.is_the_grant(on)).context(what)?;
        if *count > 0 {
            dacl.apply(handle).context(what)?;
        }
    }
    Ok(counts)
}

/// Add an inheritable allow-all ACE for `RESTRICTED` to a kernel object's DACL.
fn grant_restricted_on_object(handle: HANDLE) -> Result<()> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::ACE_FLAGS;

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
            grfAccessPermissions: GRANT_MASK,
            grfAccessMode: SET_ACCESS,
            grfInheritance: ACE_FLAGS(u32::from(GRANT_ACE_FLAGS)),
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
