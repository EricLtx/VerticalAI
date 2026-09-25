//! The state directory's ACL on Windows (SP1b Task 6 fix round 1, Critical 1).
//!
//! On Unix `paths::private_dir` makes the state directory `0700` and refuses
//! one that others can reach. Windows had no counterpart: the directory was
//! created with `create_dir_all` and took whatever the parent handed down. For
//! `%LOCALAPPDATA%` that is the user's own ACL and the premise holds. For
//! `%ProgramData%` it does not — a fresh folder there inherits
//!
//! ```text
//! BUILTIN\Users:(I)(OI)(CI)(RX)          every local account reads it, and every file in it
//! BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)    every local account may create files and folders in it
//! CREATOR OWNER:(I)(OI)(CI)(IO)(F)       whoever creates it owns it
//! ```
//!
//! — so a second unprivileged logon could read the register and the whole
//! plaintext ledger, plant a `*.jsonl` segment that `LedgerFs::open` replays
//! (a one-file denial of service) or a `shredded/` tombstone that destroys a
//! blob's key, and, worst, **create the directory before the service does** and
//! own everything the service then writes into it.
//!
//! So a service's state directory is created here instead, with an explicit
//! **protected** DACL — `D:P`, the flag that stops the parent's inheritable
//! entries being merged in — granting Full Control to exactly the accounts the
//! caller names and to nobody else, and `OICI` so that every file and
//! directory the store creates underneath inherits those entries and nothing
//! else. An existing directory is accepted only if its owner and its every ACE
//! name one of those accounts; otherwise the node refuses to start and says
//! which owner or entry stopped it. Setting a DACL after the fact would not
//! do: by then the directory is already somebody else's.

use crate::sid::ensure_string_sid;
use anyhow::{bail, ensure, Context, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;

/// `NT AUTHORITY\SYSTEM`.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// Create `dir` reachable by `allowed` and nobody else, or — if it is already
/// there — refuse unless it already is. Ancestors are created the ordinary
/// way: they hold nothing, and a directory planted at this path is caught by
/// the audit whoever made it.
pub fn create_protected_dir(dir: &Path, allowed: &[&str]) -> Result<()> {
    if dir.exists() {
        return audit_protected_dir(dir, allowed)
            .with_context(|| format!("the state directory {} is not private", dir.display()));
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let sddl = protected_sddl(allowed)?;
    let wide_sddl = wide(&sddl);
    let wide_path = wide_os(dir);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: both strings are NUL-terminated and outlive the calls; `psd` is
    // a live out-parameter, and the descriptor it names is freed once.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .with_context(|| format!("the descriptor {sddl:?} is not valid"))?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };
        let made = CreateDirectoryW(PCWSTR(wide_path.as_ptr()), Some(&attrs));
        LocalFree(Some(HLOCAL(psd.0)));
        made.with_context(|| format!("create {} with a DACL of its own", dir.display()))?;
    }
    audit_protected_dir(dir, allowed)
        .with_context(|| format!("the state directory {} was created wrong", dir.display()))
}

/// `D:P(A;OICI;FA;;;<sid>)…` — protected, so nothing is inherited from the
/// parent, and inheritable, so nothing created underneath is reachable by
/// anybody else either.
pub fn protected_sddl(allowed: &[&str]) -> Result<String> {
    ensure!(
        !allowed.is_empty(),
        "a state directory nobody may reach is one the node cannot open"
    );
    let mut sddl = String::from("D:P");
    for sid in allowed {
        ensure_string_sid(sid)?;
        sddl.push_str("(A;OICI;FA;;;");
        sddl.push_str(sid);
        sddl.push(')');
    }
    Ok(sddl)
}

/// The owner and every entry of `dir`'s DACL must name one of `allowed`.
pub fn audit_protected_dir(dir: &Path, allowed: &[&str]) -> Result<()> {
    let (owner, aces) = owner_and_ace_sids(dir)?;
    let permitted = |sid: &String| allowed.iter().any(|a| a.eq_ignore_ascii_case(sid));
    ensure!(
        permitted(&owner),
        "it is owned by {owner}, which is neither this account, nor SYSTEM, nor the local \
         administrators — somebody else created it first, so everything written into it would be \
         theirs. Move it aside, or delete it and let the node make it."
    );
    if let Some(stranger) = aces.iter().find(|s| !permitted(s)) {
        bail!(
            "its DACL has an entry for {stranger}, which is not this account, SYSTEM or the local \
             administrators. Reset it (`icacls \"{dir}\" /inheritance:r /grant *{first}:(OI)(CI)F`, \
             then the other accounts), or delete the directory and let the node make it.",
            dir = dir.display(),
            first = allowed[0]
        );
    }
    Ok(())
}

/// The DACL as SDDL — what the tests assert against, and what a refusal can
/// quote.
pub fn dacl_sddl(path: &Path) -> Result<String> {
    let descriptor = Descriptor::of(path)?;
    // SAFETY: `descriptor` owns a live security descriptor for the whole
    // block; the string the conversion allocates is freed once, after it has
    // been read.
    unsafe {
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        );
        let sddl = converted
            .map(|()| text.to_string().unwrap_or_default())
            .map_err(anyhow::Error::from);
        LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
        sddl
    }
}

fn owner_and_ace_sids(path: &Path) -> Result<(String, Vec<String>)> {
    let d = Descriptor::of(path)?;
    // SAFETY: `d` keeps the descriptor — and therefore the owner SID and the
    // ACL, which point into it — alive for the whole of this block.
    unsafe {
        let owner = sid_to_string(d.owner)?;
        ensure!(
            !d.dacl.is_null(),
            "it has no DACL at all, which on Windows means every account has every access"
        );
        let mut size = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            d.dacl,
            &mut size as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .context("read the size of its DACL")?;
        let mut sids = Vec::with_capacity(size.AceCount as usize);
        for i in 0..size.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            GetAce(d.dacl, i, &mut ace).with_context(|| format!("read entry {i} of its DACL"))?;
            // Every entry that names a principal — allow or deny — carries the
            // SID straight after the header and the mask. A deny entry for
            // somebody else is as much of a surprise as an allow one, so both
            // are collected.
            let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
            sids.push(sid_to_string(PSID(
                &ace.SidStart as *const u32 as *mut c_void,
            ))?);
        }
        Ok((owner, sids))
    }
}

/// A `LocalAlloc`-ed security descriptor from `GetNamedSecurityInfoW`, with the
/// owner and DACL pointers that live inside it.
struct Descriptor {
    psd: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *const ACL,
}

impl Descriptor {
    fn of(path: &Path) -> Result<Descriptor> {
        let wide_path = wide_os(path);
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the path is NUL-terminated and outlives the call; the three
        // out-parameters are live, and the descriptor is freed in `Drop`.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide_path.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut psd,
            )
        };
        ensure!(
            rc.is_ok(),
            "read the owner and DACL of {}: {rc:?}",
            path.display()
        );
        Ok(Descriptor {
            psd,
            owner,
            dacl: dacl as *const ACL,
        })
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `GetNamedSecurityInfoW`, which
        // documents `LocalFree` as the way to release it, exactly once.
        unsafe { LocalFree(Some(HLOCAL(self.psd.0))) };
    }
}

/// SAFETY: `sid` must point at a valid SID that outlives the call.
unsafe fn sid_to_string(sid: PSID) -> Result<String> {
    unsafe {
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).context("format a SID")?;
        let s = text.to_string().context("a SID is not UTF-16");
        LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
        s
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// This process's token user, as a string SID. `vk-ipc` has the same lookup
/// for the pipe's DACL, but it depends on this crate, so the dependency cannot
/// run the other way.
pub fn current_process_sid() -> Result<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: the token handle is closed on every path, the buffer is sized by
    // the OS, and its length is checked before the cast.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("open this process's token")?;
        let mut needed = 0u32;
        // Expected to fail with ERROR_INSUFFICIENT_BUFFER; `needed` is the point.
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
        ensure!(
            buf.len() >= std::mem::size_of::<TOKEN_USER>(),
            "the token user is shorter than a TOKEN_USER"
        );
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vk-acl-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn me_system_admins() -> (String, [String; 3]) {
        let me = current_process_sid().unwrap();
        let all = [
            me.clone(),
            LOCAL_SYSTEM_SID.to_string(),
            ADMINISTRATORS_SID.to_string(),
        ];
        (me, all)
    }

    fn refs(all: &[String; 3]) -> Vec<&str> {
        all.iter().map(String::as_str).collect()
    }

    #[test]
    fn the_directory_is_created_with_exactly_those_accounts_and_inherits_nothing() {
        let (me, all) = me_system_admins();
        let allowed = refs(&all);
        let dir = temp_path("made");
        create_protected_dir(&dir, &allowed).unwrap();
        let sddl = dacl_sddl(&dir).unwrap();
        // `P`: nothing from the parent was merged in.
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 3, "{sddl}");
        assert!(sddl.contains(&me), "{sddl}");
        // The well-known two come back as their SDDL aliases.
        assert!(sddl.contains(";SY)"), "{sddl}");
        assert!(sddl.contains(";BA)"), "{sddl}");
        // And nobody else — in particular not the Users group, Everyone,
        // Authenticated Users, Anonymous or Creator Owner, every one of which
        // `%ProgramData%` hands down.
        for stranger in [";BU)", ";WD)", ";AU)", ";AN)", ";CO)"] {
            assert!(!sddl.contains(stranger), "{stranger} in {sddl}");
        }
        // The audit agrees with the string, and a child inherits the same list
        // — which is what protects the ledger, the register and the blobs.
        audit_protected_dir(&dir, &allowed).unwrap();
        let child = dir.join("ledger");
        std::fs::create_dir(&child).unwrap();
        audit_protected_dir(&child, &allowed).expect("a child inherits the same entries");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_directory_a_second_account_could_reach_is_refused_by_name() {
        let (me, all) = me_system_admins();
        let allowed = refs(&all);
        let dir = temp_path("planted");
        // What a second local logon's pre-creation looks like from here: us,
        // plus an entry for the Users group. Staging it under our own name is
        // the only way to do this without a second account; what is under test
        // is the entry check, and `BU` is a principal that is not on the list.
        create_with_sddl(&dir, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;BU)"));
        let err = format!("{:#}", create_protected_dir(&dir, &allowed).unwrap_err());
        assert!(err.contains("not private"), "{err}");
        assert!(err.contains("S-1-5-32-545"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_existing_directory_that_is_already_private_is_accepted() {
        let (_, all) = me_system_admins();
        let allowed = refs(&all);
        let dir = temp_path("again");
        create_protected_dir(&dir, &allowed).unwrap();
        // The second start of the same service.
        create_protected_dir(&dir, &allowed).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_sddl_is_protected_and_inheritable_and_takes_string_sids_only() {
        assert_eq!(
            protected_sddl(&["S-1-5-18", "S-1-5-32-544"]).unwrap(),
            "D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)"
        );
        assert!(protected_sddl(&[]).is_err());
        assert!(protected_sddl(&["BA"]).is_err());
    }

    #[test]
    fn this_process_has_a_string_sid() {
        let sid = current_process_sid().unwrap();
        crate::sid::ensure_string_sid(&sid).unwrap();
    }

    fn create_with_sddl(dir: &Path, sddl: &str) {
        let wide_sddl = wide(sddl);
        let wide_path = wide_os(dir);
        unsafe {
            let mut psd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide_sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
            .unwrap();
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd.0,
                bInheritHandle: false.into(),
            };
            CreateDirectoryW(PCWSTR(wide_path.as_ptr()), Some(&attrs)).unwrap();
            LocalFree(Some(HLOCAL(psd.0)));
        }
    }
}
