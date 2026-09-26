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
//!
//! **Every comparison here is of SIDs by value** (CI fix, Ruling 35). A
//! descriptor read back is walked entry by entry and each SID is formatted
//! with `ConvertSidToStringSidW`, which always gives the numeric
//! `S-1-5-…` form; the SIDs it is compared against are put through the same
//! function first (`canonical_sid`). What is never compared is the *SDDL
//! rendering* of a descriptor: `ConvertSecurityDescriptorToStringSecurityDescriptorW`
//! prints a well-known SID as its two-letter alias — `SY`, `BA`, and, for the
//! built-in local Administrator, `LA` — so the same entry reads
//! `(A;;FA;;;S-1-5-21-…-500)` on one machine and `(A;;FA;;;LA)` on a CI
//! runner that happens to run as that account, and it prints `GENERIC_ALL`
//! as `FA` once the object's generic mapping has been applied.

use crate::sid::ensure_string_sid;
use anyhow::{bail, ensure, Context, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;

/// `NT AUTHORITY\SYSTEM`.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACE_ALLOW: u8 = 0;
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` — what `OICI` sets.
pub const ACE_OBJECT_AND_CONTAINER_INHERIT: u8 = 0x03;
/// `INHERITED_ACE` — the entry came from the parent rather than being set here.
pub const ACE_INHERITED: u8 = 0x10;
/// `FILE_ALL_ACCESS`. What an `FA` entry holds, and what a `GA` entry holds
/// once a file or pipe object's generic mapping has been applied to it — the
/// kernel stores the mapped mask, which is why the SDDL rendering of a pipe
/// created with `GA` reads `FA`.
pub const FILE_ALL_ACCESS_MASK: u32 = 0x001F_01FF;

/// One entry of a DACL, by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceEntry {
    /// `ACE_HEADER.AceType`: [`ACE_ALLOW`] for an allow entry.
    pub kind: u8,
    /// `ACE_HEADER.AceFlags`: inheritance bits, and [`ACE_INHERITED`].
    pub flags: u8,
    /// The access mask as stored, i.e. after generic mapping.
    pub mask: u32,
    /// Canonical `S-1-…`, from `ConvertSidToStringSidW`. Never an SDDL alias.
    pub sid: String,
}

/// An object's owner and DACL, by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaclView {
    /// Canonical `S-1-…` of the owner.
    pub owner: String,
    /// `SE_DACL_PROTECTED`: nothing is inherited from the parent.
    pub protected: bool,
    pub entries: Vec<AceEntry>,
}

impl DaclView {
    /// The SIDs the DACL names, in order.
    pub fn sids(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.sid.as_str()).collect()
    }
}

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
/// anybody else either. This is a string this crate *writes*; it is never
/// what a read-back is compared against.
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

/// The owner and every entry of `dir`'s DACL must name one of `allowed`,
/// compared **by value**: the object's SIDs come out of `path_dacl` in their
/// canonical numeric form, and `allowed` is canonicalised the same way before
/// the comparison — so an entry the OS would render as `LA`, and an `allowed`
/// written as `BA` rather than `S-1-5-32-544`, still meet.
pub fn audit_protected_dir(dir: &Path, allowed: &[&str]) -> Result<()> {
    let view = path_dacl(dir)?;
    let canonical: Vec<String> = allowed
        .iter()
        .map(|s| canonical_sid(s).with_context(|| format!("{s:?} in the allowed list")))
        .collect::<Result<_>>()?;
    let permitted = |sid: &str| canonical.iter().any(|a| a == sid);
    ensure!(
        permitted(&view.owner),
        "it is owned by {}, which is neither this account, nor SYSTEM, nor the local \
         administrators — somebody else created it first, so everything written into it would be \
         theirs. Move it aside, or delete it and let the node make it.",
        view.owner
    );
    if let Some(stranger) = view.entries.iter().find(|e| !permitted(&e.sid)) {
        bail!(
            "its DACL has an entry for {}, which is not this account, SYSTEM or the local \
             administrators. Reset it (`icacls \"{dir}\" /inheritance:r /grant *{first}:(OI)(CI)F`, \
             then the other accounts), or delete the directory and let the node make it.",
            stranger.sid,
            dir = dir.display(),
            first = allowed[0]
        );
    }
    Ok(())
}

/// The canonical `S-1-…` form of a SID given as a string — numeric already, or
/// an SDDL alias such as `SY`, `BA` or `LA` — by converting it to the binary
/// SID and back. Two strings name the same account exactly when their
/// canonical forms are equal; that is the only SID comparison this module
/// makes.
pub fn canonical_sid(sid: &str) -> Result<String> {
    let wide_sid = wide(sid);
    // SAFETY: the string is NUL-terminated and outlives the call; the binary
    // SID the conversion allocates is formatted and then freed exactly once.
    unsafe {
        let mut psid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(wide_sid.as_ptr()), &mut psid)
            .with_context(|| format!("{sid:?} is not a SID Windows can read"))?;
        let text = sid_to_string(psid);
        LocalFree(Some(HLOCAL(psid.0)));
        text
    }
}

/// The owner and DACL of a file or directory, by value.
pub fn path_dacl(path: &Path) -> Result<DaclView> {
    Descriptor::of_path(path)?.view()
}

/// The owner and DACL of an open kernel handle — a named pipe instance, in
/// this workspace — by value. The handle needs `READ_CONTROL`, which the
/// creator of an object always has on its own handle.
pub fn handle_dacl(handle: std::os::windows::io::RawHandle) -> Result<DaclView> {
    Descriptor::of_handle(HANDLE(handle))?.view()
}

/// A `LocalAlloc`-ed security descriptor, with the owner and DACL pointers
/// that live inside it.
struct Descriptor {
    psd: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *const ACL,
}

impl Descriptor {
    fn of_path(path: &Path) -> Result<Descriptor> {
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

    fn of_handle(handle: HANDLE) -> Result<Descriptor> {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the caller's handle is live for the call; the out-parameters
        // are live, and the descriptor is freed in `Drop`.
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                Some(&mut psd),
            )
        };
        ensure!(rc.is_ok(), "read the owner and DACL of a handle: {rc:?}");
        Ok(Descriptor {
            psd,
            owner,
            dacl: dacl as *const ACL,
        })
    }

    /// Walk the descriptor into a `DaclView`: the owner, the protection bit,
    /// and every entry with its type, flags, mask and canonical SID.
    fn view(&self) -> Result<DaclView> {
        // SAFETY: `self` keeps the descriptor — and therefore the owner SID
        // and the ACL, which point into it — alive for the whole block.
        unsafe {
            let owner = sid_to_string(self.owner)?;
            let mut control = 0u16;
            let mut revision = 0u32;
            GetSecurityDescriptorControl(self.psd, &mut control, &mut revision)
                .context("read the descriptor's control bits")?;
            let protected = control & SE_DACL_PROTECTED.0 != 0;
            ensure!(
                !self.dacl.is_null(),
                "it has no DACL at all, which on Windows means every account has every access"
            );
            let mut size = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                self.dacl,
                &mut size as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .context("read the size of its DACL")?;
            let mut entries = Vec::with_capacity(size.AceCount as usize);
            for i in 0..size.AceCount {
                let mut ace: *mut c_void = std::ptr::null_mut();
                GetAce(self.dacl, i, &mut ace)
                    .with_context(|| format!("read entry {i} of its DACL"))?;
                // Every entry that names a principal — allow, deny, or their
                // callback forms — carries the SID straight after the header
                // and the mask, which is what `ACCESS_ALLOWED_ACE` lays out; a
                // deny entry for somebody else is as much of a surprise as an
                // allow one, so both are collected. The *object* ACE forms put
                // a GUID there instead, and this cast would misread one — but
                // they exist only in directory-service DACLs, never on a file
                // or pipe object, which is all this module looks at.
                let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
                entries.push(AceEntry {
                    kind: ace.Header.AceType,
                    flags: ace.Header.AceFlags,
                    mask: ace.Mask,
                    sid: sid_to_string(PSID(&ace.SidStart as *const u32 as *mut c_void))?,
                });
            }
            Ok(DaclView {
                owner,
                protected,
                entries,
            })
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `GetNamedSecurityInfoW` or
        // `GetSecurityInfo`, both of which document `LocalFree` as the way to
        // release it, exactly once.
        unsafe { LocalFree(Some(HLOCAL(self.psd.0))) };
    }
}

/// The canonical numeric form of a binary SID. `ConvertSidToStringSidW`
/// never produces an SDDL alias, which is what makes its output safe to
/// compare.
///
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
    use windows::Win32::Foundation::CloseHandle;
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
    use std::collections::BTreeSet;
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

    fn set_of<'a>(it: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
        it.into_iter().map(str::to_string).collect()
    }

    /// The SDDL *rendering* of a descriptor, which the tests below use only to
    /// show what a string comparison would have seen — never to decide.
    fn rendered_dacl(path: &Path) -> String {
        use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let d = Descriptor::of_path(path).unwrap();
        unsafe {
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                d.psd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .unwrap();
            let s = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
            s
        }
    }

    #[test]
    fn the_directory_is_created_with_exactly_those_accounts_and_inherits_nothing() {
        let (_, all) = me_system_admins();
        let allowed = refs(&all);
        let dir = temp_path("made");
        create_protected_dir(&dir, &allowed).unwrap();
        let view = path_dacl(&dir).unwrap();
        // Protected: nothing from `%TEMP%`, or `%ProgramData%`, merged in.
        assert!(view.protected, "{view:?}");
        // Exactly the three accounts, compared as SIDs — so the Users group,
        // Everyone, Authenticated Users, Anonymous and Creator Owner that the
        // parent would have handed down are absent by construction, and it
        // does not matter how the OS would *render* this account (`LA` for the
        // built-in Administrator a CI runner runs as).
        assert_eq!(
            set_of(view.sids()),
            set_of(allowed.iter().copied()),
            "{view:?}"
        );
        assert_eq!(view.entries.len(), 3, "{view:?}");
        for e in &view.entries {
            assert_eq!(e.kind, ACE_ALLOW, "{e:?}");
            assert_eq!(e.mask, FILE_ALL_ACCESS_MASK, "{e:?}");
            assert_eq!(
                e.flags & ACE_OBJECT_AND_CONTAINER_INHERIT,
                ACE_OBJECT_AND_CONTAINER_INHERIT,
                "every entry is inheritable: {e:?}"
            );
            assert_eq!(e.flags & ACE_INHERITED, 0, "set here, not inherited: {e:?}");
        }
        // The audit agrees, and a child inherits the same list — which is what
        // protects the ledger, the register and the blobs.
        audit_protected_dir(&dir, &allowed).unwrap();
        let child = dir.join("ledger");
        std::fs::create_dir(&child).unwrap();
        let child_view = path_dacl(&child).unwrap();
        assert_eq!(set_of(child_view.sids()), set_of(allowed.iter().copied()));
        assert!(
            child_view
                .entries
                .iter()
                .all(|e| e.flags & ACE_INHERITED != 0),
            "a child's entries are the parent's, inherited: {child_view:?}"
        );
        audit_protected_dir(&child, &allowed).expect("a child inherits the same entries");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The CI failure, reproduced on any machine (Ruling 35). An entry for the
    /// built-in local Administrator is *rendered* `LA`, SYSTEM `SY`, the
    /// administrators `BA`; the same accounts compared by value are the
    /// numeric SIDs. A descriptor written with the aliases must be accepted by
    /// an audit written with the numbers, and the reverse, and the alias and
    /// numeric forms must be one SID to `EqualSid` as well as to
    /// `canonical_sid`.
    #[test]
    fn an_alias_and_its_numeric_sid_are_the_same_account() {
        use windows::Win32::Security::EqualSid;
        let me = current_process_sid().unwrap();
        let la = canonical_sid("LA").expect("the built-in Administrator has a SID here");
        assert!(la.starts_with("S-1-5-21-") && la.ends_with("-500"), "{la}");
        assert_eq!(canonical_sid("SY").unwrap(), LOCAL_SYSTEM_SID);
        assert_eq!(canonical_sid("BA").unwrap(), ADMINISTRATORS_SID);
        assert_eq!(
            canonical_sid(&la).unwrap(),
            la,
            "canonical is a fixed point"
        );
        assert_ne!(canonical_sid("SY").unwrap(), canonical_sid("BA").unwrap());

        // `EqualSid` says the same thing about the same pairs.
        let binary = |s: &str| {
            let w = wide(s);
            let mut p = PSID::default();
            unsafe { ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut p).unwrap() };
            p
        };
        for (alias, numeric, same) in [
            ("LA", la.as_str(), true),
            ("SY", LOCAL_SYSTEM_SID, true),
            ("BA", ADMINISTRATORS_SID, true),
            ("SY", ADMINISTRATORS_SID, false),
        ] {
            let (a, b) = (binary(alias), binary(numeric));
            let equal = unsafe { EqualSid(a, b).is_ok() };
            unsafe {
                LocalFree(Some(HLOCAL(a.0)));
                LocalFree(Some(HLOCAL(b.0)));
            }
            assert_eq!(equal, same, "EqualSid({alias}, {numeric})");
            assert_eq!(
                canonical_sid(alias).unwrap() == canonical_sid(numeric).unwrap(),
                same,
                "canonical_sid agrees with EqualSid for {alias} / {numeric}"
            );
        }

        // A descriptor written with the aliases…
        let dir = temp_path("aliases");
        create_with_sddl(
            &dir,
            &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;LA)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"),
        );
        // …renders with the aliases, which is exactly what a string comparison
        // would have tripped on…
        let rendered = rendered_dacl(&dir);
        assert!(rendered.contains(";LA)"), "{rendered}");
        assert!(!rendered.contains(&format!(";{la})")), "{rendered}");
        // …reads back by value as the numbers…
        let view = path_dacl(&dir).unwrap();
        assert_eq!(
            set_of(view.sids()),
            set_of([
                me.as_str(),
                la.as_str(),
                ADMINISTRATORS_SID,
                LOCAL_SYSTEM_SID
            ])
        );
        // …and is accepted by an audit written either way.
        audit_protected_dir(&dir, &[&me, &la, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID])
            .expect("numeric allow list, aliased descriptor");
        audit_protected_dir(&dir, &[&me, "LA", "BA", "SY"])
            .expect("aliased allow list, aliased descriptor");
        // Taking the built-in Administrator off the list is still a refusal,
        // naming it by number — unless this test *is* the built-in
        // Administrator (a GitHub Windows runner is), in which case `me` is
        // `LA` and keeping `me` keeps it.
        if me != la {
            let err = format!(
                "{:#}",
                audit_protected_dir(&dir, &[&me, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID])
                    .unwrap_err()
            );
            assert!(err.contains(&la), "{err}");
        }
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
        assert_eq!(canonical_sid(&sid).unwrap(), sid, "already canonical");
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
