//! Who the service's endpoint admits.
//!
//! A named pipe created with the default DACL grants the creating account and
//! the local administrators. For a daemon a person starts in their own session
//! that is the right list — it is already their account. For a daemon running
//! as `NT SERVICE\vkd` on a machine that may have other logons it is not: the
//! endpoint is the kernel's first authentication factor (spec §3.11), and
//! "every administrator" is not the same principal as "the human this node
//! serves".
//!
//! So the service's pipe is created with an explicit DACL naming two accounts
//! and nobody else:
//!
//! ```text
//! D:(A;;GA;;;<service SID>)(A;;GA;;;<interactive user SID>)
//! ```
//!
//! The daemon reads its own half off its process token at bind time
//! (`vk_ipc::transport::os::current_process_sid`), so it is right whatever
//! account the service is configured to run as. This module derives the same
//! SID from the *service name* instead, which is what lets `vkd-service
//! install` print the DACL the service will use before the service has ever
//! run — and what lets the SDDL be written down in a plan and checked against
//! `sc.exe showsid vkd`.

use anyhow::Result;

/// The service as the SCM knows it.
pub const SERVICE_NAME: &str = "vkd";
/// The virtual account. `CreateService` with this name and a null password is
/// what makes Windows manage the account itself: no password to store, no
/// password to rotate, a profile and a Credential Manager store of its own.
pub const SERVICE_ACCOUNT: &str = r"NT SERVICE\vkd";
/// The SID Windows gives the virtual account of a service called `name`:
/// `S-1-5-80-` followed by the SHA-1 of the **uppercased** name in UTF-16LE,
/// read as five little-endian 32-bit sub-authorities. This is the derivation
/// `sc.exe showsid <name>` prints, and it needs neither the service to exist
/// nor any privilege to compute — which is the whole reason it is here rather
/// than a `LookupAccountName` call.
pub fn service_account_sid(name: &str) -> String {
    use sha1::{Digest, Sha1};
    let utf16: Vec<u8> = name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha1::digest(&utf16);
    // Five sub-authorities out of twenty bytes; SHA-1 is exactly that long, so
    // the remainder `as_chunks` returns is empty by construction.
    let (words, _) = digest.as_chunks::<4>();
    let mut sid = String::from("S-1-5-80");
    for word in words {
        sid.push('-');
        sid.push_str(&u32::from_le_bytes(*word).to_string());
    }
    sid
}

/// The SDDL the service's pipe is created with, as `install` predicts it.
pub fn pipe_sddl(service_name: &str, user_sid: &str) -> Result<String> {
    vk_ipc::transport::pipe_dacl(&[&service_account_sid(service_name), user_sid])
}

/// The account running `vkd-service install` — the default for `--user-sid`.
/// An elevated shell is the same account as the desktop that raised it (the
/// token differs, the user SID does not), so this is the interactive user even
/// though `install` must be run elevated.
#[cfg(windows)]
pub fn interactive_user_sid() -> Result<String> {
    vk_ipc::transport::os::current_process_sid()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sc.exe showsid vkd` on this machine, 2026-09-25 — the derivation is
    /// checked against Windows itself, not only against itself.
    const VKD_SID: &str = "S-1-5-80-2321736676-1855261038-2536180385-746309522-2788627728";
    const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn the_vkd_virtual_account_has_the_sid_sc_showsid_prints() {
        assert_eq!(service_account_sid(SERVICE_NAME), VKD_SID);
    }

    /// The published SID of `NT SERVICE\TrustedInstaller`: a value Microsoft
    /// documents, so a test that passes it is testing the algorithm rather
    /// than this implementation's own output.
    /// `vk-ipc` carries the same SID as a constant, because a *client* must
    /// know which account may be serving the machine-wide pipe before it
    /// trusts anything on it, and `vk-ipc` cannot call this crate. The two may
    /// never drift.
    #[test]
    fn the_constant_the_client_checks_against_is_this_same_sid() {
        assert_eq!(
            service_account_sid(SERVICE_NAME),
            vk_ipc::transport::VKD_SERVICE_SID
        );
    }

    #[test]
    fn the_derivation_matches_a_service_sid_microsoft_publishes() {
        assert_eq!(
            service_account_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
    }

    #[test]
    fn the_name_is_uppercased_before_it_is_hashed() {
        assert_eq!(service_account_sid("VKD"), service_account_sid("vkd"));
        assert_eq!(service_account_sid("Vkd"), VKD_SID);
    }

    #[test]
    fn the_pipe_dacl_is_the_two_accounts_and_nobody_else() {
        assert_eq!(
            pipe_sddl(SERVICE_NAME, USER).unwrap(),
            format!("D:(A;;GA;;;{VKD_SID})(A;;GA;;;{USER})")
        );
    }

    #[test]
    fn a_user_sid_that_is_not_a_sid_never_reaches_the_dacl() {
        for bad in ["BA", "MACHINE\\eric", "S-1-5-21-1-2-3-1001)(A;;GA;;;WD"] {
            assert!(
                pipe_sddl(SERVICE_NAME, bad).is_err(),
                "{bad:?} must not become an ACE"
            );
        }
    }
}
