//! String SIDs, for the two places a Windows access list is written down: the
//! endpoint's DACL (`vk_ipc::transport::pipe_dacl`) and the state directory's
//! (`win_acl`). Both build SDDL by concatenation, so what may go into one is
//! decided once, here, on every platform — Linux and macOS CI check the same
//! rule even though only Windows can hand the result to the kernel.

use anyhow::{ensure, Context, Result};

/// `S-1-<authority>-<sub>-…`, every part a decimal number. Deliberately
/// narrower than SDDL allows: no two-letter aliases (`BA`, `IU`), no hex
/// authorities. Everything this node puts in an access list is a SID somebody
/// read off `whoami /user` or `sc showsid`, and a string that is not one is a
/// mistake worth refusing — the more so because these lists are built by
/// concatenation, where a string carrying `)` and `(` would write its own
/// entries.
pub fn ensure_string_sid(sid: &str) -> Result<()> {
    let parts = sid
        .strip_prefix("S-1-")
        .with_context(|| format!("{sid:?} is not a string SID: it does not start with S-1-"))?;
    ensure!(
        parts
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "{sid:?} is not a string SID: every part after S-1- must be a decimal number"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_sid_is_accepted() {
        for good in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "S-1-5-80-2321736676-1855261038-2536180385-746309522-2788627728",
        ] {
            ensure_string_sid(good).unwrap();
        }
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "BA",
            "S-1-",
            "S-1-5--21",
            "Administrators",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD",
            "s-1-5-18",
            "",
        ] {
            let err = ensure_string_sid(bad).unwrap_err().to_string();
            assert!(err.contains("not a string SID"), "{bad:?}: {err}");
        }
    }
}
