//! The restricted-token launch, characterised on Windows (SP1b Task 10 group G).
//!
//! These are the spike's record, not a shipped fence. They are `#[ignore]`d — a
//! founder decision stands between the mechanism here and a shipped restricted
//! harness (see `crates/vk-harness/src/restrict.rs`'s "Measured limit" note and
//! the Task 10 report's `NEEDS_CONTEXT`), so they do not gate CI; run them with
//! `cargo test -p vk-harness --test restricted -- --ignored --test-threads=1`.
//!
//! What they establish:
//!
//! * `the_mechanism_launches_a_deprivileged_child` — `CreateRestrictedToken` on
//!   this process's own token plus `CreateProcessAsUserW` runs a child and
//!   captures its output (spike 4a(iii), reconfirmed): the plumbing is sound.
//! * `a_restricting_sid_child_cannot_initialise` — the moment a restricting SID
//!   set that could deny the sensitive objects is used, a normal Win32 child
//!   fails at initialisation (`0xC0000142`). This is the measured limit that
//!   makes group G a founder decision rather than a ship.
#![cfg(windows)]

use std::path::Path;
use std::time::{Duration, Instant};
use vk_harness::restrict::{grant_restricting_sid, RestrictedChild, RestrictedToken};

/// Run `cmd /c echo hi` under `token`, in `cwd`, to completion (or a deadline),
/// returning its exit code and captured stdout.
fn cmd_echo(token: &RestrictedToken, cwd: &Path, cfg: &Path) -> (i32, String) {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| String::from("C:\\Windows"));
    let out = cfg.join("out.txt");
    let err = cfg.join("err.txt");
    let child = RestrictedChild::spawn(
        token,
        Path::new(&format!("{sysroot}\\System32\\cmd.exe")),
        &["/c".into(), "echo".into(), "hi".into()],
        cwd,
        &out,
        &err,
    )
    .expect("spawn a restricted cmd.exe");
    let deadline = Instant::now() + Duration::from_secs(15);
    let code = loop {
        match child.try_wait().expect("wait") {
            Some(c) => break c,
            None if Instant::now() >= deadline => {
                child.kill();
                break -999;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    (code, std::fs::read_to_string(&out).unwrap_or_default())
}

/// The mechanism runs a deprivileged child (no restricting SIDs): the
/// `CreateRestrictedToken` + `CreateProcessAsUserW` path is sound.
#[test]
#[ignore = "group G is a founder decision; run manually with --ignored"]
fn the_mechanism_launches_a_deprivileged_child() {
    let ws = tempfile::tempdir().unwrap();
    let cfg = tempfile::tempdir().unwrap();
    grant_restricting_sid(ws.path()).unwrap();
    grant_restricting_sid(cfg.path()).unwrap();
    // A deprivileged token, no restricting SIDs: an ordinary child.
    let token = RestrictedToken::build(&[], false, true).expect("a deprivileged token");
    let (code, out) = cmd_echo(&token, ws.path(), cfg.path());
    assert_eq!(code, 0, "the deprivileged child must run: {out:?}");
    assert!(out.contains("hi"), "and produce its output: {out:?}");
}

/// A restricting SID set that could fence the sensitive objects cannot
/// initialise a normal Win32 process on this machine — the measured limit.
#[test]
#[ignore = "group G is a founder decision; run manually with --ignored"]
fn a_restricting_sid_child_cannot_initialise() {
    let ws = tempfile::tempdir().unwrap();
    let cfg = tempfile::tempdir().unwrap();
    grant_restricting_sid(ws.path()).unwrap();
    grant_restricting_sid(cfg.path()).unwrap();
    // The full set the module documents, plus the window station/desktop grant.
    vk_harness::restrict::grant_restricted_on_winsta_desktop().expect("winsta/desktop grant");
    let token = RestrictedToken::for_this_process().expect("the restricting token");
    let (code, out) = cmd_echo(&token, ws.path(), cfg.path());
    assert_ne!(
        code, 0,
        "a restricting-SID child is expected to fail to initialise; if this ever runs, the \
         fence can be shipped — revisit group G: {out:?}"
    );
}
