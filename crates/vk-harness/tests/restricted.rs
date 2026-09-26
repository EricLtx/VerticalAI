//! The restricted-token launch, characterised on Windows (SP1b Task 10 group G).
//!
//! These are the spike's record, not a shipped fence. They are `#[ignore]`d — a
//! founder decision stands between the mechanism here and a shipped restricted
//! harness (see `crates/vk-harness/src/restrict.rs`'s "Measured limit" note and
//! the Task 10 report's `NEEDS_CONTEXT`), so they do not gate CI; run them with
//! `cargo test -p vk-harness --test restricted -- --ignored --test-threads=1`
//! (one thread: they read and set the DACLs of this session's window station
//! and desktop, which every test in the binary shares).
//!
//! What they establish:
//!
//! * `the_mechanism_launches_a_deprivileged_child` — `CreateRestrictedToken` on
//!   this process's own token plus `CreateProcessAsUserW` runs a child and
//!   captures its output (spike 4a(iii), reconfirmed): the plumbing is sound.
//! * `a_restricting_sid_child_cannot_initialise` — the moment a restricting SID
//!   set that could deny the sensitive objects is used, a normal Win32 child
//!   fails at initialisation (`0xC0000142`). This is the measured limit that
//!   makes group G a founder decision rather than a ship. The window-station
//!   and desktop grant it makes is held by a guard, and the test proves both
//!   DACLs come back exactly as they were.
//! * `a_test_that_fails_while_holding_the_grant_still_restores` — the guard
//!   restores on unwinding too, so a failing assertion leaves nothing behind.
//! * `the_winsta_and_desktop_carry_no_restricted_ace` — the session invariant
//!   the two above rely on; run it before and after them for the record.
//! * `strip_restricted_aces_left_by_an_unrestored_run` — the cleanup for a run
//!   that was killed before its guard could restore: it makes such a leftover
//!   itself (grants, then forgets the guard), then removes exactly the grant's
//!   entries and nothing else — any real leftover found on the way goes too.
//!
//! Every DACL comparison here is on the entries as read back (type, flags, mask
//! and the trustee's SID bytes), never on an SDDL rendering (Ruling 35).
#![cfg(windows)]

use std::path::Path;
use std::time::{Duration, Instant};
use vk_harness::restrict::{
    grant_restricted_on_winsta_desktop, grant_restricting_sid, render_aces,
    strip_restricted_from_winsta_desktop, winsta_desktop_aces, AceView, RestrictedChild,
    RestrictedToken, WindowObject,
};

type Dacls = (Vec<AceView>, Vec<AceView>);

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

/// Print both objects' entries under a heading (`--nocapture`): the report's
/// before/after evidence.
fn show(heading: &str, (winsta, desktop): &Dacls) {
    println!(
        "{heading}\n window station:\n{}\n desktop:\n{}",
        render_aces(winsta),
        render_aces(desktop)
    );
}

/// How many entries on (window station, desktop) name `RESTRICTED`.
fn restricted_count((winsta, desktop): &Dacls) -> (usize, usize) {
    let n = |v: &[AceView]| v.iter().filter(|a| a.names_restricted()).count();
    (n(winsta), n(desktop))
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
/// initialise a normal Win32 process on this machine — the measured limit —
/// and the window-station/desktop grant made for the attempt is undone
/// exactly.
#[test]
#[ignore = "group G is a founder decision; run manually with --ignored"]
fn a_restricting_sid_child_cannot_initialise() {
    let ws = tempfile::tempdir().unwrap();
    let cfg = tempfile::tempdir().unwrap();
    grant_restricting_sid(ws.path()).unwrap();
    grant_restricting_sid(cfg.path()).unwrap();

    let before = winsta_desktop_aces().expect("read both DACLs before the grant");
    show("before the grant", &before);
    // The full set the module documents, plus the window station/desktop grant.
    let grant = grant_restricted_on_winsta_desktop().expect("winsta/desktop grant");
    let during = winsta_desktop_aces().expect("read both DACLs while the grant is held");
    show("while the grant is held", &during);
    let (w, d) = restricted_count(&during);
    assert!(
        w >= 1 && d >= 1,
        "the grant must add a RESTRICTED entry to both objects: {w}/{d}"
    );

    let token = RestrictedToken::for_this_process().expect("the restricting token");
    let (code, out) = cmd_echo(&token, ws.path(), cfg.path());

    // Restore explicitly, so a failure to restore fails the test rather than
    // being a line on stderr from the guard's `Drop`.
    grant
        .restore()
        .expect("restore the window station's and desktop's DACLs");
    let after = winsta_desktop_aces().expect("read both DACLs after the restore");
    show("after the guard restored", &after);
    assert_eq!(after, before, "both DACLs must be exactly what they were");
    assert_eq!(
        restricted_count(&after),
        (0, 0),
        "no RESTRICTED entry may remain"
    );

    assert_ne!(
        code, 0,
        "a restricting-SID child is expected to fail to initialise; if this ever runs, the \
         fence can be shipped — revisit group G: {out:?}"
    );
}

/// The guard restores on unwinding: a test that fails while holding the grant
/// still leaves both DACLs exactly as they were.
#[test]
#[ignore = "group G is a founder decision; run manually with --ignored"]
fn a_test_that_fails_while_holding_the_grant_still_restores() {
    let before = winsta_desktop_aces().expect("read both DACLs before");
    let outcome = std::panic::catch_unwind(|| {
        let _grant = grant_restricted_on_winsta_desktop().expect("winsta/desktop grant");
        let during = winsta_desktop_aces().expect("read both DACLs while held");
        assert_ne!(
            restricted_count(&during),
            (0, 0),
            "the grant must be visible"
        );
        panic!("a failing assertion, on purpose, while the grant is held");
    });
    assert!(outcome.is_err(), "the closure must have panicked");
    let after = winsta_desktop_aces().expect("read both DACLs after the unwind");
    show("after the unwind", &after);
    assert_eq!(
        after, before,
        "the guard's Drop must have restored both DACLs"
    );
}

/// The session invariant: neither this window station nor this desktop names
/// `RESTRICTED`. Run it before and after the tests above for the record; if it
/// fails, a run was killed before its guard could restore — run
/// `strip_restricted_aces_left_by_an_unrestored_run`.
#[test]
#[ignore = "reads this session's window station and desktop; run manually with --ignored"]
fn the_winsta_and_desktop_carry_no_restricted_ace() {
    let now = winsta_desktop_aces().expect("read both DACLs");
    show("as found", &now);
    assert_eq!(
        restricted_count(&now),
        (0, 0),
        "a RESTRICTED entry is left over from a run that could not restore"
    );
}

/// The cleanup for a run killed before its guard could restore: remove exactly
/// the entries the grant adds, and nothing else, from both objects. The test
/// makes such a leftover itself — grants and forgets the guard, as a killed
/// process would — so it proves the strip on the shape a real run leaves; a
/// leftover already there when it starts is removed with it.
#[test]
#[ignore = "edits this session's window station and desktop; run manually with --ignored"]
fn strip_restricted_aces_left_by_an_unrestored_run() {
    let found = winsta_desktop_aces().expect("read both DACLs as found");
    show("as found", &found);
    let guard = grant_restricted_on_winsta_desktop().expect("winsta/desktop grant");
    std::mem::forget(guard); // a run killed before its guard could restore
    let before = winsta_desktop_aces().expect("read both DACLs before the strip");
    show(
        "before the strip (a forgotten grant on top of what was found)",
        &before,
    );
    assert_ne!(
        restricted_count(&before),
        (0, 0),
        "the forgotten grant must be visible"
    );
    let (w, d) = strip_restricted_from_winsta_desktop().expect("strip the grant's entries");
    println!("stripped: window station {w}, desktop {d}");
    let after = winsta_desktop_aces().expect("read both DACLs after the strip");
    show("after the strip", &after);
    assert_eq!(
        restricted_count(&after),
        (0, 0),
        "no RESTRICTED entry may remain"
    );
    // Nothing else moved: every entry that is not the grant's is still there,
    // in the same order.
    let kept = |v: &[AceView], on: WindowObject| {
        v.iter()
            .filter(|a| !a.is_the_grant(on))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        kept(&before.0, WindowObject::WindowStation),
        after.0,
        "the window station lost only the grant's entries"
    );
    assert_eq!(
        kept(&before.1, WindowObject::Desktop),
        after.1,
        "the desktop lost only the grant's entries"
    );
}
