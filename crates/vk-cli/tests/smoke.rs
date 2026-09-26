//! The usable milestone, end to end: a real `vkd` over a real endpoint, driven
//! by the real `vk` binary exactly as a person would drive it from a shell —
//! separate processes, argv in, exit code and stdout out. Nothing here links
//! the kernel, so what it proves is what a user gets.
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the daemon is given to answer its first request.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The daemon, killed however the test leaves — a failed assertion unwinds
/// through this, so a panicking test cannot leave a `vkd` holding the endpoint.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vk_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vk"))
}

/// `vkd` is a package of its own, so testing `vk-cli` does not build it. It
/// belongs next to `vk` — same target directory, same profile — and is built
/// here (`CARGO_TARGET_DIR` is inherited, so the build lands in the same place
/// this test looks).
///
/// Always built, never "only if the file is missing": a `vkd` left over from
/// an earlier checkout is exactly the binary that would make these tests pass
/// against code nobody is looking at. A fresh one makes the build a no-op.
///
/// Once per process, under a lock: the tests in this file run on threads of
/// one process and each wants `vkd`, and two `cargo build`s on one target
/// directory serialise on cargo's own lock at best and race the file this
/// function is about to hand out at worst.
fn vkd_exe() -> PathBuf {
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(|| {
        // Captured, not inherited: a no-op build has nothing to say, and the
        // one time it does have something the message is in the failure.
        // `vk-mcp` too: the daemon refuses to launch a harness without it
        // beside itself (a tool-less Claude is not a run), so the harness
        // tests need it built even when only this crate is under test.
        let out = Command::new(env!("CARGO"))
            .args(["build", "-p", "vkd", "-p", "vk-mcp"])
            .output()
            .expect("run cargo");
        assert!(
            out.status.success(),
            "cargo build -p vkd -p vk-mcp failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
    let path = vk_exe().with_file_name(format!("vkd{}", std::env::consts::EXE_SUFFIX));
    assert!(path.exists(), "no vkd next to vk at {}", path.display());
    path
}

/// A `vk` invocation with the environment a user's shell would carry.
struct Shell {
    endpoint: String,
    node_key: PathBuf,
}

impl Shell {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(vk_exe())
            .args(args)
            .env("VK_ENDPOINT", &self.endpoint)
            .env("VK_NODE_KEY_FILE", &self.node_key)
            .output()
            .expect("run vk")
    }

    /// The same, with something on stdin: `vk fsck --rebase-head` reads the
    /// typed confirmation from there, and a test types it the way a person
    /// would.
    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut child = Command::new(vk_exe())
            .args(args)
            .env("VK_ENDPOINT", &self.endpoint)
            .env("VK_NODE_KEY_FILE", &self.node_key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run vk");
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write the confirmation");
        child.wait_with_output().expect("vk")
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert!(
            o.status.success(),
            "vk {args:?} exited {:?}: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).expect("vk printed non-utf-8")
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.ok(args);
        serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("vk {args:?} did not print JSON ({e}):\n{out}"))
    }
}

fn str_of<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string field {field} in {v}"))
}

/// The `kind` of every event a `vk dmesg --json` tail carries, in order.
fn dmesg_kinds(tail: &Value) -> Vec<&str> {
    tail.as_array()
        .unwrap_or_else(|| panic!("dmesg --json is not an array: {tail}"))
        .iter()
        .map(|e| str_of(e, "kind"))
        .collect()
}

/// One `vk status --json`: the answer when a daemon is serving this shell's
/// endpoint, nothing when none is.
fn serving(sh: &Shell) -> Option<Value> {
    let o = sh.run(&["status", "--json"]);
    o.status
        .success()
        .then(|| serde_json::from_slice(&o.stdout).expect("status JSON"))
}

/// A daemon this test knows only by pid — which is all `vk boot --json` gives
/// a caller, and so exactly what it must be enough to stop it with.
struct Detached(u64);

impl Detached {
    fn kill(&self) {
        let pid = self.0.to_string();
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("taskkill");
            c.args(["/F", "/PID", &pid]);
            c
        } else {
            let mut c = Command::new("kill");
            c.args(["-9", &pid]);
            c
        };
        let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

impl Drop for Detached {
    fn drop(&mut self) {
        self.kill();
    }
}

#[test]
fn the_vk_shell_drives_a_task_from_mount_to_release() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let mut daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };

    // The daemon is up when it answers a request, not when it was spawned.
    let start = Instant::now();
    let status = loop {
        let o = sh.run(&["status", "--json"]);
        if o.status.success() {
            break serde_json::from_slice::<Value>(&o.stdout).expect("status JSON");
        }
        if let Ok(Some(exit)) = daemon.0.try_wait() {
            panic!("vkd exited before serving: {exit:?}");
        }
        assert!(
            start.elapsed() < READY_TIMEOUT,
            "vkd did not answer within {READY_TIMEOUT:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status["ledger_ok"], true, "{status}");
    let export_root = PathBuf::from(str_of(&status, "export_root"));

    // An arch to run the task on, and the namespace showing it.
    let arch = str_of(
        &sh.json(&["mount", "mock", "m1", "--ctx", "4096", "--json"]),
        "arch_id",
    )
    .to_string();
    let ls = sh.json(&["ls", "/arches", "--json"]);
    assert!(
        ls["arches"]
            .as_array()
            .expect("arches")
            .iter()
            .any(|a| a["arch_id"].as_str() == Some(arch.as_str())),
        "mounted arch missing from /arches: {ls}"
    );

    // A task that plans, drafts, waits for a human and releases.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Draft a proposal",
            "--artefact",
            "proposal",
            "--plan",
            &arch,
            "--draft",
            &arch,
            "--approve",
            "--release",
            "out",
            "--json",
        ]),
        "id",
    )
    .to_string();
    let waiting = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(waiting["status"], "waiting_human", "{waiting}");

    // STOP is a human act: the CLI signs it with the node device key. Nothing
    // steps while it holds.
    let stop_id = str_of(&sh.json(&["stop", "--json"]), "stop_id").to_string();
    let refused = sh.run(&["task", "step", &task, "--all"]);
    assert!(
        !refused.status.success(),
        "a stopped node must refuse a step"
    );
    let why = String::from_utf8_lossy(&refused.stderr);
    assert!(why.contains("stopped"), "{why}");

    // Resumed, approved by the same device, and the task runs to its release.
    sh.ok(&["resume", &stop_id]);
    let approved = sh.json(&["approve", &task, "--json"]);
    assert_eq!(approved["ok"], true, "{approved}");
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");
    let released: Vec<_> = std::fs::read_dir(export_root.join("out"))
        .expect("export directory")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(released.len(), 1, "one released artefact: {released:?}");
    assert!(
        released[0].ends_with(".proposal"),
        "released under the task's artefact type: {released:?}"
    );

    // The record of all of it, still intact.
    let verified = sh.json(&["ledger", "verify", "--json"]);
    assert_eq!(verified["ok"], true, "{verified}");
    let tail = sh.json(&["dmesg", "-n", "5", "--json"]);
    assert_eq!(tail.as_array().expect("events").len(), 5, "{tail}");
}

/// The shell verbs an operator uses on the arches themselves and on the store
/// under them: mount one, read it in full, take it away again, and verify
/// everything the node holds.
///
/// `vk fsck` is the point of this test. `vk ledger verify` answers one
/// question — does the chain recompute — and a node can pass it with every
/// blob on disk unreadable; this is the whole store, tier by tier, and a
/// healthy one must come back green with counts that say what was looked at.
#[test]
fn vk_arch_show_umount_and_fsck_cover_the_arches_and_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");

    let arch = str_of(
        &sh.json(&["mount", "mock", "m1", "--ctx", "4096", "--json"]),
        "arch_id",
    )
    .to_string();

    // `vk arch show`: the manifest, the state, and the two things a listing
    // has no room for — the identity tuple the arch id hashes, and the
    // clearance the arch may be handed.
    let shown = sh.json(&["arch", "show", &arch, "--json"]);
    assert_eq!(str_of(&shown, "arch_id"), arch, "{shown}");
    assert_eq!(str_of(&shown, "state"), "ready", "{shown}");
    assert_eq!(str_of(&shown, "kind"), "mock", "{shown}");
    assert!(
        shown["manifest"]["identity"]["engine"].is_string(),
        "the identity tuple is on the answer: {shown}"
    );
    assert!(
        shown["manifest"]["clearance"]["max_scope"].is_string(),
        "{shown}"
    );
    let page = sh.ok(&["arch", "show", &arch]);
    for named in [arch.as_str(), "identity", "clearance", "ready"] {
        assert!(page.contains(named), "{named} missing from:\n{page}");
    }
    // An id nobody mounted is not found, rather than an empty page.
    assert!(!sh.run(&["arch", "show", "sha256:nope"]).status.success());

    // A task, so the store has a blob, a register and a task row to verify.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Draft a note",
            "--plan",
            &arch,
            "--draft",
            &arch,
            "--json",
        ]),
        "id",
    )
    .to_string();
    assert_eq!(
        sh.json(&["task", "step", &task, "--all", "--json"])["status"],
        "done"
    );

    // The whole store, green, with the tiers named and counted.
    let report = sh.json(&["fsck", "--json"]);
    assert_eq!(report["ok"], true, "{report}");
    let tiers: std::collections::BTreeMap<String, Value> = report["tiers"]
        .as_array()
        .expect("tiers")
        .iter()
        .map(|t| (str_of(t, "tier").to_string(), t.clone()))
        .collect();
    for named in ["ledger", "head", "blobs", "keys", "mounts"] {
        let t = tiers
            .get(named)
            .unwrap_or_else(|| panic!("no {named} tier in {report}"));
        assert_eq!(t["ok"], true, "{named}: {t}");
    }
    assert!(
        tiers["ledger"]["checked"].as_u64().unwrap_or(0) > 0,
        "the chain was actually walked: {report}"
    );
    assert!(
        tiers["blobs"]["checked"].as_u64().unwrap_or(0) > 0,
        "the task left a blob and it was actually opened: {report}"
    );
    assert_eq!(tiers["mounts"]["checked"], 1, "{report}");
    let screen = sh.ok(&["fsck"]);
    assert!(screen.contains("the store verifies"), "{screen}");
    assert!(screen.contains("TIER"), "{screen}");

    // And `vk umount` says what it took away, after which the arch is gone
    // from every listing and `fsck` counts one mount fewer.
    let gone = sh.ok(&["umount", &arch]);
    assert!(gone.contains(&arch), "{gone}");
    assert!(!sh.ok(&["ls", "/arches"]).contains(&arch));
    let report = sh.json(&["fsck", "--json"]);
    assert_eq!(report["ok"], true, "{report}");
}

/// A record whose tail was cut — what a restore of an older copy of the
/// segment leaves, and what a tail somebody deleted leaves: the same bytes.
/// `vk fsck` says which tier failed and exits non-zero; `--rebase-head
/// --force`, with the word typed out, is the documented way back, and it is
/// on the record afterwards.
#[test]
fn vk_fsck_reports_a_cut_record_and_the_typed_rebase_is_the_way_back() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        sh.ok(&["mount", "mock", "m1", "--ctx", "4096"]);
        sh.ok(&["stop"]);
    }
    wait_until(&sh, false, "the killed daemon still holds the endpoint");
    cut_ledger_tail(dir.path());

    // The node will not serve a cut record, so `fsck` is reached the way an
    // operator reaches it: under --force, which is what --force is for.
    let _forced = Daemon(
        vkd_cmd(dir.path(), &endpoint, &["--force"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    wait_until(&sh, true, "--force did not start a daemon").expect("status");

    let refused = sh.run(&["fsck"]);
    assert!(
        !refused.status.success(),
        "a store that does not verify must exit non-zero"
    );
    let screen = String::from_utf8_lossy(&refused.stdout).to_string();
    assert!(screen.contains("FAILED"), "{screen}");
    assert!(
        screen.contains("head: the record no longer contains"),
        "the failing tier and its reason belong on the screen:\n{screen}"
    );
    assert!(
        screen.contains("--rebase-head"),
        "and the way back:\n{screen}"
    );
    // The chain that is left still links: this is a head failure, not a
    // rewritten record, and the two must not read the same.
    let report: Value = serde_json::from_slice(&sh.run(&["fsck", "--json"]).stdout).expect("json");
    let tier = |name: &str| {
        report["tiers"]
            .as_array()
            .expect("tiers")
            .iter()
            .find(|t| t["tier"] == name)
            .unwrap_or_else(|| panic!("no {name} tier in {report}"))
            .clone()
    };
    assert_eq!(report["ok"], false, "{report}");
    assert_eq!(tier("ledger")["ok"], true, "{report}");
    assert_eq!(tier("head")["ok"], false, "{report}");

    // A flag is not a confirmation: the word has to be typed, and anything
    // else leaves the head exactly where it was.
    let mistyped = sh.run_with_stdin(&["fsck", "--rebase-head", "--force"], "yes\n");
    assert!(!mistyped.status.success(), "a mistyped word must refuse");
    let why = String::from_utf8_lossy(&mistyped.stderr);
    assert!(why.contains("not confirmed"), "{why}");
    let report: Value = serde_json::from_slice(&sh.run(&["fsck", "--json"]).stdout).expect("json");
    assert_eq!(report["ok"], false, "the head was not touched: {report}");

    // Typed out: the head moves, both ends are named, and the store verifies.
    let done = sh.run_with_stdin(&["fsck", "--rebase-head", "--force"], "rebase\n");
    let screen = String::from_utf8_lossy(&done.stdout).to_string();
    assert!(
        done.status.success(),
        "{screen}{}",
        String::from_utf8_lossy(&done.stderr)
    );
    assert!(screen.contains("the store verifies"), "{screen}");
    assert!(
        screen.contains("the recorded ledger head was moved"),
        "{screen}"
    );

    // A second rebase — a no-op on a store that is now healthy — must
    // **add** to the record, not replace the real one (review Important 1).
    // The person who did the first already holds the presence the second
    // needs; the mechanism exists to stop exactly them from denying it.
    let again = sh.run_with_stdin(&["fsck", "--rebase-head", "--force"], "rebase\n");
    assert!(again.status.success(), "{:?}", again.status);
    let report: Value = serde_json::from_slice(&sh.run(&["fsck", "--json"]).stdout).expect("json");
    let history = report["rebases"].as_array().expect("a rebase history");
    assert_eq!(history.len(), 2, "both are on record: {report}");
    // The first one really moved the head — off the event the cut record
    // used to end at, onto the one it ends at now (the same seq, since the
    // forced boot appended two events of its own, but not the same event).
    assert_ne!(
        history[0]["rebased_from"]["hash"], history[0]["rebased_to"]["hash"],
        "the first rebase is unchanged and is the real one: {report}"
    );
    // And the second is the no-op that used to overwrite it.
    assert_eq!(
        history[1]["rebased_from"]["hash"], history[1]["rebased_to"]["hash"],
        "{report}"
    );
    drop(_forced);
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    // And the node serves again without --force, because the record and the
    // head now agree. The override is in what that boot said, beside the
    // `boot` event whose payload commits to it.
    let log_path = dir.path().join("boot.log");
    let log_file = std::fs::File::create(&log_path).expect("a log to read back");
    let _again = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            // The daemon's own log goes to stdout (`vkd::init_tracing`), and
            // `vk boot` is what usually redirects it into `vkd.log`; here the
            // test does the redirecting, because the daemon was spawned
            // directly.
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&sh, true, "the rebased node did not serve").expect("status");
    assert_eq!(status["ledger_ok"], true, "{status}");
    assert_eq!(status["forced"], false, "{status}");
    let log = std::fs::read_to_string(&log_path).expect("the boot log");
    assert!(
        log.contains("rebased by hand"),
        "the boot that followed the rebase says so:\n{log}"
    );
    assert_eq!(sh.json(&["fsck", "--json"])["ok"], true);

    // And it is on a surface a live operator reads, not only in whatever
    // file the daemon's stdout went to (review Important 2). Both rebases,
    // for as long as the node exists — a boot does not clear them.
    assert_eq!(
        status["fsck"].as_array().map(Vec::len),
        Some(2),
        "`boot.info` carries the history: {status}"
    );
    let screen = sh.ok(&["status"]);
    assert!(screen.contains("head rebased"), "{screen}");
    assert_eq!(
        sh.json(&["fsck", "--json"])["rebases"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "and so does `vk fsck --json`"
    );
}

/// The review's Critical 1, end to end: cutting the tail **and** deleting the
/// one SQLite row that says where the record ended.
///
/// Cutting alone is caught by the recorded head. Cutting and removing the head
/// row used to be caught by nothing at all: the node served with no `--force`,
/// `vk status` said `chain verified`, and the whole-store verifier printed
/// "the store verifies" and exited 0 — one `DELETE` turning a detectable
/// tamper into an attested-clean node. The head is written on every append, so
/// a record with no head recorded for it is a row somebody removed.
#[test]
fn vk_fsck_refuses_a_record_whose_head_row_was_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        sh.ok(&["mount", "mock", "m1", "--ctx", "4096"]);
        sh.ok(&["stop"]);
    }
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    cut_ledger_tail(dir.path());
    delete_recorded_head(dir.path());

    // The node must refuse to serve on it, exactly as it refuses a cut tail
    // whose head row is still there.
    let refused = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vkd"),
    );
    let (exit, why) = exit_of(refused, "vkd is serving a record with no recorded head");
    assert!(!exit.success(), "{exit:?}: {why}");
    assert!(why.contains("ledger") && why.contains("--force"), "{why}");
    assert!(serving(&sh).is_none(), "nothing is serving that store");

    // Forced, so `vk fsck` can be reached at all — and it names the tier.
    let _forced = Daemon(
        vkd_cmd(dir.path(), &endpoint, &["--force"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&sh, true, "--force did not start a daemon").expect("status");
    assert_eq!(status["ledger_ok"], false, "{status}");
    assert_eq!(status["forced"], true, "{status}");

    let out = sh.run(&["fsck"]);
    assert!(!out.status.success(), "a deleted head row must exit 1");
    let screen = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        screen.contains("head: no recorded head for a non-empty chain"),
        "the tier and the reason belong on the screen:\n{screen}"
    );
    assert!(screen.contains("the store DOES NOT verify"), "{screen}");
    let report: Value = serde_json::from_slice(&sh.run(&["fsck", "--json"]).stdout).expect("json");
    assert_eq!(report["ok"], false, "{report}");
    for t in report["tiers"].as_array().expect("tiers") {
        let expected = t["tier"] != "head";
        assert_eq!(t["ok"], expected, "only the head tier fails: {report}");
    }

    // And the rebase is the way back here too, naming no previous head
    // because there was none on record.
    let done = sh.run_with_stdin(&["fsck", "--rebase-head", "--force"], "rebase\n");
    let screen = String::from_utf8_lossy(&done.stdout).to_string();
    assert!(done.status.success(), "{screen}");
    assert!(screen.contains("nothing recorded"), "{screen}");
    // On the record for good, and on the screen a live operator reads.
    assert!(
        screen.contains("re-recorded by hand"),
        "the history is in the report:\n{screen}"
    );
    drop(_forced);
    wait_until(&sh, false, "the killed daemon still holds the endpoint");
    let _again = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&sh, true, "the rebased node did not serve").expect("status");
    assert_eq!(status["ledger_ok"], true, "{status}");
    assert_eq!(
        status["fsck"].as_array().map(Vec::len),
        Some(1),
        "the rebase is on `boot.info` for good, not only in a log line: {status}"
    );
    assert!(
        sh.ok(&["status"]).contains("head rebased"),
        "and `vk status` marks it: {}",
        sh.ok(&["status"])
    );
}

/// A blob whose bytes are not what its address says — a `.bin` restored from
/// the wrong backup, a flipped byte on a failing disk. Nothing else on the
/// node notices until somebody reads that one artefact; `fsck` reads all of
/// them.
#[test]
fn vk_fsck_finds_a_tampered_blob_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        let arch = str_of(
            &sh.json(&["mount", "mock", "m1", "--ctx", "4096", "--json"]),
            "arch_id",
        )
        .to_string();
        let task = str_of(
            &sh.json(&[
                "task",
                "submit",
                "--goal",
                "Draft a note",
                "--plan",
                &arch,
                "--draft",
                &arch,
                "--json",
            ]),
            "id",
        )
        .to_string();
        assert_eq!(
            sh.json(&["task", "step", &task, "--all", "--json"])["status"],
            "done"
        );
        assert_eq!(sh.json(&["fsck", "--json"])["ok"], true);
    }
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    // One ciphertext byte flipped, with the node gone — as a bad restore or
    // a failing disk would leave it.
    let blobs = dir.path().join("blobs");
    let bin = std::fs::read_dir(&blobs)
        .expect("a blob directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "bin"))
        .expect("the task left a blob");
    let mut bytes = std::fs::read(&bin).expect("read the blob");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&bin, bytes).expect("write the blob");

    // The node still boots — a damaged blob is not a damaged chain — and
    // that is exactly why `fsck` has to be the thing that finds it.
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&sh, true, "vkd did not answer").expect("status");
    assert_eq!(
        status["ledger_ok"], true,
        "the record is untouched; the payload tier is not: {status}"
    );
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);

    let refused = sh.run(&["fsck"]);
    assert!(!refused.status.success(), "a damaged blob must exit 1");
    let screen = String::from_utf8_lossy(&refused.stdout).to_string();
    assert!(screen.contains("FAILED"), "{screen}");
    assert!(
        screen.contains("blobs: sha256:") && screen.contains("integrity"),
        "the failing blob is named, by address:\n{screen}"
    );
    let report: Value = serde_json::from_slice(&sh.run(&["fsck", "--json"]).stdout).expect("json");
    assert_eq!(report["ok"], false, "{report}");
    for t in report["tiers"].as_array().expect("tiers") {
        let expected = t["tier"] != "blobs";
        assert_eq!(
            t["ok"], expected,
            "only the payload tier is damaged: {report}"
        );
    }
}

/// A scripted stand-in for `claude` at `dir/fake-claude.{cmd,sh}`: it answers
/// `--version`, swallows the prompt on stdin and prints one canned result
/// object. Enough for `vk mount claude-code --bin` to mount a real adapter and
/// for a task to run through it, without a subscription, a network or a cost.
fn fake_claude(dir: &std::path::Path) -> PathBuf {
    let reply = dir.join("reply.json");
    std::fs::write(
        &reply,
        r#"{"type":"result","subtype":"success","is_error":false,"duration_ms":120,
            "duration_api_ms":90,"num_turns":1,"result":"a stand-in completion",
            "session_id":"smoke-1","total_cost_usd":0.002,
            "usage":{"input_tokens":7,"cache_creation_input_tokens":11,
                     "cache_read_input_tokens":23,"output_tokens":5}}"#,
    )
    .expect("write the canned reply");
    let bin = dir.join(if cfg!(windows) {
        "fake-claude.cmd"
    } else {
        "fake-claude.sh"
    });
    let (r, script) = (
        path_of(&reply),
        if cfg!(windows) {
            "@echo off\r\nif \"%~1\"==\"--version\" (\r\n  echo 0.0.0-smoke\r\n  exit /b 0\r\n)\r\n\
         findstr \"^\" >nul\r\ntype \"{R}\"\r\nexit /b 0\r\n"
        } else {
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 0.0.0-smoke; exit 0; fi\n\
         cat >/dev/null\ncat '{R}'\n"
        },
    );
    std::fs::write(&bin, script.replace("{R}", &r)).expect("write the stand-in");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).expect("chmod +x");
    }
    bin
}

/// `vk mount claude-code` is the first verb that mounts a *real* adapter: two
/// arches in one call, a draft and a judge, each named for its model and each
/// with its own content-addressed id. Driven against the stand-in via `--bin`,
/// so this test needs no subscription and spends nothing.
#[test]
fn vk_mounts_two_claude_code_arches_and_a_task_runs_through_one() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");

    let claude = path_of(&fake_claude(dir.path()));
    let mounted = sh.json(&[
        "mount",
        "claude-code",
        "--bin",
        &claude,
        "--draft-model",
        "claude-sonnet-5",
        "--judge-model",
        "claude-opus-5",
        "--json",
    ]);
    let draft = str_of(&mounted["draft"], "arch_id").to_string();
    let judge = str_of(&mounted["judge"], "arch_id").to_string();
    assert_eq!(
        str_of(&mounted["draft"], "name"),
        "claude-code/claude-sonnet-5"
    );
    assert_eq!(
        str_of(&mounted["judge"], "name"),
        "claude-code/claude-opus-5"
    );
    assert_ne!(draft, judge, "two models are two arches: {mounted}");

    // Both are in the namespace, and the human rendering names both.
    let ls = sh.ok(&["ls", "/arches"]);
    for id in [&draft, &judge] {
        assert!(ls.contains(id.as_str()), "{id} missing from /arches:\n{ls}");
    }
    let plain = sh.ok(&[
        "mount",
        "claude-code",
        "--bin",
        &claude,
        "--draft-model",
        "claude-sonnet-5",
        "--judge-model",
        "claude-opus-5",
    ]);
    assert!(
        plain.contains("draft") && plain.contains("judge"),
        "{plain}"
    );
    assert!(plain.contains("claude-code/claude-opus-5"), "{plain}");

    // And the adapter really drives the child: a task runs to completion on it.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Say something",
            "--plan",
            &draft,
            "--draft",
            &draft,
            "--json",
        ]),
        "id",
    )
    .to_string();
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");
    // Both steps went out through the adapter and came back, so the arch has
    // two calls on its counters — and, because this arch measures its own
    // usage, what it measured rather than what the kernel estimated: the
    // stand-in reports 7 + 11 + 23 prompt tokens and 0.002 USD a call.
    let top = sh.json(&["top", "--json"]);
    let stats = &top["arches"][&draft];
    assert_eq!(stats["calls"], 2, "{top}");
    assert_eq!(stats["tokens_in"], 2 * (7 + 11 + 23), "{top}");
    assert_eq!(
        stats["tokens_in_measured"], stats["tokens_in"],
        "every call on this arch was measured, so none of the total is a guess: {top}"
    );
    let cost = stats["cost_list_usd"].as_f64().unwrap_or_default();
    assert!((cost - 0.004).abs() < 1e-9, "{top}");

    // A cloud arch says so, and says under whose law it answered, on the
    // same row as what it cost (SP1b Task 8).
    assert_eq!(top["locality"][&draft], "cloud", "{top}");
    assert_eq!(top["jurisdiction"][&draft], "US", "{top}");
    // The judge arch was never called, and is on the screen all the same:
    // an operator must not have to run an arch to find out it is mounted.
    assert_eq!(top["arches"][&judge]["calls"], 0, "{top}");

    // And a person reading `vk top` sees both, not only the hash of them.
    let screen = sh.ok(&["top"]);
    assert!(
        screen.contains("MEASURED") && screen.contains("COST"),
        "{screen}"
    );
    assert!(
        screen.contains("LOCALITY") && screen.contains("JURISDICTION"),
        "{screen}"
    );
    assert!(
        screen.contains("0.00400"),
        "the cost belongs on the screen:\n{screen}"
    );
    assert!(
        screen.lines().any(|l| l.starts_with(&judge)),
        "the never-called arch has a row of its own:\n{screen}"
    );

    // `--calls`: the rows behind the totals, each naming the step that spent
    // it — which the totals alone can never say (ruling 8).
    let calls = sh.json(&["top", "--calls", "--json"]);
    let rows = calls["calls"].as_array().expect("calls");
    assert_eq!(rows.len(), 2, "one row per completed call: {calls}");
    for r in rows {
        assert_eq!(str_of(r, "arch_id"), draft, "{r}");
        assert_eq!(str_of(r, "task_id"), task, "{r}");
        assert_eq!(r["tokens_in_measured"], 7 + 11 + 23, "{r}");
        assert_eq!(r["tokens_out"], 5, "{r}");
    }
    assert_eq!(
        rows.iter().map(|r| &r["step_index"]).collect::<Vec<_>>(),
        [&serde_json::json!(0), &serde_json::json!(1)],
        "in the order the steps ran: {calls}"
    );
    let screen = sh.ok(&["top", "--calls"]);
    assert!(
        screen.contains("CALL") && screen.contains(&task),
        "{screen}"
    );

    // And the task's own screen carries what each of its steps returned and
    // cost, beside the tokens it sent.
    let shown = sh.json(&["task", "show", &task, "--json"]);
    assert_eq!(
        shown["usage"].as_array().expect("usage").len(),
        2,
        "{shown}"
    );
    let page = sh.ok(&["task", "show", &task]);
    assert!(page.contains("OUT") && page.contains("COST"), "{page}");
    assert!(page.contains("0.00200"), "{page}");

    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// A stand-in Ollama on loopback: `/api/version`, `/api/tags`, `/api/show`, a
/// 404 on `/api/tokenize` exactly as 0.33.3 gives, and one canned completion.
/// Enough for `vk mount ollama --external` to mount a *real* adapter and for a
/// task to run through it, without Docker, a model or nine gigabytes.
///
/// It serves from a thread of this test process, so the daemon — a separate
/// process — reaches it over a loopback socket, which is the same path a real
/// Ollama is reached by.
struct FakeOllama {
    url: String,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeOllama {
    fn drop(&mut self) {
        // The thread is blocked in `accept`; one connection wakes it so it can
        // see the flag. Nothing is joined: a failing test must not also hang.
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
    }
}

impl FakeOllama {
    fn start(model: &str) -> FakeOllama {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let stop = Arc::new(AtomicBool::new(false));
        let (model, flag) = (model.to_string(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let Some(path) = ollama_request_path(&stream) else {
                    continue;
                };
                let (status, kind, body) = ollama_answer(&path, &model);
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n",
                    body.len()
                );
                use std::io::Write;
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });
        FakeOllama { url, stop }
    }
}

/// The five answers spike 1a measured, canned.
fn ollama_answer(path: &str, model: &str) -> (&'static str, &'static str, String) {
    const JSON: &str = "application/json";
    match path {
        "/api/version" => ("200 OK", JSON, r#"{"version":"0.33.3"}"#.into()),
        "/api/tags" => (
            "200 OK",
            JSON,
            format!(
                r#"{{"models":[{{"name":"{model}","digest":"8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc"}}]}}"#
            ),
        ),
        "/api/show" => (
            "200 OK",
            JSON,
            r#"{"details":{"family":"gemma3","parameter_size":"999.89M","quantization_level":"Q4_K_M"},
                "model_info":{"gemma3.context_length":32768}}"#
                .into(),
        ),
        // 0.33.3 has no tokenizer endpoint, and says so in plain text.
        "/api/tokenize" => ("404 Not Found", "text/plain", "404 page not found".into()),
        "/api/chat" => (
            "200 OK",
            JSON,
            r#"{"message":{"role":"assistant","content":"a stand-in completion"},
                "done":true,"done_reason":"stop","prompt_eval_count":42,"eval_count":5,
                "eval_duration":900000000,"load_duration":250000000}"#
                .into(),
        ),
        _ => ("404 Not Found", JSON, r#"{"error":"no such route"}"#.into()),
    }
}

/// The path off the request line, with the body drained so the client is never
/// left writing into a socket nobody is reading.
fn ollama_request_path(stream: &std::net::TcpStream) -> Option<String> {
    use std::io::{BufRead, Read};
    let mut reader = std::io::BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split_whitespace().nth(1)?.to_string();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 || header.trim_end().is_empty() {
            break;
        }
        if let Some(v) = header
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|v| v.parse::<usize>().ok())
        {
            length = v;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some(path)
}

/// `vk mount ollama` is the verb that mounts the *governed* kind of arch — and
/// the one that has to be honest when it is not governed. Driven against the
/// stand-in with `--external`, which is exactly the ungoverned case: the
/// daemon did not start that server and cannot cap it, so the mount says so,
/// and `vk top` keeps saying so for every call made on it.
#[test]
fn vk_mounts_an_external_ollama_as_ungoverned_and_a_task_runs_through_it() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");

    let ollama = FakeOllama::start("gemma3:1b");
    let mounted = sh.json(&[
        "mount",
        "ollama",
        "--model",
        "gemma3:1b",
        "--external",
        &ollama.url,
        "--ctx",
        "8192",
        "--json",
    ]);
    let arch = str_of(&mounted, "arch_id").to_string();
    assert_eq!(str_of(&mounted, "name"), "ollama/gemma3:1b");
    assert_eq!(
        mounted["governed"], false,
        "a server this node did not start is not one it governs: {mounted}"
    );
    assert_eq!(
        mounted["already_mounted"], false,
        "the first mount mounts it: {mounted}"
    );

    // Mounting it again is the same arch, said so, and nothing swapped
    // underneath it (Ruling 13).
    let again = sh.json(&[
        "mount",
        "ollama",
        "--model",
        "gemma3:1b",
        "--external",
        &ollama.url,
        "--ctx",
        "8192",
        "--json",
    ]);
    assert_eq!(str_of(&again, "arch_id"), arch, "{again}");
    assert_eq!(
        again["already_mounted"], true,
        "the second mount is the arch that is already there: {again}"
    );
    assert!(
        sh.ok(&["ls", "/arches"]).contains(arch.as_str()),
        "the mounted arch belongs in the namespace"
    );

    // The same mount, rendered for a person: the id, and the one thing about
    // it that matters before a prompt is sent.
    let plain = sh.ok(&[
        "mount",
        "ollama",
        "--model",
        "gemma3:1b",
        "--external",
        &ollama.url,
    ]);
    assert!(
        plain.contains("GOVERNED") && plain.contains("no"),
        "{plain}"
    );
    assert!(plain.contains("ollama/gemma3:1b"), "{plain}");
    assert!(
        plain.contains("already mounted"),
        "a person mounting it again is told so, and the verb still exits 0:
{plain}"
    );

    // And the adapter really drives the server: a task runs through it, and
    // what `vk top` reports is the server's own count of the prompt.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Say something",
            "--plan",
            &arch,
            "--draft",
            &arch,
            "--json",
        ]),
        "id",
    )
    .to_string();
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");

    let top = sh.json(&["top", "--json"]);
    let stats = &top["arches"][&arch];
    assert_eq!(stats["calls"], 2, "{top}");
    assert_eq!(
        stats["tokens_in"], 84,
        "the server counted the prompt twice over; we did not guess it: {top}"
    );
    assert_eq!(stats["tokens_in_measured"], stats["tokens_in"], "{top}");
    assert_eq!(top["governed"][&arch], false, "{top}");
    let screen = sh.ok(&["top"]);
    assert!(
        screen.contains("GOVERNED"),
        "the operator's screen says which arches this kernel contains:\n{screen}"
    );
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// `vk boot` is the verb with real logic of its own — find the daemon, refuse
/// to double it, hand it its state and keys, detach it, wait for it to answer.
/// It runs here with file-backed keys, so CI never touches a keyring.
///
/// Note that `Shell::run` waits for the child's stdout to close: a `vk boot`
/// that let the daemon inherit that pipe would hang this test rather than fail
/// it, which is the same thing `out=$(vk boot --json)` does to a user.
#[test]
fn vk_boot_detaches_a_daemon_it_can_be_asked_to_stop_and_will_not_serve_two_state_dirs() {
    // `vk boot` looks for vkd beside itself; build it if this is a bare
    // `cargo test -p vk-cli`.
    let vkd = vkd_exe();
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let node_key = dir.path().join("node.key");
    let sh = Shell {
        endpoint: vk_ipc::transport::test_endpoint().0,
        node_key: node_key.clone(),
    };
    let (here, elsewhere) = (path_of(dir.path()), path_of(other.path()));
    let master = path_of(&dir.path().join("master.key"));
    let key = path_of(&node_key);
    let boot_here = [
        "boot",
        "--state-dir",
        &here,
        "--master-key-file",
        &master,
        "--node-key-file",
        &key,
        "--web-port",
        "0",
        "--json",
    ];
    let boot_elsewhere = [
        "boot",
        "--state-dir",
        &elsewhere,
        "--master-key-file",
        &master,
        "--node-key-file",
        &key,
        "--web-port",
        "0",
        "--json",
    ];
    assert!(vkd.exists());

    let booted = sh.json(&boot_here);
    let daemon = Detached(booted["pid"].as_u64().expect("a pid to stop it with"));
    assert_eq!(str_of(&booted, "endpoint"), sh.endpoint);
    assert!(
        dir.path().join("vkd.log").exists(),
        "the daemon's output belongs in the state dir, not in this terminal"
    );

    // `vk boot` has already exited, so a daemon that answers now is one that
    // outlived the shell that started it.
    let start = Instant::now();
    let status = loop {
        if let Some(v) = serving(&sh) {
            break v;
        }
        assert!(
            start.elapsed() < READY_TIMEOUT,
            "the detached daemon never answered on {}",
            sh.endpoint
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status["ledger_ok"], true, "{status}");
    assert_eq!(
        std::fs::canonicalize(str_of(&status, "state_dir")).unwrap(),
        std::fs::canonicalize(dir.path()).unwrap()
    );

    // Again, for the same store: the daemon that is already there is the one
    // that was wanted, so nothing is started.
    let again = sh.json(&boot_here);
    assert_eq!(again["already_running"], true, "{again}");
    assert!(again["pid"].is_null(), "nothing was started: {again}");

    // For a different store on the same endpoint: refused, and both paths are
    // named — serving this silently from the first store would send every
    // later task, approval and ledger check somewhere the caller never asked.
    let clash = sh.run(&boot_elsewhere);
    assert!(!clash.status.success(), "a second store must be refused");
    let why = String::from_utf8_lossy(&clash.stderr);
    for named in [&here, &elsewhere] {
        assert!(why.contains(named.as_str()), "{why}");
    }

    // The pid it handed back is the daemon: stopping it stops the node.
    drop(daemon);
    let start = Instant::now();
    while serving(&sh).is_some() {
        assert!(
            start.elapsed() < READY_TIMEOUT,
            "the daemon outlived the pid vk boot reported"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A stand-in `claude` *harness*: unlike `fake_claude` (a pure-completion arch),
/// this ignores its arguments, writes a proposal into the workspace's `OUT/`
/// (its working directory is the workspace) and exits 0. Enough for `vk harness
/// run` to drive a whole confined run without a subscription, a network or MCP.
fn harness_standin(dir: &std::path::Path) -> PathBuf {
    let bin = dir.join(if cfg!(windows) {
        "harness-standin.cmd"
    } else {
        "harness-standin.sh"
    });
    let script = if cfg!(windows) {
        "@echo off\r\n\
         >OUT\\proposal.md echo # Proposal drafted by the confined harness\r\n\
         echo {\"type\":\"result\",\"is_error\":false,\"num_turns\":2,\"total_cost_usd\":0,\"result\":\"ok\",\"permission_denials\":[]}\r\n\
         exit /b 0\r\n"
    } else {
        "#!/bin/sh\n\
         printf '# Proposal drafted by the confined harness\\n' > OUT/proposal.md\n\
         printf '{\"type\":\"result\",\"is_error\":false,\"num_turns\":2,\"total_cost_usd\":0,\"result\":\"ok\",\"permission_denials\":[]}\\n'\n\
         exit 0\n"
    };
    std::fs::write(&bin, script).expect("write harness stand-in");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).expect("chmod +x");
    }
    bin
}

/// `vk harness run --dry-run` prints the exact launch line, the `mcp.json` it
/// would write (token redacted) and the permission fence — and runs nothing.
/// This is the verb an operator reads before ever spending a real Claude Code
/// call. The binary is the daemon's (`vkd --harness-bin`), never the verb's.
#[test]
fn vk_harness_run_dry_run_prints_the_launch_line_the_fence_and_a_redacted_mcp_config() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let standin = path_of(&harness_standin(dir.path()));
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &["--harness-bin", &standin])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");

    let dry = sh.json(&[
        "harness",
        "run",
        "task-demo",
        "--name",
        "claude-code",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(dry["dry_run"], true, "{dry}");
    let line: Vec<String> = dry["launch_line"]
        .as_array()
        .expect("a launch line")
        .iter()
        .map(|x| x.as_str().unwrap_or("").to_string())
        .collect();
    // The binary is the one the daemon was started with.
    assert_eq!(line[0], standin, "{line:?}");
    // The flags the confinement rests on are all there, and the bare-name
    // allow-everything flags of the first cut are not.
    for flag in [
        "-p",
        "--restricted",
        "--mcp-config",
        "--strict-mcp-config",
        "--settings",
        "--setting-sources",
        "--permission-mode",
        "dontAsk",
        "--permission-prompts",
        "none",
        "--output-format",
        "json",
    ] {
        assert!(
            line.iter().any(|a| a == flag),
            "{flag} missing from {line:?}"
        );
    }
    assert!(!line.iter().any(|a| a == "--allowedTools"), "{line:?}");
    assert!(!line.iter().any(|a| a == "acceptEdits"), "{line:?}");
    // The MCP config and the fence live outside the workspace.
    let workspace = dry["workspace"].as_str().unwrap();
    let config_dir = dry["config_dir"].as_str().unwrap();
    // Component-wise, not as text: `task-demo.mcp` is a sibling of
    // `task-demo`, and as a string it starts with it.
    assert!(
        !std::path::Path::new(config_dir).starts_with(workspace),
        "the config dir must not be inside the workspace: {dry}"
    );
    assert!(
        line.iter()
            .any(|a| a.starts_with(config_dir) && a.ends_with("mcp.json")),
        "{line:?}"
    );
    // The mcp.json names the vk server and redacts the token — a dry run never
    // prints a live capability.
    let mcp = dry["mcp_json"].as_str().expect("mcp_json");
    assert!(mcp.contains("vk-mcp"), "{mcp}");
    assert!(
        mcp.contains("<redacted>"),
        "the token must be redacted: {mcp}"
    );
    assert!(!mcp.contains("lease-"), "{mcp}");
    // The fence: the workspace and the kernel tools allowed, the shell, the
    // web and the claude.ai-reaching tools denied, reads outside the working
    // directories blocked in every mode, the config dir denied by its real
    // path.
    let fence = dry["settings_json"].as_str().expect("settings_json");
    for rule in [
        "Read(./**)",
        "Edit(./**)",
        "mcp__vk__*",
        "\"Bash\"",
        "\"WebFetch\"",
        "\"RemoteTrigger\"",
        "\"SendUserFile\"",
        "\"LSP\"",
        "\"blockReadsOutsideWorkingDirectories\": true",
    ] {
        assert!(
            fence.contains(rule),
            "{rule} missing from the fence:\n{fence}"
        );
    }
    assert!(
        !fence.contains("Write(") && !fence.contains("Glob("),
        "no rule Claude Code would ignore: {fence}"
    );
}

/// `vk harness run` drives the confined harness to a finished, attached proposal
/// and records its egress. Against a stand-in the daemon was started with
/// (`vkd --harness-bin`), so it needs no subscription and reaches no network —
/// the point being the daemon orchestration: lease, materialise, launch under
/// the governor, collect the declared output, one `harness.connections` event,
/// settle, and nothing of the run left behind.
#[test]
fn vk_harness_run_drives_a_stand_in_to_an_attached_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let standin = path_of(&harness_standin(dir.path()));
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &["--harness-bin", &standin])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");

    let run = sh.json(&[
        "harness",
        "run",
        "--goal",
        "Draft a proposal for Acme",
        "--name",
        "claude-code",
        "--json",
    ]);
    // The harness step is done; the approval `--goal` put after it is next.
    assert_eq!(
        run["step_status"], "done",
        "the harness step finished: {run}"
    );
    assert_eq!(
        run["status"], "running",
        "the approve step is pending: {run}"
    );
    assert_eq!(
        run["governed"],
        cfg!(windows),
        "contained on Windows, ungoverned elsewhere: {run}"
    );
    assert_eq!(run["exit"], "code 0", "{run}");
    let hash = run["artefact_hash"].as_str().unwrap_or("");
    assert!(
        hash.starts_with("sha256:"),
        "the proposal was attached: {run}"
    );
    assert_eq!(run["artefacts"], 1, "attached once: {run}");
    assert_eq!(
        run["num_turns"], 2,
        "read off the stand-in's result object: {run}"
    );
    assert!(run["error"].is_null(), "{run}");

    // Nothing of the run is left on disk: no workspace, no config directory
    // (it held the token).
    let task_id = run["task_id"].as_str().unwrap().to_string();
    assert!(!dir.path().join("harness").join(&task_id).exists());
    assert!(!dir
        .path()
        .join("harness")
        .join(format!("{task_id}.mcp"))
        .exists());

    // A person reading `vk task show` sees the step done and the task waiting
    // on its approval.
    let shown = sh.json(&["task", "show", &task_id, "--json"]);
    assert_eq!(shown["status"], "running", "{shown}");
    assert_eq!(shown["steps"][0]["status"], "done", "{shown}");
    assert_eq!(shown["steps"][1]["status"], "pending", "{shown}");

    // Exactly one harness.connections event is on the record for the run.
    let tail = sh.json(&["dmesg", "-n", "20", "--json"]);
    let conns = dmesg_kinds(&tail)
        .iter()
        .filter(|k| **k == "harness.connections")
        .count();
    assert_eq!(conns, 1, "one harness.connections event per run: {tail:?}");
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// `vk task submit --judge` and `--harness`: the two step kinds the kernel has
/// always run but the shell could not ask for (found writing the SP1 demo,
/// which needs `[Plan, Draft, Judge, Approve, Release]` and, in harness mode,
/// `[Plan, Harness, Judge, Approve, Release]`).
///
/// One daemon, two tasks: the judge step runs on a mock arch and the harness
/// step is only *reached*, because running it is `vk harness run`'s job — and
/// that refusal, naming the verb that does run it, is the thing a script
/// driving `--all` has to be able to rely on.
#[test]
fn vk_task_submit_builds_judge_and_harness_steps() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    wait_until(&sh, true, "vkd did not answer").expect("status");
    let arch = str_of(&sh.json(&["mount", "mock", "m1", "--json"]), "arch_id").to_string();

    // Plan, draft, judge, approve, release — the demo's shape.
    let judged = sh.json(&[
        "task",
        "submit",
        "--goal",
        "Draft a proposal for Acme",
        "--artefact",
        "proposal",
        "--plan",
        &arch,
        "--draft",
        &arch,
        "--judge",
        &arch,
        "--approve",
        "--release",
        "out",
        "--json",
    ]);
    let kinds: Vec<&str> = judged["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|s| str_of(&s["kind"], "kind"))
        .collect();
    assert_eq!(
        kinds,
        ["plan", "draft", "judge", "approve", "release"],
        "{judged}"
    );
    assert_eq!(judged["steps"][2]["kind"]["arch_id"], arch, "{judged}");

    // It runs: the judge step is done before the task waits for its human.
    let task = str_of(&judged, "id").to_string();
    let waiting = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(waiting["status"], "waiting_human", "{waiting}");
    assert_eq!(waiting["steps"][2]["status"], "done", "{waiting}");

    // Ruling 28: `vk task show --json` carries, per step, what that step left
    // in the register's `decisions` — which is H1's own check, asserted rather
    // than inferred from prompt-token growth. The plan left one, the draft left
    // a second, and the judge raised an open question so it left none. Metadata
    // only: a count, a byte length and a hash, never a decision's text.
    let shown = sh.json(&["task", "show", &task, "--json"]);
    let decisions = shown["decisions"].as_array().expect("decisions").clone();
    assert_eq!(
        decisions
            .iter()
            .map(|d| d["after_step"].as_u64().expect("after_step"))
            .collect::<Vec<_>>(),
        vec![0, 1],
        "the plan and the draft raise decisions; the judge does not: {shown}"
    );
    for (i, d) in decisions.iter().enumerate() {
        assert_eq!(d["count"], i as u64 + 1, "{shown}");
        assert!(
            d["last_len_bytes"].as_u64().expect("last_len_bytes") > 0,
            "a non-empty decision after step {i}: {shown}"
        );
        let hash = str_of(d, "last_hash");
        assert!(hash.starts_with("sha256:"), "{shown}");
        assert_eq!(hash.len(), 7 + 64, "{shown}");
    }
    assert_ne!(
        decisions[0]["last_hash"], decisions[1]["last_hash"],
        "the draft's decision is not the plan's: {shown}"
    );
    // And the human screen says it too, without saying what was decided.
    let table = sh.ok(&["task", "show", &task]);
    assert!(table.contains("DECISIONS"), "{table}");

    // The harness shape, up to the step the generic scheduler will not run.
    let harnessed = sh.json(&[
        "task",
        "submit",
        "--goal",
        "Draft a proposal with the harness",
        "--artefact",
        "proposal",
        "--plan",
        &arch,
        "--harness",
        "claude-code",
        "--judge",
        &arch,
        "--approve",
        "--release",
        "out",
        "--json",
    ]);
    assert_eq!(harnessed["steps"][1]["kind"]["kind"], "harness");
    assert_eq!(harnessed["steps"][1]["kind"]["name"], "claude-code");
    let task = str_of(&harnessed, "id").to_string();
    let refused = sh.run(&["task", "step", &task, "--all"]);
    assert!(!refused.status.success(), "a harness step is not stepped");
    let why = String::from_utf8_lossy(&refused.stderr);
    assert!(
        why.contains(&format!("vk harness run {task}")),
        "the refusal names the verb that does run it: {why}"
    );
    // Refused before the row was touched: the plan ran, nothing failed.
    let shown = sh.json(&["task", "show", &task, "--json"]);
    assert_eq!(shown["steps"][0]["status"], "done", "{shown}");
    assert_eq!(shown["steps"][1]["status"], "pending", "{shown}");
    assert_ne!(shown["status"], "failed", "{shown}");
}

fn path_of(p: &std::path::Path) -> String {
    p.to_str().expect("utf-8 path").to_string()
}

/// A `vkd` over this state directory, with file-backed keys so no test ever
/// touches a keyring.
fn vkd_cmd(dir: &std::path::Path, endpoint: &str, extra: &[&str]) -> Command {
    let mut c = Command::new(vkd_exe());
    c.arg("--state-dir")
        .arg(dir)
        .args(["--endpoint", endpoint])
        .arg("--master-key-file")
        .arg(dir.join("master.key"))
        .arg("--node-key-file")
        .arg(dir.join("node.key"))
        .arg("--auto-enroll-node")
        // An OS-chosen port for the passkey pages: these daemons run in
        // parallel, and beside whatever daemon the machine's owner has up.
        .args(["--web-port", "0"])
        .args(extra);
    c
}

/// Wait for the daemon on this shell's endpoint to be there, or to be gone.
fn wait_until(sh: &Shell, serving_now: bool, what: &str) -> Option<Value> {
    let start = Instant::now();
    loop {
        let answer = serving(sh);
        if answer.is_some() == serving_now {
            return answer;
        }
        assert!(start.elapsed() < READY_TIMEOUT, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for a spawned daemon to exit, and hand back its status and stderr.
/// A daemon that is still running when the timeout passes fails the test
/// with `why`.
fn exit_of(mut daemon: Daemon, why: &str) -> (std::process::ExitStatus, String) {
    let start = Instant::now();
    let exit = loop {
        match daemon.0.try_wait().expect("wait for vkd") {
            Some(exit) => break exit,
            None => assert!(start.elapsed() < READY_TIMEOUT, "{why}"),
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(daemon.0.stderr.as_mut().expect("stderr"), &mut stderr).unwrap();
    (exit, stderr)
}

/// How many events the node's record has on disk.
fn ledger_lines(state_dir: &std::path::Path) -> usize {
    std::fs::read_to_string(state_dir.join("ledger").join("seg-000000.jsonl"))
        .expect("a ledger segment")
        .lines()
        .count()
}

/// The boot sequence's refusal. A record that does not verify is not a record:
/// everything a daemon appended to it would chain onto a claim already known
/// to be false, so it does not serve — while the node stays readable, which is
/// the whole point of refusing rather than crashing.
///
/// The record is a mounted arch and a STOP on top of the node's own start,
/// then `damage` is done to it with the daemon gone; the refusal, and the
/// forced start that still serves on it, are the same for every kind.
fn vkd_refuses_to_serve_a_damaged_ledger_unless_forced(damage: fn(&std::path::Path)) {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };

    // A node with a record of its own, then stopped.
    {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        let status = wait_until(&sh, true, "vkd never answered").expect("status");
        assert_eq!(status["ledger_ok"], true, "{status}");
        assert_eq!(status["recovered_partial_line"], false, "{status}");
        sh.ok(&["mount", "mock", "m1", "--ctx", "4096"]);
        sh.ok(&["stop"]);
    }
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    damage(dir.path());

    // Refused: non-zero, one message naming the chain and the way past it.
    let refused = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vkd"),
    );
    let (exit, why) = exit_of(refused, "vkd is serving a ledger that does not verify");
    assert!(!exit.success(), "a broken chain must not exit 0: {exit:?}");
    for named in ["ledger", "--force"] {
        assert!(why.contains(named), "{why}");
    }
    assert!(serving(&sh).is_none(), "nothing is serving that store");

    // Forced: it serves, and says to every caller what it is serving on —
    // and the STOP, which the record may no longer hold, still holds.
    let _forced = Daemon(
        vkd_cmd(dir.path(), &endpoint, &["--force"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&sh, true, "--force did not start a daemon").expect("status");
    assert_eq!(status["ledger_ok"], false, "{status}");
    assert_eq!(status["forced"], true, "{status}");
    assert_eq!(
        status["stopped_scopes"],
        serde_json::json!(["node"]),
        "{status}"
    );

    // The override is itself on the record: an auditor reading the tail must
    // find exactly why this daemon is serving a chain it says is broken.
    let tail = sh.json(&["dmesg", "-n", "3", "--json"]);
    assert!(
        dmesg_kinds(&tail).contains(&"boot.forced"),
        "a forced boot must be on the record: {tail}"
    );
}

#[test]
fn vkd_refuses_to_serve_a_ledger_that_does_not_verify_unless_forced() {
    vkd_refuses_to_serve_a_damaged_ledger_unless_forced(tamper_first_ledger_line);
}

/// A shortened record: the last two lines — the mount and the STOP — cut off.
/// What is left chains perfectly; only the head the store recorded says the
/// record used to be longer, and that is enough to refuse.
#[test]
fn vkd_refuses_to_serve_a_ledger_whose_tail_was_cut_unless_forced() {
    vkd_refuses_to_serve_a_damaged_ledger_unless_forced(cut_ledger_tail);
}

/// The most ordinary operator mistake: the daemon started again over a state
/// directory one is already serving. The second must fail at once — it holds
/// no lock — without a line appended to the record, while the first keeps
/// serving and the record still verifies; and once the first is gone, the
/// same directory serves again.
#[test]
fn a_second_vkd_over_a_served_state_dir_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let first = Shell {
        endpoint: vk_ipc::transport::test_endpoint().0,
        node_key: dir.path().join("node.key"),
    };
    let second = Shell {
        endpoint: vk_ipc::transport::test_endpoint().0,
        node_key: dir.path().join("node.key"),
    };
    let daemon = Daemon(
        vkd_cmd(dir.path(), &first.endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    wait_until(&first, true, "vkd never answered");
    let before = ledger_lines(dir.path());

    // Its own endpoint, so nothing but the state directory is in the way.
    let intruder = Daemon(
        vkd_cmd(dir.path(), &second.endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vkd"),
    );
    let (exit, why) = exit_of(intruder, "a second vkd is serving the same state directory");
    assert!(
        !exit.success(),
        "a second daemon over one store must not exit 0: {exit:?}"
    );
    assert!(
        why.contains("already open") && why.contains(&path_of(&dir.path().join("lock"))),
        "the refusal must name the lock it could not take: {why}"
    );
    assert_eq!(
        ledger_lines(dir.path()),
        before,
        "the refused daemon must not have appended to the record"
    );
    assert!(
        serving(&second).is_none(),
        "nothing serves the intruder's endpoint"
    );

    // The first is untouched: still serving, record intact.
    let status = serving(&first).expect("the first daemon still serves");
    assert_eq!(status["ledger_ok"], true, "{status}");
    let verified = first.json(&["ledger", "verify", "--json"]);
    assert_eq!(verified["ok"], true, "{verified}");

    // The lock goes with its holder: the same directory serves again.
    drop(daemon);
    wait_until(&first, false, "the killed daemon still holds the endpoint");
    let _again = Daemon(
        vkd_cmd(dir.path(), &second.endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let status = wait_until(&second, true, "the directory did not serve again").expect("status");
    assert_eq!(status["ledger_ok"], true, "{status}");
    assert_eq!(second.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// The last two lines of a node's record removed, as a restore of an older
/// copy of the segment would leave it: still a chain that verifies.
fn cut_ledger_tail(state_dir: &std::path::Path) {
    let seg = state_dir.join("ledger").join("seg-000000.jsonl");
    let text = std::fs::read_to_string(&seg).expect("a ledger segment");
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 3, "a record worth cutting: {}", lines.len());
    lines.truncate(lines.len() - 2);
    std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();
}

/// The one SQLite row that says where a node's record ended, removed — the
/// second half of cutting a tail without being caught (review Critical 1).
/// Done here with the store's own API, with the daemon gone, which is the
/// same effect as the `DELETE` an attacker with the file would run.
fn delete_recorded_head(state_dir: &std::path::Path) {
    let db = vk_store::db::Db::open(&state_dir.join("vk.sqlite")).expect("the metadata tier");
    db.kv_delete(vk_store::LEDGER_HEAD).expect("delete the row");
    assert!(db.kv_get(vk_store::LEDGER_HEAD).unwrap().is_none());
}

/// One line of a node's record rewritten, exactly as an editor would leave it:
/// still valid JSON, so only the recomputed chain hash catches it.
fn tamper_first_ledger_line(state_dir: &std::path::Path) {
    let seg = state_dir.join("ledger").join("seg-000000.jsonl");
    let mut lines: Vec<String> = std::fs::read_to_string(&seg)
        .expect("a ledger segment")
        .lines()
        .map(str::to_string)
        .collect();
    let mut first: Value = serde_json::from_str(&lines[0]).expect("a ledger event");
    first["payload_hash"] = Value::String("sha256:tampered".into());
    lines[0] = serde_json::to_string(&first).unwrap();
    std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();
}

/// The same refusal, through the verb a person actually types. `vk boot` is
/// the only thing the operator is looking at, so a daemon that refused its own
/// ledger must come back as that reason — now, not as a timeout ten seconds
/// later on an endpoint that was never the problem.
#[test]
fn vk_boot_reports_the_daemons_refusal_and_serves_only_when_forced() {
    // `vk boot` spawns the vkd beside it without asking this test first, so the
    // build has to happen before the first boot rather than under it.
    assert!(vkd_exe().exists());
    let dir = tempfile::tempdir().unwrap();
    let node_key = dir.path().join("node.key");
    let sh = Shell {
        endpoint: vk_ipc::transport::test_endpoint().0,
        node_key: node_key.clone(),
    };
    let here = path_of(dir.path());
    let master = path_of(&dir.path().join("master.key"));
    let key = path_of(&node_key);
    let boot = [
        "boot",
        "--state-dir",
        &here,
        "--master-key-file",
        &master,
        "--node-key-file",
        &key,
        "--web-port",
        "0",
        "--json",
    ];

    // A node with a record of its own, stopped again by the pid it gave back.
    let booted = sh.json(&boot);
    let status = wait_until(&sh, true, "vk boot did not start a daemon").expect("status");
    assert_eq!(status["forced"], false, "a healthy boot is not forced");
    let healthy_tail = sh.json(&["dmesg", "-n", "3", "--json"]);
    assert!(
        !dmesg_kinds(&healthy_tail).contains(&"boot.forced"),
        "a healthy boot must never emit boot.forced: {healthy_tail}"
    );
    Detached(booted["pid"].as_u64().expect("a pid to stop it with")).kill();
    wait_until(&sh, false, "the daemon outlived the pid vk boot reported");

    tamper_first_ledger_line(dir.path());

    // Refused — with the daemon's own words, and long before the boot timeout.
    let start = Instant::now();
    let refused = sh.run(&boot);
    let waited = start.elapsed();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(
        waited < Duration::from_secs(5),
        "vk boot waited {waited:?} instead of asking whether the daemon it started was still alive"
    );
    let why = String::from_utf8_lossy(&refused.stderr);
    for named in ["exited", "ledger", "--force"] {
        assert!(
            why.contains(named),
            "the daemon's own reason belongs in this message: {why}"
        );
    }
    assert!(serving(&sh).is_none(), "nothing is serving that store");

    // Forced: the same command starts a node that tells every caller what it
    // is serving on.
    let mut forcing = boot.to_vec();
    forcing.push("--force");
    let forced = sh.json(&forcing);
    let _daemon = Detached(forced["pid"].as_u64().expect("a pid to stop it with"));
    let status = wait_until(&sh, true, "--force did not start a daemon").expect("status");
    assert_eq!(status["ledger_ok"], false, "{status}");
    assert_eq!(status["forced"], true, "{status}");
    assert_eq!(status["policies_version"], "0", "{status}");

    let tail = sh.json(&["dmesg", "-n", "3", "--json"]);
    assert!(
        dmesg_kinds(&tail).contains(&"boot.forced"),
        "vk boot --force must land a boot.forced event: {tail}"
    );
}

/// `vk man` is the one verb that needs no daemon: the contracts are in the
/// binary, so they are readable on a machine whose kernel will not start.
#[test]
fn vk_man_reads_the_contracts_without_a_daemon() {
    let man = |args: &[&str]| {
        Command::new(vk_exe())
            .args(args)
            .env("VK_ENDPOINT", "\\\\.\\pipe\\vk-no-daemon-here")
            .output()
            .expect("run vk man")
    };

    let list = man(&["man"]);
    assert!(list.status.success(), "vk man: {list:?}");
    let listed = String::from_utf8(list.stdout).unwrap();
    for name in ["ledger_event", "principal", "stop_event"] {
        assert!(listed.contains(name), "{listed}");
    }

    let page = String::from_utf8(man(&["man", "ledger_event"]).stdout).unwrap();
    assert!(page.contains("LedgerEvent"), "{page}");
    assert!(page.contains("payload_hash"), "{page}");
    assert!(page.contains("required:"), "{page}");

    // `--json` is the schema itself: what a generator reads.
    let raw: Value =
        serde_json::from_slice(&man(&["man", "ledger_event", "--json"]).stdout).expect("a schema");
    assert_eq!(raw["title"], "LedgerEvent");

    // A name that is not one: refused, with the list of names that are.
    let bad = man(&["man", "no-such-contract"]);
    assert_eq!(bad.status.code(), Some(1), "{bad:?}");
    let why = String::from_utf8(bad.stderr).unwrap();
    assert!(why.contains("no-such-contract"), "{why}");
    assert!(why.contains("ledger_event"), "{why}");
}

/// The restart case, end to end (Ruling 14). A daemon that comes up over a
/// store with a real arch in it re-creates that arch from the spec its mount
/// recorded — it does not put the mock there and carry on. Driven against the
/// `claude` stand-in, so the proof is in the numbers: only the real adapter
/// reports the provider's own token count, and a mock standing in for it would
/// report an estimate instead.
#[test]
fn a_real_arch_is_re_created_when_the_daemon_restarts_and_is_never_a_mock() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    let claude = path_of(&fake_claude(dir.path()));

    // A node with a real arch on it, then stopped.
    let draft = {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        let mounted = sh.json(&[
            "mount",
            "claude-code",
            "--bin",
            &claude,
            "--draft-model",
            "claude-sonnet-5",
            "--judge-model",
            "claude-opus-5",
            "--json",
        ]);
        str_of(&mounted["draft"], "arch_id").to_string()
    };
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    // The same store, a new daemon: the arch is there and it is ready.
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    wait_until(&sh, true, "vkd never answered after the restart").expect("status");
    // The node answers before its arches are built, so this waits for the
    // startup pass rather than for the endpoint (Task 1b review, Important 1).
    settled_arches(&sh);
    let ls = sh.json(&["ls", "/arches", "--json"]);
    let row = ls["arches"]
        .as_array()
        .unwrap_or_else(|| panic!("/arches is a list of arches: {ls}"))
        .iter()
        .find(|a| a["arch_id"].as_str() == Some(draft.as_str()))
        .unwrap_or_else(|| panic!("the mounted arch did not survive the restart: {ls}"));
    assert_eq!(
        row["state"], "ready",
        "a re-created arch is ready, not a placeholder: {ls}"
    );
    let screen = sh.ok(&["ls", "/arches"]);
    assert!(
        screen.contains("STATE") && screen.contains("ready"),
        "the operator reads the state off the listing:\n{screen}"
    );

    // And it is the real adapter, not the mock `load` used to fabricate: a
    // task runs through the stand-in and `vk top` reports the count the
    // stand-in measured (7 + 11 + 23 a call), which no mock ever reports.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Say something",
            "--plan",
            &draft,
            "--draft",
            &draft,
            "--json",
        ]),
        "id",
    )
    .to_string();
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");
    let top = sh.json(&["top", "--json"]);
    let stats = &top["arches"][&draft];
    assert_eq!(stats["calls"], 2, "{top}");
    assert_eq!(
        stats["tokens_in"],
        2 * (7 + 11 + 23),
        "the arch that answered measured its own call, so it is the real one: {top}"
    );
    assert_eq!(top["states"][&draft], "ready", "{top}");
    let screen = sh.ok(&["top"]);
    assert!(
        screen.contains("STATE"),
        "the operator's screen says which arches are usable:\n{screen}"
    );
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// The other half of Ruling 14: an arch whose engine is gone comes back
/// *unavailable*, with the reason, and every task step that names it is
/// refused. The stand-in is deleted while the daemon is down, which is what an
/// uninstalled `claude` looks like from here.
#[test]
fn an_arch_whose_engine_has_gone_comes_back_unavailable_and_refuses_to_run() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    let claude = fake_claude(dir.path());
    let bin = path_of(&claude);

    let draft = {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        let mounted = sh.json(&[
            "mount",
            "claude-code",
            "--bin",
            &bin,
            "--draft-model",
            "claude-sonnet-5",
            "--judge-model",
            "claude-opus-5",
            "--json",
        ]);
        str_of(&mounted["draft"], "arch_id").to_string()
    };
    wait_until(&sh, false, "the killed daemon still holds the endpoint");
    std::fs::remove_file(&claude).expect("uninstall the stand-in");

    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    wait_until(
        &sh,
        true,
        "an unavailable arch must not stop the node serving",
    )
    .expect("status");
    // It is `starting` until the factory has been tried and has failed; the
    // verdict is what this test is about, so wait for the pass.
    settled_arches(&sh);

    let ls = sh.json(&["ls", "/arches", "--json"]);
    let row = ls["arches"]
        .as_array()
        .unwrap_or_else(|| panic!("/arches is a list of arches: {ls}"))
        .iter()
        .find(|a| a["arch_id"].as_str() == Some(draft.as_str()))
        .unwrap_or_else(|| panic!("an unavailable arch is still listed: {ls}"));
    assert_eq!(row["state"], "unavailable", "{ls}");
    assert!(
        row["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "an operator is told why: {ls}"
    );

    // A task naming it fails, saying what is wrong — it does not quietly run
    // on a mock and hand back an answer nobody asked for.
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Say something",
            "--plan",
            &draft,
            "--draft",
            &draft,
            "--json",
        ]),
        "id",
    )
    .to_string();
    let refused = sh.run(&["task", "step", &task, "--all"]);
    assert!(
        !refused.status.success(),
        "a step on an unavailable arch must not succeed"
    );
    let why = String::from_utf8_lossy(&refused.stderr);
    assert!(why.contains("arch unavailable"), "{why}");
    let top = sh.json(&["top", "--json"]);
    assert_eq!(top["states"][&draft], "unavailable", "{top}");
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
}

/// A `claude` stand-in that is *slow* to answer `--version`, and otherwise
/// identical to `fake_claude`'s — same version string, so the same arch
/// identity, so the same arch id. Swapping one for the other is a node whose
/// engine has become slow to start, which is the ordinary case after a machine
/// reboot: Docker Desktop still coming up, a model still loading.
fn slow_claude(dir: &std::path::Path, bin: &std::path::Path) {
    let reply = path_of(&dir.join("reply.json"));
    // `ping` rather than `timeout`: `timeout` refuses to run when stdin is
    // redirected, which is exactly how the adapter runs it.
    let script = if cfg!(windows) {
        "@echo off\r\nif \"%~1\"==\"--version\" (\r\n  ping -n 4 127.0.0.1 >nul\r\n  \
         echo 0.0.0-smoke\r\n  exit /b 0\r\n)\r\nfindstr \"^\" >nul\r\ntype \"{R}\"\r\nexit /b 0\r\n"
    } else {
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then sleep 3; echo 0.0.0-smoke; exit 0; fi\n\
         cat >/dev/null\ncat '{R}'\n"
    };
    std::fs::write(bin, script.replace("{R}", &reply)).expect("write the slow stand-in");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o700)).expect("chmod +x");
    }
}

/// Every arch in `vk ls /arches --json`, by id.
fn arch_states(sh: &Shell) -> std::collections::BTreeMap<String, String> {
    sh.json(&["ls", "/arches", "--json"])["arches"]
        .as_array()
        .expect("/arches is a list of arches")
        .iter()
        .map(|a| {
            (
                str_of(a, "arch_id").to_string(),
                str_of(a, "state").to_string(),
            )
        })
        .collect()
}

/// Wait until this node's startup pass has reached every arch: none is
/// `starting` any more, so each one is `ready` or `unavailable` for good.
///
/// A daemon answers *before* its arches are built (Task 1b review, Important
/// 1), so a test that asserts what an arch came back as has to wait for the
/// pass — the endpoint answering is no longer the same moment.
fn settled_arches(sh: &Shell) -> std::collections::BTreeMap<String, String> {
    let start = Instant::now();
    loop {
        let states = arch_states(sh);
        if !states.values().any(|s| s == "starting") {
            return states;
        }
        assert!(
            start.elapsed() < READY_TIMEOUT * 3,
            "the arches never finished starting: {states:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A node with real arches comes back **serving**, and re-creates them behind
/// the endpoint (Task 1b review, Important 1).
///
/// Re-creation used to run inside `RealKernel::open`, before the endpoint was
/// bound, so a node whose engine took longer than `vk boot`'s 10 s to answer
/// was killed by the very verb documented to start it. Here the two arches
/// take ~3 s each to probe; `vk boot` must come back in less than one of those
/// and say how many are still coming up, the listing must show `starting` and
/// then `ready`, a step submitted during the window must be retryable rather
/// than failed, and a second daemon over the same store must still be refused
/// by the store lock before anything is built.
#[test]
fn a_node_with_slow_arches_serves_while_they_start_and_vk_boot_does_not_kill_it() {
    let vkd = vkd_exe();
    assert!(vkd.exists());
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let sh = Shell {
        endpoint: endpoint.clone(),
        node_key: dir.path().join("node.key"),
    };
    let claude = fake_claude(dir.path());
    let bin = path_of(&claude);

    // Two arches, mounted while the stand-in is still fast.
    let mounted = {
        let _daemon = Daemon(
            vkd_cmd(dir.path(), &endpoint, &[])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn vkd"),
        );
        wait_until(&sh, true, "vkd never answered").expect("status");
        let m = sh.json(&[
            "mount",
            "claude-code",
            "--bin",
            &bin,
            "--draft-model",
            "claude-sonnet-5",
            "--judge-model",
            "claude-opus-5",
            "--json",
        ]);
        str_of(&m["draft"], "arch_id").to_string()
    };
    wait_until(&sh, false, "the killed daemon still holds the endpoint");

    // The same engine, now slow to say what version it is.
    slow_claude(dir.path(), &claude);

    // `vk boot`, the documented verb, over the same store.
    let here = path_of(dir.path());
    let master = path_of(&dir.path().join("master.key"));
    let key = path_of(&dir.path().join("node.key"));
    let boot = [
        "boot",
        "--state-dir",
        &here,
        "--master-key-file",
        &master,
        "--node-key-file",
        &key,
        "--web-port",
        "0",
        "--json",
    ];
    let started = Instant::now();
    let booted = sh.json(&boot);
    let took = started.elapsed();
    let daemon = Detached(booted["pid"].as_u64().expect("a pid to stop it with"));
    assert!(
        took < Duration::from_secs(3),
        "vk boot waited {took:?} for arches it should have let come up behind the endpoint"
    );
    assert_eq!(
        booted["arches_starting"], 2,
        "the node says what is still coming up: {booted}"
    );
    let human = sh.ok(&["ls", "/arches"]);
    assert!(human.contains("STATE"), "{human}");

    // Listed as `starting` while they come up, and a step that names one is
    // told to retry — the task is queued, not failed.
    let states = arch_states(&sh);
    assert_eq!(
        states.get(&mounted).map(String::as_str),
        Some("starting"),
        "{states:?}"
    );
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Say something",
            "--plan",
            &mounted,
            "--draft",
            &mounted,
            "--json",
        ]),
        "id",
    )
    .to_string();
    let retry = sh.run(&["task", "step", &task, "--all"]);
    assert!(
        !retry.status.success(),
        "a step on a starting arch does not run yet"
    );
    let why = String::from_utf8_lossy(&retry.stderr);
    assert!(why.contains("is starting; retry"), "{why}");
    let queued = sh.json(&["task", "show", &task, "--json"]);
    assert_eq!(
        queued["status"], "queued",
        "a task waiting on an arch that is coming up is queued, not failed: {queued}"
    );
    assert_eq!(queued["steps"][0]["status"], "pending", "{queued}");

    // A second daemon over the same store is still refused — by the store
    // lock, before it builds anything.
    let second = Daemon(
        vkd_cmd(dir.path(), &vk_ipc::transport::test_endpoint().0, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn a second vkd"),
    );
    let (exit, refusal) = exit_of(second, "a second vkd over a served store is still running");
    assert!(!exit.success(), "a second daemon must be refused: {exit:?}");
    assert!(
        refusal.contains("lock"),
        "refused by the store lock: {refusal}"
    );

    // They come up, and the very same task runs — no re-submission.
    let states = settled_arches(&sh);
    assert!(
        states.values().all(|s| s == "ready"),
        "every arch was re-created: {states:?}"
    );
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");
    let top = sh.json(&["top", "--json"]);
    assert_eq!(
        top["arches"][&mounted]["tokens_in"],
        2 * (7 + 11 + 23),
        "it is the real adapter that answered: {top}"
    );
    assert_eq!(sh.json(&["ledger", "verify", "--json"])["ok"], true);
    drop(daemon);
}

/// One raw HTTP/1.1 GET against the daemon's loopback pages: the status line
/// and the body, with no HTTP client in the way.
fn http_get(port: u16, path_and_query: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to the pages");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path_and_query} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// The passkey verbs, as far as a shell can drive them without a browser and
/// an authenticator (SP1b Task 5): `vk status` names the pages' origin; `vk
/// passkey ls` says none is enrolled; `vk passkey enroll` prints a link that
/// opens the enrolment page, and only a link does; `vk approve --passkey`
/// prints the approval page's link and waits, then times out when nobody
/// approves; and `vk approve` with the node key still completes the task
/// through the kernel-minted challenge. The Windows Hello half is the
/// founder's manual check (README).
#[test]
fn vk_passkey_verbs_print_links_that_open_the_pages_and_approve_waits() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let _daemon = Daemon(
        vkd_cmd(dir.path(), &endpoint, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vkd"),
    );
    let sh = Shell { endpoint, node_key };
    let status = wait_until(&sh, true, "vkd did not answer").expect("status");
    let origin = str_of(&status, "web").to_string();
    assert!(
        origin.starts_with("http://localhost:"),
        "the pages' origin: {status}"
    );
    let port: u16 = origin.rsplit(':').next().unwrap().parse().unwrap();
    let rendered = sh.ok(&["status"]);
    assert!(
        rendered.contains("web") && rendered.contains(&origin),
        "the rendered status names the origin: {rendered}"
    );

    // Nothing enrolled yet, in both renderings.
    assert_eq!(sh.json(&["passkey", "ls", "--json"]), serde_json::json!([]));
    assert!(sh.ok(&["passkey", "ls"]).contains("no passkey enrolled"));

    // The enrolment link: printed, not opened (no `--open`), and it opens
    // the page — where no link, or a made-up one, does.
    let enroll = sh.json(&["passkey", "enroll", "--json"]);
    let url = str_of(&enroll, "url").to_string();
    assert!(
        url.starts_with(&format!("{origin}/enroll?t=")),
        "an enrol link on the pages' origin: {url}"
    );
    assert_eq!(enroll["opened"], false);
    let printed = sh.ok(&["passkey", "enroll"]);
    assert!(
        printed.contains(&format!("{origin}/enroll?t=")),
        "the plain rendering prints the link too: {printed}"
    );
    let path = url.strip_prefix(&origin).unwrap();
    let (code, body) = http_get(port, path);
    assert_eq!(code, 200, "{body}");
    assert!(
        body.contains("Enrol") && body.contains("/vk.js"),
        "the enrolment page: {body}"
    );
    assert_eq!(http_get(port, "/enroll").0, 404, "no link, no page");
    assert_eq!(http_get(port, "/enroll?t=made-up").0, 404);

    // A task waiting for a human.
    let arch = str_of(&sh.json(&["mount", "mock", "m1", "--json"]), "arch_id").to_string();
    let task = str_of(
        &sh.json(&[
            "task",
            "submit",
            "--goal",
            "Draft a proposal",
            "--artefact",
            "proposal",
            "--plan",
            &arch,
            "--draft",
            &arch,
            "--approve",
            "--json",
        ]),
        "id",
    )
    .to_string();
    let waiting = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(waiting["status"], "waiting_human", "{waiting}");

    // `vk approve --passkey`: the link is printed at once, the approval page
    // opens from it, and with nobody there to approve, the wait times out —
    // non-zero, naming the task and the link, the task still waiting.
    let started = Instant::now();
    let out = sh.run(&["approve", &task, "--passkey", "--timeout", "1"]);
    assert!(!out.status.success(), "nobody approved: the wait must fail");
    assert!(started.elapsed() >= Duration::from_secs(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let prefix = format!("{origin}/approve/{task}?t=");
    let link = stdout
        .split_whitespace()
        .find(|w| w.starts_with(&prefix))
        .unwrap_or_else(|| panic!("the approval link must be printed before the wait: {stdout}"))
        .to_string();
    assert!(
        stderr.contains("no passkey approval") && stderr.contains(&task),
        "{stderr}"
    );
    let (code, body) = http_get(port, link.strip_prefix(&origin).unwrap());
    assert_eq!(code, 200, "{body}");
    assert!(
        body.contains("Draft a proposal") && body.contains("Approve with Windows Hello"),
        "the approval page shows the goal and the button: {body}"
    );
    assert_eq!(
        http_get(port, &format!("/approve/{task}")).0,
        404,
        "no link, no page"
    );
    assert_eq!(
        sh.json(&["task", "show", &task, "--json"])["status"],
        "waiting_human"
    );
    // A task that is not waiting gets no link at all.
    let refused = sh.run(&["approve", "task-none", "--passkey", "--timeout", "1"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("not found"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    // The node-key ceremony, through the kernel-minted challenge: still the
    // way a shell approves without a browser, and it completes the task.
    let approved = sh.json(&["approve", &task, "--json"]);
    assert_eq!(approved["ok"], true, "{approved}");
    let done = sh.json(&["task", "step", &task, "--all", "--json"]);
    assert_eq!(done["status"], "done", "{done}");
    // Once done, nothing is waiting: no challenge and no link can be minted.
    let late = sh.run(&["approve", &task]);
    assert!(!late.status.success());
    assert!(
        String::from_utf8_lossy(&late.stderr).contains("not waiting"),
        "{}",
        String::from_utf8_lossy(&late.stderr)
    );
    let tail = sh.json(&["dmesg", "-n", "8", "--json"]);
    assert!(
        dmesg_kinds(&tail).contains(&"approval.recorded"),
        "the approval is on the record: {tail}"
    );
}

/// `vk secret set` is the one verb in this shell that handles a credential,
/// and its three rules are testable without touching anybody's keyring: a
/// name that is not one word is refused before anything is read, an empty
/// value is refused before the keyring is opened at all, and neither refusal
/// (nor the success line, which is not reached here) prints a value.
///
/// Deliberately no round trip through a real keyring. On this machine that
/// would write to the founder's credential store, and on a headless Linux
/// runner there is no secret service to write to — so what is pinned is the
/// half that is this crate's, and the keyring half is `keyring`'s.
#[test]
fn vk_secret_set_refuses_a_bad_name_and_an_empty_value_without_touching_a_keyring() {
    let bad_name = Command::new(vk_exe())
        .args(["secret", "set", "two words", "--stdin"])
        .stdin(Stdio::null())
        .output()
        .expect("run vk");
    assert!(
        !bad_name.status.success(),
        "a name with a space is not a name"
    );
    let err = String::from_utf8_lossy(&bad_name.stderr);
    assert!(err.contains("one word"), "{err}");

    // Nothing on stdin: `--stdin` reads end-of-file, which is not a secret.
    // The service name is a throwaway, and nothing is written under it.
    let empty = Command::new(vk_exe())
        .args([
            "secret",
            "set",
            "anthropic",
            "--stdin",
            "--service",
            "vk-test-never-written",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run vk");
    assert!(!empty.status.success(), "an empty value is not a secret");
    let err = String::from_utf8_lossy(&empty.stderr);
    assert!(err.contains("the keyring was not touched"), "{err}");
}

/// `vk mount bedrock` takes an EU region and no other: the manifest's
/// `jurisdiction: EU` *is* the region, so naming somewhere else is refused by
/// the shell before a daemon is even dialled.
#[test]
fn vk_mount_bedrock_refuses_a_region_outside_the_union() {
    let refused = Command::new(vk_exe())
        .args(["mount", "bedrock", "--region", "us-east-1"])
        .output()
        .expect("run vk");
    assert!(!refused.status.success(), "us-east-1 is not an EU region");
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        err.contains("eu-central-1") && err.contains("eu-west-1"),
        "{err}"
    );
}
