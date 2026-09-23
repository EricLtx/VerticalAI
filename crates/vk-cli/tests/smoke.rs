//! The usable milestone, end to end: a real `vkd` over a real endpoint, driven
//! by the real `vk` binary exactly as a person would drive it from a shell —
//! separate processes, argv in, exit code and stdout out. Nothing here links
//! the kernel, so what it proves is what a user gets.
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
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
/// once if it is not there yet (`CARGO_TARGET_DIR` is inherited, so the build
/// lands in the same place this test looks).
fn vkd_exe() -> PathBuf {
    let path = vk_exe().with_file_name(format!("vkd{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "vkd"])
            .status()
            .expect("run cargo");
        assert!(status.success(), "cargo build -p vkd failed");
    }
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

#[test]
fn the_vk_shell_drives_a_task_from_mount_to_release() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = vk_ipc::transport::test_endpoint().0;
    let node_key = dir.path().join("node.key");
    let mut daemon = Daemon(
        Command::new(vkd_exe())
            .arg("--state-dir")
            .arg(dir.path())
            .args(["--endpoint", &endpoint])
            .arg("--master-key-file")
            .arg(dir.path().join("master.key"))
            .arg("--node-key-file")
            .arg(&node_key)
            .arg("--auto-enroll-node")
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
        ls["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains(&arch))),
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
