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
        let out = Command::new(env!("CARGO"))
            .args(["build", "-p", "vkd"])
            .output()
            .expect("run cargo");
        assert!(
            out.status.success(),
            "cargo build -p vkd failed:\n{}",
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

    // And a person reading `vk top` sees both, not only the hash of them.
    let screen = sh.ok(&["top"]);
    assert!(
        screen.contains("MEASURED") && screen.contains("COST"),
        "{screen}"
    );
    assert!(
        screen.contains("0.00400"),
        "the cost belongs on the screen:\n{screen}"
    );
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
