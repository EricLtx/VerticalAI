//! Adoption, refusal and re-creation, driven against a stand-in `docker`.
//!
//! The three paths Ruling 10 turns on cannot be reached with the real Docker
//! without creating and destroying real containers: the one that matters most
//! — a container whose caps are *not* the ones being asked for — would mean
//! leaving a 4 GiB `vk-ollama` on whatever machine ran the tests. So `docker`
//! here is a script on `PATH` that answers `container inspect` and
//! `image inspect` with canned JSON and writes down every argv it was called
//! with.
//!
//! One test, not three: it puts a directory on this process's `PATH`, which is
//! process-wide state, and a binary with one test in it cannot race itself.
//! The phases run in order and each rewrites what the stand-in answers.
use std::path::{Path, PathBuf};
use vk_arch_ollama::{container, ContainerSpec};

/// The image id the stand-in says everything is built from.
const IMAGE: &str = "sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2";
/// 12 GiB and 6 CPUs — what `ContainerSpec::default()` asks for.
const ASKED_MEMORY: u64 = 12_884_901_888;
const ASKED_NANO_CPUS: u64 = 6_000_000_000;

/// The stand-in's world: what `container inspect` and `image inspect` answer,
/// and where the argv log goes.
struct FakeDocker {
    dir: tempfile::TempDir,
}

impl FakeDocker {
    fn new() -> FakeDocker {
        let dir = tempfile::tempdir().expect("temp dir");
        let fake = FakeDocker { dir };
        let script = fake.write_script();
        // On `PATH` *and* named outright. The `PATH` entry is what makes this
        // a stand-in in the ordinary sense; `VK_DOCKER` is what makes it work
        // on Windows, where `CreateProcess` only appends `.exe` to a bare
        // program name and would walk straight past a `docker.cmd` here to the
        // real Docker — which, on the machine this was written on, has a
        // container called `vk-ollama` and would have answered instead.
        let path = std::env::var("PATH").unwrap_or_default();
        let sep = if cfg!(windows) { ";" } else { ":" };
        std::env::set_var("PATH", format!("{}{sep}{path}", fake.dir.path().display()));
        std::env::set_var("VK_DOCKER", &script);
        fake
    }

    fn at(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The script itself: it appends its arguments to `log`, then prints
    /// `container.json` or `image.json` — or exits 1 the way Docker does when
    /// there is no such object. Returns where it was written.
    fn write_script(&self) -> PathBuf {
        let (log, container, image) = (
            display(&self.at("log")),
            display(&self.at("container.json")),
            display(&self.at("image.json")),
        );
        let (name, body) = if cfg!(windows) {
            (
                "docker.cmd",
                format!(
                    "@echo off\r\n\
                     echo %*>>\"{log}\"\r\n\
                     if \"%1 %2\"==\"container inspect\" (\r\n\
                       if exist \"{container}\" ( type \"{container}\" & exit /b 0 )\r\n\
                       echo Error: No such container: %3 1>&2\r\n  exit /b 1\r\n)\r\n\
                     if \"%1 %2\"==\"image inspect\" (\r\n\
                       if exist \"{image}\" ( type \"{image}\" & exit /b 0 )\r\n\
                       echo Error: No such image: %3 1>&2\r\n  exit /b 1\r\n)\r\n\
                     exit /b 0\r\n"
                ),
            )
        } else {
            (
                "docker",
                format!(
                    "#!/bin/sh\n\
                     echo \"$@\" >> '{log}'\n\
                     if [ \"$1 $2\" = 'container inspect' ]; then\n\
                       if [ -f '{container}' ]; then cat '{container}'; exit 0; fi\n\
                       echo \"Error: No such container: $3\" >&2; exit 1\n\
                     fi\n\
                     if [ \"$1 $2\" = 'image inspect' ]; then\n\
                       if [ -f '{image}' ]; then cat '{image}'; exit 0; fi\n\
                       echo \"Error: No such image: $3\" >&2; exit 1\n\
                     fi\n\
                     exit 0\n"
                ),
            )
        };
        let path = self.at(name);
        std::fs::write(&path, body).expect("write the stand-in");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("chmod +x");
        }
        std::fs::write(self.at("image.json"), format!("[{{\"Id\": \"{IMAGE}\"}}]"))
            .expect("write the image answer");
        path
    }

    /// Make `container inspect` answer with a container in this state.
    fn container_is(&self, running: bool, memory: u64, nano_cpus: u64, image: &str) {
        std::fs::write(
            self.at("container.json"),
            format!(
                "[{{\"State\": {{\"Running\": {running}}}, \"Image\": \"{image}\",
                   \"Config\": {{\"Image\": \"ollama/ollama:0.33.3\"}},
                   \"HostConfig\": {{\"Memory\": {memory}, \"NanoCpus\": {nano_cpus},
                     \"Binds\": null, \"NetworkMode\": \"default\"}}}}]"
            ),
        )
        .expect("write the container answer");
    }

    /// Make `container inspect` answer "no such container".
    fn no_container(&self) {
        let _ = std::fs::remove_file(self.at("container.json"));
    }

    /// Every `docker` invocation since the last [`Self::forget`], in order.
    fn log(&self) -> Vec<String> {
        std::fs::read_to_string(self.at("log"))
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    fn forget(&self) {
        let _ = std::fs::remove_file(self.at("log"));
    }
}

fn display(p: &Path) -> String {
    p.display().to_string()
}

#[test]
fn a_container_is_adopted_only_when_it_is_the_one_this_mount_asks_for() {
    let docker = FakeDocker::new();
    let spec = ContainerSpec::default();

    // Phase A — it is running, with this mount's image and this mount's caps:
    // adopt it, and touch nothing.
    docker.container_is(true, ASKED_MEMORY, ASKED_NANO_CPUS, IMAGE);
    docker.forget();
    assert_eq!(
        container::ensure(&spec).expect("an exact match is adopted"),
        container::State::AlreadyRunning
    );
    let log = docker.log();
    assert!(
        log.iter().all(|l| l.contains("inspect")),
        "adoption must not start, stop or create anything: {log:?}"
    );
    assert!(
        !container::started_here(container::State::AlreadyRunning),
        "a container we found running is not ours to stop"
    );
    // And what is claimed afterwards is read off it, not asked for.
    let governor = container::governor(&spec).expect("the caps in force");
    assert_eq!(governor.memory_bytes, ASKED_MEMORY);
    assert_eq!(governor.nano_cpus, ASKED_NANO_CPUS);
    assert_eq!(governor.image, IMAGE);
    assert!(governor.capped());

    // Phase B — same container, half the memory: refused, with the difference
    // named and the remedy spelled out. Nothing is started.
    docker.container_is(true, 4 * 1024 * 1024 * 1024, ASKED_NANO_CPUS, IMAGE);
    docker.forget();
    let refused = container::ensure(&spec).expect_err("4 GiB is not the 12 GiB asked for");
    let said = format!("{refused:#}");
    assert!(said.contains("memory"), "{said}");
    assert!(said.contains("4294967296"), "{said}");
    assert!(said.contains("12g"), "{said}");
    assert!(said.contains("vk mount ollama --recreate"), "{said}");
    assert!(
        !said.contains("cpus:"),
        "only what actually differs is named: {said}"
    );
    let log = docker.log();
    assert!(
        log.iter().all(|l| l.contains("inspect")),
        "a refusal must not have started anything: {log:?}"
    );

    // Phase C — `--recreate`: stop, remove, run, in that order, with the
    // pinned line and without `-v`, so the volume and its models survive.
    docker.forget();
    assert_eq!(
        container::recreate(&spec).expect("re-create it"),
        container::State::Recreated
    );
    let log = docker.log();
    let verbs: Vec<&str> = log
        .iter()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|v| *v != "container" && *v != "image")
        .collect();
    assert_eq!(verbs, ["stop", "rm", "run"], "{log:?}");
    let run = log.iter().find(|l| l.starts_with("run ")).expect("the run");
    assert!(
        run.contains("--memory 12g") && run.contains("--cpus 6"),
        "the pinned caps: {run}"
    );
    assert!(
        run.contains("-v vk-ollama:/root/.ollama"),
        "the volume is re-attached: {run}"
    );
    assert!(
        run.contains("-p 127.0.0.1:11434:11434"),
        "loopback only: {run}"
    );
    let rm = log.iter().find(|l| l.starts_with("rm ")).expect("the rm");
    assert!(
        !rm.contains(" -v"),
        "`rm -v` would take the models with it: {rm}"
    );
    assert!(
        container::started_here(container::State::Recreated),
        "a container this mount made is ours to stop again"
    );

    // Phase D — nothing there at all: created from the pinned line, and it is
    // ours.
    docker.no_container();
    docker.forget();
    assert_eq!(
        container::ensure(&spec).expect("create it"),
        container::State::Started
    );
    let log = docker.log();
    assert!(log.iter().any(|l| l.starts_with("run ")), "{log:?}");
    assert!(
        !log.iter().any(|l| l.starts_with("stop ")),
        "there was nothing to stop: {log:?}"
    );
    assert!(container::started_here(container::State::Started));
}
