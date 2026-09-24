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
mod fake;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use vk_arch_ollama::{container, ContainerSpec, OllamaAdapter, OllamaConfig};
use vk_kernel::arch::ArchAdapter;
use vk_kernel::RealKernel;

/// The image id the stand-in says everything is built from.
const IMAGE: &str = "sha256:32931b46719f673c05fdbaa81ccb26da18ea4a1c57590a754874ab28ba269eb2";
/// Docker's id for the container the stand-in describes.
const CONTAINER_ID: &str = "c0ffee0000000000000000000000000000000000000000000000000000000000";
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
        let (running, stopped) = (
            display(&self.at("running.json")),
            display(&self.at("stopped.json")),
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
                     if \"%1\"==\"start\" (\r\n\
                       if exist \"{running}\" copy /y \"{running}\" \"{container}\" >nul\r\n\
                       exit /b 0\r\n)\r\n\
                     if \"%1\"==\"stop\" (\r\n\
                       if exist \"{stopped}\" copy /y \"{stopped}\" \"{container}\" >nul\r\n\
                       exit /b 0\r\n)\r\n\
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
                     if [ \"$1\" = start ]; then\n\
                       if [ -f '{running}' ]; then cp '{running}' '{container}'; fi\n\
                       exit 0\n\
                     fi\n\
                     if [ \"$1\" = stop ]; then\n\
                       if [ -f '{stopped}' ]; then cp '{stopped}' '{container}'; fi\n\
                       exit 0\n\
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
                "[{{\"Id\": \"{CONTAINER_ID}\", \"State\": {{\"Running\": {running}}},
                   \"Image\": \"{image}\",
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

    /// Give the stand-in the two states `docker start` and `docker stop`
    /// switch between, so a mount that starts the container then reads it back
    /// sees it running — as it would against the real Docker.
    fn arm_start_stop(&self) {
        for (name, running) in [("running.json", true), ("stopped.json", false)] {
            self.container_is(running, ASKED_MEMORY, ASKED_NANO_CPUS, IMAGE);
            std::fs::rename(self.at("container.json"), self.at(name)).expect("arm the state");
        }
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

    // Phase E — the container is not running, and somebody else is on the
    // published port (Ruling 12). Nothing is started: the mount would either
    // fail to publish the port or read its identity off that server.
    //
    // The port is free while `vk-ollama` is stopped, which the test above has
    // just arranged; if something on this machine already holds it, the
    // condition under test is true anyway and the listener is not needed.
    {
        let _squatter = std::net::TcpListener::bind(container::PUBLISHED_ENDPOINT).ok();
        docker.forget();
        let refused = container::check_port_free(&spec)
            .expect_err("a foreign process on the port is a refusal, not a race");
        let said = format!("{refused:#}");
        assert!(
            said.contains(&format!(
                "port {} is taken by another process",
                container::PUBLISHED_ENDPOINT
            )),
            "{said}"
        );
        assert!(said.contains("--external"), "the way out is named: {said}");
        assert!(
            docker.log().iter().all(|l| l.contains("inspect")),
            "the port check must not start anything: {:?}",
            docker.log()
        );

        // And the container's own listener is not a conflict: when it is running,
        // there is nothing to check.
        docker.container_is(true, ASKED_MEMORY, ASKED_NANO_CPUS, IMAGE);
        container::check_port_free(&spec)
            .expect("a running vk-ollama is what should be on that port");
    }

    // Phase F — the whole of Ruling 13, with a real kernel in the loop: a
    // repeat `vk mount ollama` with the same flags must not issue a
    // `docker stop`. It used to — `RealKernel::mount`'s replace branch swapped
    // the adapter and dropped the old one in place, and the old one owned the
    // container the new one had just adopted.
    docker.arm_start_stop();
    docker.container_is(false, ASKED_MEMORY, ASKED_NANO_CPUS, IMAGE);
    let ollama = fake::Fake::start(fake::Canned::default());
    let cfg = || OllamaConfig {
        base_url: ollama.base_url.clone(),
        model: "gemma3:1b".into(),
        container: Some(spec.clone()),
        ..Default::default()
    };
    docker.forget();

    // The first mount finds it stopped and starts it: this one owns it.
    let first = OllamaAdapter::mount(cfg()).expect("the first mount");
    assert!(
        first.started_here(),
        "the container was stopped, so this mount is what started it"
    );
    assert!(first.manifest().governed);
    // The second finds it running and adopts it: this one does not own it.
    let second = OllamaAdapter::mount(cfg()).expect("the second mount");
    assert!(!second.started_here(), "the second mount adopted it");
    assert_eq!(
        first.manifest().arch_id(),
        second.manifest().arch_id(),
        "same flags, same container, same weights: one arch"
    );

    let state = tempfile::tempdir().expect("state dir");
    let mut kernel = RealKernel::open(
        state.path(),
        vk_store::keys::KeySource::File(state.path().join("master.key")),
        "n1",
    )
    .expect("open a kernel");
    // The spec a real `arch.mount` would record beside the manifest, so the
    // next boot could make this arch again.
    let spec = |_: ()| {
        vk_kernel::arch::MountSpec::new(
            "ollama",
            serde_json::json!({ "model": "gemma3:1b", "num_ctx": 8192 }),
        )
        .expect("a spec of plain configuration")
    };
    let mounted = kernel
        .mount(Arc::new(first), spec(()))
        .expect("mount the arch");
    assert!(!mounted.already_mounted);
    let again = kernel
        .mount(Arc::new(second), spec(()))
        .expect("mount it again");
    assert_eq!(again.arch_id, mounted.arch_id);
    assert!(again.already_mounted, "the same arch, said so");
    assert!(
        again.replaced.is_none(),
        "an idempotent re-mount replaces nothing, so nothing is dropped"
    );
    let log = docker.log();
    assert!(
        !log.iter().any(|l| l.starts_with("stop ")),
        "a repeat mount must not stop the container it just re-mounted: {log:?}"
    );

    // And the arch the kernel kept is the one that owns the container: when
    // the kernel goes, the container is stopped.
    docker.forget();
    drop(kernel);
    let log = docker.log();
    assert!(
        log.iter().any(|l| l.starts_with("stop ")),
        "the adapter that started the container stops it when the kernel drops it: {log:?}"
    );
}
