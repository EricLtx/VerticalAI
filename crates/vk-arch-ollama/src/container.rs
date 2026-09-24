//! The container the model runs in, driven through the `docker` CLI.
//!
//! The CLI rather than the Docker socket: the socket is a different API on
//! each of the three platforms this has to build on, and what is needed here
//! is five verbs — what is there, start it, re-create it, what caps does it
//! have, stop it.
//!
//! This module is what `governed: true` means in the manifest. The kernel
//! starts the process and the process runs under a memory cap and a CPU cap it
//! did not choose. Two rules keep that claim honest:
//!
//! * **Nothing is adopted silently** (Ruling 10). An existing `vk-ollama` is
//!   reused only when its image and both caps are *exactly* what this mount
//!   asks for. A container left over from `--memory 4g` is not a 12 GiB
//!   governor, and starting it while reporting the asked-for caps is how
//!   somebody ends up believing a claim nobody enforced. When they differ the
//!   mount is refused, every difference is named, and the remedy is
//!   `vk mount ollama --recreate` — which keeps the volume, and so the models.
//! * **The caps are read back**, off the running container, by [`governor`],
//!   after it has been adopted or created. What the request asked for never
//!   decides `governed`.
//!
//! Every `docker` invocation runs under a timeout and is killed at it
//! (Ruling 9b): a wedged Docker daemon must fail one mount, not hang it.
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where the model's weights and the server's state live between runs. Fixed:
/// the whole point of a named volume is that the next mount does not pull
/// 9.6 GB again — and it is why `--recreate` can throw the container away.
pub const VOLUME_MOUNTPOINT: &str = "/root/.ollama";
/// Where the container's port lands on this machine. Loopback only — a model
/// this node governs is not a service on the network.
pub const PUBLISHED_ENDPOINT: &str = "127.0.0.1:11434";
/// The loopback publication of the server's port, as `docker run -p` takes it.
pub const PORT_MAPPING: &str = "127.0.0.1:11434:11434";
/// How long a process on the published port is given to accept a connection
/// before it is taken to be absent.
const PORT_PROBE: Duration = Duration::from_millis(500);

/// How long a `docker` command that only reads or switches state is given.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
/// How long `docker run` is given. Longer, because it may be pulling an image.
const RUN_TIMEOUT: Duration = Duration::from_secs(300);
/// How often a running `docker` is looked at while waiting for it.
const POLL: Duration = Duration::from_millis(25);

/// What [`ensure`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// It was not running; it is now — started, or created and started.
    Started,
    /// It was already running, and was left exactly as it was.
    AlreadyRunning,
    /// It was there, it was not what this mount asks for, and `--recreate`
    /// said to replace it: stopped, removed, created again from the pinned
    /// line. The volume, and the models in it, were kept.
    Recreated,
}

/// Did *this* mount start the process? A container this node created or
/// re-created is one it may stop again when the arch is unmounted; one that
/// was already running when we arrived belongs to whoever started it and is
/// left alone, however the mount ends.
pub fn started_here(state: State) -> bool {
    matches!(state, State::Started | State::Recreated)
}

/// The container a mount asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub image: String,
    pub name: String,
    /// Docker's own memory syntax (`12g`): the hard cap the kernel imposes.
    pub memory: String,
    /// Docker's own CPU syntax (`6`): how much of this machine it may take.
    pub cpus: String,
    pub volume: String,
}

impl Default for ContainerSpec {
    fn default() -> ContainerSpec {
        ContainerSpec {
            image: crate::DEFAULT_IMAGE.into(),
            name: "vk-ollama".into(),
            memory: "12g".into(),
            cpus: "6".into(),
            volume: "vk-ollama".into(),
        }
    }
}

/// What a container *is*, read off it rather than asked of it: the image it
/// actually runs and the caps actually in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Governor {
    /// The image id (`sha256:…`) the container was created from.
    pub image: String,
    /// `HostConfig.Memory`, in bytes. Zero means uncapped.
    pub memory_bytes: u64,
    /// `HostConfig.NanoCpus`. Zero means uncapped.
    pub nano_cpus: u64,
}

impl Governor {
    /// Is this a governor at all? Both caps have to be set: a container with
    /// all the memory of the host is not contained in any useful sense.
    pub fn capped(&self) -> bool {
        self.memory_bytes > 0 && self.nano_cpus > 0
    }
}

/// The container as it is now: `None` when there is no such container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    /// Docker's own id for *this* container. Not the name: a `--recreate`
    /// puts a different container behind the same name, and an adapter that
    /// stops "vk-ollama" without checking would stop the one that replaced it.
    pub id: String,
    pub running: bool,
    pub governor: Governor,
}

/// Refuse before anything is started when a *foreign* process already answers
/// on the published port (Ruling 12).
///
/// The failure this prevents is quiet and expensive: a host-native Ollama, or
/// another project's container, holding 11434 while `vk-ollama` is stopped.
/// `docker start` would fail with a port conflict — or, worse, the mount would
/// go on to read its identity from *that* server and stamp `backend: "docker"`
/// and `governed: true` on somebody else's process. The container's own
/// listener is not a conflict: when it is running, there is nothing to check.
pub fn check_port_free(spec: &ContainerSpec) -> Result<()> {
    if inspected(spec)?.is_some_and(|i| i.running) {
        return Ok(());
    }
    if !answers_on(PUBLISHED_ENDPOINT) {
        return Ok(());
    }
    bail!(
        "port {PUBLISHED_ENDPOINT} is taken by another process, and the container {} is not the \
         one answering on it: a mount would either fail to publish the port or read its identity \
         off somebody else's server. Stop whatever is listening there — a host-native Ollama, or \
         another container — or mount that server with `--external http://{PUBLISHED_ENDPOINT}` \
         (ungoverned)",
        spec.name
    )
}

/// Does anything accept a connection there right now?
fn answers_on(endpoint: &str) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    endpoint
        .to_socket_addrs()
        .into_iter()
        .flatten()
        .any(|addr| TcpStream::connect_timeout(&addr, PORT_PROBE).is_ok())
}

/// Start the container if it is not running, create it if it does not exist,
/// and adopt an existing one **only if it is the one being asked for**.
///
/// Never `docker run` over an existing container: the one that exists holds
/// the volume with the weights in it, and re-creating it behind the caller's
/// back is how a mount turns into a 9.6 GB download. When it does not match,
/// the caller is told what differs and asked to decide.
pub fn ensure(spec: &ContainerSpec) -> Result<State> {
    let Some(found) = inspected(spec)? else {
        create(spec)?;
        return Ok(State::Started);
    };
    if let Some(differences) = mismatch(spec, &found.governor)? {
        bail!("{}", refusal(spec, &differences));
    }
    if found.running {
        return Ok(State::AlreadyRunning);
    }
    docker(&["start", &spec.name], CONTROL_TIMEOUT)
        .with_context(|| format!("start the existing container {} again", spec.name))?;
    Ok(State::Started)
}

/// Throw the container away and make it again from the pinned line, keeping
/// the volume — and so the models — exactly where they are (Ruling 10).
///
/// `docker rm` without `-v`: the named volume is not the container's to take
/// with it, and a `--recreate` that re-downloaded 9.6 GB of weights would be a
/// remedy nobody would use.
pub fn recreate(spec: &ContainerSpec) -> Result<State> {
    if inspected(spec)?.is_some() {
        docker(&["stop", &spec.name], CONTROL_TIMEOUT)
            .with_context(|| format!("stop {} before replacing it", spec.name))?;
        docker(&["rm", &spec.name], CONTROL_TIMEOUT)
            .with_context(|| format!("remove {} before replacing it", spec.name))?;
    }
    create(spec)?;
    Ok(State::Recreated)
}

fn create(spec: &ContainerSpec) -> Result<()> {
    let line = run_line(spec);
    docker(
        &line.iter().map(String::as_str).collect::<Vec<_>>(),
        RUN_TIMEOUT,
    )
    .with_context(|| format!("create the container {}", spec.name))?;
    Ok(())
}

/// Every way the container that is there differs from the container asked
/// for, in a person's words. `None` when it is the same one.
fn mismatch(spec: &ContainerSpec, found: &Governor) -> Result<Option<Vec<String>>> {
    let mut differences = cap_differences(spec, found)?;
    // The image is compared by id, not by tag: a tag moves, and what is
    // running is whatever it pointed at when the container was created. An
    // image this machine does not have cannot be shown to be the one running,
    // which is itself a difference worth refusing over.
    match image_id(&spec.image)? {
        Some(asked) if asked == found.image => {}
        Some(asked) => differences.push(format!(
            "image: it runs {}, this mount asks for {} ({asked})",
            found.image, spec.image
        )),
        None => differences.push(format!(
            "image: it runs {}, and {} is not on this machine, so the two cannot be shown to be \
             the same",
            found.image, spec.image
        )),
    }
    Ok((!differences.is_empty()).then_some(differences))
}

/// The caps half of that comparison, which asks Docker nothing — so it can be
/// tested on a machine that has none.
fn cap_differences(spec: &ContainerSpec, found: &Governor) -> Result<Vec<String>> {
    let mut differences = Vec::new();
    let asked_memory = memory_bytes(&spec.memory)?;
    let asked_cpus = nano_cpus(&spec.cpus)?;
    if found.memory_bytes != asked_memory {
        differences.push(format!(
            "memory: it runs under {} bytes, this mount asks for {} ({asked_memory} bytes)",
            found.memory_bytes, spec.memory
        ));
    }
    if found.nano_cpus != asked_cpus {
        differences.push(format!(
            "cpus: it runs under {} nanocpus, this mount asks for {} ({asked_cpus} nanocpus)",
            found.nano_cpus, spec.cpus
        ));
    }
    Ok(differences)
}

fn refusal(spec: &ContainerSpec, differences: &[String]) -> String {
    format!(
        "the container {} is already here, but it is not the one this mount asks for:\n  - {}\n\
         adopting it would make `governed: true` a claim about caps nobody set. Re-create it — the \
         volume {} and the models in it are kept — with: vk mount ollama --recreate",
        spec.name,
        differences.join("\n  - "),
        spec.volume,
    )
}

/// The `docker run` line, argv after `docker`. Pinned here rather than built
/// at the call site, so what the kernel promises (a cap on memory, a cap on
/// CPU, loopback only, one named volume) is one list a reader can check.
pub fn run_line(spec: &ContainerSpec) -> Vec<String> {
    vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        spec.name.clone(),
        "-p".into(),
        PORT_MAPPING.into(),
        "-v".into(),
        format!("{}:{VOLUME_MOUNTPOINT}", spec.volume),
        "--memory".into(),
        spec.memory.clone(),
        "--cpus".into(),
        spec.cpus.clone(),
        spec.image.clone(),
    ]
}

/// The container as it is now, or `None` when there is none of that name.
pub fn inspected(spec: &ContainerSpec) -> Result<Option<Inspected>> {
    let Some(v) = inspect(&["container", "inspect", &spec.name])? else {
        return Ok(None);
    };
    Ok(Some(Inspected {
        id: v["Id"].as_str().unwrap_or_default().to_string(),
        running: v["State"]["Running"].as_bool().unwrap_or(false),
        governor: Governor {
            image: v["Image"].as_str().unwrap_or_default().to_string(),
            memory_bytes: v["HostConfig"]["Memory"].as_u64().unwrap_or(0),
            nano_cpus: v["HostConfig"]["NanoCpus"].as_u64().unwrap_or(0),
        },
    }))
}

/// What is actually in force, for the mount that is about to claim it. An
/// error rather than a shrug when the container cannot be read: a Docker that
/// stopped answering between `ensure` and here is not evidence of an
/// ungoverned arch, it is evidence of nothing (SP1b Task 1 review, Minor 5).
pub fn governor(spec: &ContainerSpec) -> Result<Governor> {
    inspected(spec)?
        .map(|i| i.governor)
        .with_context(|| format!("no container {} to read the caps off", spec.name))
}

/// The image the container actually runs, by digest. The container's own, not
/// the tag's: a tag moves, and what is running is what was running when it
/// started.
pub fn image_digest(spec: &ContainerSpec) -> Result<String> {
    if let Some(i) = inspected(spec)? {
        return Ok(i.governor.image);
    }
    image_id(&spec.image)?.with_context(|| format!("no image {} on this machine", spec.image))
}

/// Is this container capped as this spec asks? Both caps, read back off it.
/// `false` — not an error — when there is no such container: a container that
/// is not there is not governing anything.
pub fn caps_applied(spec: &ContainerSpec) -> Result<bool> {
    Ok(inspected(spec)?.is_some_and(|i| i.governor.capped()))
}

pub fn stop(spec: &ContainerSpec) -> Result<()> {
    docker(&["stop", &spec.name], CONTROL_TIMEOUT)
        .with_context(|| format!("stop the container {}", spec.name))?;
    Ok(())
}

/// The local id of an image, or `None` when this machine does not have it.
fn image_id(image: &str) -> Result<Option<String>> {
    Ok(inspect(&["image", "inspect", image])?
        .and_then(|v| v["Id"].as_str().map(str::to_owned))
        .filter(|id| !id.is_empty()))
}

/// `docker … inspect` as the first object it prints; `None` when there is no
/// such container or image — which is an answer, not a failure. Anything else
/// (no `docker` on `PATH`, a daemon that is not up) is an error naming Docker
/// Desktop, because that is what the person has to go and fix.
///
/// The whole JSON object, not a `--format` template: what is wanted here is
/// four fields off two different shapes, and a parser that reads the document
/// is both shorter and easier to put a stand-in behind than four Go templates.
fn inspect(args: &[&str]) -> Result<Option<Value>> {
    let (ok, out, err) = run_docker(args, CONTROL_TIMEOUT)?;
    if !ok {
        let said = err.to_ascii_lowercase();
        if said.contains("no such container")
            || said.contains("no such image")
            || said.contains("no such object")
        {
            return Ok(None);
        }
        bail!(
            "cannot ask Docker about {}: {}{DESKTOP_HINT}",
            args.last().copied().unwrap_or_default(),
            err.trim()
        );
    }
    let parsed: Value = serde_json::from_str(out.trim()).with_context(|| {
        format!(
            "docker {} printed something that is not JSON",
            args.join(" ")
        )
    })?;
    Ok(parsed
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .filter(|v| !v.is_null()))
}

/// Run a `docker` subcommand for its effect, returning what it printed.
fn docker(args: &[&str], timeout: Duration) -> Result<String> {
    let (ok, out, err) = run_docker(args, timeout)?;
    if !ok {
        bail!(
            "docker {} failed: {}{DESKTOP_HINT}",
            args.join(" "),
            err.trim()
        );
    }
    Ok(out)
}

/// One `docker` invocation, bounded (Ruling 9b). A Docker daemon that has
/// stopped answering must cost one mount its timeout and no more, so the
/// child is polled and killed at the deadline rather than waited on; both
/// pipes are drained on threads of their own, because a `container inspect`
/// prints more than a pipe buffer holds and a child nobody is reading from
/// blocks forever.
fn run_docker(args: &[&str], timeout: Duration) -> Result<(bool, String, String)> {
    let mut child = Command::new(docker_program())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| no_docker(&e.to_string()))?;
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().context("wait for docker")? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "docker {} did not answer within {}s and was killed{DESKTOP_HINT}",
                    args.join(" "),
                    timeout.as_secs()
                );
            }
            None => std::thread::sleep(POLL),
        }
    };
    Ok((status.success(), joined(out), joined(err)))
}

/// The Docker CLI to run: `docker` on `PATH`, or whatever `VK_DOCKER` names.
///
/// The variable exists for two reasons. A test has to be able to put a
/// stand-in in front of this module — and on Windows it cannot do that with
/// `PATH` alone, because `CreateProcess` only ever appends `.exe` to a bare
/// program name, so a `docker.cmd` earlier on `PATH` is never found. And some
/// machines drive Docker through a wrapper of their own (a `podman` shim, a
/// `sudo` wrapper), which is now sayable instead of impossible. Anyone able to
/// set this on the daemon can already run code as the daemon.
fn docker_program() -> std::ffi::OsString {
    std::env::var_os("VK_DOCKER").unwrap_or_else(|| "docker".into())
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut r| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    })
}

fn joined(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Docker's memory syntax in bytes: a number, optionally followed by `b`,
/// `k`, `m` or `g` (binary multiples), optionally followed by `b`. Refused
/// rather than guessed at, because the number is what a cap is compared with.
fn memory_bytes(memory: &str) -> Result<u64> {
    let text = memory.trim().to_ascii_lowercase();
    let text = text.strip_suffix('b').unwrap_or(&text);
    let (digits, scale) = match text.chars().last() {
        Some('k') => (&text[..text.len() - 1], 1024),
        Some('m') => (&text[..text.len() - 1], 1024 * 1024),
        Some('g') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .with_context(|| format!("--memory {memory} is not a size Docker would understand"))
}

/// Docker's `--cpus` in nanocpus: `6` is 6_000_000_000, and `1.5` is allowed.
fn nano_cpus(cpus: &str) -> Result<u64> {
    let parsed: f64 = cpus
        .trim()
        .parse()
        .ok()
        .filter(|n: &f64| n.is_finite() && *n >= 0.0)
        .with_context(|| format!("--cpus {cpus} is not a number Docker would understand"))?;
    Ok((parsed * 1e9).round() as u64)
}

const DESKTOP_HINT: &str =
    "\nhint: a container arch needs Docker Desktop installed and running; mount with \
     `--external URL` to use an Ollama that is already serving (ungoverned)";

fn no_docker(why: &str) -> anyhow::Error {
    anyhow::anyhow!("cannot run `docker`: {why}{DESKTOP_HINT}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_endpoint_is_the_host_half_of_the_port_mapping() {
        // The port check and the run line must never drift apart: one refuses
        // a mount because something holds the port, the other publishes it.
        assert_eq!(PORT_MAPPING, format!("{PUBLISHED_ENDPOINT}:11434"));
    }

    #[test]
    fn the_run_line_is_the_one_the_caps_are_promised_in() {
        let line = run_line(&ContainerSpec::default()).join(" ");
        assert_eq!(
            line,
            "run -d --name vk-ollama -p 127.0.0.1:11434:11434 -v vk-ollama:/root/.ollama \
             --memory 12g --cpus 6 ollama/ollama:0.33.3"
        );
    }

    #[test]
    fn a_spec_with_other_caps_asks_for_those_caps() {
        let line = run_line(&ContainerSpec {
            memory: "4g".into(),
            cpus: "2".into(),
            ..Default::default()
        });
        let at = |flag: &str| {
            line.iter()
                .position(|a| a == flag)
                .and_then(|i| line.get(i + 1))
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(at("--memory"), "4g");
        assert_eq!(at("--cpus"), "2");
        // The published port stays on loopback whatever else changes.
        assert_eq!(at("-p"), PORT_MAPPING);
    }

    #[test]
    fn docker_sizes_are_read_the_way_docker_reads_them() {
        assert_eq!(memory_bytes("12g").unwrap(), 12_884_901_888);
        assert_eq!(memory_bytes("12G").unwrap(), 12_884_901_888);
        assert_eq!(memory_bytes("12gb").unwrap(), 12_884_901_888);
        assert_eq!(memory_bytes("512m").unwrap(), 536_870_912);
        assert_eq!(memory_bytes("1073741824").unwrap(), 1_073_741_824);
        assert!(memory_bytes("a lot").is_err());
        assert_eq!(nano_cpus("6").unwrap(), 6_000_000_000);
        assert_eq!(nano_cpus("1.5").unwrap(), 1_500_000_000);
        assert!(nano_cpus("all of them").is_err());
    }

    #[test]
    fn a_container_is_the_asked_for_one_only_when_every_part_matches() {
        let spec = ContainerSpec::default();
        let exact = Governor {
            image: "sha256:aaa".into(),
            memory_bytes: 12_884_901_888,
            nano_cpus: 6_000_000_000,
        };
        // The caps half only: the image half asks Docker, which this test
        // deliberately does not, and the whole comparison is driven against a
        // stand-in `docker` in `tests/container_fake.rs`.
        let named = |g: &Governor| cap_differences(&spec, g).unwrap().join("; ");
        assert_eq!(named(&exact), "", "an exact match differs in nothing");
        let small = Governor {
            memory_bytes: 4 * 1024 * 1024 * 1024,
            ..exact.clone()
        };
        assert!(named(&small).contains("memory: it runs under 4294967296 bytes"));
        assert!(named(&small).contains("12g (12884901888 bytes)"));
        let slow = Governor {
            nano_cpus: 2_000_000_000,
            ..exact
        };
        assert!(named(&slow).contains("cpus: it runs under 2000000000 nanocpus"));
    }

    #[test]
    fn the_refusal_names_the_remedy_that_keeps_the_models() {
        let spec = ContainerSpec::default();
        let said = refusal(&spec, &["memory: …".to_string()]);
        assert!(said.contains("vk mount ollama --recreate"), "{said}");
        assert!(said.contains("the models in it are kept"), "{said}");
        assert!(said.contains("vk-ollama"), "{said}");
    }

    #[test]
    fn only_a_container_this_mount_started_is_one_it_may_stop() {
        assert!(started_here(State::Started));
        assert!(started_here(State::Recreated));
        assert!(!started_here(State::AlreadyRunning));
    }
}
