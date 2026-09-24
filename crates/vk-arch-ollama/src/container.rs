//! The container the model runs in, driven through the `docker` CLI.
//!
//! The CLI rather than the Docker socket: the socket is a different API on
//! each of the three platforms this has to build on, and what is needed here
//! is four verbs — is it there, start it, what caps does it have, stop it.
//!
//! This module is what `governed: true` means in the manifest. The kernel
//! starts the process and the process runs under a memory cap and a CPU cap it
//! did not choose; [`caps_applied`] reads those back off the running container
//! rather than trusting the command line that asked for them, because a
//! container that lost its caps (started by hand, restored from an older
//! `docker run`) is not governed however it was meant to be started.
use anyhow::{bail, Context, Result};
use std::process::{Command, Stdio};

/// Where the model's weights and the server's state live between runs. Fixed:
/// the whole point of a named volume is that the next mount does not pull
/// 9.6 GB again.
pub const VOLUME_MOUNTPOINT: &str = "/root/.ollama";
/// The loopback publication of the server's port. Loopback only — a model
/// this node governs is not a service on the network.
pub const PORT_MAPPING: &str = "127.0.0.1:11434:11434";

/// What [`ensure`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// It was not running; it is now — started, or created and started.
    Started,
    /// It was already running, and was left exactly as it was.
    AlreadyRunning,
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

/// Start the container if it is not running, create it if it does not exist,
/// and leave it alone if it is already up.
///
/// Never `docker run` over an existing container: the one that exists holds
/// the volume with the weights in it, and re-creating it is how a mount turns
/// into a 9.6 GB download.
pub fn ensure(spec: &ContainerSpec) -> Result<State> {
    match inspect(&spec.name, "{{.State.Running}}")? {
        Some(running) if running.trim() == "true" => Ok(State::AlreadyRunning),
        Some(_) => {
            docker(&["start", &spec.name])
                .with_context(|| format!("start the existing container {} again", spec.name))?;
            Ok(State::Started)
        }
        None => {
            docker(
                &run_line(spec)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
            .with_context(|| format!("create the container {}", spec.name))?;
            Ok(State::Started)
        }
    }
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

/// The image the container actually runs, by digest. The container's own, not
/// the tag's: a tag moves, and what is running is what was running when it
/// started.
pub fn image_digest(spec: &ContainerSpec) -> Result<String> {
    if let Some(id) = inspect(&spec.name, "{{.Image}}")? {
        return Ok(id.trim().to_string());
    }
    let out = docker(&["image", "inspect", &spec.image, "--format", "{{.Id}}"])
        .with_context(|| format!("inspect the image {}", spec.image))?;
    Ok(out.trim().to_string())
}

/// Is this container actually capped? Both caps, read back off the running
/// container. `false` — not an error — when there is no such container: a
/// container that is not there is not governing anything.
pub fn caps_applied(spec: &ContainerSpec) -> Result<bool> {
    let Some(out) = inspect(
        &spec.name,
        "{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}",
    )?
    else {
        return Ok(false);
    };
    let mut fields = out.split_whitespace();
    let memory: u64 = fields.next().unwrap_or("0").parse().unwrap_or(0);
    let nano_cpus: u64 = fields.next().unwrap_or("0").parse().unwrap_or(0);
    Ok(memory > 0 && nano_cpus > 0)
}

pub fn stop(spec: &ContainerSpec) -> Result<()> {
    docker(&["stop", &spec.name]).with_context(|| format!("stop the container {}", spec.name))?;
    Ok(())
}

/// `docker container inspect` with a format, as `Some(output)`; `None` when
/// there is no such container — which is an answer, not a failure. Anything
/// else (no `docker` on `PATH`, a daemon that is not up) is an error naming
/// Docker Desktop, because that is what the person has to go and fix.
fn inspect(name: &str, format: &str) -> Result<Option<String>> {
    let out = Command::new("docker")
        .args(["container", "inspect", name, "--format", format])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| no_docker(&e.to_string()))?;
    if out.status.success() {
        return Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()));
    }
    let said = String::from_utf8_lossy(&out.stderr);
    if said.contains("No such container") || said.contains("no such container") {
        return Ok(None);
    }
    bail!(
        "cannot ask Docker about the container {name}: {}{}",
        said.trim(),
        DESKTOP_HINT
    );
}

/// Run a `docker` subcommand for its effect, returning what it printed.
fn docker(args: &[&str]) -> Result<String> {
    let out = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| no_docker(&e.to_string()))?;
    if !out.status.success() {
        bail!(
            "docker {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
            DESKTOP_HINT
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
}
