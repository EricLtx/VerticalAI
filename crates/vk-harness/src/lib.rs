//! The harness: how this kernel launches an agent it does not trust with its
//! store — confined, capped, and dead the moment the kernel is.
//!
//! What lives here now is the process governor, [`confine`]: on Windows a Job
//! Object that a kernel-launched process tree (the Claude Code harness, an
//! optional llama-server) is assigned to, so it dies when the kernel's handle
//! closes and stays under a memory cap and, if asked, a CPU cap. On Linux and
//! macOS nothing confines yet — [`confine::NoopGovernor`] says so in the log
//! and the manifest says `governed: false` — until SP4 brings cgroups and
//! `sandbox-exec`. The workspace projection, the launch line and the egress
//! telemetry of the harness arrive with SP1b Task 4.
//!
//! The Ollama arch is not governed here: its caps are its container's.

pub mod confine;
