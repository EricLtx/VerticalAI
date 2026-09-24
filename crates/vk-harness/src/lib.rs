//! The harness: how this kernel launches an agent it does not trust with its
//! store — confined, capped, given only what it may see, and watched.
//!
//! Four things live here, and the kernel drives them in this order for a
//! [`StepKind::Harness`](../vk_kernel/tasks/enum.StepKind.html) step:
//!
//! * [`confine`] — the process governor. On Windows a Job Object the launched
//!   tree is assigned to, so it dies with the kernel and stays under a memory
//!   and CPU cap; elsewhere a [`confine::NoopGovernor`] that says so.
//! * [`workspace`] — the label-projected workspace. Only the register's goal,
//!   its plan, and the evidence whose label flows to the harness clearance (I2)
//!   are written into `<state_dir>/harness/<task_id>/`; each projection is
//!   logged, and everything above the clearance is refused.
//! * [`launch`] — the confined launch of Claude Code: the `.mcp.json` that
//!   points it back at the kernel through [`vk-mcp`], the launch line, the run
//!   under the governor, and the artefact and telemetry it leaves.
//! * [`netwatch`] — the egress telemetry. Every 500 ms the launched process's
//!   established TCP connections are sampled (`GetExtendedTcpTable` on Windows,
//!   a no-op elsewhere) so the run record can say what it talked to.
//!
//! The crate depends on `vk-contracts` and nothing else of ours: the kernel
//! depends on *it*, so the dependency cannot run back. The kernel hands the
//! workspace projection what it needs through the [`workspace::Host`] trait,
//! whose every type is a contract, and drives [`launch::launch_claude_code`]
//! from outside its own lock — because the launched harness calls back into the
//! kernel over MCP while it runs, and a lock held across the wait would deadlock
//! the harness against its own syscalls.

pub mod confine;
pub mod launch;
pub mod netwatch;
pub mod workspace;

pub use workspace::{harness_clearance, Host, ProjectionRecord, Workspace};
