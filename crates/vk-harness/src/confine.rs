//! Process governor: a kernel-launched process tree that dies with the kernel
//! and stays under caps.
//!
//! The kernel spawns a process (Task 4's harness, an optional llama-server),
//! then hands the [`Child`] to a [`Governor`], which puts it under whatever
//! this platform can enforce. On Windows that is a Job Object
//! ([`JobGovernor`]): every process in the job, and every process those spawn,
//! is terminated by the kernel of the OS when the job's last handle closes —
//! which is what dropping the governor does — and the job carries a memory
//! cap and, when asked, a hard CPU cap. Elsewhere it is [`NoopGovernor`],
//! which enforces nothing and says so: the manifest then says
//! `governed: false` until SP4 brings cgroups and `sandbox-exec`.
//!
//! What a governor is not: a sandbox around what the process does. It caps
//! and it kills; it does not filter files or sockets. The workspace ACL and
//! the egress telemetry of Task 4 are separate measures, and `contracts/tcb.md`
//! lists what none of them cover.
//!
//! Every `unsafe` block of the crate is in this file, each with the reason it
//! is sound.
use anyhow::Result;
use std::process::Child;

/// What the kernel does with a process it launched: hands it over to be
/// contained, and asks whether that containment was verified.
pub trait Governor: Send + Sync {
    /// Puts a running child under this governor. An error means the child is
    /// *not* contained — the caller decides whether to kill it or run it
    /// ungoverned, and says `governed: false` if it does.
    fn contain(&self, child: &Child) -> Result<()>;

    /// Whether containment was verified: true only when a
    /// [`contain`](Governor::contain) has succeeded with the OS confirming
    /// the process is under this governor — the answer the manifest's
    /// `governed` field carries. False before any `contain`, false after one
    /// that failed, and always false for [`NoopGovernor`].
    fn governed(&self) -> bool;
}

/// A governor that enforces nothing — the one platforms without a governor
/// get until SP4. It says so once, in the log, when it is made.
pub struct NoopGovernor {
    _private: (),
}

impl NoopGovernor {
    pub fn new() -> NoopGovernor {
        tracing::warn!(
            "ungoverned: this governor confines nothing — the process it is given runs \
             with no memory or CPU cap and does not die with the kernel"
        );
        NoopGovernor { _private: () }
    }
}

impl Default for NoopGovernor {
    fn default() -> Self {
        NoopGovernor::new()
    }
}

impl Governor for NoopGovernor {
    fn contain(&self, _child: &Child) -> Result<()> {
        Ok(())
    }

    fn governed(&self) -> bool {
        false
    }
}

/// The governor this platform has: a Job Object on Windows, and elsewhere a
/// [`NoopGovernor`], which is not a governor and says so. An error is the OS
/// refusing the job or its caps; nothing here falls back quietly — the caller
/// decides whether to launch ungoverned, and says `governed: false` if it does.
///
/// `max_memory_bytes` caps the committed memory of the whole process tree and
/// of each process in it; `cpu_rate_percent`, if given, is a hard cap in
/// percent of the machine's total CPU capacity (all logical processors).
pub fn for_this_platform(
    max_memory_bytes: u64,
    cpu_rate_percent: Option<u32>,
) -> Result<Box<dyn Governor>> {
    #[cfg(windows)]
    {
        Ok(Box::new(JobGovernor::new(
            max_memory_bytes,
            cpu_rate_percent,
        )?))
    }
    #[cfg(not(windows))]
    {
        // One warning per governor made: this is the Noop's own, carrying the
        // caps that nothing will enforce, so `new()` is not called on top.
        tracing::warn!(
            max_memory_bytes,
            ?cpu_rate_percent,
            "ungoverned: no process governor on this platform until SP4 — the caps asked for \
             are not enforced, the process runs with no memory or CPU cap and does not die \
             with the kernel"
        );
        Ok(Box::new(NoopGovernor { _private: () }))
    }
}

#[cfg(windows)]
pub use job::JobGovernor;

#[cfg(windows)]
mod job {
    use super::Governor;
    use anyhow::{bail, Context, Result};
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows::core::BOOL;
    use windows::Win32::Foundation::{HANDLE, STILL_ACTIVE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, GetExitCodeProcess};

    /// A Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, a
    /// memory cap and, when asked, a hard CPU cap. Its one handle is owned
    /// here and non-inheritable, so closing it — dropping the governor — is
    /// closing the job's last handle, and the OS terminates every process in
    /// it, grandchildren included.
    ///
    /// The memory cap is set twice over: `JOB_OBJECT_LIMIT_JOB_MEMORY` bounds
    /// the committed memory of the whole tree, without which a process could
    /// take the cap once per child it spawns, and
    /// `JOB_OBJECT_LIMIT_PROCESS_MEMORY` bounds each process in it. Past
    /// either, an allocation fails and the process sees it; nothing is killed
    /// for it. The CPU cap is `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`: the
    /// scheduler withholds cycles past the rate in every interval.
    ///
    /// Spike 3a established (on Windows 11, `windows` 0.62.2) that a process
    /// already in a job — this kernel's own children are, when the kernel runs
    /// under one — is assigned to a fresh job by nesting, so no breakaway is
    /// asked of the parent job.
    ///
    /// `governed()` is not a property of the job but of what was put in it
    /// (Ruling 18): it is true only once a [`contain`](Governor::contain) has
    /// read back from the OS that the process is in the job, and it is false
    /// for good once a `contain` has failed — a governor that was refused one
    /// process cannot claim the tree it governs is whole.
    pub struct JobGovernor {
        job: OwnedHandle,
        max_memory_bytes: u64,
        cpu_rate_percent: Option<u32>,
        /// Set only where `IsProcessInJob` answered yes for a contained child.
        verified: AtomicBool,
        /// Set where a `contain` returned an error; never cleared.
        refused: AtomicBool,
    }

    impl JobGovernor {
        /// Makes the job and sets its caps; no process is in it yet.
        /// `max_memory_bytes` must be positive, `cpu_rate_percent` within
        /// `1..=100` — a cap outside its range is refused here, not by the OS.
        pub fn new(max_memory_bytes: u64, cpu_rate_percent: Option<u32>) -> Result<JobGovernor> {
            if max_memory_bytes == 0 {
                bail!("a memory cap of 0 bytes is not a cap: every allocation would be refused");
            }
            let memory_limit = usize::try_from(max_memory_bytes)
                .context("the memory cap does not fit this platform's address space")?;
            if let Some(pct) = cpu_rate_percent {
                if !(1..=100).contains(&pct) {
                    bail!("a CPU rate of {pct} % is outside 1..=100 % of the machine's total capacity");
                }
            }

            // SAFETY: no security attributes and no name make an anonymous job
            // whose only handle is the one returned, non-inheritable; the call
            // reads nothing of ours.
            let raw = unsafe { CreateJobObjectW(None, None) }.context("CreateJobObjectW")?;
            // SAFETY: `raw` is a valid handle that nothing but this function
            // holds; from here `OwnedHandle` closes it exactly once, on drop —
            // including when a cap below is refused and `new` returns early.
            let job = unsafe { OwnedHandle::from_raw_handle(raw.0) };
            let governor = JobGovernor {
                job,
                max_memory_bytes,
                cpu_rate_percent,
                verified: AtomicBool::new(false),
                refused: AtomicBool::new(false),
            };

            let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                        | JOB_OBJECT_LIMIT_JOB_MEMORY,
                    ..Default::default()
                },
                ProcessMemoryLimit: memory_limit,
                JobMemoryLimit: memory_limit,
                ..Default::default()
            };
            // SAFETY: the pointer and the length describe `limits`, a fully
            // initialised struct of exactly the class named, alive for the
            // duration of the call; the job handle is open, owned by `governor`.
            unsafe {
                SetInformationJobObject(
                    governor.handle(),
                    JobObjectExtendedLimitInformation,
                    &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            }
            .with_context(|| {
                format!("the job refused a memory cap of {max_memory_bytes} bytes (JobObjectExtendedLimitInformation)")
            })?;

            if let Some(pct) = cpu_rate_percent {
                let rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                        | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    // `CpuRate` is in hundredths of a percent of total capacity.
                    Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: pct * 100 },
                };
                // SAFETY: as above, for `rate` and its class.
                unsafe {
                    SetInformationJobObject(
                        governor.handle(),
                        JobObjectCpuRateControlInformation,
                        &rate as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION as *const c_void,
                        size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                    )
                }
                .with_context(|| {
                    format!("the job refused a hard CPU cap of {pct} % (JobObjectCpuRateControlInformation)")
                })?;
            }

            Ok(governor)
        }

        /// The cap on committed memory, for the tree and for each process in it.
        pub fn max_memory_bytes(&self) -> u64 {
            self.max_memory_bytes
        }

        /// The hard CPU cap in percent of the machine's total capacity, if one
        /// was set.
        pub fn cpu_rate_percent(&self) -> Option<u32> {
            self.cpu_rate_percent
        }

        fn handle(&self) -> HANDLE {
            HANDLE(self.job.as_raw_handle())
        }

        /// Whether the process is in this job, by the OS's account.
        fn holds(&self, process: HANDLE) -> windows::core::Result<bool> {
            let mut inside = BOOL(0);
            // SAFETY: both handles are open for the duration of the call: the
            // job is owned by `self`, the process by the `Child` the caller
            // borrows; `inside` outlives the call.
            unsafe { IsProcessInJob(process, Some(self.handle()), &mut inside) }?;
            Ok(inside.as_bool())
        }

        /// Assigns the child to the job and answers `Ok` only once the OS has
        /// read back that it is in it. A child that is in it already is left
        /// there: a second call is not a second job. A refusal carries its
        /// cause, looked up: the process gone already, or a job it is already
        /// in that would not nest this one.
        fn assign(&self, child: &Child) -> Result<()> {
            let pid = child.id();
            let process = HANDLE(child.as_raw_handle());
            if self
                .holds(process)
                .with_context(|| format!("IsProcessInJob on process {pid}"))?
            {
                return Ok(());
            }

            // SAFETY: both handles are open for the duration of the call: the
            // job is owned by `self`, the process by `child`, which the borrow
            // keeps alive; the OS reads nothing else.
            let assigned = unsafe { AssignProcessToJobObject(self.handle(), process) };
            if let Err(e) = assigned {
                return Err(e).with_context(|| {
                    format!(
                        "process {pid} could not be contained in the job object: {}",
                        refusal_cause(process)
                    )
                });
            }

            if !self
                .holds(process)
                .with_context(|| format!("IsProcessInJob on process {pid} after assignment"))?
            {
                bail!("process {pid} was assigned to the job object but is not in it");
            }
            Ok(())
        }
    }

    impl Governor for JobGovernor {
        /// [`JobGovernor::assign`], remembered: a positive read-back is what
        /// makes [`governed`](Governor::governed) true, and a failure is what
        /// makes it false from then on.
        fn contain(&self, child: &Child) -> Result<()> {
            let outcome = self.assign(child);
            match &outcome {
                Ok(()) => self.verified.store(true, Ordering::SeqCst),
                Err(_) => self.refused.store(true, Ordering::SeqCst),
            }
            outcome
        }

        fn governed(&self) -> bool {
            self.verified.load(Ordering::SeqCst) && !self.refused.load(Ordering::SeqCst)
        }
    }

    impl Drop for JobGovernor {
        fn drop(&mut self) {
            // The `OwnedHandle` field closes the job's only handle right after
            // this body, and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE has the OS
            // terminate every process still in the job. Nothing to do here
            // but say so.
            tracing::debug!(
                max_memory_bytes = self.max_memory_bytes,
                cpu_rate_percent = ?self.cpu_rate_percent,
                "job object closed; every process contained in it is terminated"
            );
        }
    }

    /// Why `AssignProcessToJobObject` said no. It answers `ERROR_ACCESS_DENIED`
    /// both for a process that has exited and for one whose current job
    /// refuses to nest a new one under it, so the difference is looked up
    /// here, for the caller to log the true reason. A look-up that fails is
    /// reported as exactly that — the query and its error — never as a guess.
    fn refusal_cause(process: HANDLE) -> String {
        let mut code = 0u32;
        // SAFETY: `process` is an open process handle (its `Child` is borrowed
        // by the caller) and `code` outlives the call.
        match unsafe { GetExitCodeProcess(process, &mut code) } {
            Err(e) => {
                return format!(
                    "whether the process is still running could not be determined \
                     (GetExitCodeProcess: {e})"
                );
            }
            Ok(()) if code != STILL_ACTIVE.0 as u32 => {
                return format!("the process had already exited with code {code}");
            }
            Ok(()) => {}
        }

        let mut in_job = BOOL(0);
        // SAFETY: as above; a `None` job asks about any job at all.
        match unsafe { IsProcessInJob(process, None, &mut in_job) } {
            Err(e) => {
                return format!(
                    "whether the process is in a job object could not be determined \
                     (IsProcessInJob: {e})"
                );
            }
            Ok(()) if !in_job.as_bool() => {
                return "the process is running and in no job object; the process handle may \
                        lack PROCESS_SET_QUOTA | PROCESS_TERMINATE"
                    .to_owned();
            }
            Ok(()) => {}
        }

        // It is in a job already whose hierarchy would not nest this job under
        // it. If that job is this process's own — inherited by the child when
        // it was spawned — the question is whether a launch that breaks away
        // from it would have been allowed.
        let mut own = BOOL(0);
        // SAFETY: `GetCurrentProcess` is the calling process's pseudo-handle,
        // valid for the life of the process; `own` outlives the call.
        let breakaway = match unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut own) } {
            Err(e) => format!("unknown (IsProcessInJob on this process: {e})"),
            Ok(()) if !own.as_bool() => {
                "moot: this process is in no job of its own, so the child's job was set by \
                 something else"
                    .to_owned()
            }
            Ok(()) => own_job_breakaway(),
        };
        format!(
            "the process is already in a job object that refused to nest this one; \
             breakaway from this process's own job is {breakaway} (JOB_OBJECT_LIMIT_BREAKAWAY_OK)"
        )
    }

    /// Whether the calling process's own job permits breakaway, by its limit
    /// flags — or why that could not be read.
    fn own_job_breakaway() -> String {
        let mut own_job = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: a `None` job handle queries the calling process's own job;
        // the pointer and the length describe `own_job`, alive for the call.
        match unsafe {
            QueryInformationJobObject(
                None,
                JobObjectExtendedLimitInformation,
                &mut own_job as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                None,
            )
        } {
            Err(e) => {
                format!("unknown (QueryInformationJobObject on this process's own job: {e})")
            }
            Ok(()) => {
                let flags = own_job.BasicLimitInformation.LimitFlags;
                if flags.contains(JOB_OBJECT_LIMIT_BREAKAWAY_OK)
                    || flags.contains(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
                {
                    "permitted".to_owned()
                } else {
                    "not permitted".to_owned()
                }
            }
        }
    }
}
