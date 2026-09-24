//! The syscall surface (spec §3.11). Userland reaches arches, registers and
//! approvals only through this trait; interceptors enforce I1–I4′ on every call.
use crate::arch::Capability;
use crate::labels::{Clearance, Label, Scope};
use crate::ledger::Ledger;
use crate::locks::{Lease, LockError};
use crate::module::{GateVerdict, ModuleError, ModuleManifest};
use crate::principal::{Approval, Principal, PrincipalError};
use crate::register::{Register, RegisterId};
use crate::stop::StopError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Built by the channel layer from an authenticated connection — never by userland.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Ctx {
    pub principal: Principal,
    pub clearance: Clearance,
    pub partition: String,
    pub now_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("I1 violated: {0}")]
    I1(String),
    #[error("I2 violated: {0}")]
    I2(String),
    #[error("I3 violated: {0}")]
    I3(String),
    #[error("I4 violated: {0}")]
    I4(String),
    #[error("I4' violated: {0}")]
    I4Prime(String),
    #[error("scope is stopped: {0}")]
    Stopped(String),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(transparent)]
    Principal(#[from] PrincipalError),
    #[error(transparent)]
    Stop(#[from] StopError),
    #[error(transparent)]
    Module(#[from] ModuleError),
    #[error("gate verdict missing or failed: {0}")]
    Gate(String),
    #[error("not found: {0}")]
    NotFound(String),
    /// The arch is mounted and listed, and it cannot run: the factory could
    /// not re-create it at boot, or the runtime behind it has changed (SP1b
    /// ruling 14). Distinct from `NotFound`, which is an id this node has
    /// never heard of — the difference is the difference between "no such
    /// arch" and "that arch is not usable, here is why", and only the second
    /// tells an operator what to go and fix.
    #[error("arch unavailable: {0}")]
    ArchUnavailable(String),
    /// A durable write or read failed. A syscall that cannot persist its effect
    /// must fail loudly: a swallowed write is an invariant that survives only
    /// until the next restart.
    #[error("store failure: {0}")]
    Store(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferOutcome {
    pub arch_id: String,
    pub projected: bool,
    pub tokens_in: u32,
}

pub trait Kernel {
    fn submit_task(
        &mut self,
        ctx: &Ctx,
        goal: &str,
        label: Label,
    ) -> Result<RegisterId, KernelError>;
    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError>;
    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError>;
    fn infer(
        &mut self,
        ctx: &Ctx,
        arch_id: &str,
        capability: Capability,
        reg: &RegisterId,
    ) -> Result<InferOutcome, KernelError>;
    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError>;
    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError>;
    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError>;
    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError>;
    /// Non-human-initiated execution of a Hot automation; gated by STOP and the liveness lease (I4).
    fn run_automation(
        &mut self,
        ctx: &Ctx,
        business: &str,
        module: &str,
    ) -> Result<(), KernelError>;
    fn promote(
        &mut self,
        ctx: &Ctx,
        module: &ModuleManifest,
        verdicts: &[GateVerdict],
    ) -> Result<(), KernelError>;
    fn export(
        &mut self,
        ctx: &Ctx,
        module_hash: &str,
        to_scope: Scope,
        verdicts: &[GateVerdict],
    ) -> Result<(), KernelError>;
    fn ledger(&self) -> &Ledger;
}
