//! Interceptors (spec §3.11): decidable invariants only.
use vk_contracts::arch::ArchManifest;
use vk_contracts::labels::Label;
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry, Principal};
use vk_contracts::stop::{LivenessLease, StopSet};
use vk_contracts::syscalls::KernelError;

/// I1: human approvals only from human ceremonies; STOP/RESUME require human presence.
pub fn i1_approval(
    ctx_principal: &Principal,
    ap: &Approval,
    devices: &DeviceRegistry,
    now_ms: u64,
) -> Result<(), KernelError> {
    if ap.kind == ApprovalKind::Human {
        if !ctx_principal.is_human() || ap.approver != *ctx_principal {
            return Err(KernelError::I1(
                "human approval requires the human's own authenticated channel".into(),
            ));
        }
        ap.verify_human(devices, now_ms)?;
    }
    Ok(())
}

pub fn i1_presence(ctx_principal: &Principal) -> Result<(), KernelError> {
    if ctx_principal.is_human() {
        Ok(())
    } else {
        Err(KernelError::I1(
            "STOP/RESUME require a human principal".into(),
        ))
    }
}

/// I2: the register's label must flow to the arch's effective clearance.
pub fn i2_flow(label: &Label, arch: &ArchManifest) -> Result<(), KernelError> {
    if label.flows_to(&arch.clearance) {
        Ok(())
    } else {
        Err(KernelError::I2(format!(
            "label {:?} exceeds clearance of arch {}",
            label.scope, arch.name
        )))
    }
}

/// I4: machine-initiated automation needs an unexpired liveness lease and no active STOP.
pub fn i4_liveness(
    business: &str,
    lease: Option<&LivenessLease>,
    stops: &StopSet,
    now_ms: u64,
) -> Result<(), KernelError> {
    let scope = format!("business:{business}");
    if stops.stopped(&scope) {
        return Err(KernelError::Stopped(scope));
    }
    match lease {
        Some(l) if l.alive(now_ms) => Ok(()),
        _ => Err(KernelError::I4(format!(
            "no live autonomy lease for {business}"
        ))),
    }
}
