//! Test-only hooks every kernel implementation exposes so the invariant property
//! tests run unchanged against the stub and the real kernel.
use crate::arch::ArchManifest;
use crate::labels::Label;
use crate::principal::Approval;
use crate::stop::StopSet;
use crate::syscalls::Kernel;

pub trait KernelTestHooks: Kernel {
    fn register_arch(&mut self, m: ArchManifest) -> String;
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]);
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64);
    fn set_context_budget(&mut self, arch_id: &str, tokens: u32);
    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval>;
    fn hot_modules(&self) -> Vec<String>;
    fn infer_log(&self) -> Vec<(String, Label)>;
    fn stops(&self) -> StopSet;
}
