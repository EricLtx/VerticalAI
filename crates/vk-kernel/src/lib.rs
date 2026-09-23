//! The real single-node kernel (spec §3): the stub's semantics over vk-store.
pub mod arch;

use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use vk_contracts::arch::{ArchManifest, Capability};
use vk_contracts::hash_canonical;
use vk_contracts::interceptors;
use vk_contracts::labels::{Label, Scope};
use vk_contracts::ledger::{ClockQuality, HlcClock, Ledger, RetentionClass};
use vk_contracts::locks::{Lease, LockHome, LockTable};
use vk_contracts::module::{GateKind, GateVerdict, ModuleManifest};
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry};
use vk_contracts::register::{ArtefactRef, Register, RegisterId};
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopEvent, StopSet};
use vk_contracts::storage::BlobEnvelope;
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;
use vk_store::keys::KeySource;
use vk_store::Store;

/// An enrolled human device, as the `devices` table stores it.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceRow {
    vk_hex: String,
    trust_class: String,
}

/// Cumulative per-arch call counters, persisted under the `kv` key `stats:<arch_id>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchStats {
    pub calls: u64,
    pub tokens_in: u64,
    pub projected: u64,
}

pub struct RealKernel {
    pub node_id: String,
    store: Store,
    clock: HlcClock,
    adapters: BTreeMap<String, Arc<dyn arch::ArchAdapter>>,
    budgets: BTreeMap<String, u32>,
    locks: LockTable,
    home: LockHome,
    devices: DeviceRegistry,
    stops: StopSet,
    infer_log: Vec<(String, Label)>,
    counter: u64,
}

impl RealKernel {
    pub fn open(state_dir: &Path, key_source: KeySource, node_id: &str) -> Result<RealKernel> {
        let store = Store::open(state_dir, key_source)?;
        let mut k = RealKernel {
            node_id: node_id.into(),
            store,
            clock: HlcClock::new(node_id),
            adapters: BTreeMap::new(),
            budgets: BTreeMap::new(),
            locks: LockTable::default(),
            home: LockHome::default(),
            devices: DeviceRegistry::default(),
            stops: StopSet::default(),
            infer_log: vec![],
            counter: 0,
        };
        k.load()?;
        Ok(k)
    }

    fn load(&mut self) -> Result<()> {
        for (_, s) in self.store.db.list_json::<StopEvent>("stops")? {
            let _ = self.stops.try_add_stop(s);
        }
        for (_, r) in self.store.db.list_json::<ResumeEvent>("resumes")? {
            let _ = self.stops.add_resume(r);
        }
        for (id, d) in self.store.db.list_json::<DeviceRow>("devices")? {
            if let Ok(bytes) = hex::decode(&d.vk_hex) {
                if let Ok(vk) = <[u8; 32]>::try_from(bytes) {
                    self.devices.register(id, vk);
                }
            }
        }
        for (id, m) in self.store.db.list_json::<ArchManifest>("arches")? {
            let budget = m.context_ceiling;
            self.adapters.insert(
                id.clone(),
                Arc::new(arch::MockAdapter {
                    manifest: m,
                    budget,
                }),
            );
            self.budgets.insert(id, budget);
        }
        self.counter = self
            .store
            .db
            .kv_get("counter")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(())
    }

    /// Mount a real adapter (replaces the mock loaded from the manifest table).
    pub fn mount(&mut self, adapter: Arc<dyn arch::ArchAdapter>) -> Result<String> {
        let m = adapter.manifest().clone();
        m.validate()?;
        let id = m.arch_id();
        self.store.db.put_json("arches", &id, &m)?;
        self.budgets.insert(id.clone(), adapter.context_budget());
        self.adapters.insert(id.clone(), adapter);
        self.log("arch.mounted", now_ms(), &id);
        Ok(id)
    }

    pub fn unmount(&mut self, arch_id: &str) -> Result<()> {
        self.adapters.remove(arch_id);
        self.budgets.remove(arch_id);
        self.store.db.delete("arches", arch_id)?;
        self.log("arch.unmounted", now_ms(), &arch_id);
        Ok(())
    }

    pub fn arches(&self) -> Vec<(String, ArchManifest)> {
        self.adapters
            .iter()
            .map(|(k, a)| (k.clone(), a.manifest().clone()))
            .collect()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn devices(&self) -> &DeviceRegistry {
        &self.devices
    }

    pub fn attach_artefact(
        &mut self,
        ctx: &Ctx,
        reg_id: &RegisterId,
        kind: &str,
        bytes: &[u8],
    ) -> Result<BlobEnvelope, KernelError> {
        let mut reg = self.read_register(ctx, reg_id)?;
        let env = self
            .store
            .blobs
            .put(&format!("task:{}", reg.task_id), reg.label.clone(), bytes)
            .map_err(|e| KernelError::NotFound(e.to_string()))?;
        reg.artefacts.push(ArtefactRef {
            hash: env.hash.clone(),
            kind: kind.into(),
        });
        self.write_register(ctx, reg)?;
        Ok(env)
    }

    pub fn read_artefact(&self, ctx: &Ctx, hash: &str) -> Result<Vec<u8>, KernelError> {
        let env = self
            .store
            .blobs
            .envelope(hash)
            .map_err(|e| KernelError::NotFound(e.to_string()))?;
        if !env.label.flows_to(&ctx.clearance) {
            return Err(KernelError::I2(format!(
                "artefact {hash} exceeds caller clearance"
            )));
        }
        self.store
            .blobs
            .get(hash)
            .map_err(|e| KernelError::NotFound(e.to_string()))
    }

    fn log(&mut self, kind: &str, wall_ms: u64, payload: &impl serde::Serialize) {
        let hlc = self.clock.now(wall_ms);
        let _ = self.store.ledger.append(
            kind,
            RetentionClass::Operational90d,
            wall_ms,
            ClockQuality::Synced,
            hlc,
            vec![],
            hash_canonical(payload),
        );
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        let _ = self.store.db.kv_set("counter", &self.counter.to_string());
        format!("{prefix}-{}-{}", self.node_id, self.counter)
    }

    fn liveness(&self, business: &str) -> Option<LivenessLease> {
        self.store.db.get_json("liveness", business).ok().flatten()
    }

    /// Accumulate the per-arch counters a later cost/quota task reads back.
    fn bump_stats(&self, arch_id: &str, tokens_in: u32, projected: bool) {
        let key = format!("stats:{arch_id}");
        let mut stats: ArchStats = self
            .store
            .db
            .kv_get(&key)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        stats.calls += 1;
        stats.tokens_in += u64::from(tokens_in);
        stats.projected += u64::from(projected);
        if let Ok(json) = serde_json::to_string(&stats) {
            let _ = self.store.db.kv_set(&key, &json);
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Kernel for RealKernel {
    fn submit_task(
        &mut self,
        ctx: &Ctx,
        goal: &str,
        label: Label,
    ) -> Result<RegisterId, KernelError> {
        let id = RegisterId(self.next_id("reg"));
        let task_id = self.next_id("task");
        let reg = Register {
            id: id.clone(),
            task_id,
            label,
            goal: goal.into(),
            constraints: vec![],
            evidence: vec![],
            decisions: vec![],
            open_questions: vec![],
            artefacts: vec![],
        };
        self.store
            .db
            .put_json("registers", &id.0, &reg)
            .map_err(|e| KernelError::NotFound(e.to_string()))?;
        self.log("task.submitted", ctx.now_ms, &id);
        Ok(id)
    }

    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError> {
        let reg: Register = self
            .store
            .db
            .get_json("registers", &id.0)
            .ok()
            .flatten()
            .ok_or_else(|| KernelError::NotFound(id.0.clone()))?;
        if !reg.label.flows_to(&ctx.clearance) {
            return Err(KernelError::I2(format!(
                "register {} exceeds caller clearance",
                id.0
            )));
        }
        Ok(reg)
    }

    fn write_register(&mut self, ctx: &Ctx, reg: Register) -> Result<(), KernelError> {
        self.store
            .db
            .put_json("registers", &reg.id.0, &reg)
            .map_err(|e| KernelError::NotFound(e.to_string()))?;
        self.log("register.written", ctx.now_ms, &reg.id);
        Ok(())
    }

    fn infer(
        &mut self,
        ctx: &Ctx,
        arch_id: &str,
        capability: Capability,
        reg_id: &RegisterId,
    ) -> Result<InferOutcome, KernelError> {
        let adapter = self
            .adapters
            .get(arch_id)
            .cloned()
            .ok_or_else(|| KernelError::NotFound(arch_id.into()))?;
        let mut reg = self.read_register(ctx, reg_id)?;
        interceptors::i2_flow(&reg.label, adapter.manifest())?;
        let role = match capability {
            Capability::Plan => "plan",
            Capability::Judge => "judge",
            _ => "draft",
        };
        let prompt = arch::lower(&reg, role);
        let tokens = adapter.count_tokens(&prompt);
        let budget = self
            .budgets
            .get(arch_id)
            .copied()
            .unwrap_or_else(|| adapter.context_budget());
        let projected = tokens > budget;
        let prompt = if projected {
            self.log("infer.projected", ctx.now_ms, &(arch_id, tokens, budget));
            arch::project(&prompt, budget)
        } else {
            prompt
        };
        let output = adapter
            .complete(&prompt, budget.min(1024))
            .map_err(|e| KernelError::NotFound(format!("arch error: {e}")))?;
        arch::raise(&mut reg, role, &output);
        self.write_register(ctx, reg.clone())?;
        self.log("infer", ctx.now_ms, &(arch_id, reg_id));
        self.infer_log.push((arch_id.into(), reg.label));
        let tokens_in = tokens.min(budget);
        self.bump_stats(arch_id, tokens_in, projected);
        Ok(InferOutcome {
            arch_id: arch_id.into(),
            projected,
            tokens_in,
        })
    }

    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError> {
        let l = self.locks.acquire(
            resource,
            ctx.principal.clone(),
            ctx.now_ms,
            ttl_ms,
            &ctx.partition,
            &mut self.home,
        )?;
        let _ = self.store.db.put_json("leases", &l.id, &l);
        self.log("lease.granted", ctx.now_ms, &l.id);
        Ok(l)
    }

    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError> {
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        let key = format!("{}:{}", approval.subject_hash, hash_canonical(&approval));
        let _ = self.store.db.put_json("approvals", &key, &approval);
        self.log("approval.recorded", ctx.now_ms, &approval);
        Ok(())
    }

    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("stop");
        let e = StopEvent {
            id: id.clone(),
            scope: scope.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
            causal_heads: vec![],
        };
        self.stops.try_add_stop(e.clone())?;
        let _ = self.store.db.put_json("stops", &id, &e);
        self.log("stop", ctx.now_ms, &id);
        Ok(id)
    }

    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("resume");
        let e = ResumeEvent {
            id: id.clone(),
            cites: stop_id.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
        };
        self.stops.add_resume(e.clone())?;
        let _ = self.store.db.put_json("resumes", &id, &e);
        self.log("resume", ctx.now_ms, &stop_id);
        Ok(())
    }

    fn run_automation(
        &mut self,
        ctx: &Ctx,
        business: &str,
        module: &str,
    ) -> Result<(), KernelError> {
        if ctx.principal.is_human() {
            return Ok(()); // human-initiated runs are not automations
        }
        let lease = self.liveness(business);
        interceptors::i4_liveness(business, lease.as_ref(), &self.stops, ctx.now_ms)?;
        self.log("automation.ran", ctx.now_ms, &(business, module));
        Ok(())
    }

    fn promote(
        &mut self,
        ctx: &Ctx,
        module: &ModuleManifest,
        verdicts: &[GateVerdict],
    ) -> Result<(), KernelError> {
        module.validate()?;
        let subject = module.provenance.content_hash.clone();
        if !verdicts
            .iter()
            .any(|v| v.gate == GateKind::AnnexIii && v.subject_hash == subject && v.pass)
        {
            return Err(KernelError::Gate(
                "annex_iii verdict required for promotion".into(),
            ));
        }
        let needs_human = module
            .autonomy_profile
            .as_ref()
            .map(|p| !p.auto_approve_allowed)
            .unwrap_or(true);
        let has_human = self
            .approvals_for(&subject)
            .iter()
            .any(|a| a.kind == ApprovalKind::Human);
        if needs_human && !has_human {
            return Err(KernelError::I1(format!(
                "promotion of {} requires a human approval",
                module.name
            )));
        }
        let _ = self.store.db.put_json("hot", &subject, module);
        self.log("module.promoted", ctx.now_ms, &subject);
        Ok(())
    }

    fn export(
        &mut self,
        ctx: &Ctx,
        module_hash: &str,
        to_scope: Scope,
        verdicts: &[GateVerdict],
    ) -> Result<(), KernelError> {
        if to_scope <= Scope::Vertical
            && !verdicts.iter().any(|v| {
                v.gate == GateKind::Declassification && v.subject_hash == module_hash && v.pass
            })
        {
            return Err(KernelError::Gate(
                "declassification verdict required to leave the business".into(),
            ));
        }
        self.log("module.exported", ctx.now_ms, &(module_hash, to_scope));
        Ok(())
    }

    fn ledger(&self) -> &Ledger {
        self.store.ledger.chain()
    }
}

impl KernelTestHooks for RealKernel {
    fn register_arch(&mut self, m: ArchManifest) -> String {
        let budget = m.context_ceiling;
        self.mount(Arc::new(arch::MockAdapter {
            manifest: m,
            budget,
        }))
        .expect("mount")
    }

    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]) {
        self.devices.register(device_id.into(), vk);
        let _ = self.store.db.put_json(
            "devices",
            device_id,
            &DeviceRow {
                vk_hex: hex::encode(vk),
                trust_class: "full".into(),
            },
        );
        self.log("device.enrolled", now_ms(), &device_id);
    }

    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64) {
        let _ = self.store.db.put_json(
            "liveness",
            business,
            &LivenessLease {
                business: business.into(),
                renewed_by_device: device_id.into(),
                expires_at_ms,
            },
        );
    }

    fn set_context_budget(&mut self, arch_id: &str, tokens: u32) {
        self.budgets.insert(arch_id.into(), tokens);
    }

    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval> {
        self.store
            .db
            .list_json::<Approval>("approvals")
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&format!("{subject_hash}:")))
            .map(|(_, a)| a)
            .collect()
    }

    fn hot_modules(&self) -> Vec<String> {
        self.store
            .db
            .list_json::<ModuleManifest>("hot")
            .unwrap_or_default()
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    fn infer_log(&self) -> Vec<(String, Label)> {
        self.infer_log.clone()
    }

    fn stops(&self) -> StopSet {
        self.stops.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_contracts::arch::*;
    use vk_contracts::labels::*;
    use vk_contracts::principal::*;
    use vk_contracts::testing::KernelTestHooks;
    use vk_store::keys::KeySource;

    fn open(dir: &std::path::Path) -> RealKernel {
        RealKernel::open(dir, KeySource::File(dir.join("master.key")), "n1").unwrap()
    }

    pub(crate) fn local(clearance: Clearance) -> ArchManifest {
        ArchManifest {
            name: "mock".into(),
            capabilities: [Capability::Generate, Capability::Plan].into(),
            locality: Locality::Local,
            jurisdiction: "FR".into(),
            retention_days: None,
            cost_per_1k_tokens_eur: 0.0,
            latency_ms_p50: 1,
            context_ceiling: 100,
            determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity {
                weights_sha256: "sha256:mock".into(),
                engine: "mock".into(),
                engine_version: "1".into(),
                backend: "cpu".into(),
                quant: "-".into(),
                kv_cache: "-".into(),
                threads: 1,
                batch: 1,
                sampling: Default::default(),
                seed: Some(1),
            },
            clearance,
            governed: true,
        }
    }

    fn machine(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "cli".into(),
            },
            clearance: Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            },
            partition: "p1".into(),
            now_ms: now,
        }
    }

    fn human(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Human {
                device_id: "phone-1".into(),
            },
            ..machine(now)
        }
    }

    #[test]
    fn state_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let (arch, reg, stop_id) = {
            let mut k = open(d.path());
            let arch = k.register_arch(local(Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            }));
            let reg = k
                .submit_task(&machine(1), "draft a proposal", Label::bottom())
                .unwrap();
            k.infer(&machine(2), &arch, Capability::Plan, &reg).unwrap();
            let s = k.stop(&human(3), "business:acme").unwrap();
            (arch, reg, s)
        };
        let mut k = open(d.path());
        let r = k.read_register(&machine(4), &reg).unwrap();
        assert!(
            !r.decisions.is_empty(),
            "the plan raised into the IR must persist"
        );
        assert!(k.stops().stopped("business:acme"));
        assert!(k.ledger().verify_chain());
        assert!(k.ledger().events().iter().any(|e| e.kind == "infer"));
        k.resume(&human(5), &stop_id).unwrap();
        assert!(!k.stops().stopped("business:acme"));
        let _ = arch;
    }

    #[test]
    fn i2_and_i4_prime_hold_on_the_real_kernel() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let cloud = k.register_arch(ArchManifest {
            locality: Locality::Cloud,
            clearance: Clearance {
                max_scope: Scope::Business,
                third_party_allowed: false,
            },
            ..local(Clearance {
                max_scope: Scope::Public,
                third_party_allowed: false,
            })
        });
        let r = k
            .submit_task(
                &machine(1),
                "x",
                Label {
                    scope: Scope::Personal,
                    data_class: DataClass::Own,
                    origins: Default::default(),
                },
            )
            .unwrap();
        assert!(matches!(
            k.infer(&machine(1), &cloud, Capability::Generate, &r),
            Err(KernelError::I2(_))
        ));
        let small = k.register_arch(local(Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }));
        k.set_context_budget(&small, 5);
        let r2 = k
            .submit_task(&machine(1), &"g".repeat(400), Label::bottom())
            .unwrap();
        assert!(
            k.infer(&machine(1), &small, Capability::Generate, &r2)
                .unwrap()
                .projected
        );
        assert!(k
            .ledger()
            .events()
            .iter()
            .any(|e| e.kind == "infer.projected"));
    }

    #[test]
    fn artefacts_are_stored_as_encrypted_blobs_under_the_task_subject() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let r = k.submit_task(&machine(1), "x", Label::bottom()).unwrap();
        let env = k
            .attach_artefact(&machine(2), &r, "proposal.md", b"# Proposal")
            .unwrap();
        assert_eq!(
            k.read_artefact(&machine(3), &env.hash).unwrap(),
            b"# Proposal".to_vec()
        );
        let reg = k.read_register(&machine(4), &r).unwrap();
        assert_eq!(reg.artefacts[0].hash, env.hash);
    }
}
