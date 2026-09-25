//! In-memory stub kernel: enough behaviour to test invariants I1–I4′.
use std::collections::BTreeMap;
use vk_contracts::arch::{ArchManifest, Capability};
use vk_contracts::hash_canonical;
use vk_contracts::interceptors;
use vk_contracts::labels::{Label, Scope};
use vk_contracts::ledger::{ClockQuality, HlcClock, Ledger, RetentionClass};
use vk_contracts::locks::{Lease, LockHome, LockTable};
use vk_contracts::module::{GateKind, GateVerdict, ModuleManifest};
use vk_contracts::principal::{Approval, ApprovalKind, DeviceRegistry};
use vk_contracts::register::{Register, RegisterId};
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopEvent, StopSet};
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;

pub struct StubKernel {
    node_id: String,
    clock: HlcClock,
    ledger: Ledger,
    registers: BTreeMap<RegisterId, Register>,
    arches: BTreeMap<String, ArchManifest>,
    budgets: BTreeMap<String, u32>,
    locks: LockTable,
    home: LockHome,
    devices: DeviceRegistry,
    approvals: Vec<Approval>,
    stops: StopSet,
    liveness: BTreeMap<String, LivenessLease>,
    hot: Vec<String>,
    infer_log: Vec<(String, Label)>,
    counter: u64,
}

impl StubKernel {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.into(),
            clock: HlcClock::new(node_id),
            ledger: Ledger::default(),
            registers: BTreeMap::new(),
            arches: BTreeMap::new(),
            budgets: BTreeMap::new(),
            locks: LockTable::default(),
            home: LockHome::default(),
            devices: DeviceRegistry::default(),
            approvals: vec![],
            stops: StopSet::default(),
            liveness: BTreeMap::new(),
            hot: vec![],
            infer_log: vec![],
            counter: 0,
        }
    }
    fn log(&mut self, kind: &str, now_ms: u64, payload: &impl serde::Serialize) {
        let hlc = self.clock.now(now_ms);
        let payload_hash = hash_canonical(payload);
        self.ledger.append(
            kind,
            RetentionClass::Operational90d,
            now_ms,
            ClockQuality::Synced,
            hlc,
            vec![],
            payload_hash,
        );
    }
    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("{prefix}-{}-{}", self.node_id, self.counter)
    }
    /// Rough token estimate for the stub: 1 token per 4 bytes of goal + evidence.
    fn estimate_tokens(reg: &Register) -> u32 {
        ((reg.goal.len() + reg.evidence.iter().map(|e| e.content.len()).sum::<usize>()) / 4) as u32
            + 1
    }
}

impl Kernel for StubKernel {
    fn submit_task(
        &mut self,
        ctx: &Ctx,
        goal: &str,
        label: Label,
    ) -> Result<RegisterId, KernelError> {
        let id = RegisterId(self.next_id("reg"));
        let reg = Register {
            id: id.clone(),
            task_id: self.next_id("task"),
            label,
            goal: goal.into(),
            constraints: vec![],
            evidence: vec![],
            decisions: vec![],
            open_questions: vec![],
            artefacts: vec![],
        };
        self.registers.insert(id.clone(), reg);
        self.log("task.submitted", ctx.now_ms, &id);
        Ok(id)
    }

    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError> {
        let reg = self
            .registers
            .get(id)
            .cloned()
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
        self.log("register.written", ctx.now_ms, &reg.id);
        self.registers.insert(reg.id.clone(), reg);
        Ok(())
    }

    fn infer(
        &mut self,
        ctx: &Ctx,
        arch_id: &str,
        _capability: Capability,
        reg_id: &RegisterId,
    ) -> Result<InferOutcome, KernelError> {
        let arch = self
            .arches
            .get(arch_id)
            .cloned()
            .ok_or_else(|| KernelError::NotFound(arch_id.into()))?;
        let reg = self
            .registers
            .get(reg_id)
            .cloned()
            .ok_or_else(|| KernelError::NotFound(reg_id.0.clone()))?;
        interceptors::i2_flow(&reg.label, &arch)?;
        let tokens = Self::estimate_tokens(&reg);
        let budget = *self.budgets.get(arch_id).unwrap_or(&arch.context_ceiling);
        let projected = tokens > budget;
        if projected {
            self.log("infer.projected", ctx.now_ms, &(arch_id, tokens, budget));
        }
        self.log("infer", ctx.now_ms, &(arch_id, reg_id));
        self.infer_log.push((arch_id.into(), reg.label.clone()));
        Ok(InferOutcome {
            arch_id: arch_id.into(),
            projected,
            tokens_in: tokens.min(budget),
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
        self.log("lease.granted", ctx.now_ms, &l.id);
        Ok(l)
    }

    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError> {
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        self.log("approval.recorded", ctx.now_ms, &approval);
        self.approvals.push(approval);
        Ok(())
    }

    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("stop");
        self.stops.try_add_stop(StopEvent {
            id: id.clone(),
            scope: scope.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
            causal_heads: vec![],
        })?;
        self.log("stop", ctx.now_ms, &id);
        Ok(id)
    }

    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("resume");
        self.stops.add_resume(ResumeEvent {
            id,
            cites: stop_id.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
        })?;
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
        interceptors::i4_liveness(
            business,
            self.liveness.get(business),
            &self.stops,
            ctx.now_ms,
        )?;
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
            .approvals
            .iter()
            .any(|a| a.subject_hash == subject && a.kind == ApprovalKind::Human);
        if needs_human && !has_human {
            return Err(KernelError::I1(format!(
                "promotion of {} requires a human approval",
                module.name
            )));
        }
        self.hot.push(subject.clone());
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
        &self.ledger
    }
}

impl KernelTestHooks for StubKernel {
    fn register_arch(&mut self, m: ArchManifest) -> String {
        let id = m.arch_id();
        self.budgets.insert(id.clone(), m.context_ceiling);
        self.arches.insert(id.clone(), m);
        id
    }
    fn enroll_device(&mut self, device_id: &str, vk: [u8; 32]) {
        self.devices.register(device_id.into(), vk);
    }
    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64) {
        self.liveness.insert(
            business.into(),
            LivenessLease {
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
        self.approvals
            .iter()
            .filter(|a| a.subject_hash == subject_hash)
            .cloned()
            .collect()
    }
    fn hot_modules(&self) -> Vec<String> {
        self.hot.clone()
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

    fn gemma(clearance: Clearance) -> ArchManifest {
        ArchManifest {
            name: "gemma".into(),
            capabilities: [Capability::Generate].into(),
            locality: Locality::Local,
            jurisdiction: "FR".into(),
            retention_days: None,
            cost_per_1k_tokens_eur: Some(0.0),
            latency_ms_p50: 1,
            context_ceiling: 100,
            determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity {
                weights_sha256: "sha256:w".into(),
                engine: "e".into(),
                engine_version: "1".into(),
                backend: "cpu".into(),
                quant: "q4".into(),
                kv_cache: "f16".into(),
                threads: 1,
                batch: 1,
                sampling: Default::default(),
                seed: None,
            },
            clearance,
            governed: true,
        }
    }
    fn machine_ctx(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "l1".into(),
            },
            clearance: Clearance {
                max_scope: Scope::Personal,
                third_party_allowed: true,
            },
            partition: "p1".into(),
            now_ms: now,
        }
    }
    fn human_ctx(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Human {
                device_id: "phone-1".into(),
            },
            ..machine_ctx(now)
        }
    }

    #[test]
    fn i2_infer_refuses_register_above_arch_clearance() {
        let mut k = StubKernel::new("n1");
        let cloud = k.register_arch(ArchManifest {
            locality: Locality::Cloud,
            clearance: Clearance {
                max_scope: Scope::Business,
                third_party_allowed: false,
            },
            ..gemma(Clearance {
                max_scope: Scope::Public,
                third_party_allowed: false,
            })
        });
        let ctx = machine_ctx(1);
        let r = k
            .submit_task(
                &ctx,
                "draft",
                Label {
                    scope: Scope::Personal,
                    data_class: DataClass::Own,
                    origins: Default::default(),
                },
            )
            .unwrap();
        assert!(matches!(
            k.infer(&ctx, &cloud, Capability::Generate, &r),
            Err(KernelError::I2(_))
        ));
        assert!(k.infer_log().is_empty());
    }

    #[test]
    fn i1_machine_cannot_approve_as_human_but_stop_needs_only_presence() {
        let mut k = StubKernel::new("n1");
        let ap = Approval {
            subject_hash: "sha256:m".into(),
            kind: ApprovalKind::Human,
            approver: Principal::Human {
                device_id: "phone-1".into(),
            },
            challenge: None,
            signature_hex: None,
        };
        assert!(matches!(
            k.approve(&machine_ctx(1), ap.clone()),
            Err(KernelError::I1(_))
        ));
        assert!(matches!(
            k.stop(&machine_ctx(1), "business:acme"),
            Err(KernelError::I1(_))
        ));
        assert!(k.stop(&human_ctx(1), "business:acme").is_ok());
    }

    #[test]
    fn i4_automation_needs_liveness_and_no_stop() {
        let mut k = StubKernel::new("n1");
        let m = machine_ctx(10);
        assert!(matches!(
            k.run_automation(&m, "acme", "mod"),
            Err(KernelError::I4(_))
        ));
        k.renew_liveness("acme", "phone-1", 100);
        assert!(k.run_automation(&m, "acme", "mod").is_ok());
        let s = k.stop(&human_ctx(11), "business:acme").unwrap();
        assert!(matches!(
            k.run_automation(&m, "acme", "mod"),
            Err(KernelError::Stopped(_))
        ));
        k.resume(&human_ctx(12), &s).unwrap();
        assert!(k.run_automation(&m, "acme", "mod").is_ok());
        assert!(matches!(
            k.run_automation(&machine_ctx(100), "acme", "mod"),
            Err(KernelError::I4(_))
        ));
    }

    #[test]
    fn i4_prime_over_budget_lowering_is_refused_or_logged_projection() {
        let mut k = StubKernel::new("n1");
        let arch = k.register_arch(gemma(Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }));
        k.set_context_budget(&arch, 5);
        let ctx = machine_ctx(1);
        let r = k
            .submit_task(&ctx, &"x".repeat(50), Label::bottom())
            .unwrap();
        let out = k.infer(&ctx, &arch, Capability::Generate, &r).unwrap();
        assert!(out.projected);
        assert!(k
            .ledger()
            .events()
            .iter()
            .any(|e| e.kind == "infer.projected"));
        assert!(k.ledger().verify_chain());
    }

    #[test]
    fn promotion_requires_annex_iii_verdict_and_human_approval() {
        use vk_contracts::module::*;
        let mut k = StubKernel::new("n1");
        let module = ModuleManifest {
            name: "quote-drafter".into(),
            kind: ModuleKind::Skill,
            version: "0.1.0".into(),
            machine_evolved: true,
            files: vec!["SKILL.md".into()],
            provenance: Provenance {
                content_hash: "sha256:c".into(),
                lineage: vec![],
                signer: "founder".into(),
                arch_compat: vec![],
                origin_taints: Default::default(),
            },
            pool_epoch: None,
            autonomy_profile: None,
            tags: Default::default(),
        };
        let verdict = GateVerdict {
            gate: GateKind::AnnexIii,
            subject_hash: "sha256:c".into(),
            pass: true,
            evidence_hash: "sha256:e".into(),
            signer: "founder".into(),
        };
        assert!(matches!(
            k.promote(&machine_ctx(1), &module, &[]),
            Err(KernelError::Gate(_))
        ));
        assert!(matches!(
            k.promote(&machine_ctx(1), &module, std::slice::from_ref(&verdict)),
            Err(KernelError::I1(_))
        ));
        let key = SoftwareHumanKey::generate("phone-1");
        k.enroll_device("phone-1", key.verifying_key_bytes());
        let ch = Challenge {
            resource: "module:quote-drafter".into(),
            action_digest: "sha256:c".into(),
            nonce: "n".into(),
            expires_at_ms: 10,
        };
        let sig = key.sign(&ch.digest());
        let ap = Approval {
            subject_hash: "sha256:c".into(),
            kind: ApprovalKind::Human,
            approver: Principal::Human {
                device_id: "phone-1".into(),
            },
            challenge: Some(ch),
            signature_hex: Some(hex::encode(sig)),
        };
        k.approve(&human_ctx(2), ap).unwrap();
        assert!(k.promote(&machine_ctx(3), &module, &[verdict]).is_ok());
        assert_eq!(k.hot_modules(), vec!["sha256:c".to_string()]);
    }
}
