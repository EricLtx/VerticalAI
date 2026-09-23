//! The real single-node kernel (spec §3): the stub's semantics over vk-store.
pub mod arch;
pub mod ns;
pub mod presence;
pub mod tasks;

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
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopError, StopEvent, StopSet};
use vk_contracts::storage::BlobEnvelope;
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;
use vk_store::keys::KeySource;
use vk_store::Store;

/// Any durable read or write that failed. A syscall that cannot persist its
/// effect must not report success: the effect would survive only until the next
/// restart, and every invariant this kernel enforces is a claim about what is
/// still true after one.
fn store_failed(e: impl std::fmt::Display) -> KernelError {
    KernelError::Store(e.to_string())
}

/// An artefact's `kind` is not free-form text: a `Release` step turns it into a
/// file name (`<hash12>.<kind>`), so a kind containing a separator or a `..`
/// would be a path, and a path is an escape from wherever the release was
/// confined to. It is validated here, at the only door artefacts come in by,
/// rather than sanitised on the way out — a register is durable, and a value
/// that must never be written is better refused than repaired forever after.
fn validate_artefact_kind(kind: &str) -> Result<(), KernelError> {
    let ok = !kind.is_empty()
        && kind.len() <= 32
        && !kind.starts_with('.')
        && kind
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        return Err(KernelError::Gate(
            "artefact kind must be a short plain token".into(),
        ));
    }
    Ok(())
}

/// The `kv` key holding the version of the policy set this node runs under.
const POLICIES_VERSION: &str = "policies_version";

/// An enrolled human device, as the `devices` table stores it.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceRow {
    vk_hex: String,
    trust_class: String,
}

/// What this node came up with: the verdict on its own record, what it had to
/// repair to read it, and the durable state it will serve. `vkd` logs it,
/// refuses to serve on `ledger_ok: false` unless forced, and the `boot` ledger
/// event commits to its canonical hash — so the report a person reads and the
/// one the record keeps are the same value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BootReport {
    /// Did the hash chain verify? The chain as found, before the `boot` event.
    pub ledger_ok: bool,
    /// How many events that chain had — again, before this boot's own event.
    pub ledger_len: usize,
    /// A crash mid-`append` left an unterminated last line, which the store
    /// dropped and truncated away. One event is missing from the record.
    pub recovered_partial_line: bool,
    pub arches: Vec<String>,
    pub devices: Vec<String>,
    pub stopped_scopes: Vec<String>,
    /// Placeholder (spec §4.3): there is no policy engine in SP1a, so boot
    /// writes `"0"` the first time it finds no version and reports it
    /// unchanged afterwards. It exists so that the first policy set has a
    /// predecessor to migrate from.
    pub policies_version: String,
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
        // Fences first, and from `kv` rather than from the lease rows: a fence
        // must stay monotonic for the life of the resource, including after the
        // last lease that carried it has expired and been swept away below.
        for (key, value) in self.store.db.kv_list_prefix("fence:")? {
            if let (Some(resource), Ok(fence)) = (key.strip_prefix("fence:"), value.parse::<u64>())
            {
                self.home.restore(resource, fence);
            }
        }
        // A lease outlives the process that granted it: a restart must not hand
        // the resource to somebody else while the first holder still has time.
        //
        // Exactly one live row per (resource, partition) is restored. `acquire`
        // matches the *first* row it finds, so restoring a superseded one — a
        // renewal whose predecessor outlived a crash — would let it answer for
        // a resource whose real holder is somebody else.
        let now = now_ms();
        let mut newest: BTreeMap<(String, String), (String, Lease)> = BTreeMap::new();
        let mut stale: Vec<String> = Vec::new();
        for (key, lease) in self.store.db.list_json::<Lease>("leases")? {
            self.home.restore(&lease.resource, lease.fence);
            if lease.expired(now) {
                stale.push(key);
                continue;
            }
            let slot = (lease.resource.clone(), lease.partition.clone());
            match newest.remove(&slot) {
                Some((prev_key, prev))
                    if (prev.granted_at_ms, prev.fence) >= (lease.granted_at_ms, lease.fence) =>
                {
                    stale.push(key);
                    newest.insert(slot, (prev_key, prev));
                }
                Some((prev_key, _)) => {
                    stale.push(prev_key);
                    newest.insert(slot, (key, lease));
                }
                None => {
                    newest.insert(slot, (key, lease));
                }
            }
        }
        for key in stale {
            self.store.db.delete("leases", &key)?;
        }
        for (_, (_, lease)) in newest {
            self.locks.restore(lease);
        }
        self.counter = self
            .store
            .db
            .kv_get("counter")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(())
    }

    /// The boot sequence: verify the ledger chain, load the policies version,
    /// enumerate what this node has, and record that it started.
    ///
    /// The `boot` event is appended whatever the verdict: a node that came up
    /// on a chain that does not verify is exactly the thing an auditor must
    /// find in the record afterwards. Whether to *serve* on that verdict is
    /// not the kernel's call — `vkd` refuses unless `--force` says otherwise —
    /// because the one thing a broken chain must not do is stop the operator
    /// from looking at it.
    ///
    /// The event's payload is the hash of this very report, so the record says
    /// what the node found and not merely that it started.
    pub fn boot(&mut self) -> Result<BootReport, KernelError> {
        let report = BootReport {
            ledger_ok: self.store.ledger.verify(),
            ledger_len: self.store.ledger.len(),
            recovered_partial_line: self.recovered_partial_line(),
            arches: self.arches().into_iter().map(|(id, _)| id).collect(),
            devices: self.devices.ids(),
            stopped_scopes: self.stops.stopped_scopes(),
            policies_version: self.policies_version()?,
        };
        self.log("boot", now_ms(), &report)?;
        Ok(report)
    }

    /// The policy set this node runs under. SP1a has no policy engine, so the
    /// key is written once with `"0"` and read back unchanged; the version is
    /// in the boot report from the start so that the first real policy set has
    /// a predecessor in the record to migrate from.
    fn policies_version(&mut self) -> Result<String, KernelError> {
        if let Some(v) = self
            .store
            .db
            .kv_get(POLICIES_VERSION)
            .map_err(store_failed)?
        {
            return Ok(v);
        }
        self.store
            .db
            .kv_set(POLICIES_VERSION, "0")
            .map_err(store_failed)?;
        Ok("0".into())
    }

    /// Did opening the ledger have to drop an unterminated last line (a crash
    /// mid-`append`)? True for the life of this kernel, which is the life of
    /// the `LedgerFs` that repaired it.
    pub fn recovered_partial_line(&self) -> bool {
        self.store.ledger.recovered_partial_line
    }

    /// Every scope a live STOP still holds.
    pub fn stopped_scopes(&self) -> Vec<String> {
        self.stops.stopped_scopes()
    }

    /// Mount an adapter for its manifest's arch id, replacing the mock that
    /// `load` built from the `arches` table.
    ///
    /// The arch id hashes only `ArchIdentity`, so two manifests can agree on it
    /// and still disagree about clearance — the very field `i2_flow` consults.
    /// Letting the second silently win would relabel a mounted arch, so a
    /// conflicting manifest is refused; re-mounting an identical one only swaps
    /// the adapter (a real engine taking over from the mock) and is otherwise a
    /// no-op.
    pub fn mount(&mut self, adapter: Arc<dyn arch::ArchAdapter>) -> Result<String> {
        let m = adapter.manifest().clone();
        m.validate()?;
        let id = m.arch_id();
        if let Some(mounted) = self.adapters.get(&id) {
            anyhow::ensure!(
                *mounted.manifest() == m,
                "arch {id} is already mounted with a different manifest; unmount first"
            );
            self.budgets.insert(id.clone(), adapter.context_budget());
            self.adapters.insert(id.clone(), adapter);
            return Ok(id);
        }
        self.store.db.put_json("arches", &id, &m)?;
        self.budgets.insert(id.clone(), adapter.context_budget());
        self.adapters.insert(id.clone(), adapter);
        self.log("arch.mounted", now_ms(), &id)?;
        Ok(id)
    }

    pub fn unmount(&mut self, arch_id: &str) -> Result<()> {
        self.adapters.remove(arch_id);
        self.budgets.remove(arch_id);
        self.store.db.delete("arches", arch_id)?;
        self.log("arch.unmounted", now_ms(), &arch_id)?;
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

    /// Enrol a human device. The `KernelTestHooks` hook of the same name cannot
    /// report a failed write, so production callers (the IPC admin syscall) use
    /// this one.
    pub fn enroll_device_persisted(
        &mut self,
        device_id: &str,
        vk: [u8; 32],
    ) -> Result<(), KernelError> {
        self.store
            .db
            .put_json(
                "devices",
                device_id,
                &DeviceRow {
                    vk_hex: hex::encode(vk),
                    trust_class: "full".into(),
                },
            )
            .map_err(store_failed)?;
        self.devices.register(device_id.into(), vk);
        self.log("device.enrolled", now_ms(), &device_id)?;
        Ok(())
    }

    /// Enrol the node's own device key as `node:<node_id>`, trust class `full`.
    ///
    /// Idempotent: the same key again is a no-op (no row written, no event
    /// logged). A *different* key is refused: the node device is the key that
    /// makes local requests human, and swapping it would be swapping who the
    /// human is — an I1 matter, not an update.
    pub fn enroll_node_key(&mut self, vk: [u8; 32]) -> Result<(), KernelError> {
        let id = format!("node:{}", self.node_id);
        let existing: Option<DeviceRow> = self
            .store
            .db
            .get_json("devices", &id)
            .map_err(store_failed)?;
        match existing {
            Some(row) if row.vk_hex == hex::encode(vk) => Ok(()),
            Some(_) => Err(KernelError::I1(format!(
                "device {id} is already enrolled with a different key"
            ))),
            None => self.enroll_device_persisted(&id, vk),
        }
    }

    /// `enroll_node_key` for the device `vk boot` loaded; a device made for
    /// another node id is not this node's device.
    pub fn enroll_node_device(&mut self, dev: &presence::NodeDevice) -> Result<(), KernelError> {
        use vk_contracts::principal::HumanKey;
        let expected = format!("node:{}", self.node_id);
        if dev.device_id() != expected {
            return Err(KernelError::I1(format!(
                "device {} is not this node's device ({expected})",
                dev.device_id()
            )));
        }
        self.enroll_node_key(dev.verifying_key_bytes())
    }

    /// Renew a business's liveness lease (I4). As above: the test hook cannot
    /// report a failed write, production callers use this one.
    pub fn renew_liveness_persisted(
        &mut self,
        business: &str,
        device_id: &str,
        expires_at_ms: u64,
    ) -> Result<(), KernelError> {
        self.store
            .db
            .put_json(
                "liveness",
                business,
                &LivenessLease {
                    business: business.into(),
                    renewed_by_device: device_id.into(),
                    expires_at_ms,
                },
            )
            .map_err(store_failed)
    }

    pub fn attach_artefact(
        &mut self,
        ctx: &Ctx,
        reg_id: &RegisterId,
        kind: &str,
        bytes: &[u8],
    ) -> Result<BlobEnvelope, KernelError> {
        validate_artefact_kind(kind)?;
        let mut reg = self.read_register(ctx, reg_id)?;
        let env = self
            .store
            .blobs
            .put(&format!("task:{}", reg.task_id), reg.label.clone(), bytes)
            .map_err(store_failed)?;
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

    fn log(
        &mut self,
        kind: &str,
        wall_ms: u64,
        payload: &impl serde::Serialize,
    ) -> Result<(), KernelError> {
        let hlc = self.clock.now(wall_ms);
        self.store
            .ledger
            .append(
                kind,
                RetentionClass::Operational90d,
                wall_ms,
                ClockQuality::Synced,
                hlc,
                vec![],
                hash_canonical(payload),
            )
            .map_err(store_failed)?;
        Ok(())
    }

    fn next_id(&mut self, prefix: &str) -> Result<String, KernelError> {
        self.counter += 1;
        self.store
            .db
            .kv_set("counter", &self.counter.to_string())
            .map_err(store_failed)?;
        Ok(format!("{prefix}-{}-{}", self.node_id, self.counter))
    }

    fn liveness(&self, business: &str) -> Result<Option<LivenessLease>, KernelError> {
        self.store
            .db
            .get_json("liveness", business)
            .map_err(store_failed)
    }

    /// Accumulate the per-arch counters a later cost/quota task reads back.
    fn bump_stats(
        &self,
        arch_id: &str,
        tokens_in: u32,
        projected: bool,
    ) -> Result<(), KernelError> {
        let key = format!("stats:{arch_id}");
        let mut stats: ArchStats = match self.store.db.kv_get(&key).map_err(store_failed)? {
            Some(v) => serde_json::from_str(&v).map_err(store_failed)?,
            None => ArchStats::default(),
        };
        stats.calls += 1;
        stats.tokens_in += u64::from(tokens_in);
        stats.projected += u64::from(projected);
        let json = serde_json::to_string(&stats).map_err(store_failed)?;
        self.store.db.kv_set(&key, &json).map_err(store_failed)
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
        let id = RegisterId(self.next_id("reg")?);
        let task_id = self.next_id("task")?;
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
            .map_err(store_failed)?;
        self.log("task.submitted", ctx.now_ms, &id)?;
        Ok(id)
    }

    fn read_register(&mut self, ctx: &Ctx, id: &RegisterId) -> Result<Register, KernelError> {
        let reg: Register = self
            .store
            .db
            .get_json("registers", &id.0)
            .map_err(store_failed)?
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
            .map_err(store_failed)?;
        self.log("register.written", ctx.now_ms, &reg.id)
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
        let count = |text: &str| adapter.count_tokens(text);
        let prompt = arch::lower(&reg, role);
        let tokens = count(&prompt);
        let budget = self
            .budgets
            .get(arch_id)
            .copied()
            .unwrap_or_else(|| adapter.context_budget());
        let projected = tokens > budget;
        let prompt = if projected {
            // Project first, log second: an `infer.projected` event has to mean
            // a projection that actually happened.
            let fitted = arch::project(&prompt, budget, &count).ok_or_else(|| {
                KernelError::I4Prime(format!(
                    "arch {arch_id} has {budget} tokens of context, too few for the role and goal \
                     of register {}; refusing rather than sending a mutilated prompt",
                    reg_id.0
                ))
            })?;
            self.log("infer.projected", ctx.now_ms, &(arch_id, tokens, budget))?;
            fitted
        } else {
            prompt
        };
        // What the arch is actually handed, not a clamp of what we wished for.
        let tokens_in = count(&prompt);
        let output = adapter
            .complete(&prompt, budget.min(1024))
            .map_err(|e| KernelError::NotFound(format!("arch error: {e}")))?;
        // The call has left the kernel: record it before doing anything that
        // could fail, or a real send to a real arch could leave no trace.
        self.log("infer", ctx.now_ms, &(arch_id, reg_id))?;
        self.infer_log.push((arch_id.into(), reg.label.clone()));
        self.bump_stats(arch_id, tokens_in, projected)?;
        arch::raise(&mut reg, role, &output);
        self.write_register(ctx, reg)?;
        Ok(InferOutcome {
            arch_id: arch_id.into(),
            projected,
            tokens_in,
        })
    }

    fn lease(&mut self, ctx: &Ctx, resource: &str, ttl_ms: u64) -> Result<Lease, KernelError> {
        // `acquire` retains the superseded lease away in memory when the same
        // holder renews; the row it was loaded from has to go with it, or a
        // later boot restores a lease nobody holds any more.
        let superseded: Vec<String> = self
            .store
            .db
            .list_json::<Lease>("leases")
            .map_err(store_failed)?
            .into_iter()
            .filter(|(_, l)| l.resource == resource && l.partition == ctx.partition)
            .map(|(key, _)| key)
            .collect();
        let l = self.locks.acquire(
            resource,
            ctx.principal.clone(),
            ctx.now_ms,
            ttl_ms,
            &ctx.partition,
            &mut self.home,
        )?;
        self.store
            .db
            .put_json("leases", &l.id, &l)
            .map_err(store_failed)?;
        for key in superseded {
            if key != l.id {
                self.store.db.delete("leases", &key).map_err(store_failed)?;
            }
        }
        // The fence outlives the lease: persist it separately so a resource
        // whose leases have all expired still cannot see a fence reissued.
        self.store
            .db
            .kv_set(&format!("fence:{resource}"), &l.fence.to_string())
            .map_err(store_failed)?;
        self.log("lease.granted", ctx.now_ms, &l.id)?;
        Ok(l)
    }

    fn approve(&mut self, ctx: &Ctx, approval: Approval) -> Result<(), KernelError> {
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        let key = format!("{}:{}", approval.subject_hash, hash_canonical(&approval));
        // Ledger first: an approval that is stored but reported as failed would
        // still satisfy a later promote's human-approval gate.
        self.log("approval.recorded", ctx.now_ms, &approval)?;
        self.store
            .db
            .put_json("approvals", &key, &approval)
            .map_err(store_failed)
    }

    fn stop(&mut self, ctx: &Ctx, scope: &str) -> Result<String, KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        let id = self.next_id("stop")?;
        let e = StopEvent {
            id: id.clone(),
            scope: scope.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
            causal_heads: vec![],
        };
        // Durable before in-memory: a STOP that this process believes in but
        // that no restart would find is the one failure a STOP may never have.
        self.store
            .db
            .put_json("stops", &id, &e)
            .map_err(store_failed)?;
        self.stops.try_add_stop(e)?;
        self.log("stop", ctx.now_ms, &id)?;
        Ok(id)
    }

    fn resume(&mut self, ctx: &Ctx, stop_id: &str) -> Result<(), KernelError> {
        interceptors::i1_presence(&ctx.principal)?;
        // Before anything is written down. `add_resume` would catch this too,
        // but only after the row existed, and stop ids are sequential: a resume
        // citing an id no STOP has taken yet would be waiting on disk to lift
        // the STOP that takes it after the next reboot.
        if !self.stops.has_stop(stop_id) {
            return Err(StopError::UnknownStop.into());
        }
        let id = self.next_id("resume")?;
        let e = ResumeEvent {
            id: id.clone(),
            cites: stop_id.into(),
            issuer: ctx.principal.clone(),
            hlc_ms: ctx.now_ms,
        };
        // Ledger first: lifting a STOP is granting authority back, and a call
        // that reports failure must not have lifted anything.
        self.log("resume", ctx.now_ms, &stop_id)?;
        self.store
            .db
            .put_json("resumes", &id, &e)
            .map_err(store_failed)?;
        self.stops.add_resume(e)?;
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
        let lease = self.liveness(business)?;
        interceptors::i4_liveness(business, lease.as_ref(), &self.stops, ctx.now_ms)?;
        self.log("automation.ran", ctx.now_ms, &(business, module))
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
        // Ledger first: a module that is Hot but reported as not promoted would
        // be running unaudited.
        self.log("module.promoted", ctx.now_ms, &subject)?;
        self.store
            .db
            .put_json("hot", &subject, module)
            .map_err(store_failed)
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
        self.log("module.exported", ctx.now_ms, &(module_hash, to_scope))
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
        self.enroll_device_persisted(device_id, vk)
            .expect("store write");
    }

    fn renew_liveness(&mut self, business: &str, device_id: &str, expires_at_ms: u64) {
        self.renew_liveness_persisted(business, device_id, expires_at_ms)
            .expect("store write");
    }

    fn set_context_budget(&mut self, arch_id: &str, tokens: u32) {
        self.budgets.insert(arch_id.into(), tokens);
    }

    fn approvals_for(&self, subject_hash: &str) -> Vec<Approval> {
        // On the stored value, never on the composite key: `hash_canonical`
        // contains ':' itself, so a key-prefix match would let the subject
        // "sha256" stand in for every approval in the table.
        self.store
            .db
            .list_json::<Approval>("approvals")
            .unwrap_or_default()
            .into_iter()
            .map(|(_, a)| a)
            .filter(|a| a.subject_hash == subject_hash)
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
    use vk_contracts::register::Evidence;
    use vk_contracts::testing::KernelTestHooks;
    use vk_store::keys::KeySource;

    fn open(dir: &std::path::Path) -> RealKernel {
        RealKernel::open(dir, KeySource::File(dir.join("master.key")), "n1").unwrap()
    }

    /// The arch id hashes `ArchIdentity` alone, so two fixtures that differ only
    /// in clearance collide on it and `mount` (rightly) refuses the second. Name
    /// the weights when a test needs two arches mounted at once.
    pub(crate) fn local_named(name: &str, clearance: Clearance) -> ArchManifest {
        ArchManifest {
            name: name.into(),
            capabilities: [Capability::Generate, Capability::Plan].into(),
            locality: Locality::Local,
            jurisdiction: "FR".into(),
            retention_days: None,
            cost_per_1k_tokens_eur: 0.0,
            latency_ms_p50: 1,
            context_ceiling: 100,
            determinism: Determinism::SeededDeterministic,
            identity: ArchIdentity {
                weights_sha256: format!("sha256:mock-{name}"),
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

    pub(crate) fn local(clearance: Clearance) -> ArchManifest {
        local_named("mock", clearance)
    }

    fn personal() -> Clearance {
        Clearance {
            max_scope: Scope::Personal,
            third_party_allowed: true,
        }
    }

    fn machine(now: u64) -> Ctx {
        Ctx {
            principal: Principal::Machine {
                node_id: "n1".into(),
                lease_id: "cli".into(),
            },
            clearance: personal(),
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
    fn boot_verifies_the_chain_and_records_that_the_node_started() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let boots = |k: &RealKernel| {
            k.ledger()
                .events()
                .iter()
                .filter(|e| e.kind == "boot")
                .count()
        };

        let first = k.boot().unwrap();
        assert!(first.ledger_ok, "a fresh chain verifies");
        // The report counts the chain boot *verified*; its own event follows.
        assert_eq!(first.ledger_len + 1, k.ledger().events().len());
        assert_eq!(boots(&k), 1, "one boot event per boot");

        // Every start is on the record, and the event it appends is part of
        // the chain it just verified.
        let second = k.boot().unwrap();
        assert!(second.ledger_ok);
        assert_eq!(second.ledger_len, first.ledger_len + 1);
        assert_eq!(boots(&k), 2);
        assert!(k.ledger().verify_chain());

        // The event commits to the report, so the record says what the node
        // found at boot and not merely that it started.
        let logged = k
            .ledger()
            .events()
            .iter()
            .rfind(|e| e.kind == "boot")
            .unwrap()
            .clone();
        assert_eq!(logged.payload_hash, hash_canonical(&second));
    }

    /// The whole report, from a node that has something to report: a mounted
    /// arch, an enrolled device, a held STOP and a policies version that boot
    /// writes down the first time it does not find one.
    #[test]
    fn boot_reports_what_this_node_came_up_with() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k
            .mount(Arc::new(arch::MockAdapter {
                manifest: local(personal()),
                budget: 100,
            }))
            .unwrap();
        k.enroll_device_persisted("phone-1", [7u8; 32]).unwrap();
        let stop = k.stop(&human(1), "business:acme").unwrap();

        let r = k.boot().unwrap();
        assert!(r.ledger_ok);
        assert!(!r.recovered_partial_line, "nothing was recovered");
        assert_eq!(r.arches, vec![arch.clone()]);
        assert_eq!(r.devices, vec!["phone-1".to_string()]);
        assert_eq!(r.stopped_scopes, vec!["business:acme".to_string()]);
        assert_eq!(r.policies_version, "0", "the placeholder, written at boot");

        // A resumed scope is not stopped any more, and a restart reports the
        // same thing this one does: the report is read back from disk.
        k.resume(&human(2), &stop).unwrap();
        drop(k);
        let mut k = open(d.path());
        let r2 = k.boot().unwrap();
        assert!(r2.stopped_scopes.is_empty(), "{r2:?}");
        assert_eq!(r2.arches, vec![arch]);
        assert_eq!(r2.devices, vec!["phone-1".to_string()]);
        assert_eq!(r2.policies_version, "0");
    }

    /// A ledger line changed under the kernel's feet. Boot still starts — the
    /// node must be able to say what happened — but it says the chain is
    /// broken, and `vkd` refuses to serve on that unless it is forced.
    #[test]
    fn boot_reports_a_tampered_chain_rather_than_trusting_it() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut k = open(d.path());
            k.boot().unwrap();
            assert!(k.boot().unwrap().ledger_ok);
        }
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        first["payload_hash"] = serde_json::json!("sha256:tampered");
        lines[0] = serde_json::to_string(&first).unwrap();
        std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();

        let mut k = open(d.path());
        let r = k.boot().unwrap();
        assert!(!r.ledger_ok, "a rewritten line must not pass as the record");
        assert!(!r.recovered_partial_line);
    }

    /// A crash mid-append leaves an unterminated last line. The store drops it
    /// and truncates; boot says so, because "one event is missing" is a thing
    /// an operator has to be told rather than left to find.
    #[test]
    fn boot_reports_a_recovered_partial_line() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut k = open(d.path());
            k.boot().unwrap();
        }
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        std::io::Write::write_all(&mut f, b"{\"seq\":99,\"prev_hash\":\"x\"").unwrap();
        drop(f);

        {
            let mut k = open(d.path());
            let r = k.boot().unwrap();
            assert!(r.recovered_partial_line);
            assert!(r.ledger_ok, "what is left of the chain still verifies");
        }
        // And the next start has nothing left to recover: the partial line was
        // truncated away, not merely skipped.
        let mut k = open(d.path());
        assert!(!k.boot().unwrap().recovered_partial_line);
    }

    #[test]
    fn state_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let (arch, reg, stop_id) = {
            let mut k = open(d.path());
            let arch = k.register_arch(local(personal()));
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
            ..local_named(
                "cloud",
                Clearance {
                    max_scope: Scope::Public,
                    third_party_allowed: false,
                },
            )
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

        let small = k.register_arch(local_named("small", personal()));
        k.set_context_budget(&small, 40);
        let r2 = k
            .submit_task(&machine(1), "draft a proposal", Label::bottom())
            .unwrap();
        // Bulky evidence: the part a projection is allowed to drop.
        let mut reg = k.read_register(&machine(1), &r2).unwrap();
        reg.evidence.push(Evidence {
            content: "e".repeat(400),
            origin: Origin::Web,
            source_hash: "sha256:e".into(),
        });
        k.write_register(&machine(1), reg).unwrap();

        let out = k
            .infer(&machine(1), &small, Capability::Generate, &r2)
            .unwrap();
        assert!(out.projected);
        assert!(
            out.tokens_in <= 40,
            "tokens_in must be what was sent, not a clamp: {}",
            out.tokens_in
        );
        assert!(k
            .ledger()
            .events()
            .iter()
            .any(|e| e.kind == "infer.projected"));
        // The mock echoes its prompt back, so the raised decision shows what the
        // arch really saw: the goal survived and the drop was declared.
        let raised = k.read_register(&machine(1), &r2).unwrap().decisions[0].clone();
        assert!(raised.contains("GOAL: draft a proposal"), "{raised}");
        assert!(raised.contains("1 lines dropped"), "{raised}");
    }

    #[test]
    fn a_context_too_small_for_the_goal_is_refused_not_truncated() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let a = k.register_arch(local(personal()));
        k.set_context_budget(&a, 5);
        let r = k
            .submit_task(&machine(1), &"g".repeat(400), Label::bottom())
            .unwrap();
        assert!(matches!(
            k.infer(&machine(1), &a, Capability::Generate, &r),
            Err(KernelError::I4Prime(_))
        ));
        assert!(k.infer_log().is_empty());
        assert!(
            !k.ledger()
                .events()
                .iter()
                .any(|e| e.kind == "infer" || e.kind == "infer.projected"),
            "a refused inference must not claim a projection it never made"
        );
    }

    #[test]
    fn the_infer_event_is_recorded_before_the_register_it_updates() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let a = k.register_arch(local(personal()));
        let r = k
            .submit_task(&machine(1), "draft a proposal", Label::bottom())
            .unwrap();
        k.infer(&machine(2), &a, Capability::Plan, &r).unwrap();
        let kinds: Vec<&str> = k
            .ledger()
            .events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        let sent = kinds.iter().position(|x| *x == "infer").unwrap();
        let written = kinds.iter().position(|x| *x == "register.written").unwrap();
        assert!(
            sent < written,
            "the send must reach the ledger before its result: {kinds:?}"
        );
    }

    fn lease_rows(k: &RealKernel, resource: &str) -> usize {
        k.store()
            .db
            .list_json::<Lease>("leases")
            .unwrap()
            .into_iter()
            .filter(|(_, l)| l.resource == resource)
            .count()
    }

    #[test]
    fn a_refused_resume_leaves_no_row_and_cannot_lift_a_later_stop() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut k = open(d.path());
            // Ids are sequential, so this is the one the *next* STOP will take.
            let ghost = "stop-n1-1";
            assert!(matches!(
                k.resume(&human(1), ghost),
                Err(KernelError::Stop(_))
            ));
            assert_eq!(
                k.store()
                    .db
                    .list_json::<ResumeEvent>("resumes")
                    .unwrap()
                    .len(),
                0,
                "a refused resume must leave nothing durable"
            );
            let s = k.stop(&human(2), "business:acme").unwrap();
            assert_eq!(s, ghost, "the STOP takes the id the refused resume cited");
            assert!(k.stops().stopped("business:acme"));
        }
        let k = open(d.path());
        assert!(
            k.stops().stopped("business:acme"),
            "a resume refused before the STOP existed must not lift it after a reboot"
        );
    }

    #[test]
    fn renewing_a_lease_leaves_one_live_row_and_still_excludes_others() {
        let d = tempfile::tempdir().unwrap();
        let t0 = now_ms();
        {
            let mut k = open(d.path());
            let first = k.lease(&machine(t0), "doc:1", 60_000).unwrap();
            let renewed = k.lease(&machine(t0 + 1_000), "doc:1", 60_000).unwrap();
            assert_ne!(first.id, renewed.id);
            assert_eq!(
                lease_rows(&k, "doc:1"),
                1,
                "the superseded row must go with the lease it recorded"
            );
            // And if a crash had landed between that write and that delete:
            k.store().db.put_json("leases", &first.id, &first).unwrap();
            assert_eq!(lease_rows(&k, "doc:1"), 2);
        }
        let mut k = open(d.path());
        assert_eq!(
            lease_rows(&k, "doc:1"),
            1,
            "boot restores only the newest live row per resource"
        );
        let other = Ctx {
            principal: Principal::Machine {
                node_id: "n2".into(),
                lease_id: "cli".into(),
            },
            ..machine(t0 + 2_000)
        };
        assert!(
            matches!(k.lease(&other, "doc:1", 1_000), Err(KernelError::Lock(_))),
            "the renewed lease still runs, so nobody else gets the resource"
        );
    }

    #[test]
    fn leases_and_fences_survive_reopen() {
        let d = tempfile::tempdir().unwrap();
        // Lease expiry is a wall-clock property and `load` sweeps on the wall
        // clock, so the contexts here are anchored to it as a real caller's are.
        let t0 = now_ms();
        let fence_before = {
            let mut k = open(d.path());
            k.lease(&machine(t0), "doc:1", 60_000).unwrap().fence
        };
        let mut k = open(d.path());
        let other = Ctx {
            principal: Principal::Machine {
                node_id: "n2".into(),
                lease_id: "cli".into(),
            },
            ..machine(t0 + 1_000)
        };
        assert!(
            matches!(k.lease(&other, "doc:1", 1_000), Err(KernelError::Lock(_))),
            "a restart must not release a lease that still has time to run"
        );
        let l2 = k
            .lease(
                &Ctx {
                    now_ms: t0 + 61_000,
                    ..other
                },
                "doc:1",
                1_000,
            )
            .unwrap();
        assert!(
            l2.fence > fence_before,
            "fences must stay monotonic across a restart: {} vs {fence_before}",
            l2.fence
        );
    }

    #[test]
    fn remounting_a_different_manifest_under_the_same_identity_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let mounted = local(personal());
        let id = k.register_arch(mounted.clone());
        // Same ArchIdentity, so the same arch id, but a clearance that would
        // quietly widen what i2_flow lets through.
        let widened = ArchManifest {
            clearance: Clearance {
                max_scope: Scope::Holdout,
                third_party_allowed: true,
            },
            ..mounted.clone()
        };
        let budget = widened.context_ceiling;
        let err = k
            .mount(Arc::new(arch::MockAdapter {
                manifest: widened,
                budget,
            }))
            .unwrap_err();
        assert!(
            err.to_string().contains("already mounted with a different"),
            "{err}"
        );
        assert_eq!(k.arches()[0].1.clearance, personal());

        // Re-mounting the identical manifest is accepted and logs nothing new.
        fn mounts(k: &RealKernel) -> usize {
            k.ledger()
                .events()
                .iter()
                .filter(|e| e.kind == "arch.mounted")
                .count()
        }
        let before = mounts(&k);
        assert_eq!(k.register_arch(mounted), id);
        assert_eq!(mounts(&k), before);
        assert_eq!(k.arches().len(), 1);
    }

    #[test]
    fn an_approval_for_one_subject_never_approves_another() {
        use vk_contracts::module::{ModuleKind, Provenance};
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let key = SoftwareHumanKey::generate("phone-1");
        k.enroll_device("phone-1", key.verifying_key_bytes());
        let ch = Challenge {
            resource: "module:quote-drafter".into(),
            action_digest: "sha256:c".into(),
            nonce: "n".into(),
            expires_at_ms: 10,
        };
        let sig = key.sign(&ch.digest());
        k.approve(
            &human(2),
            Approval {
                subject_hash: "sha256:c".into(),
                kind: ApprovalKind::Human,
                approver: Principal::Human {
                    device_id: "phone-1".into(),
                },
                challenge: Some(ch),
                signature_hex: Some(hex::encode(sig)),
            },
        )
        .unwrap();

        assert_eq!(k.approvals_for("sha256:c").len(), 1);
        // The row's key is "<subject>:<hash_canonical>" and hash_canonical is
        // itself "sha256:…", so a key-prefix match would let a module whose
        // content hash is the bare string "sha256" inherit this approval.
        assert!(k.approvals_for("sha256").is_empty());
        assert!(k.approvals_for("sha256:c2").is_empty());

        let impostor = ModuleManifest {
            name: "impostor".into(),
            kind: ModuleKind::Skill,
            version: "0.1.0".into(),
            machine_evolved: true,
            files: vec!["SKILL.md".into()],
            provenance: Provenance {
                content_hash: "sha256".into(),
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
            subject_hash: "sha256".into(),
            pass: true,
            evidence_hash: "sha256:e".into(),
            signer: "founder".into(),
        };
        assert!(matches!(
            k.promote(&machine(3), &impostor, &[verdict]),
            Err(KernelError::I1(_))
        ));
        assert!(k.hot_modules().is_empty());
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

    #[test]
    fn an_artefact_kind_that_is_not_a_plain_token_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let r = k.submit_task(&machine(1), "x", Label::bottom()).unwrap();
        let too_long = "k".repeat(33);
        // A kind becomes a file name when the artefact is released, so a
        // separator, a `..`, a leading dot or an unbounded string is refused
        // here rather than written into a durable register.
        for bad in [
            "",
            "../x",
            "a/b",
            "a\\b",
            ".hidden",
            "a:b",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    k.attach_artefact(&machine(2), &r, bad, b"payload"),
                    Err(KernelError::Gate(_))
                ),
                "{bad:?} must be refused"
            );
        }
        assert!(
            k.read_register(&machine(3), &r)
                .unwrap()
                .artefacts
                .is_empty(),
            "a refused kind must not reach the register"
        );
        let blobs = std::fs::read_dir(d.path().join("blobs"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "bin").unwrap_or(false))
            .count();
        assert_eq!(blobs, 0, "a refused kind must store no blob");
    }
}
