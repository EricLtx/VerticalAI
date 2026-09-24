//! The real single-node kernel (spec §3): the stub's semantics over vk-store.
pub mod arch;
pub mod ns;
pub mod presence;
pub mod tasks;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vk_contracts::arch::{ArchManifest, Capability};
use vk_contracts::hash_canonical;
use vk_contracts::interceptors;
use vk_contracts::labels::{Label, Scope};
use vk_contracts::ledger::{is_allowed_kind, ClockQuality, HlcClock, Ledger, RetentionClass};
use vk_contracts::locks::{Lease, LockHome, LockTable};
use vk_contracts::module::{GateKind, GateVerdict, ModuleManifest};
use vk_contracts::principal::{Approval, ApprovalKind, Challenge, DeviceRegistry, Principal};
use vk_contracts::register::{ArtefactRef, Register, RegisterId};
use vk_contracts::stop::{LivenessLease, ResumeEvent, StopError, StopEvent, StopSet};
use vk_contracts::storage::{BlobEnvelope, StorageError};
use vk_contracts::syscalls::{Ctx, InferOutcome, Kernel, KernelError};
use vk_contracts::testing::KernelTestHooks;
use vk_store::keys::KeySource;
use vk_store::{HeadVerdict, Store};

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
///
/// Two kinds share the table (SP1b Task 5): a device *key* row carries the
/// ed25519 verifying key that `DeviceRegistry` checks presence proofs and
/// node-key approvals against; a *passkey* row (`trust_class: "passkey"`)
/// carries the WebAuthn credential instead, opaque to the kernel — it is
/// `vk-web`'s verifier that reads it — and an empty `vk_hex`, so `load`
/// registers nothing for it. A row written before passkeys existed has
/// neither new field and reads back exactly as it was.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceRow {
    vk_hex: String,
    trust_class: String,
    /// The serialised passkey of a `trust_class: "passkey"` row; absent on a
    /// device-key row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passkey: Option<serde_json::Value>,
    #[serde(default)]
    enrolled_ms: u64,
}

/// The trust class of a device row that holds a passkey rather than a key.
pub const PASSKEY_TRUST_CLASS: &str = "passkey";
/// Every passkey's device id starts with this; what follows is the
/// credential id, base64url.
pub const PASSKEY_DEVICE_PREFIX: &str = "passkey:";

/// An enrolled passkey as `passkeys` hands it out: the device id, the
/// credential as the enroller serialised it (the kernel never parses it),
/// and when it was enrolled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PasskeyRow {
    pub device_id: String,
    pub credential: serde_json::Value,
    pub enrolled_ms: u64,
}

/// How long a minted approval challenge stays answerable (SP1b Task 5). Two
/// minutes: a person has to get from the terminal to a browser and a Windows
/// Hello prompt, and nothing more — the challenge is minted when the
/// ceremony starts, not when the task starts waiting.
pub const APPROVAL_CHALLENGE_TTL_MS: u64 = 120_000;
/// Open approval challenges are bounded, as presence nonces are in the
/// transport: past this many, the one closest to expiry is dropped. A caller
/// that mints challenges it never spends cannot grow the map without limit.
const MAX_APPROVAL_CHALLENGES: usize = 256;

/// An approval challenge this kernel minted and no approval has spent yet
/// (SP1b Task 5): the task it was minted for and the challenge itself. What
/// [`RealKernel::pending_approvals`] lists.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingApproval {
    pub task_id: String,
    pub challenge: Challenge,
}

/// The `approval.recorded` payload (SP1b Task 5): the approval and which
/// ceremony verified it — `device-key` for an ed25519 signature checked
/// against the device registry, `webauthn` for a passkey assertion checked by
/// `vk-web`'s verifier. Not a contract type; the ledger keeps its hash.
#[derive(serde::Serialize)]
struct ApprovalRecord<'a> {
    approval: &'a Approval,
    proof: &'a str,
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
    /// Which of `arches` came up unusable, and could not be re-created from
    /// the spec their mount recorded (SP1b ruling 14). In the report, and so
    /// in the `boot` event's payload hash, because "this node came up without
    /// Gemma" is exactly the kind of thing an auditor should find in the
    /// record rather than in a log line nobody kept. Empty on a node where
    /// every arch came back, and absent from a report written before this
    /// existed.
    #[serde(default)]
    pub unavailable_arches: Vec<String>,
    /// Which of `arches` were still being built when the node started serving
    /// (Task 1b review, Important 1). The node answers throughout; these are
    /// the ones a step would be told to retry on for a few seconds more.
    #[serde(default)]
    pub starting_arches: Vec<String>,
    pub devices: Vec<String>,
    pub stopped_scopes: Vec<String>,
    /// Placeholder (spec §4.3): there is no policy engine in SP1a, so boot
    /// writes `"0"` the first time it finds no version and reports it
    /// unchanged afterwards. It exists so that the first policy set has a
    /// predecessor to migrate from.
    pub policies_version: String,
}

/// Cumulative per-arch call counters, persisted under the `kv` key
/// `stats:<arch_id>`. What `vk top` reads, and — until per-call usage rows
/// exist — the only place the numbers a real arch reported survive the call
/// (SP1b rulings 7 and 8).
///
/// The new fields default to zero, so a stats row written before them reads
/// back as an arch that has measured nothing, which is what it is.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ArchStats {
    pub calls: u64,
    /// Prompt tokens, the best number available per call: what the arch
    /// measured when it reported one, the adapter's estimate otherwise.
    pub tokens_in: u64,
    /// How much of `tokens_in` was measured rather than estimated. Equal to
    /// `tokens_in` when every call on this arch reported its own usage, zero
    /// for an arch that never does — so a reader can tell a figure they can
    /// bill against from a heuristic.
    #[serde(default)]
    pub tokens_in_measured: u64,
    /// List-price equivalent of every call on this arch, in USD. Under a
    /// subscription this is what the calls would have cost, not what they
    /// did; the manifest's `cost_per_1k_tokens_eur` says which.
    #[serde(default)]
    pub cost_list_usd: f64,
    pub projected: u64,
}

/// The `boot.forced` event's payload (founder decision 2026-09-24): the
/// verdict `boot` found, named rather than recomputed, so this event and the
/// `boot` event it follows can never disagree about what was overridden.
#[derive(serde::Serialize)]
struct BootForcedRecord<'a> {
    /// `BootReport::ledger_ok` — the chain and the recorded head combined.
    ledger_ok: bool,
    /// The recorded-head half of that verdict on its own: a chain that fails
    /// to verify but still reaches the head this store last wrote is a
    /// different failure from a tail that was cut or rewritten, and an
    /// auditor reading `boot.forced` should not have to guess which.
    head_ok: bool,
    ledger_len: usize,
    /// `hash_canonical` of the `BootReport` this event is about — the same
    /// value already committed to as that report's own `boot` event's
    /// `payload_hash`, so the two events verifiably name the same boot.
    report_hash: &'a str,
}

/// The `infer` event's payload: which arch ran which register, and — when the
/// arch measured its own call — what it cost and what it spent (SP1b ruling 3).
///
/// The optional halves are skipped when absent, so the mock's `infer` commits
/// to exactly what it used to: which arch, which register, nothing invented.
/// Nothing here is a contract type; the ledger stores only the hash of this
/// object, and an auditor recomputes it from the same values.
#[derive(serde::Serialize)]
struct InferRecord<'a> {
    arch_id: &'a str,
    register: &'a str,
    /// Which half of the call this record is: `requested` before the prompt is
    /// handed to the adapter, `completed` once it has answered (SP1b review,
    /// M2). Two events of one kind rather than two kinds, because they are one
    /// thing — a call — and an auditor reading the chain wants them adjacent
    /// and comparable. A `requested` with no `completed` after it is a call
    /// that left this kernel and never came back.
    phase: &'a str,
    /// Prompt tokens: the arch's own count when it reported one, this node's
    /// estimate otherwise. `measured` says which, so the record never leaves a
    /// reader guessing whether a number is a fact or a heuristic.
    tokens_in: u32,
    measured: bool,
    /// `Completion::cost_list_usd` — list price for a call the subscription
    /// did not bill, so the record says what it would have cost.
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_list_usd: Option<f64>,
    /// `Completion::details` — the arch's own measurements of the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a serde_json::Value>,
}

/// What a mount did, and what it left the caller holding (Ruling 13).
///
/// `replaced` is the whole point of the type: an adapter that was swapped out
/// leaves the kernel by this field, so the daemon can release the kernel mutex
/// before dropping it. Dropping an adapter can be slow and can reach outside
/// the process — the Ollama arch stops the container it started — and the
/// kernel lock is the one thing that must never be held across that.
pub struct MountOutcome {
    pub arch_id: String,
    /// The adapter this mount took the place of, for the caller to drop
    /// *after* releasing the lock. `None` on a first mount and on an
    /// idempotent re-mount, which replaces nothing.
    pub replaced: Option<Arc<dyn arch::ArchAdapter>>,
    /// Was this arch already mounted? True both for the idempotent case and
    /// for a deliberate replacement, so a client can say "already mounted"
    /// rather than pretending something new happened.
    pub already_mounted: bool,
}

/// What to do about an arch that is already mounted under the same id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remount {
    /// Keep it: the arch that is there is the answer. The default, and what
    /// makes a repeat mount idempotent.
    Keep,
    /// Replace it: the caller has re-made whatever is behind the arch, so the
    /// adapter in the table is stale however identical its manifest looks.
    Replace,
}

/// An arch's refusal, as the kernel must report it.
///
/// `I4Prime` is the kernel's own invariant raised by the adapter that knows
/// the real limit, and it reaches the client as an invariant refusal, like
/// every other I4′. Everything else is machinery that did not work — the
/// engine would not start, the answer would not parse — which is a store-class
/// failure, not "no such arch" (SP1b review, Important 2).
fn adapter_failed(arch_id: &str, e: arch::AdapterError) -> KernelError {
    match e {
        arch::AdapterError::I4Prime { .. } => KernelError::I4Prime(format!("arch {arch_id}: {e}")),
        arch::AdapterError::Other(e) => KernelError::Store(format!("arch {arch_id} failed: {e}")),
    }
}

/// How this node makes an adapter out of a [`arch::MountSpec`] (SP1b ruling 14).
///
/// The kernel persists the spec and hands it back at boot; it has no idea what
/// a `claude-code` or an `ollama` is, and should not — the arch kinds a build
/// has are the daemon's, and a kernel that knew them would have to be rebuilt
/// to gain one. `vkd` passes the real factory to
/// [`RealKernel::open_with_factory`]; [`RealKernel::open`] uses one that knows
/// only the mock, which is all a kernel test needs.
/// `Arc`, not `Box`: the daemon calls the factory on a background task with
/// the kernel mutex *not* held, so the same factory has to be reachable from
/// outside the kernel as well as from `start_arches_now` inside it
/// (Task 1b review, Important 1).
pub type AdapterFactory =
    Arc<dyn Fn(&arch::MountSpec) -> Result<Box<dyn arch::ArchAdapter>> + Send + Sync>;

/// Is this arch usable, and if not, why not (SP1b ruling 14)?
///
/// The state exists because the alternative is worse. `load` used to build a
/// `MockAdapter` for every persisted manifest, so an arch whose engine had
/// gone away came back as the mock under the same id and answered prompts
/// with an echo — the one failure a node must never have, because nothing
/// downstream can tell it from an answer. An arch that cannot be made again is
/// named, listed and refused instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchState {
    /// The adapter is there: the factory made it and it is the arch the id says.
    Ready,
    /// The spec is known and the adapter is being built right now — a
    /// `docker start`, a cold model load, a `claude --version` (Task 1b
    /// review, Important 1). The node serves throughout; a step that names
    /// this arch is told to retry rather than failed, because nothing is
    /// wrong: the arch is seconds away.
    Starting,
    /// It is not, and this is what stopped it — the factory's own error, or
    /// what differs between the manifest that was stored and the one the
    /// factory just made.
    Unavailable(String),
}

impl ArchState {
    /// The word every read surface prints: `ready`, `starting` or `unavailable`.
    pub fn name(&self) -> &'static str {
        match self {
            ArchState::Ready => "ready",
            ArchState::Starting => "starting",
            ArchState::Unavailable(_) => "unavailable",
        }
    }

    /// Why it is not usable; `None` for one that is, and for one still coming
    /// up — there is nothing wrong with it to explain.
    pub fn reason(&self) -> Option<&str> {
        match self {
            ArchState::Ready | ArchState::Starting => None,
            ArchState::Unavailable(why) => Some(why),
        }
    }
}

/// An arch this node has mounted and cannot run: its manifest, so it can still
/// be listed and so a re-mount can be checked against it, and the reason.
struct UnavailableArch {
    manifest: ArchManifest,
    reason: String,
}

/// An arch whose adapter has not been built yet: the manifest it must come
/// back as, and the spec to build it from.
struct PendingMount {
    manifest: ArchManifest,
    spec: arch::MountSpec,
}

/// What differs between the manifest an arch was mounted with and the one the
/// factory has just made — `None` when they are the same manifest (Task 1b
/// review, Important 2).
///
/// The whole manifest, not the arch id. `arch_id` hashes `ArchIdentity` alone,
/// so `clearance`, `capabilities`, `retention_days`, `governed` and the rest
/// can all differ under an id that matches — and the adapter's manifest is the
/// one `i2_flow` consults on the very next prompt. The mount path has always
/// refused exactly this ("already mounted with a different manifest"); the
/// boot path used to let it through.
///
/// The field names are read off the serialised manifests rather than listed
/// here, so a field added to `ArchManifest` later is named by this without
/// anybody having to remember to come back.
fn manifest_difference(stored: &ArchManifest, made: &ArchManifest) -> Option<String> {
    if hash_canonical(stored) == hash_canonical(made) {
        return None;
    }
    let (stored_id, made_id) = (stored.arch_id(), made.arch_id());
    if stored_id != made_id {
        return Some(format!("identity {stored_id} → {made_id}"));
    }
    let (a, b) = (
        serde_json::to_value(stored).unwrap_or_default(),
        serde_json::to_value(made).unwrap_or_default(),
    );
    let named: Vec<&str> = a
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(field, value)| b.get(field) != Some(*value))
                .map(|(field, _)| field.as_str())
                .collect()
        })
        .unwrap_or_default();
    Some(if named.is_empty() {
        "it is not the manifest that was stored".into()
    } else {
        named.join(", ")
    })
}

pub struct RealKernel {
    pub node_id: String,
    store: Store,
    clock: HlcClock,
    adapters: BTreeMap<String, Arc<dyn arch::ArchAdapter>>,
    /// The arches whose adapter is still being built. Disjoint from
    /// `adapters` and `unavailable`: an id is in exactly one of the three,
    /// which is what makes `arch_state` a lookup rather than a question.
    starting: BTreeMap<String, PendingMount>,
    /// The arches that are mounted and not usable.
    unavailable: BTreeMap<String, UnavailableArch>,
    /// Makes an adapter out of a persisted spec. Never called with the kernel
    /// mutex held — building an adapter starts containers and waits on
    /// binaries. `vkd` clones this out and drives startup from a background
    /// task; `start_arches_now` is the in-process version, for callers that
    /// have no mutex.
    factory: AdapterFactory,
    budgets: BTreeMap<String, u32>,
    locks: LockTable,
    home: LockHome,
    devices: DeviceRegistry,
    stops: StopSet,
    infer_log: Vec<(String, Label)>,
    counter: u64,
    /// Set by `record_forced_boot`. In memory only, for as long as this
    /// process runs — the same lifetime `ledger_holds`'s doc comment already
    /// promises for a `--force` verdict — never persisted, so it says
    /// nothing about a previous or a future run.
    forced_boot: bool,
    /// The live harness runs, keyed by the **hash** of each run's lease token
    /// (SP1b Task 4, Ruling 21.2). In memory only: a harness cannot outlive
    /// this process (the Job Object kills it when the daemon's handle closes),
    /// so a token that was live before a restart is rightly unknown after one.
    /// The token itself is never stored, logged or put in a payload; the
    /// ledger and every principal carry the lease id.
    harness_tokens: BTreeMap<String, HarnessTokenState>,
    /// The approval challenges this kernel has minted and no approval has
    /// spent yet, keyed by nonce (SP1b Task 5, invariant I1). In memory only:
    /// a challenge is a moment's thing, bound to a task that is waiting *now*,
    /// and one that was open when this process stopped is rightly unknown to
    /// the next — the person mints another.
    approval_challenges: BTreeMap<String, PendingApproval>,
}

/// One live harness run, as the token map holds it: which lease and task the
/// token stands for, and how much the run has attached so far (the 16 MiB
/// per-run cap, Ruling 21.6). `oversize` remembers a file the run tried to
/// attach past a cap, so settle can fail the step naming it.
struct HarnessTokenState {
    lease_id: String,
    task_id: String,
    bytes_attached: u64,
    oversize: Option<String>,
}

/// The factory [`RealKernel::open`] uses: the mock and nothing else.
///
/// A kernel opened without a daemon around it can still bring its mock arches
/// back, and every other kind is honestly unavailable — which is the point of
/// the state. The mock's spec carries the whole manifest, because the arch id
/// is a hash of it and re-deriving it from a name and a ceiling would mint a
/// different arch.
pub fn mock_factory() -> AdapterFactory {
    Arc::new(|spec: &arch::MountSpec| {
        anyhow::ensure!(
            spec.kind == "mock",
            "this kernel was opened without a factory for arch kind {}; \
             open it with `open_with_factory` to mount one",
            spec.kind
        );
        let manifest: ArchManifest = serde_json::from_value(spec.config["manifest"].clone())
            .context("a mock mount spec carries the manifest it was mounted with")?;
        let budget = spec.config["budget"]
            .as_u64()
            .and_then(|b| u32::try_from(b).ok())
            .unwrap_or(manifest.context_ceiling);
        Ok(Box::new(arch::MockAdapter { manifest, budget }) as Box<dyn arch::ArchAdapter>)
    })
}

impl RealKernel {
    /// Open the store, bring this node's state back, and build every mounted
    /// arch before returning, with a factory that knows only the mock.
    ///
    /// What every kernel test uses. The building is synchronous here because
    /// the mock is instantaneous and there is no mutex in the way; `vkd` uses
    /// [`RealKernel::open_with_factory`] and drives startup itself, because
    /// real engines are not instantaneous and its kernel is behind a mutex.
    pub fn open(state_dir: &Path, key_source: KeySource, node_id: &str) -> Result<RealKernel> {
        let mut k = RealKernel::open_with_factory(state_dir, key_source, node_id, mock_factory())?;
        k.start_arches_now();
        Ok(k)
    }

    /// The same, with the factory that re-creates every kind this node can
    /// mount (SP1b ruling 14) — and **without building anything**.
    ///
    /// Every persisted arch comes back `Starting`, and the caller brings them
    /// up afterwards through [`RealKernel::pending_mounts`] and
    /// [`RealKernel::install_arch`]. That split is the whole point: building
    /// an adapter runs `claude --version`, a `docker start`, a cold model
    /// load — up to minutes of it — and doing that inside `open` left the
    /// node unreachable for the whole time, so `vk boot` timed out after 10 s
    /// and *killed* the daemon it had just started (Task 1b review,
    /// Important 1). The store lock is still taken here, before anything
    /// else, so a second daemon is refused before a single container is
    /// touched.
    pub fn open_with_factory(
        state_dir: &Path,
        key_source: KeySource,
        node_id: &str,
        factory: AdapterFactory,
    ) -> Result<RealKernel> {
        let store = Store::open(state_dir, key_source)?;
        let mut k = RealKernel {
            node_id: node_id.into(),
            store,
            clock: HlcClock::new(node_id),
            adapters: BTreeMap::new(),
            starting: BTreeMap::new(),
            unavailable: BTreeMap::new(),
            factory,
            budgets: BTreeMap::new(),
            locks: LockTable::default(),
            home: LockHome::default(),
            devices: DeviceRegistry::default(),
            stops: StopSet::default(),
            forced_boot: false,
            infer_log: vec![],
            counter: 0,
            harness_tokens: BTreeMap::new(),
            approval_challenges: BTreeMap::new(),
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
        self.load_arches()?;
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

    /// Read every mounted arch back off disk (SP1b ruling 14). Builds nothing.
    ///
    /// An arch with a spec becomes `Starting` — the caller builds it, after
    /// the endpoint is answering. An arch with no spec (one mounted before
    /// Task 1b existed) has nothing to build from, so it is `Unavailable` at
    /// once and says to mount it again; there is no point in making the
    /// operator wait for a startup pass to tell them that.
    fn load_arches(&mut self) -> Result<()> {
        let specs: BTreeMap<String, arch::MountSpec> =
            self.store.db.list_json("mounts")?.into_iter().collect();
        let manifests: Vec<(String, ArchManifest)> = self.store.db.list_json("arches")?;
        for (id, manifest) in &manifests {
            match specs.get(id) {
                None => self.mark_unavailable(
                    id,
                    manifest,
                    "no mount spec was recorded for this arch, so there is nothing to make it \
                     from; mount it again"
                        .into(),
                ),
                Some(spec) => {
                    self.starting.insert(
                        id.clone(),
                        PendingMount {
                            manifest: manifest.clone(),
                            spec: spec.clone(),
                        },
                    );
                }
            }
        }
        // A spec whose arch is gone is a leftover of a failed write, never a
        // mount: `unmount` deletes both rows and `mount` writes both together.
        // Swept rather than kept, so it cannot come back as an arch nobody
        // mounted if that id is ever minted again.
        for id in specs.keys() {
            if !manifests.iter().any(|(m, _)| m == id) {
                self.store.db.delete("mounts", id)?;
            }
        }
        Ok(())
    }

    /// Every arch still waiting for its adapter, with the spec to build it
    /// from. What the daemon's startup task iterates (Task 1b review,
    /// Important 1).
    ///
    /// A snapshot, taken under the kernel lock and then let go of: the caller
    /// builds each adapter with the lock **released** and hands the result to
    /// [`RealKernel::install_arch`], which takes the lock again for as long as
    /// a map insert. The mutex is never held across a `docker start`.
    pub fn pending_mounts(&self) -> Vec<(String, arch::MountSpec)> {
        self.starting
            .iter()
            .map(|(id, p)| (id.clone(), p.spec.clone()))
            .collect()
    }

    /// This node's adapter factory, for a caller that will use it outside the
    /// kernel lock.
    pub fn adapter_factory(&self) -> AdapterFactory {
        self.factory.clone()
    }

    /// How many arches are still coming up. `boot.info`'s `arches_starting`,
    /// and what `vk boot` reports to the person who just started the node.
    pub fn arches_starting(&self) -> usize {
        self.starting.len()
    }

    /// Install what the factory made for a `Starting` arch — or record why it
    /// could not be made (SP1b ruling 14, Task 1b review Importants 1 and 2).
    ///
    /// Returns an adapter the **caller** must drop, once it has released the
    /// kernel lock: dropping one can `docker stop` a container, which is the
    /// one thing that must never happen under the mutex. `None` when there is
    /// nothing to throw away.
    ///
    /// Three ways this ends with nothing installed, and each of them is a case
    /// the daemon actually meets:
    /// - the arch left `Starting` while its adapter was being built — an
    ///   operator ran `vk mount` or `vk umount` in those seconds — so what was
    ///   built is stale and goes back to the caller to drop;
    /// - the factory failed → `Unavailable` with its error;
    /// - what came back is not the manifest that was stored → `Unavailable`
    ///   naming what differs and how to retire the old id. Never installed:
    ///   the adapter's manifest is what `i2_flow` reads, so adopting a
    ///   manifest whose clearance is not the one on disk would widen what an
    ///   arch may see, on the first prompt after a restart, with nothing
    ///   anywhere recording that it had changed.
    pub fn install_arch(
        &mut self,
        arch_id: &str,
        made: Result<Box<dyn arch::ArchAdapter>>,
    ) -> Option<Box<dyn arch::ArchAdapter>> {
        let Some(pending) = self.starting.remove(arch_id) else {
            tracing::debug!(
                arch_id = %arch_id,
                "this arch stopped waiting while its adapter was being built; discarding it"
            );
            return made.ok();
        };
        match made {
            Err(e) => {
                self.mark_unavailable(arch_id, &pending.manifest, format!("{e:#}"));
                None
            }
            Ok(adapter) => match manifest_difference(&pending.manifest, adapter.manifest()) {
                Some(what) => {
                    self.mark_unavailable(
                        arch_id,
                        &pending.manifest,
                        format!(
                            "manifest changed: {what} — run `vk umount {arch_id}` to retire it"
                        ),
                    );
                    Some(adapter)
                }
                None => {
                    self.budgets
                        .insert(arch_id.into(), adapter.context_budget());
                    self.adapters.insert(arch_id.into(), Arc::from(adapter));
                    tracing::info!(arch_id = %arch_id, name = %pending.manifest.name, "arch ready");
                    None
                }
            },
        }
    }

    /// Build and install every `Starting` arch on this thread, now.
    ///
    /// For a caller that holds no mutex: [`RealKernel::open`], and tests. The
    /// daemon must **not** use it — its kernel is behind a mutex it would have
    /// to hold for the whole pass — and uses `pending_mounts` +
    /// `install_arch` around its own lock instead.
    pub fn start_arches_now(&mut self) {
        let factory = self.adapter_factory();
        for (id, spec) in self.pending_mounts() {
            // The adapter this did not install, dropped here rather than left
            // to fall inside `install_arch`: same rule, no lock is held.
            drop(self.install_arch(&id, factory(&spec)));
        }
    }

    fn mark_unavailable(&mut self, id: &str, manifest: &ArchManifest, reason: String) {
        tracing::warn!(
            arch_id = %id,
            name = %manifest.name,
            "this arch could not be brought up and is unavailable: {reason}"
        );
        self.unavailable.insert(
            id.into(),
            UnavailableArch {
                manifest: manifest.clone(),
                reason,
            },
        );
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
    ///
    /// `ledger_ok` asks two things of the chain: that every link and hash
    /// recomputes, and that it still reaches the head the store recorded the
    /// last time it appended. A hash chain proves nothing about its length —
    /// the tail cut off the newest segment would still "verify" — and the
    /// tail is where the latest STOP, approval or release lives.
    pub fn boot(&mut self) -> Result<BootReport, KernelError> {
        if let HeadVerdict::Diverged { recorded, found } = &self.store.ledger_head {
            tracing::warn!(
                recorded_seq = recorded.seq,
                recorded_hash = %recorded.hash,
                found_seq = found.as_ref().map(|h| h.seq),
                "the ledger on disk no longer contains the head this node last recorded: \
                 its tail was cut or rewritten"
            );
        }
        let report = BootReport {
            ledger_ok: self.ledger_holds(),
            ledger_len: self.store.ledger.len(),
            recovered_partial_line: self.recovered_partial_line(),
            arches: self.arches().into_iter().map(|(id, _)| id).collect(),
            unavailable_arches: self.unavailable.keys().cloned().collect(),
            starting_arches: self.starting.keys().cloned().collect(),
            devices: self.device_ids(),
            stopped_scopes: self.stops.stopped_scopes(),
            policies_version: self.load_policies_version()?,
        };
        self.log("boot", now_ms(), &report)?;
        // After the `boot` event, so the record reads in the order things
        // happened: this node came up, and then it found what the last one
        // left half-done (SP1b review, M11).
        self.recover_interrupted_steps(now_ms())?;
        // No harness survives a restart (the Job Object dies with the daemon's
        // handle), so every harness lease and workspace on disk is a leftover:
        // swept here, so no stale token resolves and no projected plaintext
        // lingers (SP1b Task 4 review, I4).
        self.sweep_harness_state()?;
        Ok(report)
    }

    /// Does the record hold? Both halves of the verdict `boot` reports, for
    /// every caller that asks after it (`boot.info`, `ledger.verify`): the
    /// chain's links and hashes recompute, and the chain still reaches the
    /// head the store recorded. The second half is fixed when the store is
    /// opened — a cut tail is not something this process can repair — so a
    /// node serving under `--force` on a shortened record says so for as
    /// long as it runs.
    pub fn ledger_holds(&self) -> bool {
        self.store.ledger.verify()
            && !matches!(self.store.ledger_head, HeadVerdict::Diverged { .. })
    }

    /// Ledger event for a daemon that decided to serve `report` anyway
    /// (founder decision 2026-09-24). Kept separate from `boot` so `vk
    /// dmesg` and an auditor can find, without replaying the whole chain,
    /// every time this node's operator overrode a verdict that said not to
    /// serve. `report` must be the value `boot` just returned — its own
    /// `boot` event already committed to `report`'s hash, so naming that
    /// same hash here lets the two events be tied together without either
    /// trusting the other.
    ///
    /// Ledger before the in-memory flag, as `boot` itself: an append that
    /// fails must leave nothing for `boot.info` or `vk status` to show.
    ///
    /// Callers: `vkd`, exactly on the path where it has already decided to
    /// serve under `--force`; never when `report.ledger_ok` is true.
    pub fn record_forced_boot(&mut self, report: &BootReport) -> Result<(), KernelError> {
        let head_ok = !matches!(self.store.ledger_head, HeadVerdict::Diverged { .. });
        let report_hash = hash_canonical(report);
        self.log(
            "boot.forced",
            now_ms(),
            &BootForcedRecord {
                ledger_ok: report.ledger_ok,
                head_ok,
                ledger_len: report.ledger_len,
                report_hash: &report_hash,
            },
        )?;
        self.forced_boot = true;
        Ok(())
    }

    /// Did this run serve under `--force`? Set only by `record_forced_boot`,
    /// and only for as long as this process runs: `boot.info` and `vk
    /// status` surface it as `forced`/`forced boot`.
    pub fn forced_boot(&self) -> bool {
        self.forced_boot
    }

    /// The policy set this node runs under, as the store has it — `None` on a
    /// node that has never booted. Read-only, so a status call can report the
    /// version without being the thing that decides it.
    pub fn policies_version(&self) -> Option<String> {
        self.store.db.kv_get(POLICIES_VERSION).ok().flatten()
    }

    /// The boot step that loads it. SP1a has no policy engine, so the key is
    /// written once with `"0"` and read back unchanged; the version is in the
    /// boot report from the start so that the first real policy set has a
    /// predecessor in the record to migrate from.
    fn load_policies_version(&mut self) -> Result<String, KernelError> {
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

    /// Mount an adapter for its manifest's arch id (Ruling 13).
    ///
    /// Mounting the same arch twice is **idempotent**: the adapter already in
    /// the table stays, nothing is written, nothing is appended, and the
    /// outcome says `already_mounted`. That is not an optimisation. An adapter
    /// can own something outside this process — the Ollama arch owns the
    /// container it started — and dropping it is how that thing gets stopped,
    /// so a plain `vk mount ollama` run twice used to stop the container out
    /// from under the arch it had just re-mounted, under the kernel lock (SP1b
    /// Task 1 re-review, Important). An arch that is already there and usable
    /// is the answer to "mount this".
    ///
    /// The arch id hashes only `ArchIdentity`, so two manifests can agree on it
    /// and still disagree about clearance — the very field `i2_flow` consults.
    /// Letting the second silently win would relabel a mounted arch, so a
    /// conflicting manifest is refused.
    ///
    /// The spec is not optional (Task 1b review, Minor 4): a mount that
    /// recorded nothing would come back `Unavailable` at the next restart,
    /// which is the bug this whole task is about, one layer down.
    pub fn mount(
        &mut self,
        adapter: Arc<dyn arch::ArchAdapter>,
        spec: arch::MountSpec,
    ) -> Result<MountOutcome> {
        self.mount_with(adapter, spec, Remount::Keep)
    }

    /// The same with the spec the next boot re-creates this arch from, and for
    /// a caller that knows the thing behind the arch has been re-made and that
    /// the adapter in the table is therefore stale — `vk mount ollama
    /// --recreate`, which replaces the container itself.
    ///
    /// An arch that is mounted but `Unavailable` — or still `Starting` — is
    /// re-attached here: the placeholder is replaced by the adapter the caller
    /// just built, and the outcome says `already_mounted: false`, because what
    /// was there was not an arch anybody could use (Ruling 13 for the
    /// unavailable case). A startup pass that finishes building that arch
    /// afterwards finds it gone from `starting` and throws its result away.
    pub fn mount_with(
        &mut self,
        adapter: Arc<dyn arch::ArchAdapter>,
        spec: arch::MountSpec,
        remount: Remount,
    ) -> Result<MountOutcome> {
        let m = adapter.manifest().clone();
        m.validate()?;
        spec.validate()?;
        let id = m.arch_id();
        // The manifest an arch that is down or still coming up was mounted
        // with is still the manifest of that id, and it is checked exactly as
        // a live one is: an id whose clearance quietly widened is the same
        // danger whether the engine behind it happens to be up.
        let recorded = self
            .unavailable
            .get(&id)
            .map(|down| &down.manifest)
            .or_else(|| self.starting.get(&id).map(|p| &p.manifest));
        if let Some(recorded) = recorded {
            anyhow::ensure!(
                *recorded == m,
                "arch {id} is already mounted with a different manifest; unmount first"
            );
        }
        if let Some(mounted) = self.adapters.get(&id) {
            anyhow::ensure!(
                *mounted.manifest() == m,
                "arch {id} is already mounted with a different manifest; unmount first"
            );
            // Keep what is there unless the caller says it is stale, or the
            // entry itself is no longer usable. The spec is not rewritten
            // either: the adapter that is mounted is the one the *stored* spec
            // describes, and replacing the spec without replacing the adapter
            // would make the next boot build something this one never ran.
            if remount == Remount::Keep && self.mounted_arch_is_ready(&id) {
                return Ok(MountOutcome {
                    arch_id: id,
                    replaced: None,
                    already_mounted: true,
                });
            }
            self.persist_mount(&id, &m, &spec)?;
            self.budgets.insert(id.clone(), adapter.context_budget());
            // The replaced adapter leaves by the return value, never by a
            // dropped temporary: dropping it here would run its `Drop` — a
            // `docker stop` for the Ollama arch — with the kernel mutex held.
            let replaced = self.adapters.insert(id.clone(), adapter);
            return Ok(MountOutcome {
                arch_id: id,
                replaced,
                already_mounted: true,
            });
        }
        self.persist_mount(&id, &m, &spec)?;
        // A placeholder is not an adapter, so there is nothing to hand back
        // and nothing to drop: an `Unavailable` entry, or one still waiting
        // for its adapter, is a manifest and a spec, and it goes out here.
        self.unavailable.remove(&id);
        self.starting.remove(&id);
        self.budgets.insert(id.clone(), adapter.context_budget());
        self.adapters.insert(id.clone(), adapter);
        self.log("arch.mounted", now_ms(), &id)?;
        Ok(MountOutcome {
            arch_id: id,
            replaced: None,
            already_mounted: false,
        })
    }

    /// The manifest and the spec, together or not at all.
    ///
    /// One transaction because they are two halves of one fact: a manifest
    /// whose spec did not land is an arch the next boot lists as unavailable
    /// although its mount succeeded, and a spec whose manifest did not land is
    /// a row for an arch that is not there.
    fn persist_mount(
        &self,
        id: &str,
        manifest: &ArchManifest,
        spec: &arch::MountSpec,
    ) -> Result<()> {
        self.store.db.transaction(|| {
            self.store.db.put_json("arches", id, manifest)?;
            self.store.db.put_json("mounts", id, spec)
        })
    }

    /// Is the adapter already mounted under `arch_id` still usable?
    ///
    /// The Ready half of the state (Ruling 14): an arch whose engine has gone
    /// away is held in `unavailable` and never in `adapters`, so an adapter in
    /// the table is one the factory made and checked. A re-mount of an
    /// unavailable arch therefore never takes the idempotent branch — there is
    /// no adapter there to keep.
    fn mounted_arch_is_ready(&self, arch_id: &str) -> bool {
        self.adapters.contains_key(arch_id)
    }

    /// Unmount an arch, and hand the caller the adapter that was removed.
    ///
    /// The adapter comes back rather than being dropped here because dropping
    /// one can be slow: the Ollama arch stops the container it started, which
    /// is a `docker stop` of ten seconds or more. This runs under the kernel
    /// mutex, which is the one thing that must never be held across a slow
    /// external call, so the daemon releases the lock and *then* drops what
    /// this returned (SP1b Task 1 review, Minor 10). A caller that lets the
    /// value fall here gets the old behaviour, which is why it is
    /// `#[must_use]`-shaped: `Option` already is.
    ///
    /// Unmounting an `Unavailable` arch is how an operator clears one whose
    /// runtime has changed for good: the placeholder, the manifest and the
    /// mount spec all go, so the next boot has nothing to try to re-create.
    ///
    /// The durable delete happens **before** the in-memory tables are touched
    /// (Task 1b review, Minor 6): a delete that fails used to leave the arch
    /// gone from this process and still on disk, with no `arch.unmounted`
    /// event — so it came back at the next boot and the operator was never
    /// told the unmount had not taken.
    pub fn unmount(&mut self, arch_id: &str) -> Result<Option<Arc<dyn arch::ArchAdapter>>> {
        self.store.db.transaction(|| {
            self.store.db.delete("arches", arch_id)?;
            self.store.db.delete("mounts", arch_id)
        })?;
        let removed = self.adapters.remove(arch_id);
        self.unavailable.remove(arch_id);
        self.starting.remove(arch_id);
        self.budgets.remove(arch_id);
        self.log("arch.unmounted", now_ms(), &arch_id)?;
        Ok(removed)
    }

    /// Every arch this node has mounted, usable or not.
    ///
    /// Unavailable ones are in here on purpose (Ruling 14): an arch left out
    /// of the listing is one nobody goes and fixes, and the id is still
    /// mounted — a task may name it, and `vk umount` is how it goes away. Ask
    /// [`RealKernel::arch_states`] which is which.
    pub fn arches(&self) -> Vec<(String, ArchManifest)> {
        self.arch_states()
            .into_iter()
            .map(|(id, m, _)| (id, m))
            .collect()
    }

    /// The same, each with its state: what `arch.ls`, `/arches`, `top` and the
    /// boot report all print.
    pub fn arch_states(&self) -> Vec<(String, ArchManifest, ArchState)> {
        let ready = self
            .adapters
            .iter()
            .map(|(id, a)| (id.clone(), (a.manifest().clone(), ArchState::Ready)));
        // The manifest of an arch still coming up is the stored one, which is
        // the one it must come back as — so a listing during startup shows
        // what the operator mounted, not a guess.
        let coming = self
            .starting
            .iter()
            .map(|(id, p)| (id.clone(), (p.manifest.clone(), ArchState::Starting)));
        let down = self.unavailable.iter().map(|(id, u)| {
            (
                id.clone(),
                (u.manifest.clone(), ArchState::Unavailable(u.reason.clone())),
            )
        });
        // Through a `BTreeMap` rather than chained: sorted sequences
        // concatenated are not one sorted sequence, and every caller of this
        // prints it in order.
        ready
            .chain(coming)
            .chain(down)
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(id, (m, state))| (id, m, state))
            .collect()
    }

    /// One arch's state; `None` for an id this node has never mounted.
    pub fn arch_state(&self, arch_id: &str) -> Option<ArchState> {
        if self.adapters.contains_key(arch_id) {
            return Some(ArchState::Ready);
        }
        if self.starting.contains_key(arch_id) {
            return Some(ArchState::Starting);
        }
        self.unavailable
            .get(arch_id)
            .map(|u| ArchState::Unavailable(u.reason.clone()))
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn devices(&self) -> &DeviceRegistry {
        &self.devices
    }

    /// Every enrolled device, sorted: the device keys the registry holds and
    /// the passkeys beside them. What the boot report and `boot.info` count —
    /// a passkey is a device that speaks for a human, whatever verifies it.
    pub fn device_ids(&self) -> Vec<String> {
        let mut ids = self.devices.ids();
        ids.extend(
            self.passkeys()
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.device_id),
        );
        ids.sort();
        ids.dedup();
        ids
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
                    passkey: None,
                    enrolled_ms: now_ms(),
                },
            )
            .map_err(store_failed)?;
        self.devices.register(device_id.into(), vk);
        self.log("device.enrolled", now_ms(), &device_id)?;
        Ok(())
    }

    /// Enrol a passkey as device `passkey:<credential id>` (SP1b Task 5).
    ///
    /// In-process only, never a syscall: the enrolment ceremony is `vk-web`'s
    /// registration flow, whose `finish` verified the attestation with
    /// `webauthn-rs` before it calls this. `credential` is that verifier's
    /// `Passkey`, serialised, and the kernel never looks inside it — it holds
    /// it for the verifier the way it holds a verifying key for the registry.
    /// A second enrolment under an id already there is refused as an I1
    /// matter, exactly as a different key for the node device is: a device id
    /// names one credential for good.
    pub fn enroll_passkey(
        &mut self,
        device_id: &str,
        credential: serde_json::Value,
        now_ms: u64,
    ) -> Result<(), KernelError> {
        if !device_id.starts_with(PASSKEY_DEVICE_PREFIX)
            || device_id.len() == PASSKEY_DEVICE_PREFIX.len()
        {
            return Err(KernelError::I1(format!(
                "a passkey's device id is `{PASSKEY_DEVICE_PREFIX}<credential id>`, not {device_id:?}"
            )));
        }
        let existing: Option<DeviceRow> = self
            .store
            .db
            .get_json("devices", device_id)
            .map_err(store_failed)?;
        if existing.is_some() {
            return Err(KernelError::I1(format!(
                "device {device_id} is already enrolled"
            )));
        }
        self.store
            .db
            .put_json(
                "devices",
                device_id,
                &DeviceRow {
                    vk_hex: String::new(),
                    trust_class: PASSKEY_TRUST_CLASS.into(),
                    passkey: Some(credential),
                    enrolled_ms: now_ms,
                },
            )
            .map_err(store_failed)?;
        self.log("device.enrolled", now_ms, &device_id)
    }

    /// Replace an enrolled passkey's credential with what the verifier holds
    /// after an assertion — its signature counter moved. The device id, its
    /// trust class and its enrolment time stay; nothing is appended, because
    /// nothing was enrolled. An id that is not an enrolled passkey is refused.
    pub fn update_passkey(
        &mut self,
        device_id: &str,
        credential: serde_json::Value,
    ) -> Result<(), KernelError> {
        let row: DeviceRow = self
            .store
            .db
            .get_json("devices", device_id)
            .map_err(store_failed)?
            .filter(|r: &DeviceRow| r.trust_class == PASSKEY_TRUST_CLASS)
            .ok_or_else(|| KernelError::NotFound(format!("passkey {device_id}")))?;
        self.store
            .db
            .put_json(
                "devices",
                device_id,
                &DeviceRow {
                    passkey: Some(credential),
                    ..row
                },
            )
            .map_err(store_failed)
    }

    /// Every enrolled passkey, sorted by device id: what `vk-web`'s verifier
    /// loads before an authentication and what `vk passkey ls` prints.
    pub fn passkeys(&self) -> Result<Vec<PasskeyRow>, KernelError> {
        Ok(self
            .store
            .db
            .list_json::<DeviceRow>("devices")
            .map_err(store_failed)?
            .into_iter()
            .filter(|(_, row)| row.trust_class == PASSKEY_TRUST_CLASS)
            .filter_map(|(device_id, row)| {
                row.passkey.map(|credential| PasskeyRow {
                    device_id,
                    credential,
                    enrolled_ms: row.enrolled_ms,
                })
            })
            .collect())
    }

    /// Mint the challenge a human approval of `task_id` must answer (SP1b
    /// Task 5, invariant I1): the task's current approval subject as the
    /// action digest, `task:<id>` as the resource, a random nonce and a short
    /// expiry. The only way a `Challenge` a human signs comes into being. A
    /// task that is not waiting at its `Approve` step gets no challenge
    /// (`approval_subject` refuses), so nothing can be signed for a subject
    /// the scheduler would not ask about.
    pub fn mint_approval_challenge(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
    ) -> Result<Challenge, KernelError> {
        self.mint_approval_challenge_with_ttl(ctx, task_id, APPROVAL_CHALLENGE_TTL_MS)
    }

    /// The same with an explicit lifetime — the default for every caller but a
    /// test that needs a challenge to expire while it watches.
    pub fn mint_approval_challenge_with_ttl(
        &mut self,
        ctx: &Ctx,
        task_id: &str,
        ttl_ms: u64,
    ) -> Result<Challenge, KernelError> {
        let subject = self.approval_subject(ctx, task_id)?;
        let now = ctx.now_ms;
        self.approval_challenges
            .retain(|_, p| p.challenge.expires_at_ms > now);
        if self.approval_challenges.len() >= MAX_APPROVAL_CHALLENGES {
            if let Some(soonest) = self
                .approval_challenges
                .iter()
                .min_by_key(|(_, p)| p.challenge.expires_at_ms)
                .map(|(nonce, _)| nonce.clone())
            {
                self.approval_challenges.remove(&soonest);
            }
        }
        let nonce = {
            use base64::Engine;
            let bytes: [u8; 32] = rand::random();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        };
        let challenge = Challenge {
            resource: format!("task:{task_id}"),
            action_digest: subject,
            nonce: nonce.clone(),
            expires_at_ms: now.saturating_add(ttl_ms),
        };
        self.approval_challenges.insert(
            nonce,
            PendingApproval {
                task_id: task_id.into(),
                challenge: challenge.clone(),
            },
        );
        Ok(challenge)
    }

    /// The challenges minted and not yet spent or expired, oldest expiry
    /// first. A read surface for a client that wants to know whether a
    /// ceremony is under way; it hands out nothing a client could not have
    /// asked to be minted.
    pub fn pending_approvals(&self, now_ms: u64) -> Vec<PendingApproval> {
        let mut open: Vec<PendingApproval> = self
            .approval_challenges
            .values()
            .filter(|p| p.challenge.expires_at_ms > now_ms)
            .cloned()
            .collect();
        open.sort_by_key(|p| p.challenge.expires_at_ms);
        open
    }

    /// Spend a minted challenge: the one presented must be, field for field,
    /// one this kernel minted, not yet spent and not yet expired. It leaves
    /// the map here, before anything else about the approval is looked at,
    /// whatever the verdict — a nonce presented is a nonce spent, as for
    /// presence nonces in the transport, so a challenge that fails a check
    /// cannot be shown again to a check it would pass. Both ceremonies go
    /// through this: the node-key path from `approve`, the passkey path from
    /// `record_verified_human_approval`. Returns the task the challenge was
    /// minted for.
    fn spend_approval_challenge(
        &mut self,
        presented: &Challenge,
        now_ms: u64,
    ) -> Result<String, KernelError> {
        let minted = self
            .approval_challenges
            .remove(&presented.nonce)
            .ok_or_else(|| {
                KernelError::I1(
                    "approval challenge was not minted by this node, or was already spent".into(),
                )
            })?;
        if minted.challenge != *presented {
            return Err(KernelError::I1(
                "approval challenge is not the one this node minted for that nonce".into(),
            ));
        }
        if now_ms >= presented.expires_at_ms {
            return Err(KernelError::I1("approval challenge expired".into()));
        }
        Ok(minted.task_id)
    }

    /// Record a human approval whose ceremony has already been verified by
    /// this process — the passkey path (SP1b Task 5).
    ///
    /// **I1 argument.** A human approval reaches the record by exactly two
    /// doors. One is the `approve` syscall, where the approver must be the
    /// human principal the transport derived from an enrolled ed25519 device
    /// key's presence proof, and the signature must verify against that key.
    /// The other is this method, which no syscall reaches: it is called only
    /// in-process, by `vk-web`'s `POST /approve/<task>/finish`, after
    /// `webauthn-rs` has verified the assertion against a passkey that was
    /// enrolled through the admin flow — so the *approver* here is the passkey
    /// the verifier identified, never a principal a client asserted, and the
    /// *challenge* is checked here to be one this kernel minted, unspent and
    /// unexpired, never one a client supplied. What a client sends over the
    /// loopback page is an assertion; what becomes an approval is decided on
    /// this side of it. `proof` names the ceremony on the ledger.
    pub fn record_verified_human_approval(
        &mut self,
        now_ms: u64,
        approval: Approval,
        proof: &str,
    ) -> Result<(), KernelError> {
        if approval.kind != ApprovalKind::Human {
            return Err(KernelError::I1(
                "a verified human approval is of kind human".into(),
            ));
        }
        if !approval.approver.is_human() {
            return Err(KernelError::I1(
                "a verified human approval names a human device".into(),
            ));
        }
        let challenge = approval
            .challenge
            .as_ref()
            .ok_or_else(|| KernelError::I1("a human approval answers a challenge".into()))?;
        if approval
            .signature_hex
            .as_deref()
            .is_none_or(|s| s.is_empty())
        {
            return Err(KernelError::I1(
                "a human approval carries the assertion's signature".into(),
            ));
        }
        if challenge.action_digest != approval.subject_hash {
            return Err(KernelError::I1(
                "approval subject does not match the challenge's action".into(),
            ));
        }
        self.spend_approval_challenge(challenge, now_ms)?;
        self.record_approval(now_ms, &approval, proof)
    }

    /// The approval onto the record, ledger first: an approval that is stored
    /// but reported as failed would still satisfy a later promote's
    /// human-approval gate and the scheduler's waiting step.
    fn record_approval(
        &mut self,
        now_ms: u64,
        approval: &Approval,
        proof: &str,
    ) -> Result<(), KernelError> {
        let key = format!("{}:{}", approval.subject_hash, hash_canonical(approval));
        self.log(
            "approval.recorded",
            now_ms,
            &ApprovalRecord { approval, proof },
        )?;
        self.store
            .db
            .put_json("approvals", &key, approval)
            .map_err(store_failed)
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
            .map_err(|e| match e.downcast_ref::<StorageError>() {
                Some(missing) => KernelError::NotFound(missing.to_string()),
                // The store has bytes at this address and they are not the
                // ones the address names: a swapped, restored or altered
                // blob. That is a store that cannot be trusted for this
                // artefact, not an artefact that is not there.
                None => KernelError::Store(e.to_string()),
            })
    }

    /// The label an artefact carries, or `None` when it is not there. Read for
    /// the workspace projection's record (`vk_harness::ProjectionRecord`), which
    /// names the class of data admitted to a harness.
    pub fn artefact_label(&self, hash: &str) -> Option<Label> {
        self.store.blobs.envelope(hash).ok().map(|e| e.label)
    }

    /// Where a task's harness workspace lives: `<state_dir>/harness/<task_id>`,
    /// the label-projected directory the harness is launched in (`0700` on Unix).
    pub fn harness_workspace_dir(&self, task_id: &str) -> PathBuf {
        self.store.state_dir.join("harness").join(task_id)
    }

    /// Where a run's `mcp.json` (with the lease token) and `settings.json` (the
    /// permission fence) are written: `<state_dir>/harness/<task_id>.mcp`,
    /// **outside** the workspace, so no allow rule reaches them and the fence
    /// denies them by name (Ruling 19).
    pub fn harness_config_dir(&self, task_id: &str) -> PathBuf {
        self.store
            .state_dir
            .join("harness")
            .join(format!("{task_id}.mcp"))
    }

    /// The map key a token is looked up by: its SHA-256, so the token itself
    /// is never held anywhere but in the run's `mcp.json`.
    fn harness_token_key(token: &str) -> String {
        vk_contracts::hash_bytes(token.as_bytes())
    }

    /// Mint a run's lease token: 32 random bytes, base64url (Ruling 21.2). A
    /// secret, returned once to the launcher and hashed into the token map.
    fn mint_harness_token(&mut self, lease_id: &str, task_id: &str) -> String {
        use base64::Engine;
        let bytes: [u8; 32] = rand::random();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        self.harness_tokens.insert(
            Self::harness_token_key(&token),
            HarnessTokenState {
                lease_id: lease_id.into(),
                task_id: task_id.into(),
                bytes_attached: 0,
                oversize: None,
            },
        );
        token
    }

    /// Forget a run's token, so it stops resolving at once (Ruling 21.4).
    fn revoke_harness_token(&mut self, token: &str) {
        self.harness_tokens.remove(&Self::harness_token_key(token));
    }

    /// Is a harness run live for this task right now?
    pub fn harness_running(&self, task_id: &str) -> bool {
        self.harness_tokens.values().any(|s| s.task_id == task_id)
    }

    /// The harness session a lease token names (SP1b Task 4).
    ///
    /// The token is the secret a run was launched with; possessing it is the
    /// capability that lets `vk-mcp` act as the harness. This resolves it — by
    /// its hash, through the token map — to the machine principal it stands for
    /// (`lease_id` = the lease id, never the token) at the harness clearance
    /// (Business, no third-party), never the caller's own, and to the task and
    /// register it may touch. An unknown, revoked or expired token is refused as
    /// an I1 violation (the transport maps that to `E_INVARIANT`); no presence
    /// proof is ever accepted for a `harness.*` call, because a lease is a
    /// machine capability, not a human's presence.
    pub fn harness_session(&self, token: &str, now_ms: u64) -> Result<HarnessSession, KernelError> {
        let state = self
            .harness_tokens
            .get(&Self::harness_token_key(token))
            .ok_or_else(|| KernelError::I1("unknown harness token".into()))?;
        let lease: Lease = self
            .store
            .db
            .get_json("leases", &state.lease_id)
            .map_err(store_failed)?
            .ok_or_else(|| KernelError::I1("harness token's lease is gone".into()))?;
        if lease.expired(now_ms) {
            return Err(KernelError::I1("expired harness token".into()));
        }
        if lease.resource != format!("harness:{}", state.task_id) {
            return Err(KernelError::I1("token is not a harness lease".into()));
        }
        let task: crate::tasks::Task = self
            .store
            .db
            .get_json("tasks", &state.task_id)
            .map_err(store_failed)?
            .ok_or_else(|| KernelError::NotFound(state.task_id.clone()))?;
        let ctx = Ctx {
            principal: Principal::Machine {
                node_id: self.node_id.clone(),
                lease_id: state.lease_id.clone(),
            },
            clearance: vk_harness::harness_clearance(),
            partition: lease.partition.clone(),
            now_ms,
        };
        Ok(HarnessSession {
            ctx,
            task_id: state.task_id.clone(),
            register: task.register,
        })
    }

    fn log(
        &mut self,
        kind: &str,
        wall_ms: u64,
        payload: &impl serde::Serialize,
    ) -> Result<(), KernelError> {
        // The sole choke point every kernel-originated event passes through
        // (review finding, Task 0 fix-wave): a kind outside the contract's
        // list is refused here, before the clock advances or anything is
        // appended, rather than being silently hashed into the permanent
        // record. `Ledger::append` itself stays free-form — it is shared
        // with the stub and a node must still be able to *read* a kind a
        // newer version minted — this gate is only on what this kernel
        // itself will originate.
        if !is_allowed_kind(kind) {
            return Err(KernelError::Store(format!(
                "ledger kind not allowed: {kind}"
            )));
        }
        let hlc = self.clock.now(wall_ms);
        // Through the store, not the ledger tier alone: the store records the
        // new head beside the event, which is what lets the next boot tell a
        // record that was shortened from one that verifies.
        self.store
            .append_event(
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

    /// Accumulate the per-arch counters `vk top` reads back — and, for an arch
    /// that measures its own calls, the only place those measurements outlive
    /// the call until per-call usage rows exist (SP1b rulings 7 and 8).
    ///
    /// `measured` is `None` for an arch that reports no usage; `tokens_in` is
    /// then the estimate and only the total moves. When it is `Some`, the
    /// measurement is what both totals take, so `tokens_in_measured` is the
    /// part of `tokens_in` that is a fact rather than a heuristic.
    fn bump_stats(
        &self,
        arch_id: &str,
        tokens_in: u32,
        measured: Option<u32>,
        cost_list_usd: Option<f64>,
        projected: bool,
    ) -> Result<(), KernelError> {
        let key = format!("stats:{arch_id}");
        let mut stats: ArchStats = match self.store.db.kv_get(&key).map_err(store_failed)? {
            Some(v) => serde_json::from_str(&v).map_err(store_failed)?,
            None => ArchStats::default(),
        };
        stats.calls += 1;
        stats.tokens_in += u64::from(tokens_in);
        stats.tokens_in_measured += u64::from(measured.unwrap_or(0));
        // A cost that is not a finite number is not a cost: adding it would
        // turn the arch's running total into a NaN nothing can read back.
        if let Some(cost) = cost_list_usd.filter(|c| c.is_finite()) {
            stats.cost_list_usd += cost;
        }
        stats.projected += u64::from(projected);
        let json = serde_json::to_string(&stats).map_err(store_failed)?;
        self.store.db.kv_set(&key, &json).map_err(store_failed)
    }
}

/// Who a harness lease token is, and what it may act on: the machine principal
/// at the harness clearance, plus the task and register the lease is for. What
/// [`RealKernel::harness_session`] hands the transport for every `harness.*`
/// call.
pub struct HarnessSession {
    pub ctx: Ctx,
    pub task_id: String,
    pub register: RegisterId,
}

/// The kernel as the workspace projection sees it (SP1b Task 4). `vk-harness`
/// defines this trait so it need not depend on the kernel; the kernel's own
/// read paths back it, and the projection's log rides `infer.projected` — the
/// existing "an object was projected" kind, no new event kind.
impl vk_harness::Host for RealKernel {
    fn read_register(&mut self, ctx: &Ctx, reg: &RegisterId) -> Result<Register, KernelError> {
        <Self as vk_contracts::syscalls::Kernel>::read_register(self, ctx, reg)
    }

    fn read_artefact(&self, ctx: &Ctx, hash: &str) -> Result<Vec<u8>, KernelError> {
        RealKernel::read_artefact(self, ctx, hash)
    }

    fn artefact_label(&self, hash: &str) -> Option<Label> {
        RealKernel::artefact_label(self, hash)
    }

    fn log_projection(
        &mut self,
        now_ms: u64,
        rec: &vk_harness::ProjectionRecord,
    ) -> Result<(), KernelError> {
        self.log("infer.projected", now_ms, rec)
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
        // Before the register is read and before anything is appended: an arch
        // that cannot run is refused by name, with the reason `load` recorded,
        // and no `infer` event is written — an inference that never left this
        // node must leave no trace of having been attempted (Ruling 14). It is
        // never quietly served by a mock, which is what this used to be.
        let adapter = match self.adapters.get(arch_id).cloned() {
            Some(adapter) => adapter,
            None if self.starting.contains_key(arch_id) => {
                return Err(KernelError::ArchStarting(arch_id.into()))
            }
            None => {
                return Err(match self.unavailable.get(arch_id) {
                    Some(down) => KernelError::ArchUnavailable(down.reason.clone()),
                    None => KernelError::NotFound(arch_id.into()),
                })
            }
        };
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
        let estimated = count(&prompt);
        // The prompt is about to leave this kernel. Record the attempt before
        // it does: an engine can hang, be killed, or take the machine down
        // with it, and an inference that happened with nothing in the record
        // saying so is the one gap an auditor cannot close afterwards (SP1b
        // review, M2). This half knows only the estimate — the measurement is
        // what comes back — so it says `measured: false` and claims nothing.
        self.log(
            "infer",
            ctx.now_ms,
            &InferRecord {
                arch_id,
                register: &reg_id.0,
                phase: "requested",
                tokens_in: estimated,
                measured: false,
                cost_list_usd: None,
                details: None,
            },
        )?;
        let completion = adapter
            .complete(&prompt, budget.min(1024))
            .map_err(|e| adapter_failed(arch_id, e))?;
        // An arch that counted the prompt itself has the number; the estimate
        // was only ever a stand-in for it (ruling 7).
        let tokens_in = completion.tokens_in_measured.unwrap_or(estimated);
        // The call has come back: record it before doing anything that could
        // fail, so the answer is never acted on before it is written down.
        //
        // `now_ms()`, not `ctx.now_ms`: the call took as long as it took, and
        // two records of one inference stamped with the same instant tell a
        // ledger reader nothing about how long the arch was away (SP1b Task 1
        // review, Minor 7). The HLC keeps the order whatever the wall clock
        // does.
        self.log(
            "infer",
            now_ms(),
            &InferRecord {
                arch_id,
                register: &reg_id.0,
                phase: "completed",
                tokens_in,
                measured: completion.tokens_in_measured.is_some(),
                cost_list_usd: completion.cost_list_usd,
                details: completion.details.as_ref(),
            },
        )?;
        self.infer_log.push((arch_id.into(), reg.label.clone()));
        self.bump_stats(
            arch_id,
            tokens_in,
            completion.tokens_in_measured,
            completion.cost_list_usd,
            projected,
        )?;
        arch::raise(&mut reg, role, &completion.text);
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
        // The challenge first, before the principal or the signature is
        // looked at (SP1b Task 5): a human approval answers a challenge this
        // node minted for the task, unspent and unexpired, or it is nothing —
        // a client that builds its own `Challenge`, however well it signs it,
        // is signing a subject and an expiry of its own choosing. Spent here
        // whatever follows, so a failed signature burns the nonce too.
        if approval.kind == ApprovalKind::Human {
            let challenge = approval.challenge.as_ref().ok_or_else(|| {
                KernelError::I1("a human approval answers a minted challenge".into())
            })?;
            self.spend_approval_challenge(challenge, ctx.now_ms)?;
        }
        interceptors::i1_approval(&ctx.principal, &approval, &self.devices, ctx.now_ms)?;
        self.record_approval(ctx.now_ms, &approval, "device-key")
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
        // With the spec that makes it again, so a mock arch survives a restart
        // the way a real one does — `open`'s own factory knows this kind.
        let spec = arch::MountSpec::mock(&m, budget);
        self.mount(
            Arc::new(arch::MockAdapter {
                manifest: m,
                budget,
            }),
            spec,
        )
        .expect("mount")
        .arch_id
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
        let manifest = local(personal());
        let spec = arch::MountSpec::mock(&manifest, 100);
        let arch = k
            .mount(
                Arc::new(arch::MockAdapter {
                    manifest,
                    budget: 100,
                }),
                spec,
            )
            .unwrap()
            .arch_id;
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

    /// The last two lines of the record removed — where a STOP and a mount
    /// live. What is left still chains, so `verify_chain` is satisfied; boot
    /// is not, because the store knows where its head was. And it stays not
    /// satisfied on the next start: the boot event it appends onto the cut
    /// chain must not turn that chain into the record.
    #[test]
    fn boot_reports_a_cut_tail_rather_than_trusting_the_shorter_chain() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut k = open(d.path());
            k.boot().unwrap();
            k.register_arch(local(personal()));
            k.stop(&human(1), "node").unwrap();
        }
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.truncate(lines.len() - 2);
        std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();

        {
            let mut k = open(d.path());
            let r = k.boot().unwrap();
            assert!(
                !r.ledger_ok,
                "a shortened record must not pass as the record"
            );
            assert!(
                k.ledger().verify_chain(),
                "the chain itself still links: only the recorded head says it is short"
            );
            assert!(
                k.stops().stopped("node"),
                "the STOP the record lost still holds in the state"
            );
        }
        let mut k = open(d.path());
        assert!(
            !k.boot().unwrap().ledger_ok,
            "the verdict must survive the boot event appended onto the cut chain"
        );
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

    /// A healthy `boot` never marks the node forced: `record_forced_boot` is
    /// the only thing that does, and only `vkd`'s `--force` path calls it.
    #[test]
    fn boot_alone_never_marks_the_node_forced() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        assert!(!k.forced_boot());
        k.boot().unwrap();
        assert!(!k.forced_boot(), "a healthy boot must not look forced");
    }

    /// `vkd` calls this on the serve-under-force path, with the very report
    /// `boot` returned. The ledger gains a `boot.forced` event naming exactly
    /// that verdict — not a fresh recomputation, which could disagree with
    /// what `boot` already committed to — so `vk dmesg` shows an auditor
    /// when and why an operator overrode a chain that said not to serve.
    #[test]
    fn record_forced_boot_appends_the_event_boot_reported() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut k = open(d.path());
            k.boot().unwrap();
            assert!(k.boot().unwrap().ledger_ok);
        }
        // Tamper the first of the two boot events: `verify_chain` fails, but
        // the recorded head — the second boot's `{seq, hash}` — is untouched,
        // so only the chain half of the verdict breaks.
        let seg = d.path().join("ledger").join("seg-000000.jsonl");
        let text = std::fs::read_to_string(&seg).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        first["payload_hash"] = serde_json::json!("sha256:tampered");
        lines[0] = serde_json::to_string(&first).unwrap();
        std::fs::write(&seg, format!("{}\n", lines.join("\n"))).unwrap();

        let mut k = open(d.path());
        let report = k.boot().unwrap();
        assert!(!report.ledger_ok, "the tampered chain must not verify");
        assert!(!k.forced_boot());

        k.record_forced_boot(&report).unwrap();
        assert!(k.forced_boot());

        let last = k.ledger().events().last().unwrap().clone();
        assert_eq!(last.kind, "boot.forced");
        let report_hash = hash_canonical(&report);
        assert_eq!(
            last.payload_hash,
            hash_canonical(&BootForcedRecord {
                ledger_ok: false,
                head_ok: true,
                ledger_len: report.ledger_len,
                report_hash: &report_hash,
            }),
            "the payload must name the verdict `boot` found"
        );
    }

    /// An adapter that answers however a test needs it to, so the kernel's
    /// side of the `ArchAdapter` contract can be exercised without an engine.
    struct Scripted {
        manifest: ArchManifest,
        answer: Box<dyn Fn() -> Result<arch::Completion, arch::AdapterError> + Send + Sync>,
    }

    impl arch::ArchAdapter for Scripted {
        fn manifest(&self) -> &ArchManifest {
            &self.manifest
        }
        fn context_budget(&self) -> u32 {
            self.manifest.context_ceiling
        }
        fn count_tokens(&self, text: &str) -> u32 {
            (text.len() / 4) as u32 + 1
        }
        fn complete(&self, _: &str, _: u32) -> Result<arch::Completion, arch::AdapterError> {
            (self.answer)()
        }
    }

    /// An adapter that says which instance it is and counts its own drops, so
    /// a re-mount can be shown to have *kept* the one already there rather
    /// than swapped it — and so that a swap can be shown to hand the old one
    /// back instead of dropping it in place (Ruling 13).
    struct Counted {
        manifest: ArchManifest,
        tag: u32,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl arch::ArchAdapter for Counted {
        fn manifest(&self) -> &ArchManifest {
            &self.manifest
        }
        fn context_budget(&self) -> u32 {
            self.manifest.context_ceiling
        }
        fn count_tokens(&self, text: &str) -> u32 {
            (text.len() / 4) as u32 + 1
        }
        fn complete(&self, _: &str, _: u32) -> Result<arch::Completion, arch::AdapterError> {
            Ok(arch::Completion::text(format!("adapter {}", self.tag)))
        }
    }

    /// Ruling 13: mounting an arch that is already there keeps what is there.
    ///
    /// The adapter in the table can own something outside this process — the
    /// Ollama arch owns the container it started — so silently swapping it and
    /// dropping the old one is how a plain repeat `vk mount ollama` stopped
    /// the container it had just re-mounted, with the kernel lock held. A
    /// deliberate replacement is still possible, and hands the old adapter
    /// back for the caller to drop after it has let the lock go.
    #[test]
    fn an_identical_re_mount_keeps_the_adapter_that_is_already_there() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = |tag: u32| {
            Arc::new(Counted {
                manifest: local_named("counted", personal()),
                tag,
                dropped: dropped.clone(),
            })
        };
        let fallen = || dropped.load(std::sync::atomic::Ordering::SeqCst);

        let spec = || arch::MountSpec::mock(&local_named("counted", personal()), 100);
        let first = k.mount(counted(1), spec()).expect("the first mount");
        assert!(!first.already_mounted);
        assert!(first.replaced.is_none());
        let events = k.ledger().events().len();

        let again = k.mount(counted(2), spec()).expect("the same arch again");
        assert_eq!(again.arch_id, first.arch_id, "the same arch is the same id");
        assert!(again.already_mounted);
        assert!(
            again.replaced.is_none(),
            "an idempotent re-mount replaces nothing"
        );
        assert_eq!(
            k.ledger().events().len(),
            events,
            "and appends nothing to the record"
        );
        assert_eq!(fallen(), 1, "the newcomer was dropped, not the incumbent");

        // Which one is actually mounted: the answer comes out of the arch.
        let reg = k
            .submit_task(&machine(1), "a goal", Label::bottom())
            .unwrap();
        k.infer(&machine(2), &again.arch_id, Capability::Plan, &reg)
            .unwrap();
        let after = k.read_register(&machine(3), &reg).unwrap();
        assert!(
            after.decisions.iter().any(|d| d.contains("adapter 1")),
            "the first adapter is still the one mounted: {:?}",
            after.decisions
        );

        // The deliberate replacement: it swaps, and the old adapter leaves by
        // the return value rather than being dropped here.
        let swapped = k
            .mount_with(counted(3), spec(), Remount::Replace)
            .expect("a replacement");
        assert_eq!(swapped.arch_id, first.arch_id);
        assert!(swapped.already_mounted);
        let old = swapped.replaced.expect("the adapter it took the place of");
        assert_eq!(
            fallen(),
            1,
            "the replaced adapter is still alive, in the caller's hand"
        );
        drop(old);
        assert_eq!(fallen(), 2, "and dies when the caller drops it");
        k.infer(&machine(4), &first.arch_id, Capability::Plan, &reg)
            .unwrap();
        let after = k.read_register(&machine(5), &reg).unwrap();
        assert!(
            after.decisions.iter().any(|d| d.contains("adapter 3")),
            "the replacement is the one mounted now: {:?}",
            after.decisions
        );
    }

    fn scripted(
        k: &mut RealKernel,
        name: &str,
        answer: impl Fn() -> Result<arch::Completion, arch::AdapterError> + Send + Sync + 'static,
    ) -> String {
        let manifest = local_named(name, personal());
        let spec = arch::MountSpec::mock(&manifest, manifest.context_ceiling);
        k.mount(
            Arc::new(Scripted {
                manifest,
                answer: Box::new(answer),
            }),
            spec,
        )
        .expect("mount")
        .arch_id
    }

    /// Ruling 7: an arch that counted the prompt itself has the number, and the
    /// estimate was only ever a stand-in for it. What the kernel accounts and
    /// reports is the measurement — and ruling 8's counters say how much of the
    /// total is measurement rather than heuristic, so nobody has to guess
    /// whether a figure could be billed against.
    #[test]
    fn a_measured_call_is_accounted_by_its_measurement_not_by_the_estimate() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let measured = scripted(&mut k, "measured", || {
            Ok(arch::Completion {
                text: "ok".into(),
                tokens_in_measured: Some(14_435),
                cost_list_usd: Some(0.0148193),
                details: Some(serde_json::json!({ "session_id": "s-1" })),
            })
        });
        let guessing = scripted(&mut k, "guessing", || Ok(arch::Completion::text("ok")));

        let reg = k
            .submit_task(&machine(1), "a goal", Label::bottom())
            .unwrap();
        let out = k
            .infer(&machine(2), &measured, Capability::Plan, &reg)
            .unwrap();
        assert_eq!(
            out.tokens_in, 14_435,
            "the arch counted the prompt; the estimate is not the number to keep"
        );
        let guessed = k
            .infer(&machine(3), &guessing, Capability::Plan, &reg)
            .unwrap();
        assert!(
            guessed.tokens_in > 0 && guessed.tokens_in < 1_000,
            "an arch that measures nothing still gets the estimate: {}",
            guessed.tokens_in
        );

        let stats = k.top(&machine(4)).arches;
        let m = &stats[&measured];
        assert_eq!(m.calls, 1);
        assert_eq!(m.tokens_in, 14_435);
        assert_eq!(m.tokens_in_measured, 14_435, "all of it was measured");
        assert!((m.cost_list_usd - 0.0148193).abs() < 1e-9, "{m:?}");
        let g = &stats[&guessing];
        assert_eq!(g.tokens_in, u64::from(guessed.tokens_in));
        assert_eq!(g.tokens_in_measured, 0, "nothing here was measured");
        assert_eq!(g.cost_list_usd, 0.0);

        // And it is on disk, not in this process: `vk top` after a restart.
        drop(k);
        let k = open(d.path());
        let after = k.top(&machine(5)).arches;
        assert_eq!(after[&measured].tokens_in_measured, 14_435);
        assert!((after[&measured].cost_list_usd - 0.0148193).abs() < 1e-9);
    }

    /// Review finding (SP1b, Important 2): an adapter refusing a prompt its
    /// context cannot hold is raising the kernel's own I4′, and it must reach
    /// the caller as an invariant refusal — not as `NotFound`, which the
    /// transport sends as "no such arch". Everything else an adapter can fail
    /// at is machinery, which is a store-class failure.
    #[test]
    fn an_adapters_i4_prime_stays_an_invariant_and_its_other_failures_do_not() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let too_big = scripted(&mut k, "too-big", || {
            Err(arch::AdapterError::I4Prime {
                needed: 190_000,
                ceiling: 180_000,
            })
        });
        let broken = scripted(&mut k, "broken", || {
            Err(arch::AdapterError::Other(anyhow::anyhow!(
                "claude exited 1: nothing on stderr"
            )))
        });
        let reg = k
            .submit_task(&machine(1), "a goal", Label::bottom())
            .unwrap();

        let err = k
            .infer(&machine(2), &too_big, Capability::Plan, &reg)
            .unwrap_err();
        assert!(
            matches!(&err, KernelError::I4Prime(m) if m.contains("190000") && m.contains("180000")),
            "{err:?}"
        );
        let err = k
            .infer(&machine(3), &broken, Capability::Plan, &reg)
            .unwrap_err();
        assert!(
            matches!(&err, KernelError::Store(m) if m.contains("claude exited 1")),
            "{err:?}"
        );

        // A refused call is not a call. Both arches are on the screen — they
        // are mounted, and `top` says so (Ruling 9d) — with nothing counted
        // against either of them.
        let top = k.top(&machine(4));
        assert_eq!(top.arches.len(), 2, "both mounted arches are listed");
        assert!(
            top.arches
                .values()
                .all(|s| s.calls == 0 && s.tokens_in == 0),
            "a refusal must not bump the counters: {:?}",
            top.arches
        );
    }

    /// Review finding (Task 0 fix-wave, Ruling 2): `ALLOWED_KINDS` must be
    /// load-bearing, not decorative. `log` is the sole choke point every
    /// kernel-originated event passes through, so an unlisted or misspelled
    /// kind is refused there, before the append — nothing lands in the
    /// permanent record, and the chain that was already there is untouched.
    #[test]
    fn log_refuses_a_kind_outside_the_allowed_list() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        k.boot().unwrap();
        let before = k.ledger().events().len();

        let err = k.log("not.a.real.kind", now_ms(), &"payload").unwrap_err();
        assert!(
            matches!(&err, KernelError::Store(msg) if msg.contains("not.a.real.kind")),
            "{err}"
        );

        assert_eq!(
            k.ledger().events().len(),
            before,
            "an unlisted kind must not be appended"
        );
        assert!(
            k.ledger().verify_chain(),
            "the existing chain must still verify"
        );
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

    /// Review M2: a call that leaves the kernel has to be in the record
    /// *before* it leaves. An adapter can hang, be killed, or take the machine
    /// down with it, and an inference that happened with nothing saying so is
    /// the one kind of gap an auditor cannot close afterwards. So `infer` is
    /// appended twice — the same kind, with `phase` saying which half — and
    /// the second one still carries everything the record carried before.
    #[test]
    fn a_send_is_recorded_before_it_leaves_and_again_when_it_comes_back() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let answers = scripted(&mut k, "answers", || {
            Ok(arch::Completion {
                text: "ok".into(),
                tokens_in_measured: Some(12),
                cost_list_usd: None,
                details: None,
            })
        });
        let dies = scripted(&mut k, "dies", || {
            Err(arch::AdapterError::Other(anyhow::anyhow!(
                "the engine went away"
            )))
        });
        let r = k
            .submit_task(&machine(1), "a goal", Label::bottom())
            .unwrap();

        k.infer(&machine(2), &answers, Capability::Plan, &r)
            .unwrap();
        let events = k.ledger().events().to_vec();
        let infers: Vec<_> = events.iter().filter(|e| e.kind == "infer").collect();
        assert_eq!(
            infers.len(),
            2,
            "one record for the send, one for the answer"
        );
        assert_ne!(
            infers[0].payload_hash, infers[1].payload_hash,
            "the two halves must not hash alike, or `phase` is not in the payload"
        );
        let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
        let requested = kinds.iter().position(|x| *x == "infer").unwrap();
        let written = kinds.iter().position(|x| *x == "register.written").unwrap();
        assert!(requested < written, "{kinds:?}");

        // A send that never comes back leaves the first record and no second.
        let before = k.ledger().events().len();
        assert!(k.infer(&machine(3), &dies, Capability::Plan, &r).is_err());
        let after: Vec<&str> = k.ledger().events()[before..]
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert_eq!(
            after,
            ["infer"],
            "the attempt belongs in the record even though no answer came: {after:?}"
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
        let spec = arch::MountSpec::mock(&widened, budget);
        let err = k
            .mount(
                Arc::new(arch::MockAdapter {
                    manifest: widened,
                    budget,
                }),
                spec,
            )
            .map(|o| o.arch_id)
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
        // A task waiting at its approve step, so a challenge can be minted
        // for it (SP1b Task 5): the subject is the drafted artefact's hash.
        let (task, subject) = waiting_task(&mut k);
        let ch = k.mint_approval_challenge(&machine(2), &task).unwrap();
        assert_eq!(ch.action_digest, subject);
        let sig = key.sign(&ch.digest());
        k.approve(
            &human(2),
            Approval {
                subject_hash: subject.clone(),
                kind: ApprovalKind::Human,
                approver: Principal::Human {
                    device_id: "phone-1".into(),
                },
                challenge: Some(ch),
                signature_hex: Some(hex::encode(sig)),
            },
        )
        .unwrap();

        assert_eq!(k.approvals_for(&subject).len(), 1);
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

    /// A task drafted through a mock arch and now waiting at its approve
    /// step, with the subject a human approval of it must name.
    fn waiting_task(k: &mut RealKernel) -> (String, String) {
        use crate::tasks::{StepKind, TaskStatus};
        let arch = k.register_arch(local(personal()));
        let task = k
            .create_task(
                &machine(1),
                "draft a proposal",
                "proposal",
                Label::bottom(),
                vec![StepKind::Draft { arch_id: arch }, StepKind::Approve],
            )
            .unwrap()
            .id;
        k.run_task_step(&machine(1), &task).unwrap();
        let t = k.run_task_step(&machine(1), &task).unwrap();
        assert_eq!(t.status, TaskStatus::WaitingHuman);
        let subject = k.approval_subject(&machine(1), &task).unwrap();
        (task, subject)
    }

    /// `key`'s approval of exactly `ch`.
    fn signed(key: &SoftwareHumanKey, ch: &Challenge) -> Approval {
        Approval {
            subject_hash: ch.action_digest.clone(),
            kind: ApprovalKind::Human,
            approver: Principal::Human {
                device_id: key.device_id(),
            },
            challenge: Some(ch.clone()),
            signature_hex: Some(hex::encode(key.sign(&ch.digest()))),
        }
    }

    /// SP1b Task 5, invariant I1: the kernel mints every approval challenge,
    /// bound to the task's subject and resource with a fresh nonce and a
    /// short expiry; a task that is not waiting gets none; the map of open
    /// challenges is bounded and drops the expired.
    #[test]
    fn mint_approval_challenge_binds_the_waiting_task_and_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let arch = k.register_arch(local(personal()));
        let queued = k
            .create_task(
                &machine(1),
                "later",
                "note",
                Label::bottom(),
                vec![
                    crate::tasks::StepKind::Draft { arch_id: arch },
                    crate::tasks::StepKind::Approve,
                ],
            )
            .unwrap()
            .id;
        // Not waiting yet: no challenge, and nothing left open.
        let err = k.mint_approval_challenge(&machine(1), &queued).unwrap_err();
        assert!(
            matches!(&err, KernelError::Gate(m) if m.contains("not waiting")),
            "{err}"
        );
        assert!(k.pending_approvals(1).is_empty());

        let (task, subject) = waiting_task(&mut k);
        let a = k.mint_approval_challenge(&machine(10), &task).unwrap();
        let b = k.mint_approval_challenge(&machine(10), &task).unwrap();
        assert_eq!(a.resource, format!("task:{task}"));
        assert_eq!(a.action_digest, subject);
        assert_eq!(a.expires_at_ms, 10 + APPROVAL_CHALLENGE_TTL_MS);
        assert_ne!(a.nonce, b.nonce, "every mint is a fresh nonce");
        assert!(
            a.nonce.len() >= 40,
            "32 random bytes, base64url: {}",
            a.nonce
        );
        // Both open, both for this task; equal expiries, so the order between
        // them is the nonces', which is random.
        let mut open: Vec<(String, Challenge)> = k
            .pending_approvals(10)
            .into_iter()
            .map(|p| (p.task_id, p.challenge))
            .collect();
        open.sort_by(|x, y| x.1.nonce.cmp(&y.1.nonce));
        let mut expected = vec![(task.clone(), a.clone()), (task.clone(), b.clone())];
        expected.sort_by(|x, y| x.1.nonce.cmp(&y.1.nonce));
        assert_eq!(open, expected);
        // Expired ones are not pending, and are swept by the next mint.
        assert!(k.pending_approvals(a.expires_at_ms).is_empty());
        let c = k
            .mint_approval_challenge(&machine(a.expires_at_ms), &task)
            .unwrap();
        assert_eq!(k.approval_challenges.len(), 1);
        assert_eq!(k.pending_approvals(a.expires_at_ms)[0].challenge, c);
        // Bounded: past the cap the one closest to expiry goes.
        for _ in 0..(MAX_APPROVAL_CHALLENGES + 5) {
            k.mint_approval_challenge(&machine(a.expires_at_ms + 1), &task)
                .unwrap();
        }
        assert_eq!(k.approval_challenges.len(), MAX_APPROVAL_CHALLENGES);
        assert!(
            !k.approval_challenges.contains_key(&c.nonce),
            "the earliest expiry was the one dropped"
        );
    }

    /// The node-key path through the shared verifier: a challenge nobody
    /// minted is refused before the signature is looked at, an altered one is
    /// refused and burns the nonce, an expired one is refused, and a minted
    /// one is accepted exactly once — after which the waiting step completes.
    #[test]
    fn approve_spends_a_minted_challenge_once_and_refuses_every_other() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let key = SoftwareHumanKey::generate("phone-1");
        k.enroll_device("phone-1", key.verifying_key_bytes());
        let (task, subject) = waiting_task(&mut k);
        let events = |k: &RealKernel| k.ledger().events().len();

        // Unminted, well signed, right subject.
        let forged = Challenge {
            resource: format!("task:{task}"),
            action_digest: subject.clone(),
            nonce: "made-up".into(),
            expires_at_ms: 1_000_000,
        };
        let before = events(&k);
        let err = k.approve(&human(5), signed(&key, &forged)).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );
        assert_eq!(events(&k), before, "nothing appended");

        // Minted, then altered: refused, and the nonce is gone with it.
        let minted = k.mint_approval_challenge(&machine(5), &task).unwrap();
        let altered = Challenge {
            action_digest: "sha256:other".into(),
            ..minted.clone()
        };
        let mut wrong_subject = signed(&key, &altered);
        wrong_subject.subject_hash = "sha256:other".into();
        let err = k.approve(&human(6), wrong_subject).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("not the one")),
            "{err}"
        );
        let err = k.approve(&human(6), signed(&key, &minted)).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );

        // Minted and expired.
        let stale = k
            .mint_approval_challenge_with_ttl(&machine(7), &task, 3)
            .unwrap();
        let err = k.approve(&human(10), signed(&key, &stale)).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("expired")),
            "{err}"
        );

        // Minted, and signed by a key that is not the device's: the nonce is
        // spent by the failed signature, so the real key cannot use it after.
        let minted = k.mint_approval_challenge(&machine(8), &task).unwrap();
        let impostor = SoftwareHumanKey::generate("phone-1");
        let err = k
            .approve(&human(9), signed(&impostor, &minted))
            .unwrap_err();
        assert!(matches!(err, KernelError::Principal(_)), "{err}");
        let err = k.approve(&human(9), signed(&key, &minted)).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );
        assert!(k.approvals_for(&subject).is_empty());
        assert_eq!(events(&k), before);

        // Minted, signed, presented once: recorded, with the ceremony named.
        let minted = k.mint_approval_challenge(&machine(11), &task).unwrap();
        k.approve(&human(12), signed(&key, &minted)).unwrap();
        assert_eq!(k.approvals_for(&subject).len(), 1);
        let last = k.ledger().events().last().unwrap();
        assert_eq!(last.kind, "approval.recorded");
        assert_eq!(
            last.payload_hash,
            hash_canonical(&ApprovalRecord {
                approval: &signed(&key, &minted),
                proof: "device-key",
            })
        );
        // Presented again: spent.
        let err = k.approve(&human(13), signed(&key, &minted)).unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );
        assert_eq!(k.approvals_for(&subject).len(), 1);
        assert!(k.pending_approvals(13).is_empty());
        let t = k.run_task_step(&machine(14), &task).unwrap();
        assert_eq!(t.status, crate::tasks::TaskStatus::Done);
    }

    /// The passkey path (SP1b Task 5): an approval the web verifier already
    /// checked is recorded in-process against a minted challenge, once, with
    /// `proof: webauthn` on the ledger; one that names no minted challenge,
    /// a machine approver, or a subject other than the challenge's is refused
    /// with nothing recorded.
    #[test]
    fn record_verified_human_approval_takes_a_minted_challenge_once() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let (task, subject) = waiting_task(&mut k);
        let passkey = || Principal::Human {
            device_id: "passkey:abc".into(),
        };
        let approval = |ch: &Challenge| Approval {
            subject_hash: ch.action_digest.clone(),
            kind: ApprovalKind::Human,
            approver: passkey(),
            challenge: Some(ch.clone()),
            signature_hex: Some("3045".into()),
        };
        let before = k.ledger().events().len();

        // No minted challenge behind it.
        let unminted = Challenge {
            resource: format!("task:{task}"),
            action_digest: subject.clone(),
            nonce: "n".into(),
            expires_at_ms: 1_000_000,
        };
        let err = k
            .record_verified_human_approval(5, approval(&unminted), "webauthn")
            .unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );

        // A machine approver, a missing signature, a subject that is not the
        // challenge's: each refused before the challenge is spent.
        let minted = k.mint_approval_challenge(&machine(5), &task).unwrap();
        let mut machine_made = approval(&minted);
        machine_made.approver = Principal::Machine {
            node_id: "n1".into(),
            lease_id: "web".into(),
        };
        assert!(matches!(
            k.record_verified_human_approval(6, machine_made, "webauthn"),
            Err(KernelError::I1(_))
        ));
        let mut unsigned = approval(&minted);
        unsigned.signature_hex = None;
        assert!(matches!(
            k.record_verified_human_approval(6, unsigned, "webauthn"),
            Err(KernelError::I1(_))
        ));
        let mut other = approval(&minted);
        other.subject_hash = "sha256:other".into();
        assert!(matches!(
            k.record_verified_human_approval(6, other, "webauthn"),
            Err(KernelError::I1(_))
        ));
        assert_eq!(k.pending_approvals(6).len(), 1, "still unspent");
        assert!(k.approvals_for(&subject).is_empty());
        assert_eq!(k.ledger().events().len(), before);

        // The genuine one: recorded, named, spent.
        k.record_verified_human_approval(7, approval(&minted), "webauthn")
            .unwrap();
        assert_eq!(k.approvals_for(&subject), vec![approval(&minted)]);
        let last = k.ledger().events().last().unwrap();
        assert_eq!(last.kind, "approval.recorded");
        assert_eq!(
            last.payload_hash,
            hash_canonical(&ApprovalRecord {
                approval: &approval(&minted),
                proof: "webauthn",
            })
        );
        assert!(k.pending_approvals(7).is_empty());
        let err = k
            .record_verified_human_approval(8, approval(&minted), "webauthn")
            .unwrap_err();
        assert!(
            matches!(&err, KernelError::I1(m) if m.contains("minted")),
            "{err}"
        );
        assert_eq!(k.approvals_for(&subject).len(), 1);
        assert_eq!(
            k.run_task_step(&machine(9), &task).unwrap().status,
            crate::tasks::TaskStatus::Done
        );
    }

    /// A passkey is a device row of its own class: listed with its credential
    /// and enrolment time, counted among the devices, absent from the key
    /// registry (it has no ed25519 key), refused a second time under the same
    /// id, updatable in place without a second `device.enrolled`, and there
    /// again after a reopen.
    #[test]
    fn a_passkey_is_enrolled_once_listed_counted_and_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let cred = serde_json::json!({ "cred": { "id": "abc", "counter": 0 } });
        {
            let mut k = open(d.path());
            let enrolled = |k: &RealKernel| {
                k.ledger()
                    .events()
                    .iter()
                    .filter(|e| e.kind == "device.enrolled")
                    .count()
            };
            let err = k.enroll_passkey("laptop", cred.clone(), 1).unwrap_err();
            assert!(matches!(err, KernelError::I1(_)), "{err}");
            let err = k
                .enroll_passkey(PASSKEY_DEVICE_PREFIX, cred.clone(), 1)
                .unwrap_err();
            assert!(matches!(err, KernelError::I1(_)), "{err}");
            k.enroll_passkey("passkey:abc", cred.clone(), 1).unwrap();
            assert_eq!(enrolled(&k), 1);
            let err = k
                .enroll_passkey("passkey:abc", cred.clone(), 2)
                .unwrap_err();
            assert!(
                matches!(&err, KernelError::I1(m) if m.contains("already")),
                "{err}"
            );
            assert_eq!(enrolled(&k), 1);

            assert_eq!(
                k.passkeys().unwrap(),
                vec![PasskeyRow {
                    device_id: "passkey:abc".into(),
                    credential: cred.clone(),
                    enrolled_ms: 1,
                }]
            );
            assert!(k.devices().ids().is_empty(), "no key in the registry");
            k.enroll_device_persisted("phone-1", [7u8; 32]).unwrap();
            assert_eq!(
                k.device_ids(),
                vec!["passkey:abc".to_string(), "phone-1".to_string()]
            );
            assert_eq!(k.boot().unwrap().devices, k.device_ids());

            // A counter moved: the row is replaced, nothing is appended.
            let moved = serde_json::json!({ "cred": { "id": "abc", "counter": 3 } });
            k.update_passkey("passkey:abc", moved.clone()).unwrap();
            assert_eq!(k.passkeys().unwrap()[0].credential, moved);
            assert_eq!(enrolled(&k), 2, "phone-1's, and nothing for the update");
            assert!(matches!(
                k.update_passkey("phone-1", moved.clone()),
                Err(KernelError::NotFound(_))
            ));
            assert!(matches!(
                k.update_passkey("passkey:nope", moved),
                Err(KernelError::NotFound(_))
            ));
        }
        let k = open(d.path());
        let rows = k.passkeys().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "passkey:abc");
        assert_eq!(rows[0].credential["cred"]["counter"], 3);
        assert_eq!(rows[0].enrolled_ms, 1);
        assert_eq!(k.devices().ids(), vec!["phone-1".to_string()]);
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

    /// Two artefacts of one task share a DEK; their ciphertexts swapped on
    /// disk would decrypt cleanly under each other's address. The kernel must
    /// not hand out the wrong bytes under the right hash — the approval that
    /// named the hash would have bound nothing — and must not call it "not
    /// found" either, since something is there.
    #[test]
    fn a_swapped_artefact_is_refused_as_a_store_failure_not_served_under_the_wrong_hash() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let r = k.submit_task(&machine(1), "x", Label::bottom()).unwrap();
        let a = k
            .attach_artefact(&machine(2), &r, "proposal.md", b"# Draft one")
            .unwrap();
        let b = k
            .attach_artefact(&machine(2), &r, "proposal.md", b"# Draft two")
            .unwrap();
        let bin = |hash: &str| {
            d.path()
                .join("blobs")
                .join(hash.trim_start_matches("sha256:"))
                .with_extension("bin")
        };
        let tmp = d.path().join("swap.tmp");
        std::fs::rename(bin(&a.hash), &tmp).unwrap();
        std::fs::rename(bin(&b.hash), bin(&a.hash)).unwrap();
        std::fs::rename(&tmp, bin(&b.hash)).unwrap();
        for hash in [&a.hash, &b.hash] {
            match k.read_artefact(&machine(3), hash) {
                Err(KernelError::Store(msg)) => assert!(msg.contains("integrity"), "{msg}"),
                other => panic!("a swapped blob must be a store failure, got {other:?}"),
            }
        }
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

    // ---------------------------------------------------------------------
    // Task 1b (Ruling 14): an arch is re-created at boot from the spec its
    // mount recorded. What cannot be re-created is listed as unavailable —
    // never quietly replaced by the mock, which is what `load` used to do.
    // ---------------------------------------------------------------------

    /// A stand-in for a real adapter: not a `MockAdapter`, and it says so in
    /// every completion, so a test can tell which of the two answered.
    struct StandIn {
        manifest: ArchManifest,
        budget: u32,
    }

    impl arch::ArchAdapter for StandIn {
        fn manifest(&self) -> &ArchManifest {
            &self.manifest
        }
        fn context_budget(&self) -> u32 {
            self.budget
        }
        fn count_tokens(&self, text: &str) -> u32 {
            (text.len() / 4) as u32 + 1
        }
        fn complete(
            &self,
            _prompt: &str,
            _max: u32,
        ) -> Result<arch::Completion, arch::AdapterError> {
            Ok(arch::Completion::text("the stand-in answered"))
        }
    }

    /// The spec `arch.mount` would record for one of those.
    fn standin_spec(name: &str) -> arch::MountSpec {
        arch::MountSpec::new("standin", serde_json::json!({ "name": name })).unwrap()
    }

    /// One stand-in adapter, and the mount that records how to make it again.
    fn mount_standin(k: &mut RealKernel, name: &str) -> String {
        mount_standin_outcome(k, name).arch_id
    }

    fn mount_standin_outcome(k: &mut RealKernel, name: &str) -> MountOutcome {
        let manifest = local_named(name, personal());
        let budget = manifest.context_ceiling;
        k.mount_with(
            Arc::new(StandIn { manifest, budget }),
            standin_spec(name),
            Remount::Keep,
        )
        .expect("mount")
    }

    /// A factory that makes the stand-in `standin_spec` names — the daemon's
    /// job, here in miniature. `weights` renames the weights the re-created
    /// arch claims, which is how a runtime that changed under a node is
    /// simulated: different weights, different `ArchIdentity`, different id.
    fn standin_factory(weights: Option<&'static str>) -> AdapterFactory {
        Arc::new(move |spec: &arch::MountSpec| {
            anyhow::ensure!(spec.kind == "standin", "no arch kind {}", spec.kind);
            let name = spec.config["name"].as_str().unwrap_or("standin");
            let mut manifest = local_named(name, personal());
            if let Some(w) = weights {
                manifest.identity.weights_sha256 = w.into();
            }
            let budget = manifest.context_ceiling;
            Ok(Box::new(StandIn { manifest, budget }) as Box<dyn arch::ArchAdapter>)
        })
    }

    /// A factory that cannot make anything: the engine is gone, Docker is not
    /// running, the binary was uninstalled.
    fn broken_factory() -> AdapterFactory {
        Arc::new(|spec: &arch::MountSpec| anyhow::bail!("no engine for {} here", spec.kind))
    }

    /// Open the store and let the arches come up, as a node does — the two
    /// phases the daemon runs, back to back, because a test has no mutex to
    /// keep them apart. `open_starting` is the same without the second phase,
    /// for the tests that are about the window between them.
    fn open_with(dir: &std::path::Path, factory: AdapterFactory) -> RealKernel {
        let mut k = open_starting(dir, factory);
        k.start_arches_now();
        k
    }

    fn open_starting(dir: &std::path::Path, factory: AdapterFactory) -> RealKernel {
        RealKernel::open_with_factory(dir, KeySource::File(dir.join("master.key")), "n1", factory)
            .unwrap()
    }

    /// Mount the stand-in, drop the kernel, open it again over the same store:
    /// the arch is Ready and the completion comes back from the stand-in. The
    /// bug this pins down is the one Task 2 found — `load` fabricated a
    /// `MockAdapter` for every persisted manifest, so a restart turned every
    /// real arch into the mock without a word to anybody.
    #[test]
    fn a_persisted_arch_is_re_created_at_boot_and_never_replaced_by_a_mock() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };

        let mut k = open_with(d.path(), standin_factory(None));
        assert_eq!(
            k.arch_state(&id),
            Some(ArchState::Ready),
            "re-created at boot"
        );
        let reg = k
            .submit_task(&machine(1), "say something", Label::bottom())
            .unwrap();
        k.infer(&machine(2), &id, Capability::Plan, &reg).unwrap();
        let decisions = k.read_register(&machine(3), &reg).unwrap().decisions;
        assert!(
            decisions
                .iter()
                .any(|d| d.contains("the stand-in answered")),
            "the arch that answered after the restart must be the real one: {decisions:?}"
        );
    }

    /// The factory cannot make it: the arch is listed, with its reason, and
    /// every step that names it fails saying so. Nothing is mocked, and no
    /// `infer` event is written for a call that never left this node.
    #[test]
    fn an_arch_the_factory_cannot_re_create_is_unavailable_and_the_scheduler_refuses_it() {
        use crate::tasks::{StepKind, StepStatus, TaskStatus};
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };

        let mut k = open_with(d.path(), broken_factory());
        match k.arch_state(&id) {
            Some(ArchState::Unavailable(why)) => assert!(why.contains("no engine"), "{why}"),
            other => panic!("an arch that could not be re-created is unavailable, got {other:?}"),
        }
        assert!(
            k.arches().iter().any(|(i, _)| *i == id),
            "an unavailable arch is still listed: it is what an operator has to go and fix"
        );

        let infers = |k: &RealKernel| {
            k.ledger()
                .events()
                .iter()
                .filter(|e| e.kind == "infer")
                .count()
        };
        let before = infers(&k);
        let t = k
            .create_task(
                &machine(1),
                "say something",
                "note",
                Label::bottom(),
                vec![StepKind::Plan {
                    arch_id: id.clone(),
                }],
            )
            .unwrap();
        let err = k.run_task_step(&machine(2), &t.id).unwrap_err();
        assert!(
            err.to_string().starts_with("arch unavailable: "),
            "the scheduler names the state, not a mock's answer: {err}"
        );
        let row = k.task(&machine(3), &t.id).unwrap();
        assert!(matches!(row.status, TaskStatus::Failed));
        match &row.steps[0].status {
            StepStatus::Failed(why) => assert!(why.starts_with("arch unavailable: "), "{why}"),
            other => panic!("the step must be Failed, got {other:?}"),
        }
        assert_eq!(
            infers(&k),
            before,
            "nothing was inferred, so nothing may be recorded as having been"
        );
    }

    /// The runtime under the node changed — a new image, new weights — so the
    /// arch the factory makes is a *different* arch. The stored id becomes
    /// unavailable saying exactly that, and the new one is not mounted in its
    /// place: substituting one model for another behind an id is the thing an
    /// arch id exists to prevent.
    #[test]
    fn an_arch_whose_re_created_manifest_changed_is_unavailable_and_nothing_takes_its_place() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };

        let k = open_with(d.path(), standin_factory(Some("sha256:new-weights")));
        match k.arch_state(&id) {
            Some(ArchState::Unavailable(why)) => {
                assert!(why.starts_with("manifest changed: "), "{why}");
                assert!(why.contains(&id), "the id that was stored: {why}");
            }
            other => panic!("a changed manifest is unavailable, got {other:?}"),
        }
        assert_eq!(
            k.arches().len(),
            1,
            "the arch the factory made is not mounted behind the operator's back: {:?}",
            k.arches().iter().map(|(i, _)| i).collect::<Vec<_>>()
        );
    }

    /// Ruling 13 for the unavailable case: mounting the same manifest again is
    /// how an operator repairs one. It replaces the placeholder and says it
    /// mounted something, because it did — the arch was not usable before.
    #[test]
    fn mounting_an_unavailable_arch_again_re_attaches_it() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };
        let mut k = open_with(d.path(), broken_factory());
        assert!(matches!(k.arch_state(&id), Some(ArchState::Unavailable(_))));

        let outcome = {
            let manifest = local_named("standin", personal());
            let budget = manifest.context_ceiling;
            k.mount_with(
                Arc::new(StandIn { manifest, budget }),
                standin_spec("standin"),
                Remount::Keep,
            )
            .unwrap()
        };
        assert_eq!(outcome.arch_id, id);
        assert!(
            !outcome.already_mounted,
            "what was there was a placeholder, not an arch: this mount mounted one"
        );
        assert!(
            outcome.replaced.is_none(),
            "a placeholder holds no adapter to drop"
        );
        assert_eq!(k.arch_state(&id), Some(ArchState::Ready));
        assert_eq!(k.arches().len(), 1);
    }

    /// A mount spec is durable, and a durable file is the last place a
    /// credential belongs. Neither adapter this node has takes one today; the
    /// guard is here for the kind that will (Ruling 14).
    #[test]
    fn a_mount_spec_refuses_to_carry_anything_shaped_like_a_secret() {
        for named in ["api_key", "token", "secret", "AuthToken", "password"] {
            let err = arch::MountSpec::new("x", serde_json::json!({ named: "sk-live-1" }))
                .expect_err("a spec carrying a credential must be refused");
            assert!(err.to_string().contains(named), "{err}");
        }
        // Nested, too: a config is a tree and a credential can sit anywhere in it.
        assert!(
            arch::MountSpec::new("x", serde_json::json!({ "auth": { "key": "sk-1" } })).is_err()
        );
        // Including through a list, and through an object with innocent keys
        // of its own (Task 1b review, Minor 1): the name over the collection
        // is what makes everything inside it a credential. A list of secrets
        // is a secret.
        assert!(
            arch::MountSpec::new("x", serde_json::json!({ "api_keys": ["sk-live-1"] })).is_err(),
            "a list under a credential-shaped name is a list of credentials"
        );
        assert!(arch::MountSpec::new(
            "x",
            serde_json::json!({ "credentials": { "user": "eric", "value": "sk-1" } })
        )
        .is_err());
        assert!(
            arch::MountSpec::new("x", serde_json::json!({ "outer": [{ "token": "sk-1" }] }))
                .is_err()
        );
        // And the counts every adapter here does carry are not credentials:
        // `max_tokens` is a number, and a number is not a secret.
        arch::MountSpec::new(
            "ollama",
            serde_json::json!({ "model": "gemma3:1b", "max_tokens": 2048, "num_ctx": 8192 }),
        )
        .expect("a spec of plain configuration is not a secret");
    }

    /// An arch whose adapter has not been built yet is `Starting`, and a step
    /// that names one is told to **retry** — not failed (Task 1b review,
    /// Important 1). A container that takes four seconds to start must not
    /// cost a task a human re-submission, so nothing is written down as a
    /// failure and nothing is inferred; the step goes back to Pending and the
    /// task to Queued, and the next `vk task step` runs it.
    #[test]
    fn a_step_that_names_an_arch_still_starting_is_retryable_and_then_runs() {
        use crate::tasks::{StepKind, StepStatus, TaskStatus};
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };

        // Opened, not yet started: this is the window the daemon serves in.
        let mut k = open_starting(d.path(), standin_factory(None));
        assert_eq!(k.arch_state(&id), Some(ArchState::Starting));
        assert_eq!(k.arches_starting(), 1);
        assert!(
            k.arches().iter().any(|(i, _)| *i == id),
            "an arch coming up is listed while it does"
        );

        let infers = |k: &RealKernel| {
            k.ledger()
                .events()
                .iter()
                .filter(|e| e.kind == "infer")
                .count()
        };
        let before = infers(&k);
        let t = k
            .create_task(
                &machine(1),
                "say something",
                "note",
                Label::bottom(),
                vec![StepKind::Plan {
                    arch_id: id.clone(),
                }],
            )
            .unwrap();
        let err = k.run_task_step(&machine(2), &t.id).unwrap_err();
        assert!(
            matches!(err, KernelError::ArchStarting(ref named) if *named == id),
            "{err}"
        );
        assert_eq!(err.to_string(), format!("arch {id} is starting; retry"));
        let row = k.task(&machine(3), &t.id).unwrap();
        assert!(
            matches!(row.status, TaskStatus::Queued),
            "a task waiting on an arch that is coming up is queued, not failed: {:?}",
            row.status
        );
        assert!(
            matches!(row.steps[0].status, StepStatus::Pending),
            "the step is still to run: {:?}",
            row.steps[0].status
        );
        assert_eq!(row.steps[0].started_ms, None);
        assert_eq!(
            infers(&k),
            before,
            "nothing was inferred, so nothing is recorded"
        );

        // The arch comes up, and the very same task runs — no re-submission.
        k.start_arches_now();
        assert_eq!(k.arch_state(&id), Some(ArchState::Ready));
        assert_eq!(k.arches_starting(), 0);
        let done = k.run_task_step(&machine(4), &t.id).unwrap();
        assert!(matches!(done.status, TaskStatus::Done), "{:?}", done.status);
        let decisions = k.read_register(&machine(5), &t.register).unwrap().decisions;
        assert!(
            decisions
                .iter()
                .any(|x| x.contains("the stand-in answered")),
            "{decisions:?}"
        );
    }

    /// Opening a store builds nothing (Task 1b review, Important 1). The whole
    /// reason is timing: a factory that takes seconds must not run before the
    /// daemon's endpoint answers, or `vk boot` times out and kills the node.
    #[test]
    fn opening_a_store_builds_no_adapter() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = {
            let calls = calls.clone();
            let inner = standin_factory(None);
            Arc::new(move |spec: &arch::MountSpec| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                inner(spec)
            }) as AdapterFactory
        };
        let mut k = open_starting(d.path(), counted);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "open must not have built anything: the node is not reachable yet"
        );
        assert_eq!(k.pending_mounts().len(), 1);
        k.start_arches_now();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(k.arch_state(&id), Some(ArchState::Ready));
    }

    /// Important 2: the boot path compares the **whole** manifest, not the
    /// arch id. `arch_id` hashes `ArchIdentity` alone, so an adapter can come
    /// back under the right id carrying a clearance that is not the one on
    /// disk — and the adapter's manifest is what `i2_flow` reads on the very
    /// next prompt. The mount path has always refused this; so does boot now.
    #[test]
    fn an_arch_re_created_with_the_same_identity_but_a_different_manifest_is_unavailable() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };

        // Same `ArchIdentity` — so the same arch id — and a clearance that
        // would quietly widen what this arch may be shown.
        let widening: AdapterFactory = Arc::new(|spec: &arch::MountSpec| {
            let name = spec.config["name"].as_str().unwrap_or("standin");
            let manifest = local_named(
                name,
                Clearance {
                    max_scope: Scope::Holdout,
                    third_party_allowed: true,
                },
            );
            let budget = manifest.context_ceiling;
            Ok(Box::new(StandIn { manifest, budget }) as Box<dyn arch::ArchAdapter>)
        });
        let mut k = open_with(d.path(), widening);

        match k.arch_state(&id) {
            Some(ArchState::Unavailable(why)) => {
                assert!(why.starts_with("manifest changed: "), "{why}");
                assert!(why.contains("clearance"), "it names what differs: {why}");
                assert!(
                    why.contains(&format!("vk umount {id}")),
                    "and how to retire it: {why}"
                );
            }
            other => panic!("a widened clearance must not be adopted, got {other:?}"),
        }
        // The listing still shows the clearance that was stored, never the one
        // that came back.
        assert_eq!(
            k.arch_states()[0].1.clearance,
            personal(),
            "the stored manifest is the one this node still answers with"
        );
        // And `i2_flow` never sees the new clearance, because the arch cannot
        // be called at all.
        let reg = k
            .submit_task(&machine(1), "say something", Label::bottom())
            .unwrap();
        assert!(matches!(
            k.infer(&machine(2), &id, Capability::Plan, &reg),
            Err(KernelError::ArchUnavailable(_))
        ));
    }

    /// Mounting an arch while its adapter is still being built is the operator
    /// getting there first: their adapter is installed, and the one the
    /// startup pass finishes building afterwards is handed back to be thrown
    /// away rather than installed over the top of it.
    #[test]
    fn an_arch_mounted_while_it_was_starting_keeps_the_adapter_the_operator_mounted() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };
        let mut k = open_starting(d.path(), standin_factory(None));
        assert_eq!(k.arch_state(&id), Some(ArchState::Starting));

        // The operator mounts it before the startup pass reaches it.
        let pending = k.pending_mounts();
        assert_eq!(pending.len(), 1);
        let outcome = mount_standin_outcome(&mut k, "standin");
        assert!(!outcome.already_mounted, "a placeholder is not an arch");
        assert_eq!(k.arch_state(&id), Some(ArchState::Ready));
        assert_eq!(k.arches_starting(), 0);

        // The pass finishes and finds it gone from the queue: what it built is
        // handed back, and nothing is installed over the operator's adapter.
        let factory = k.adapter_factory();
        let stale = k.install_arch(&pending[0].0, factory(&pending[0].1));
        assert!(
            stale.is_some(),
            "the adapter nobody wanted comes back to be dropped outside the lock"
        );
        assert_eq!(k.arch_state(&id), Some(ArchState::Ready));
        assert_eq!(k.arches().len(), 1);
    }

    /// Unmounting an arch that is still coming up clears it everywhere, and
    /// what the startup pass built afterwards is not resurrected.
    #[test]
    fn an_arch_unmounted_while_it_was_starting_does_not_come_back() {
        let d = tempfile::tempdir().unwrap();
        let id = {
            let mut k = open_with(d.path(), standin_factory(None));
            mount_standin(&mut k, "standin")
        };
        let mut k = open_starting(d.path(), standin_factory(None));
        let pending = k.pending_mounts();
        assert!(
            k.unmount(&id).unwrap().is_none(),
            "a placeholder holds no adapter"
        );
        assert_eq!(k.arch_state(&id), None);

        let factory = k.adapter_factory();
        drop(k.install_arch(&pending[0].0, factory(&pending[0].1)));
        assert_eq!(k.arch_state(&id), None, "an unmounted arch stays unmounted");
        assert!(k.arches().is_empty());
        // And the store agrees: nothing is left for the next boot to re-create.
        assert!(k
            .store()
            .db
            .list_json::<arch::MountSpec>("mounts")
            .unwrap()
            .is_empty());
    }
}
