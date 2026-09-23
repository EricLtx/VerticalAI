# VerticalAI — System Design

**Status:** approved in brainstorming, pending founder review of this document
**Date:** 2026-09-22
**Scope:** the whole system (kernel + userland + distribution + federation) at design level, and the ordering of sub-projects. Each sub-project gets its own implementation plan; SP0 is next.
**Inputs:** brainstorming session of 2026-09-22; literature brief (`01_Architectural_Documentation/2026-09-22_userland-self-improvement_literature-brief.md`, 32 sources); adversarial design review (`01_Architectural_Documentation/2026-09-22_design-redteam-review.md`, 40 confirmed findings); founder's pattern sheet (`SoftwareEngineeringPatterns.pdf`).

---

## 1. Vision and positioning

VerticalAI is a **self-improving, peer-to-peer, local-first orchestration runtime for businesses** — from a one-person company to the employees of a large enterprise. The business owns everything it accumulates (its model inventory, its knowledge, its self-built modules); that userland is movable, replicated across the business's own machines with no cloud dependency, and shareable within a trade through a curated federation. Cloud models are optional *arches*, never a dependency.

**Internal analogy (kept):** "Linux for AI". A small kernel inspired by micro-architecture — orchestration (pipeline/scheduler), registers, locks — with everything else in userland. Models are the *instruction set*; the kernel's task-state IR is the common intermediate representation that lets heterogeneous models cooperate.

**External naming (decided):** the product is described as an *orchestration runtime / agent runtime*, not an "AI operating system" — the phrase carries Cyber Resilience Act connotations (Annex III class I) the product does not need, and the identity component is packaged separately for its own CRA classification. The analogy stays in internal documentation.

**The OS approach, kept in the architecture (decided 2026-09-23):** internally the kernel is `vk` and **VerticalAI is the distribution** — kernel + userland + the signed module repository, the way a Linux distribution relates to its kernel. The OS correspondences are explicit and deliberate: syscalls and interceptors (kernel/user split), tasks and harnesses under leases (processes), the scheduler and resource governor (preemption), labels with join-on-write and clearance (mandatory access control), principals and scopes (users and privilege), arches and drivers behind manifests (devices), the ledger (audit log), the TUF-signed federation (package repository). Three OS surfaces are added: a **unified namespace** (`/arches`, `/tasks`, `/artefacts`, `/modules`, `/policies`, `/devices`, `/ledger`) that syscalls address by path; a **shell**, `vk` (`boot`, `ps`, `top`, `stop`, `resume`, `approve`, `ls`, `mount`, `dmesg`, `man`), whose man pages are generated from the contracts; and a **boot sequence** (verify the ledger, load policies, enumerate arches, drivers and enrolled keys, announce presence) of which the SP2 baseline inventory is the userland continuation.

**First trade:** freelancers and SMEs selling services or products, in any craft (design, consulting, content, AI-native platforms…). **First user:** the founder's one-person company (sole-trader mode). Workplace mode (nodes whose user is not the owner) is deferred.

**Commercial model (decided):** commercial first, to build activity; the kernel is open-sourced later to democratise the commercial offering (userland, federation, support). The CRA analysis in §5.6 assumes a commercial product; it is revisited at open-sourcing.

### 1.1 Value ladder

1. **Baseline** — one local workspace inventorying every model and tool the business already uses, with metadata (conversations, usage, licences, master prompts, cost, locality, jurisdiction). Valuable alone; also the register every later decision is measured against.
2. **Shadowing + technology watch** — with a valid lawful basis (consent for a sole trader; see §5.6 for workplaces), the node observes the owner's usage; in parallel the technology watch observes the outside.
3. **Proposals** — once a two-dimensional threshold is crossed (data maturity *and* verifier readiness), the vertical process proposes candidate modules, shown as outcomes.
4. **Promotion and delegation** — the owner promotes, tunes, and chooses which kinds of promotion to auto-approve; later, promotes modules to business and vertical scope.

### 1.2 Non-functional requirements (from the founder)

Cybersecurity and privacy by design; user-centric; organic and autonomous construction *within gates*; pedagogic (show outcomes, not explanations); compliance by design (EU AI Act, GDPR, e-Privacy, NIS 2, CRA, PLD); easy and low-cost deployment; movable and traceable configuration; simple end-to-end migration; latest patterns with an ongoing technology watch.

---

## 2. Decisions log

| # | Decision | Notes |
|---|---|---|
| D1 | Kernel owns only orchestration, registers, locks; everything else is userland | mechanism in kernel, policy in userland |
| D2 | Model = ISA; heterogeneous arches behind manifests; kernel is model-agnostic | any AI system: local LLMs, cloud LLMs, world models, classical NLP |
| D3 | P2P multi-node, one shared userland per business, no cloud dependency | offline-first, merge on reconnect |
| D4 | Locks: tagged union (LEASE / APPROVAL / lock-home) behind one syscall surface | revises the earlier "one lock primitive" after review |
| D5 | Irreversible external actions: per-resource-class lock home + logged human override when unreachable; quorum groups later | |
| D6 | Human principal = hardware-key ceremony; phone is an approval channel, never a lock home, persists nothing | |
| D7 | Storage tiering: Automerge for small metadata only; encrypted content-addressed blobs for payloads; per-node hash-chained ledger | |
| D8 | Learning signals phase 1: shadowing + technology watch; explicit teaching later | |
| D9 | Three value scopes: personal → business → vertical; vertical scope is part of the product | |
| D10 | Vertical federation: curated, founder as explicit root of trust (2-of-3 threshold key), signer admission by legal-entity check, progressive delegation | "no central party" is the end-state goal, not Sybil-safe today |
| D11 | Validators are a separate object class excluded from machine evolution | |
| D12 | Sole-trader mode first; workplace mode deferred until DPIA/LIA/works-council objects exist | |
| D13 | EU-hosted frontier arch as first-class adapter ("your data, your jurisdiction") | Anthropic first-party API has no EU inference geography |
| D14 | Spec-first, then a Rust user-space kernel; SP1 demo gated on isolation and code signing | |
| D15 | Commercial first; kernel open-sourced later | |

---

## 3. Kernel

### 3.1 Responsibilities and refusals

The kernel **owns**: scheduling and orchestration; registers (task-state IR); the lock surface (leases, approvals, lock homes); STOP; principals and identity; the arch layer (manifests, adapters, routing mechanism); storage tiering and the ledger; replication mechanics; the interceptor chain for invariants.

The kernel **refuses to own**: any domain knowledge, skill, business memory, policy, specific model, application driver, channel, or user interface. Anything policy-shaped (who may do what, which data may go where, which actions need a human, merge rules, thresholds) is a userland object the kernel *reads* and *enforces* but never *writes* on its own initiative.

Pattern names used throughout (from the founder's pattern sheet): registers = **Blackboard** (arches are its knowledge sources); lock surface = **Strategized Locking**; invariants = **Interceptors** on the syscall path; manifests = **Extension Interface**; add/remove arches at runtime = **Component Configurator**; scheduler = **Active Object** with **Half-Sync/Half-Async** between channels and execution; ledger = **Kappa** (event log as source of truth); distribution = **AP/BASE** by design.

### 3.2 Registers — the task-state IR

A register set holds the state of one task in a model-agnostic form: goal, constraints, evidence gathered (with origin taint), decisions taken, open questions, artefacts referenced by hash, and **classification labels**. Every hand-off between arches goes through the IR — never through one model's native transcript. Rationale: provider-side state (e.g. Anthropic thinking blocks) is bound to the producing model and dropped by any other; kernel-owned state is the only thing that makes model swapping mid-task possible.

Rules:
- **Lowering/raising** to and from an arch is done by the adapter against the arch's manifest; the kernel logs the projection.
- **I4′ — no silent truncation:** every adapter reports its actually loaded context and a token count; `infer()` refuses an over-budget lowering or applies a *logged, structural* projection (never a silent front-truncation).
- **Information-flow labelling:** any object written by a task inherits the join of the classifications of every register the task read. A candidate born from personal-scope traces is personal-scope until explicitly declassified through a measurable gate (§4.3).
- Secrets never enter registers.

### 3.3 Scheduler and resource governor

The scheduler decides which task, module or harness runs, on which arch, with which budget. Inputs: lease contention, autonomy liveness (§3.5), resource governor state, arch manifests (cost, latency, locality, clearance), and policy.

The governor reserves a configurable share of host resources — more when the user is idle — and is implemented as OS containment of kernel-launched inference processes (Job Objects/AppContainer on Windows, cgroups on Linux, sandbox-exec on macOS). Only kernel-launched engines are *governed*; an externally running Ollama is usable but flagged **ungoverned**. Rehearsals (§4.3) are low-priority background jobs and may be scheduled onto a headless peer.

### 3.4 Lock surface — tagged union

One syscall surface, three kinds:

| Kind | Semantics | Use |
|---|---|---|
| **LEASE(resource, ttl, fence)** | Work-in-progress mutual exclusion. AP semantics: exclusive within the connected partition; expires on TTL; carries a fence number from the resource's lock home. | Editing an artefact, running a module against a resource; also a scheduler input (contention frees budget) |
| **APPROVAL(subject_hash, kind ∈ {test, audit, human}, signature)** | An immutable, signed, mergeable record. "Promotion" means *a valid approval exists*, never *someone holds a lock*. | Mutation gating: module promotion, policy change, curation grants, consequential actions |
| **Lock home** | Per resource class, a designated issuer of fences (default: the creating node; business scope may configure a 1/3/5-node majority group later). Integration drivers carry the fence with an idempotency key and reject stale fences. | Irreversible external actions on shared resources (send, pay, publish, delete) |

**Partition rule (D5):** if the lock home is unreachable, an irreversible action either waits or proceeds under an explicit, logged **human override** ("accept duplicate risk"). The human path therefore stays reachable offline (I1) without pretending exclusivity exists. Partition epochs are diagnostic only.

Merge rules reconcile *state*; they never reconcile *side effects*. Policy per resource class declares reversibility.

### 3.5 STOP and autonomy liveness

- **STOP** is a kernel primitive: a grow-only set of signed STOP events (scope, issuer, HLC, causal heads) stored outside the policy document. RESUME is valid only if it causally descends from and cites the STOP it lifts. "Stopped" is a pure function of causal state. STOP requires *presence* only (any enrolled human device); it needs no verification ceremony.
- **I4 — autonomy liveness lease:** machine principals may run non-human-initiated automations only while a liveness lease, renewed by any human-capable node of the business, is unexpired (TTL set per autonomy profile). A node cut off from every human stops automating when the lease lapses. Grants and expiries are ledger events.

### 3.6 Principals and identity (I1)

No syscall accepts a caller-asserted "holder". The kernel derives the principal from the authenticated channel (lease token, node identity, harness lease).

**Human principal:** a challenge-response ceremony — the kernel issues `H(resource, action digest, nonce, expiry)`; a hardware-backed, user-verified key (Windows Hello/TPM, Secure Enclave/StrongBox on the phone) signs it. Human approvals are short-lived and bound to one action digest. Autonomy profiles may require two devices for high-impact kinds.

**Devices:** enrolment and revocation happen under the business admin key on a full node (invitation ticket + out-of-band code + admin approval). The phone bootstrap protocol is specified in SP0. The phone thin node persists no registers and no secrets.

**Invariant I1 (restated):** an approval of kind `human` can only be produced by a human ceremony; no machine principal can produce or forge it; and the human path (STOP, override, approval) is always reachable — no queue, budget or partition can starve it.

### 3.7 Arches and manifests

An **arch** is any AI system behind an adapter, described by a signed **manifest**:

- `capabilities` ⊆ {generate, embed, predict, perceive, plan, judge, …}; I/O types
- `locality` ∈ {local, on-prem, peer, cloud}; `jurisdiction`; `retention`; `provider_terms_ref`
- `cost`, `latency`, `context_ceiling`, `determinism`
- **identity tuple** (content-addressed): weights hash, engine + version, backend, quantisation, KV-cache type, threads, batch, sampling params, seed — any change is a Component Configurator event and a new arch id. A peer's network-reached arch is a distinct arch id.
- `clearance`: effective clearance = min(manifest clearance, hosting node trust class, channel class). Manifests are signed by the business admin key and countersigned by the hosting node; node trust class is set at enrolment, never from discovery.

**Invariant I2 (restated):** no object whose classification exceeds a principal's or arch's effective clearance is ever *projected into its reachable set* — not sent, not mounted, not readable. Enforced by: the daemon running under a dedicated service account with the store ACL'd to it; secrets in the OS keyring under that account; harnesses confined (Job Object/AppContainer, landlock, sandbox-exec) with network only through the kernel proxy; and a **materialised per-lease workspace** containing only what the harness may see. SaaS assistants embedded inside third-party applications are flagged as *unmediated channels* in the inventory.

**Learning modes** per artefact class (policy, surfaced in the UI): `cloud-assisted` (frontier arches may receive registers within clearance), `derived-only` (frontier arches receive only outputs of the declassification gate; the gate is an interceptor on `infer()` as well as `export()`), `local-only` (no machine authoring; memory, search, explicit teaching and imported modules remain).

**EU-hosted frontier arch (D13):** Bedrock/Vertex EU regions or an EU provider are first-class adapters with `jurisdiction: EU`, so the business can choose "your data, your jurisdiction" without leaving the product.

Verified provider facts (2026-09): Anthropic first-party `inference_geo` accepts only `us`/`global`; Fable 5.1 requires 30-day retention; thinking blocks are bound to the producing model.

### 3.8 Nodes

A node is a **user-space kernel daemon** running natively on Windows (primary end-user OS), Linux and macOS; the host OS is treated as hardware (CPU/GPU/RAM, filesystem, network, and applications as devices). Node classes differ by manifest only:

| Class | Hosts arches | Drives apps | Role |
|---|---|---|---|
| **Full** | yes | yes | the owner's laptop/desktop |
| **Headless** | yes | no | server; also relay/discovery role for the business or trade |
| **Thin** | no | no | phone: identity, channel, STOP, human approvals; persists nothing |

Windows packaging (SP1 gate): daemon as a Windows service under a virtual service account; secrets under DPAPI; every shipped binary code-signed (including updater and inference runtimes); MSIX per-user install verified on stock Windows 11 Home with Smart App Control on; node state under `%LOCALAPPDATA%`, refusing OneDrive/Dropbox-synced paths.

### 3.9 Storage tiering and the ledger (D7)

- **Automerge** only for small per-scope metadata documents: IDs, classification tags, counters, provenance hashes, policies, register heads. Document rotation for thin nodes.
- **Payloads** (knowledge-entry text, artefacts, candidate bodies, shadow traces, raw imports) are envelope-encrypted, content-addressed blobs keyed per data subject/entry; data-encryption keys are never escrowed off the business. **Erasure** = a signed shred event (merges like STOP) + tombstone; the ciphertext becomes unreadable everywhere. Raw imports and shadow traces are never replicated.
- **Ledger:** per-node, hash-chained, segmented log with a retention class per event type, committing to ciphertext hashes. This is the Art. 12-style record when high-risk obligations apply, and the primary learning signal (§4.3). Three stamps per event: wall-clock + clock-quality flag, HLC, causal heads. A receive guard rejects physical timestamps beyond a configurable skew, emits `clock_anomaly` and suspends that peer's autonomy lease. Lifecycle derivations are pure functions of event-intrinsic stamps.
- **Cold pool** (candidate modules) is node-local and ephemeral.

**Invariant I3 (restated):** a merge never silently discards a write; every conflict is resolved by a declared rule or surfaced, and the resolution is logged. Logged shred events are the one sanctioned deletion.

### 3.10 Distribution

One shared userland per business; nodes replicate the metadata documents and fetch blobs on demand by hash within clearance. Discovery is LAN-first (mDNS); WAN uses a business-hosted or trade-hosted relay that sees ciphertext only. **Sovereignty restated:** no third party ever holds plaintext or performs inference; connectivity may use untrusted, self-hostable relays.

Partition behaviour: keep working, merge on reconnect, with merge rules per resource class; policies merge most-restrictive-wins (deny > defer > ask > allow); STOP, shred and human override events win merges; "current Hot version" is a set resolved most-restrictive, never a scalar last-writer-wins.

### 3.11 Syscall surface (first cut)

`submit_task`, `infer(arch, capability)`, `read_register` / `write_register`, `lease(resource, ttl)`, `approve(subject_hash, kind)`, `stop(scope)` / `resume(stop_hash)`, `emit_event`, `log`, `propose_candidate`, `promote(module)` — requires approvals per policy — `export(module, scope)` / `import(module)` — require gate verdicts per policy.

Interceptors on this path enforce I1–I4′ (decidable invariants only). The Annex III classifier and the declassification/anonymisation gate are **userland gate policies** registered through the Extension Interface; `promote`, `export` and `import` require a signed GATE-VERDICT record of each kind the applicable policy lists.

---

## 4. Userland

### 4.1 Object model

Six families, all versioned, all with a classification label and a provenance manifest (content hash, lineage, signer, arch compatibility as identity tuples, cost/applicability contract, origin taint summary):

| Object | Content | Notes |
|---|---|---|
| **Arch inventory** | every model/tool with metadata; credential *references* only (fingerprint + holding node) | `infer()` to a cloud arch routes to a node holding the credential |
| **Knowledge** | itemised entries with stable IDs and helpful/harmful counters; never prose blobs | ACE-style; mergeable as G-set + PN-counters + tombstones |
| **Modules** | *skill* (capability + tools + description), *process* (skills composed with checkpoints, carrying a CARS-style autonomy profile), *automation* (process bound to a trigger); compact directories; **no scripts and no validators in anything machine-evolved** | |
| **Validators** | structural checks per artefact type, with anchor suites; authored by humans or by a frontier arch under a human approval; community validators need two signers | excluded from machine evolution (D11) |
| **Policies** | consent/lawful-basis records, classification rules, autonomy profiles, merge rules, thresholds, learning modes, delegations, driver allow-lists | read-only for machine principals; most-restrictive-wins |
| **Integrations** | drivers exposing artefacts and events, each with a deny-by-default allow-list contract | |
| **Ledger** | see §3.9 | |

### 4.2 Learning signals (phase 1)

- **Shadowing** — drivers capture, within a user-chosen allow-list (folders, domains, app IDs): artefact created/modified with diff, tool used, duration. No keystrokes, screenshots or page text outside the allow-list. An at-ingest classifier drops special-category data. Every register/trace carries an **origin taint** ∈ {owner-authored, owner-shipped, third-party-inbound, web}; a mandatory **data class** {own, third-party-mandated, unknown} is assigned by source, `unknown` treated as third-party. Third-party-class material is verified only on arches with locality ∈ {local, on-prem} unless the controller's documented instructions allow otherwise (GDPR Art. 28).
- **Technology watch** — external candidates (new arch, tool, regulation) enter the same pipeline with taint `web`; they have no ground truth to rehearse against, so they can only reach Hot through human approval.
- Explicit teaching is a later phase.

Shadowing traces are personal-scope and non-exportable; only derived, declassified candidates move.

### 4.3 The vertical process

**Threshold** — two-dimensional: data *maturity* (volume, artefact-type diversity, lawful-basis coverage) **and** *verifier readiness* per artefact type (at least one non-LLM validator with an anchor suite, or a ledger sample of N human accept/reject decisions). VerticalAI sets a floor at which the process fires once automatically for ready artefact types; the owner then owns and adjusts the threshold and is signalled before later runs.

**Lifecycle — Cold → Warm → Hot**, gated at the front:

- **Cold:** any arch may write a candidate; the pool is node-local and ephemeral; an origin lint rejects any candidate body containing a span (URL, IBAN, e-mail, entity) that came from a tainted source. Most candidates are discarded — by design.
- **Warm — rehearsal:** in a sandbox, against a **frozen retrieval snapshot with a temporal cut-off strictly before each held-out artefact's creation**; the snapshot hash goes into the test record. A **locked hold-out set** carries an I2-style `holdout` clearance the loop can never read. Verifiers: (a) the delta between what the module would have produced and what the human actually shipped — reject-on-worse, never the sole admission signal; (b) validators (§4.1) with anchor suites; (c) one semantic check by a frontier arch, subject to the artefact's learning mode. Success-only telemetry is never used; failures with diagnostics are.
- **Hot — promotion:** requires the approvals the autonomy profile demands (human by default). The signed test record binds the module to a **pool epoch** (hash of the active Hot set + validator versions). After a merge changes the epoch, modules promoted under another epoch become **Hot-pending** — excluded from retrieval until a cheap re-rehearsal passes. Modules tagged `decision_about_person` can never be auto-approved (GDPR Art. 22).
- **Monitor / retire:** delta and outcome trends per module (outcomes such as accepted/paid/replied are used to *retire*, not to *admit*); retirement is a tombstone.

**Roles by arch:** local small arches execute modules and consume the gated pool; authoring, reflection and judging are routed to frontier arches under the learning mode and clearance — or are off, in `local-only` mode. Stated plainly in the product.

**Pedagogy:** every explanation is paired with an outcome; the UI shows what changed in the owner's real artefacts, not why the model thinks so.

### 4.4 Scopes and federation

**Scopes:** personal (a user's nodes) → business (replicated across the business) → vertical (shared within a trade). Each transition is a promotion with the same gates; personal-scope traces never leave; exported modules pass declassification and carry no scripts.

**Federation trust (D10):** TUF-style roles from SP0 — an offline **root** under a 2-of-3 threshold (founder + independent custodian + sealed recovery share); online **targets** signers with short-lived delegations; a **timestamp/freshness** role with nodes failing closed when stale; revocations are signed, propagate, and win merges. Signer admission is anchored to a one-time legal-entity check, not usage evidence. Progressive delegation to businesses with proven activity is a *policy* change under the same roles; the "no central party" end state is a goal, revisited when Sybil-resistant admission exists.

**Declassification/anonymisation gate:** a deterministic, measurable interceptor on `export()` and, in `derived-only` mode, on `infer()`; its test suite (inference, exfiltration, regurgitation, inversion, reconstruction) is documented as the Recital 26 "means reasonably likely" assessment.

### 4.5 User surface

Seven panels, each a view over userland objects: **Baseline** (inventory/register; classification set here), **Lawful basis & threshold** (what is shadowed per app/data class; consent or LIA/DPIA record; maturity and readiness gauges; threshold with floor; next-run signal), **Proposals** (Warm candidates as outcomes with diff previews; promote / tune / reject / never again), **Modules** (Hot, Hot-pending, trends, provenance, arch, autonomy profile, retire), **Delegation** (auto-approval per module kind, always revocable; the red **STOP**), **Arch routing** (clearance and learning mode per data class; cost and locality shown before the request), **Federation** (shared out, imported, trusted signers, revocations). Channels (chat, CLI, phone) are ways into `submit_task`; their design is deferred.

**SP2 addition (from review):** a browser-extension capture driver that records conversations from ChatGPT/Claude/Gemini/Midjourney web apps under the same lawful-basis record, and a receipts importer (IMAP or drop-folder of invoices) for licences, cost and renewals — so the baseline has real content in week one.

### 4.6 Compliance mapping (corrected after review)

| Obligation | Applies | Mechanism |
|---|---|---|
| GDPR lawful basis for shadowing | now | Sole trader: consent. Workplace: Art. 6(1)(f) legitimate interest + Art. 88 national rules + mandatory DPIA (Art. 35(3)(a)); works-council/CSE attestation object (FR: L2312-38). Employee consent is *not* a lawful basis. |
| e-Privacy Art. 5(3) | now | Browser/app drivers need the *device user's* consent; sole-trader self-install fits the requested-service exception |
| GDPR Art. 28 | now | Client artefacts are processed as processor; data class `third-party-mandated` restricts learning to local/on-prem arches absent documented instructions |
| GDPR Art. 17 erasure | now | Per-subject keys + signed shred events (§3.9) |
| GDPR Art. 22 | now | `decision_about_person` modules cannot be auto-approved; ledger entry is the intervention record |
| AI Act Art. 50 transparency | 2 Aug 2026 | Output-marking gate for every `generate` arch: C2PA/IPTC for media, provenance record for text; interaction disclosure in channels |
| AI Act Art. 25(2) | now | Instructions for use + machine-unwritable policies declare the system "is not to be changed into a high-risk AI system"; Annex III classifier runs at `propose_candidate`, `promote`, `import` **and on the shadowing configuration itself** (Annex III 4(b)); Art. 6(3) derogation documented where used |
| AI Act Arts. 9, 12, 14, 26, 43(4) / Art. 3(23) | conditional, high-risk only; Annex III from 2 Dec 2027 (Reg. 2026/1744) | Ledger, STOP + liveness lease + hardware-key approvals, pre-determined-change envelope per trade. The design prevents high-risk use by default; these mechanisms exist so a deployer who chooses a high-risk purpose can comply |
| CRA (Reg. 2024/2847) | reporting from 11 Sep 2026; main application 11 Dec 2027 | Integrity of programs/config against unauthorised modification ↔ approval-gated, logged self-modification; SBOM incl. weights and runtimes; default-on security updates with opt-out; 24h/72h/14d reporting via ENISA (opt-in security-event telemetry); 5-year support; **identity/key/signer component packaged separately** (class I "identity management") |
| Product Liability Directive 2024/2853 | 9 Dec 2026 | Software is a product; signer and vendor liability documented in federation terms |
| NIS 2 | customer-side | Logs, access control and incident evidence supplied to essential/important entities |

All citations are to be re-verified against the consolidated Official Journal text before any external publication.

---

## 5. Implementation approach

- **Spec-first:** language-neutral contracts (JSON Schema / protobuf) for the syscall surface, IR, manifests, ledger events, module and validator directory formats, gate-verdict records, TUF roles, phone bootstrap. These are what harnesses (e.g. Claude Code via MCP) and future ports program against.
- **Kernel in Rust:** single static binary per platform; Automerge (narrowed as §3.9); iroh or libp2p for P2P; llama-server / llama.cpp via FFI as the primary *governed* local adapter (explicit device, threads, context, batch, prompt-cache control); Ollama as a convenience adapter marked ungoverned unless kernel-launched with pinned environment; Anthropic, Google, OpenAI and an EU-hosted frontier adapter; all inference out-of-process.
- **Harnesses:** Claude Code runs as a confined userland process under a lease with a materialised workspace; its MCP connection to the kernel is the only channel; managed PreToolUse hooks with `allowManagedHooksOnly`.
- **Trusted computing base statement** for any harness that cannot be confined on a platform: documented, surfaced in the inventory as an unmediated channel.
- **Testing:** invariants I1–I4′ as property tests over generated syscall sequences and partition schedules; merge rules as CRDT convergence tests; adapters as contract tests against manifests; rehearsal isolation as leak tests against the hold-out tag.

---

## 6. Sub-projects

| | Delivers | Demo / exit criterion |
|---|---|---|
| **SP0 — Contracts & scaffold** | Syscall/IR/manifest/ledger/module/validator/gate-verdict schemas; lock tagged-union and STOP semantics; information-flow labelling; hardware-key ceremony and phone bootstrap protocol; storage tiering and retention classes; TUF role definitions; TCB statement; jurisdiction/retention manifest fields; repo scaffold, `.gitignore`, CI, code-signing pipeline | Schemas reviewed; property-test harness runs against a stub kernel |
| **SP1 — Single-node kernel (Rust)** | Scheduler + governor, registers, lease/approval, STOP + liveness, ledger, service-account daemon, keyring secrets, adapters (llama-server, Ollama, Anthropic, EU-hosted), Claude Code confined lease via MCP, CLI channel | **Gated on** service isolation, harness confinement and code signing. Demo: Gemma 4 + Claude Code co-working on a stock Windows 11 laptop, I1–I4′ property tests green |
| **SP2 — Baseline userland** | Browser-extension capture driver, receipts importer, itemised knowledge store, classification and data-class assignment, policies, local web UI v0 (Baseline, Lawful basis, Arch routing) | One workspace holding a freelancer's real conversations, licences and costs |
| **SP3 — Vertical process v1** | Allow-listed shadowing drivers (files, browser, a few apps), origin taint, threshold (maturity + readiness), Cold/Warm/Hot with snapshot cut-off and hold-out, validators class, proposals panel, tech-watch v0, output-marking gate | First self-built module promoted by its owner under a hardware-key approval |
| **SP4 — P2P** | Node identity and enrolment, discovery (LAN-first) and relay role, metadata replication + blob fetch, merge rules, lock homes and fences, STOP propagation, liveness leases, Hot-pending re-rehearsal, phone thin node | Two laptops + a phone, one business, partition test suite green |
| **SP5 — Federation** | TUF roles and threshold root, declassification gate with test suite, signer admission, import/export, revocation, CRA/PLD artefacts (SBOM, test records, terms) | First module shared into a trade under the founder's signature |

Cross-cutting from SP0: compliance substrate, sandboxed rehearsals, property tests, technology watch on dependencies.

---

## 7. Deferred and open

- Channels (chat/CLI/phone UX), explicit teaching, workplace mode objects (DPIA/LIA/CSE), quorum lock homes, the "no central party" admission mechanism, JEPA-style and classical-NLP adapters (manifests allow them; no adapter planned before SP3), on-device fine-tuning (no evidence it helps at 4–9B from one business's data), the technology-watch loop beyond candidate intake.
- Statistical design of the delta verifier (multiplicity at the Cold gate) — to be specified in SP3's plan with a locked hold-out and a false-discovery control.

---

## 8. References

- `01_Architectural_Documentation/2026-09-22_userland-self-improvement_literature-brief.md` — 32-source brief and bibliography
- `01_Architectural_Documentation/2026-09-22_design-redteam-review.md` — 40 confirmed findings, amendments, legal corrections
- `01_Architectural_Documentation/SoftwareEngineeringPatterns.pdf` — pattern vocabulary
- Prior art: AIOS (COLM 2025), LiteCUA, AgentOS, Model-Native Computing Architecture; SkillsBench, VaG, ACE, SkillsVote, SkillForge, FederatedSkill, Keyhive, AGNTCY ADS (all in the brief)
