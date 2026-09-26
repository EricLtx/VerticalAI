# VerticalAI — what has been built, against the initial specifications (heads-up, 2026-09-26)

Branch `sp1b` at the time of writing (Tasks 0–9 of SP1b complete or in their last fix round; Task 10 and the whole-branch review to come). SP1a is on `master`, tag `sp1a`. Test counts: 388 on Windows, 361 on Linux; CI on Windows, Ubuntu and macOS on every push.

## 1. The system in one paragraph

VerticalAI is a local-first AI operating system for business: a small kernel (`vk`) that owns orchestration, memory (registers), locks, the human ceremony and the record (ledger), and a userland where models, tools and policies live as replaceable parts. Models are "instruction sets" (arches) behind one adapter boundary; a task is a sequence of steps (plan, draft, judge, harness, approve, release) that models execute through the kernel's IR, never by talking to each other directly. Nothing leaves the machine unless a human ceremony authorised the arch that sends it. The ledger is the compliance record. Multi-node P2P, merge-on-reconnect and the self-improvement loops are later phases; the kernel is built so they can be added without changing what exists.

## 2. Capabilities today, mapped to the initial specifications

| Initial specification | Built (where) | Status |
|---|---|---|
| Kernel owns orchestration, registers (memory), locks/semaphores applied to AI | Registers as the task IR; lock tagged union (lease / approval / lock home); STOP grow-only set; scheduler over Plan, Draft, Judge, Harness, Approve, Release (`vk-kernel`) | done, SP1a |
| Kernel state: stable, scalable basis | Storage tiering: SQLite metadata, encrypted content-addressed blobs (per-subject keys, address bound into the AEAD), hash-chained JSONL ledger with a recorded head, single-writer lock, `vk fsck` over five tiers (`vk-store`) | done, SP1a + SP1b |
| Invariants: human path only via ceremony (I1); no read-up, label join on write (I2); no silent discard on merge (I3); autonomy under a liveness lease + STOP (I4); no silent truncation (I4′) | Interceptors on the real kernel, property tests against both kernels, honest context ceilings per arch | done; I3 exercised only single-node until P2P |
| Model as ISA; heterogeneous models; "run any model" | `ArchAdapter` with five kinds: mock, Ollama container (Gemma), Claude via subscription (Claude Code), Anthropic API (US), Bedrock (EU, opt-in); content-addressed manifests with locality, jurisdiction, retention, clearance, cost | done, SP1b |
| Claude Code scheduled by the OS | The confined harness: MCP façade, permission fence + restricted mode, Job Object governor, secret exclusive lease tokens, bounded artefact collection, egress telemetry (`harness.connections`) | done, SP1b; restricted-token launch = Task 10 G |
| Human-in-the-loop as a kernel primitive | Presence ceremony (enrolled node key), passkeys (WebAuthn in the daemon), kernel-minted approval challenges, re-verifiable assertions, STOP/resume | done, SP1b; Windows Hello live check = founder |
| Cybersecurity and privacy by design | Encryption at rest per subject; DACLs on the pipe and the service state directory; user-only SIDs; no proxy for the local arch; cloud mounts need the ceremony; fixed endpoints; no secret ever in a mount spec, log or ledger; TCB statement (`contracts/tcb.md`) | done for single-node; pipe-as-same-user caveat closes with Task 10 G |
| Compliance by design (AI Act, GDPR, NIS 2, CRA) | The ledger as the record (boot, boot.forced, approvals with assertions, infer with measured tokens, harness egress); jurisdiction-tagged arches; usage rows; the gate checklist; signing job | records exist; the formal obligation-to-evidence mapping is SP2+ |
| Easy and costless deployment | Single binaries, no system libraries (vendored D-Bus/OpenSSL), three-OS CI, release artifacts, install script, Windows service under a virtual account | done; VM gate and signing certificate = founder |
| Movable and traceable configuration; simple migration | Persisted mount specs re-created at boot; content-addressed manifests; one state directory; `vk fsck --rebase-head` as the recovery path after a restore | done; export/import of a node = later |
| Self-analysis, self-correction, learning (shadowing, technology watch) | Substrate only: per-step decisions summary, usage rows, ledger | not started (SP2/SP3) |
| P2P nodes, merge-on-reconnect, sovereignty | HLC and causal-head placeholders in every event | not started (SP3/SP4) |
| User-centric, pedagogic | `vk man` renders the contracts; README walkthroughs; the demo script; loopback passkey pages | minimal UI; an app/front is later |

## 3. Every task: goal and contribution

**SP0 (master, tag `sp0`)** — the contracts: schemas for registers, locks, approvals, manifests, ledger events; the stub kernel; property tests. Contribution: everything since implements these types; the schema-drift test keeps them honest.

**SP1a (master, tag `sp1a`)**
- T0 skeletons + test hooks — one kernel interface for stub and real.
- T1 state directory + SQLite — refuses sync folders; metadata tier.
- T2 master key, DEKs, encrypted blobs, shred — privacy at rest.
- T3 ledger segments + store — the record on disk, partial-line recovery.
- T4 real kernel + interceptors — I1–I4′ enforced on real storage.
- T5 property tests on both kernels — invariants as executable claims.
- T6 tasks, scheduler, top, namespace — steps, STOP checks, exports confined.
- T7 IPC, principal derivation, presence — who is speaking, proven.
- T8 `vk` shell + `vkd` — the first usable milestone.
- T9 boot with ledger verification, `vk man` — a node that refuses a broken record.
- Final review + fix wave — single-writer lock, head commitment, AEAD-bound addresses, Unix modes, I2 on task views.

**SP1b (branch `sp1b`)**
- T0 `boot.forced` event, allowed-kinds enforced — forced starts are on the record.
- T2 Claude Code adapter — Claude through the founder's subscription; measured usage and list cost.
- T1 Ollama adapter — Gemma in a governed container; honest half-context; strict adoption; no proxy.
- T1b re-mount at boot — real arches survive restarts; unavailable ones are listed, never mocked.
- T3 Job Object governor — kernel-launched processes die with the kernel and stay under caps.
- T4 MCP façade + confined harness — Claude Code as a fenced worker of the OS.
- T5 passkeys + kernel-minted challenges — the human ceremony as the design wanted it.
- T6 Windows service + DACLs, per-user pipe — the node as an OS service, private state.
- T7 the demo — the milestone: a proposal from a brief by Gemma and Claude in both role orders, approved, released, recorded.
- T2b API arches — customers and the EU case; cloud mounts are human acts.
- T8 shell additions + `vk fsck` + usage rows — "verified" means the whole store; spend is visible.
- T9 signing job, release, install script, gate checklist — from a build to a deployable, gated product.
- **T10 (to come)** — hardening: key zeroisation and DEK associated data; Unix payload modes; clock re-seed, verify cache, usage retention, chunked fsck; loud errors on read surfaces, liveness RPC; process and path checks; docs, the I1 property, the temp-dir leak; **G: restricted-token harness launch** (closes the pipe-as-same-user caveat).
- **Whole-branch review, fix wave, merge decision, tag** — SP1b closes.

## 4. Decisions on record

35 SP1b controller rulings and 8 founder decisions live in the SDD ledger (copied to `docs/superpowers/reviews/` at close-out), on top of SP1a's 31 rulings and the D1–D15 / R1–R8 decision record. Founder decisions to date: the Ollama + Claude-subscription arches; `boot.forced` and `harness.connections` as event kinds; the optional price field; the per-user service pipe; restricted-token launch after the service; no free cloud node yet; Bedrock opt-in.

## 5. Founder items open

Elevated `scripts/spike-6a.ps1` run (gate item 2); Windows Hello passkey check (item 5); the VM gate on a stock Windows 11 image; the signing certificate choice; disk compaction of the Docker and WSL virtual disks; the merge of `sp1b` after the whole-branch review.
