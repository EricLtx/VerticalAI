# SP1a whole-branch review (sp1-kernel 9da7859..2e546dc)

Copied verbatim from the SDD workspace on 2026-09-24 after the fix wave (2e546dc) and its re-review. Reviewer: Claude Fable 5.1; re-reviewer: Claude Opus 5.

# SP1a whole-branch review — `sp1-kernel` (9da7859..a226059)

Reviewer: senior code review (systems / security / Rust). Single reviewer, no subagents.
Scope: the 23 commits of SP1a as one system — cross-task consistency, invariants end to end through the pipe, storage security, process/platform, tests, plan alignment.
Rulings 1–29 and the deferred minors in `final-review-context.md` were taken as settled and are not re-reported; where one is escalated it says so.

## How the review was done

Seven passes over the head state of the worktree (line numbers below are head-state lines):

1. `vk-store` — `paths.rs`, `db.rs`, `keys.rs`, `blobs.rs`, `ledger_fs.rs`, `lib.rs`.
2. `vk-contracts` — the SP0 types the real kernel builds on (`ledger`, `principal`, `stop`, `locks`, `storage`, `labels`, `register`, `syscalls`, `interceptors`, `testing`) and the branch's diff to them.
3. `vk-kernel` — `lib.rs`, `tasks.rs`, `arch.rs`, `presence.rs`, `ns.rs`.
4. `vk-ipc` — `lib.rs`, `server.rs`, `transport.rs`, `client.rs`, `tests/roundtrip.rs`.
5. `vk-cli` + `vkd` — `main.rs`, `render.rs`, `man.rs`, `tests/smoke.rs`, `vkd/src/main.rs`.
6. `vk-props` (three generic property tests), the `vk-stub` diff, README, CI/release workflows, workspace manifests, the plan's changed line.
7. Build and `cargo test --workspace --no-fail-fast` on Windows (all green, exit 0), then two empirical reproductions in throwaway state directories on private pipe endpoints with file-backed keys: (a) two `vkd` on one state directory, (b) deletion of the ledger tail. Both are described under the findings they confirm. The temp directories were removed afterwards.

---

## Strengths

The branch is a serious piece of systems work and most of the hard things are done right. Naming them so the fixes below are read in proportion.

- **Fail-closed ordering is applied consistently, not just claimed.** Ledger before the durable mutation on every authority-granting path (`approve`, `resume`, `promote`, `task.step`, `artefact.released` — `vk-kernel/src/lib.rs:671-681`, `704-729`, `776-783`; `tasks.rs:334-339`, `415-427`); STOP written to disk before it enters memory (`lib.rs:693-699`); a refused `resume` leaves no row that a later STOP could inherit (`lib.rs:710-712`, tested at `lib.rs:1222-1250`); a refused release logs nothing and creates nothing (`tasks.rs:401-427`, tested at `tasks.rs:757-791`). Ruling 8 (no swallowed store writes) is honoured on every syscall path I traced.
- **The presence ceremony is tight.** The nonce is removed from the map before anything else is looked at, on every method, and a proof on a method that takes none is refused *after* being spent (`vk-ipc/src/server.rs:300-314`); presence and approval signatures live in different domains (`lib.rs:37-51` of vk-ipc vs `Challenge::digest`); enrolment over the pipe is restricted to the node's own key and a different key for the same id is refused as an I1 matter (`server.rs:540-554`, `vk-kernel/src/lib.rs:361-375`). `tests/roundtrip.rs` exercises replay, impostor-burn, expiry, wrong-method spend, approver-vs-presence mismatch and `kind != human` over a real endpoint — that is the right level to test I1 at.
- **Path confinement is unrepresentable rather than filtered.** `release_dest` whitelists path components (`tasks.rs:202-214`), `release_file_name` re-validates the composed name on the way out (`tasks.rs:225-243`), artefact kinds are validated at the only door in (`lib.rs:41-54`), blob hashes are validated before any path is built (`blobs.rs:173-183`), key ids are hex-encoded before becoming file names. The traversal tests (`tasks.rs:793-835`, `lib.rs:1453-1491`) check the filesystem, not just the return value.
- **Ledger recovery is narrow and honest.** Exactly one damage class is repaired (unterminated last line of the newest segment, truncated back so a later append cannot land mid-line), anything else is corruption and fails `open` with segment and line (`ledger_fs.rs:28-86`). The boot report commits its own hash into the `boot` event so the record says what the node found (`lib.rs:226-238`).
- **Leases and fences survive restarts correctly.** Fences are persisted separately from leases so a resource whose leases all expired still cannot see a fence reissued; replay restores exactly one live row per (resource, partition) and deletes superseded rows (`lib.rs:157-204`, `631-669`), with reopen tests that anchor to the wall clock deliberately.
- **I4′ is a real projection.** Structural, priority-ordered, marker-reserving, refuses when ROLE+GOAL do not fit, and `tokens_in` is the measured count of what was sent (`arch.rs:143-188`, `lib.rs:596-613`). The property test accepts the refusal only when nothing was logged (`vk-props/tests/i4_liveness_and_truncation.rs:81-129`).
- **The CLI's process handling is expert.** `vk boot` clears the inherit flag on its own stdio before spawning so `$(vk boot --json)` cannot hang on a pipe the daemon holds (`vk-cli/src/main.rs:478-505`), detaches with `DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP` / `process_group(0)`, quotes the daemon's own last words on refusal instead of timing out, kills a silent child, and refuses to "already serve" a different state directory on the same endpoint. `vk man` embeds the 19 schemas with a bidirectional drift test against `contracts/schemas/`.
- **The tests are real.** `smoke.rs` drives the real `vk` and `vkd` binaries as separate processes; `roundtrip.rs` runs the real kernel behind a real endpoint; nearly every kernel test reopens the store; tamper tests rewrite bytes on disk; property tests run against both kernels through one generic body. The stub diff is purely mechanical (trait impl), so the SP0 reference did not drift.
- **The Unix branch is not an afterthought.** Socket 0600 inside a 0700 directory that must already be private, live-vs-stale socket detection, regular-file-at-endpoint refusal, `EBADF/EINVAL` vs transient accept errors (`transport.rs:178-246`).

---

## Issues

### Critical

#### C1. Two daemons on one state directory corrupt the ledger chain and can collide on ids — no single-writer lock, and `boot()` appends before the endpoint is bound

- **Where:** `crates/vkd/src/main.rs:59-107` (open → enroll → `boot()` → `serve` → `bind`), `crates/vk-store/src/lib.rs:19-27` (no lock taken), `crates/vk-kernel/src/lib.rs:474-481` (`counter` loaded once per process), `crates/vk-cli/src/main.rs:573-597` (`vk boot` checks only the endpoint, not the state directory).
- **What is wrong:** Nothing prevents a second `vkd` from opening a state directory another daemon is serving. Even when the second one is refused the endpoint, it has already appended its `boot` event. **Reproduced** in a temp directory on a private pipe: daemon A serving (2 events); a second `vkd` with the same flags exits with `Accès refusé (os error 5)` on the pipe — but its `boot` is on disk at seq 2; A then appends `arch.mounted`, also at seq 2; the next start refuses: *"the ledger chain in … does not verify (4 events): refusing to serve"*, and appends its own `boot` (seq 4) onto the broken record. On-disk segment afterwards: `0 device.enrolled, 1 boot, 2 boot, 2 arch.mounted, 4 boot`. With a different endpoint (`vk boot --endpoint other --state-dir same`, or a plain `vkd --endpoint other`) both daemons *serve* the same store: each loads `counter` once, so both mint `reg-node-1-N`/`task-node-1-N`/`stop-node-1-N` for the same N and overwrite each other's rows.
- **Why it matters:** "Is it running? let me start it again" is the most ordinary operator mistake there is, and here it bricks the next boot (recovery is `--force`, after which the chain is permanently marked as not holding) and, in the two-endpoint variant, silently loses registers. The ledger is the spec's Art. 12-style record; a design that lets a duplicate start make it unverifiable is not merge-ready for the daemon that SP1b will wrap in a Windows service (service restarts are exactly this scenario). The plan is silent on single-instance; a reasonable person expects a second start to fail cleanly.
- **Fix:** (1) Take an exclusive lock on `<state_dir>/vk.lock` in `Store::open` (Windows: open with `share_mode(0)`; Unix: `flock(LOCK_EX|LOCK_NB)` — `fs4`/`fd-lock` do both) and refuse with "state directory … is already open by another vkd" *before* anything is written. (2) In `vkd`, bind the endpoint before `boot()` so a refused bind never touches the record (closes the `vk boot` probe race as well). (3) Test: two `vkd` on one dir → the second exits non-zero with no new ledger line; then the survivor's next append still verifies.

### Important

#### I1. `LedgerFs::append` mutates the in-memory chain before the disk write succeeds

- **Where:** `crates/vk-store/src/ledger_fs.rs:104-125`; `Ledger::append` pushes at `crates/vk-contracts/src/ledger.rs:164`.
- **What is wrong:** The event is pushed into `self.chain` and only then written and synced. If the write fails (disk full, permission, a segment file made read-only), the caller gets `KernelError::Store` (correct) but the phantom event stays in memory; the next successful append computes `seq`/`prev_hash` from the phantom, so the file now has a gap in the chain. On restart the chain breaks at that point and boot refuses. `verify()`/`tail()`/`vk ledger verify` in the live process all report the phantom.
- **Why it matters:** A transient IO error becomes a permanently unverifiable record — the same outcome as tampering, with no tampering. Ruling 8 made store failures loud; this makes the ledger *lie* after one.
- **Fix:** Build the event (compute hash from `events.last()` without pushing), write + `sync_data`, then push; or push and pop on error. Add a test that makes the segment unwritable, sees the error, then appends successfully and reopens with `verify() == true`.

#### I2. Deleting the tail of the ledger is invisible to `verify` and to boot — the record and the state silently diverge

- **Where:** `crates/vk-contracts/src/ledger.rs:179-202` (`verify_chain` checks links and recomputation only); `crates/vk-store/src/ledger_fs.rs:28-86` (`open` has no expected head); `crates/vk-kernel/src/lib.rs:226-238` (`boot` trusts `verify()`).
- **What is wrong:** A hash chain proves nothing about its length. **Reproduced:** after `vk mount mock` and `vk stop`, I removed the last two lines of `seg-000000.jsonl`; the daemon booted, `vk ledger verify` said *"3 events, chain verifies"*, `vk status` said *"chain verified … stopped node"* — the STOP still holds (SQLite row) but the record no longer contains it, nor the mount. A rewritten line is caught (`tampering_is_detected`); a removed tail is not, and the removed tail is precisely where a STOP, an approval or a release lives.
- **Why it matters:** Spec §3.9 positions the ledger as the compliance record and the primary learning signal; a record that can be shortened without a trace is neither. The asymmetry (rewrite detected, truncation not) will surprise anyone who reads "chain verified".
- **Fix:** Persist the head — `(len, last_hash)` — in `kv` (same process, same store; cheap) on every append, and in the boot sequence compare it with what the segments replay to; report `ledger_ok=false` (or a distinct `ledger_truncated`) on mismatch and let `--force` bypass as today. Optionally mirror the head into the keyring for an out-of-store witness. Test: delete the tail, expect refusal.

#### I3. SQLite `synchronous=NORMAL` makes STOP/resume/approval rows non-durable across power loss while the ledger is fsynced per event

- **Where:** `crates/vk-store/src/db.rs:28-29`; `stop()` at `crates/vk-kernel/src/lib.rs:693-699`.
- **What is wrong:** In WAL mode with `synchronous=NORMAL`, a committed transaction is durable against a process crash but *not* against power loss or an OS crash (the WAL is synced at checkpoints, not per commit). The ledger append does `sync_data()` per event. So after a power cut immediately following `vk stop`, the record can contain the `stop` event while the `stops` row is gone: the node comes back *not* stopped — "a STOP that this process believes in but that no restart would find is the one failure a STOP may never have" (the code's own words). Same for `resumes`, `approvals`, `leases`.
- **Why it matters:** STOP is the human path (I1/I4); its durability is a correctness claim, and a laptop losing power is not exotic.
- **Fix:** `PRAGMA synchronous=FULL` (the write rate here makes the cost irrelevant), or reconstruct STOP/resume/approval state from the ledger at boot and treat SQLite as a cache. Note the partial-line recovery already assumes the ledger is the durable truth.

#### I4. Content-addressed blobs are never verified on read (no re-hash, no AEAD associated data)

- **Where:** `crates/vk-store/src/blobs.rs:134-140` (`get`), `crates/vk-store/src/keys.rs:101-119` (`seal`/`open` without AAD).
- **What is wrong:** The address is `sha256(key_id‖0‖plaintext)`, but `get(hash)` returns whatever the envelope's DEK decrypts. Two ciphertexts of one subject share a DEK, so swapping their `.bin` files (or restoring an older `.bin` over a newer one) yields the wrong bytes under the right hash: `read_artefact` hands them out, a `Release` writes them under `<hash12>.<kind>`, and the human approval whose `subject_hash` is that address bound nothing. The AEAD tag protects each ciphertext, not the mapping from address to ciphertext.
- **Why it matters:** The approval ceremony, the release record and the "commits to hashes" story all rest on the address meaning the content. The fix is a few lines and turns the store into what its name claims.
- **Fix:** After decrypt, recompute `sha256(env.key_id‖0‖plaintext)` and refuse on mismatch (surface as a distinct `StorageError::Integrity` rather than `NotFound`); additionally pass the address as AEAD associated data in `seal`/`open`. Test: swap two `.bin` files of one subject → `get` refuses.

#### I5. On Unix the state directory and everything in it is world-readable except the two key files

- **Where:** `crates/vk-store/src/paths.rs:16` (`create_dir_all`, umask), `db.rs:26-33` (SQLite default 0644), `ledger_fs.rs:117-124` (`create(true)` → 0644), `tasks.rs:428-434` (exports written 0644); only `keys.rs:40-46` and `presence.rs:68-75` set 0600.
- **What is wrong:** Registers hold the goal, the evidence and every raised decision — i.e. the full draft text — as plaintext JSON in `vk.sqlite` (and its `-wal`); the ledger and the released plaintext under `exports/` sit next to it. On a shared Linux/macOS machine (the spec's *headless* node class is a server) every other local account can read all of it. The socket is 0600 in a 0700 directory, but the data the socket guards is not.
- **Why it matters:** "Encrypted at rest" is true only of the blob tier; a reasonable person running this on a shared box expects the store to be private to the account. SP1b's service account/ACL gate does not cover Unix.
- **Fix:** Create the state directory with mode 0700 (`DirBuilder::mode`), and when it already exists refuse one that is group/other-accessible (the same rule `private_dir` applies to the socket directory, `transport.rs:208-223`); set `umask(0o077)` at `vkd` start as belt-and-braces. On Windows `%LOCALAPPDATA%` is user-ACL'd already.

#### I6. The task read surface bypasses I2: `Task` carries the register's `goal` and is served with no label check

- **Where:** `crates/vk-ipc/src/server.rs:503-513` (`task.show`, `task.ls`, `top`), `crates/vk-kernel/src/ns.rs:51-57` (`/tasks`, `/tasks/<id>`), `crates/vk-kernel/src/tasks.rs:145-147`, `245-253` (`task()`, `tasks()` take no `Ctx`), while `read_register` refuses on `flows_to` (`lib.rs:552-557`).
- **What is wrong:** `Task.goal` duplicates `Register.goal`, and the task rows are readable by any principal regardless of the register's label. In SP1a nothing leaks *today* because `task.create` pins every pipe task to `Label::bottom()` (`server.rs:483`) and every connection gets Personal clearance; the first labelled task SP1b creates will leak its goal (and its status/step trail) to any local principal through `vk ps`/`vk ls /tasks`.
- **Why it matters:** The review brief asks whether I2 can be bypassed via namespace listing; the answer is yes by construction, and the fix is far cheaper now than after SP1b builds on `task.ls`.
- **Fix:** Give `task()`/`tasks()`/`ns::resolve` a `&Ctx` and filter by the register's label (one `get_json` per task), or drop `goal` from `Task` and have the CLI read it through `read_register`. Add a property: a task whose register does not flow to the caller is absent from `task.ls`/`ns.ls`.

### Minor

- **M1. `write_register` accepts any label and `task_id` from the caller (both kernels).** `lib.rs:561-567` and the stub agree, so cross-kernel consistency holds, but an in-process caller can relabel a register downward or overwrite one it cannot read (an I3 silent discard). The branch summary's "label join on write" is not implemented anywhere — `Register::with_read` has no caller. Not reachable over the pipe. Fix: join with the stored label, refuse a changed `task_id`, require read clearance on the existing row.
- **M2. `infer` logs after the send.** `lib.rs:614-619` records `infer` only after `adapter.complete` returns, while the comment says the opposite; a crash mid-send to a real arch (SP1b) leaves no trace. Log the intent before `complete` (keep the post-send event if you want both).
- **M3. HLC is not re-seeded from the ledger tail on open** (`lib.rs:118`): after a restart with a backwards wall clock, HLCs across restarts are not monotonic. Seed `clock.last` from the last event's `hlc`.
- **M4. No zeroisation of key material.** `MasterKey` derives `Clone` and nothing implements `Zeroize`/`ZeroizeOnDrop`; DEKs, the node seed and the base64 `String`s of both are dropped unwiped (`keys.rs`, `presence.rs`, `blobs.rs:93-97`). Add `zeroize` and drop the `Clone`.
- **M5. The server does not enforce the approval-nonce binding the CLI promises.** `main.rs:410-415` says the approval "is bound to a nonce this daemon issued", but the `approve` arm (`server.rs:523-536`) never checks `approval.challenge.nonce` against the presence nonce or the challenge map, and `verify_human` ignores `resource`. Defence in depth only (the enrolled key must sign either way), but it is a one-line check; do it, or soften the comment.
- **M6. `private_dir` checks mode but not ownership** (`transport.rs:208-223`): a pre-created 0700 `/tmp/vk-<user>` owned by another account produces a confusing bind failure rather than "not yours". Check `metadata.uid() == geteuid()`.
- **M7. `detach` on Unix does not `setsid`** (`main.rs:536-541`): `process_group(0)` leaves the daemon attached to the controlling terminal. Use `pre_exec(setsid)`.
- **M8. The default Windows state directory is `%LOCALAPPDATA%\VerticalAI\vk\data`** (directories 5 joins `data` after `<org>\<app>`; verified in the crate source), not the plan's `%LOCALAPPDATA%\VerticalAI\vk`. Harmless, but README says only "local app data"; print or document the real path.
- **M9. Sync-folder refusal matches the raw, non-canonical path** (`paths.rs:48-54`); a junction or symlink into OneDrive is not caught. Canonicalise the deepest existing ancestor before matching.
- **M10. No `liveness.renew` RPC** although the plan's Task 5 note (line 1164) says the IPC exposes `renew_liveness` as an admin syscall; `vk top` renders a liveness column nothing can populate over the pipe. Add it (human-gated) or strike the prose.
- **M11. `run_task_step` re-runs a step left `Running` by a crash** (`tasks.rs:295-303`): a Draft would infer again and attach a second artefact, changing the approval subject. Harmless with the mock; make steps idempotent or refuse-and-report before real arches.
- **M12. Master-key diagnostics.** The keyring entry is per user, not per state directory (`vkd/src/main.rs:54-57`); a deleted or replaced entry turns every blob into `not found` with no hint. Put `MasterKey::fingerprint()` in the boot report/log so a key mismatch is diagnosable.
- **M13. `boot.info` recomputes `verify_chain()` over the whole ledger on every call** (`server.rs:423`) and `vk boot` polls it every 100 ms. Cache the verdict per append.
- **M14. README omits the SP1a trust model and the headless-Linux key path.** `main.rs` docs say "the interactive machine *is* the enrolled device"; the README should say next to `vk approve` that any process running as this user holds the node key and is therefore "the human" until passkeys land, and that Linux without a Secret Service needs `--master-key-file`.
- **M15. New segment files are not followed by a directory fsync** (`ledger_fs.rs:117-124`); on some filesystems a crash right after the first append into a fresh segment can lose the file entirely (it would then read as a clean truncation — see I2).
- **M16. The I1 property never exercises a valid human approval** (`i1_human_path.rs:49-62` always sends `challenge: None`), so the property proves refusal only; acceptance is covered by unit tests. Add a signed-approval op with an enrolled test key.

---

## Declined to judge

- Windows named-pipe default DACL — SP1b hardens with an explicit one; deferred minor (Task 7).
- Every same-user process holding the node key counts as "the human" — the plan's SP1a stand-in for passkeys (Ruling 17/20); a doc gap only (M14).
- Every pipe connection gets Personal clearance and every pipe task is `Label::bottom()` — the plan's own `ctx_for` (line 1699) and single-user SP1a; I6 is about the *surface*, not this policy.
- Registers stored as plaintext JSON in SQLite — plan Task 1 puts a `registers` table there; the consequence (blob encryption does not cover the same text in the metadata tier; `shred` cannot mean "unreadable everywhere") is raised under Recommendations, not as a finding.
- `shred` unreachable from any syscall, RPC or CLI — the plan exposes only the store primitive in SP1a.
- Scheduler STOP scope is `node` only — the plan's own `top` iterates `["node"]`; Rulings 15(d)/24.
- No liveness (I4) gate on machine-driven `task.step` — the SP0 I4 path is `run_automation`; plan Task 6 asks the scheduler for STOP only.
- `boot` appends a `boot` event even when serving is refused, so each refused start grows the broken record — Ruling 7's consequence.
- Harness steps returning `WaitingHuman`, `MockAdapter` echo semantics, `arch.mount_mock` without a `Ctx` — SP1b / deferred.
- Approval challenge expiry chosen by the client and `verify_human` not checking issuance — SP0 contract behaviour; presence proves liveness in SP1a.
- `causal_heads` always empty and `ClockQuality::Synced` unconditional — deferred minor 13; the stub does the same.
- Poisoned kernel mutex, no `presence.challenge` rate limit, test temp-dir leaks, macOS `sun_path` headroom, vendored keyring weak deps — deferred minors / Ruling 29.
- `%TEMP%` `.tmp*` leak from `roundtrip.rs` on Windows — deferred (Task 9).

## Recommendations for SP1b

1. **Make the metadata tier honour the storage design.** Registers (and `Task.goal`) hold the same text as the artefact blobs. Either store register bodies as blobs and keep only heads/labels in SQLite (spec §3.9 literally), or encrypt the SQLite tier; until then `shred` cannot be exposed honestly, and I5's permissions are the interim.
2. **Kernel-issued approval challenges.** Have the server mint the `Challenge` (nonce from the challenge map, `resource`, expiry) and bind method+params (Ruling 20) so `verify_human` checks issuance rather than trusting the client's nonce/expiry.
3. **A `Ctx` on every read surface** (`task.*`, `ns.ls`, `top`, `ledger.tail`) before labelled tasks exist — I6 now, and `ledger.tail` when payload hashes start to name labelled objects.
4. **Ledger head commitment + single-writer lock before the Windows service** (C1, I2); service restart is the double-start case.
5. **Log `infer` intent before the send and give steps idempotency keys** (M2, M11) before real arches; the spec's fence/idempotency-key rule (§3.4) applies to integration drivers and the scheduler alike.
6. **`zeroize` on key material and AEAD associated data on blobs** (M4, I4).
7. **Consider a keyed blob address** (`HMAC(DEK, plaintext)` or a per-subject address key): today's `sha256(key_id‖0‖plaintext)` is deterministic and unkeyed, so anyone holding an envelope or a `task.subject` answer can confirm a guessed low-entropy artefact; spec §3.9 says the ledger commits to ciphertext hashes. Low urgency — the ledger itself stores `hash_canonical(record)`, not the artefact address.
8. **`vk fsck`**: chain + head + blob-address verification in one verb, so "verified" means the whole store.

## Assessment

**Ready to merge? With fixes.** The kernel, store, transport and shell are well-built and the invariants hold end to end through the pipe — I found no way for a machine principal to mint a human event or approval, and every store-write failure I traced fails closed. What blocks an unconditional yes is that an ordinary operator mistake (starting the daemon twice) was reproduced corrupting the audit chain and can collide ids (C1), and that the record can silently shrink (I2) or desync from disk after one IO error (I1) or a power cut (I3). All four are contained changes in `vkd`/`vk-store` (a lock file, bind-before-boot, push-after-write, a persisted head, `synchronous=FULL`) and should land on this branch before merge; I4–I6 are small and would ideally go with them, the minors can follow.

---

## Re-review: fix wave (2e546dc)

Reviewer: senior code review (systems / security / Rust), scoped re-review — the seven findings above and what the fix itself introduced, not the branch again.
Inputs: `review-a226059..2e546dc.diff` (one commit, 16 files, +1419/-106) and the head state of every file it touches. `final-fix-report.md` does not exist in this folder; the implementer's per-finding evidence and stated concerns were taken from the body of commit 2e546dc and the fix-wave entries of `progress.md`.

### How it was done

1. The diff read against the head state of `vk-store` (`lock.rs`, `lib.rs`, `paths.rs`, `db.rs`, `keys.rs`, `blobs.rs`, `ledger_fs.rs`), `vk-kernel` (`lib.rs`, `tasks.rs`, `ns.rs`), `vk-ipc/server.rs`, `vkd/main.rs`, plus `Ledger` in `vk-contracts` (for the rollback question) and every call site of the changed APIs.
2. The two reproductions of the whole-branch review re-run by hand on Windows in throwaway state directories on private pipes with file-backed keys, plus the `vk boot` operator path, a full task run (submit → plan → draft → release) through a real daemon, and the same double-start on Linux (WSL) over both ext4 (`/tmp`) and DrvFS (`/mnt/c`).
3. `cargo test --workspace --no-fail-fast`, `cargo clippy --workspace --all-targets -- -D warnings` (also from scratch in a clean target dir) and `cargo fmt --all -- --check` on Windows; the workspace suite again on Linux for the `#[cfg(unix)]` tests.
4. Afterwards: no `vkd` process left, my temp state directories and the `.tmp*` dirs that this session's test run leaked removed.

### Reproductions

**A — two daemons on one state directory.** Daemon A serving on `pipe\vk-rr-a` over `…\vk-rr\state-a` (2 events on disk). A second `vkd`, same state directory, **different** endpoint: exit 1, `state directory …\state-a is already open by another vkd: …\state-a\lock is locked by another process; stop that daemon or choose another --state-dir`. Ledger lines before = 2, after = 2 — nothing appended. A still served: `status` `ledger_ok: true`, `ledger verify` `{"len":2,"ok":true}`. Same-endpoint second start: identical refusal, again at the lock, i.e. before the bind. After `kill -9` of A the zero-byte `lock` file stayed on disk and did **not** block the next start (the store re-opened and appended seq 2, chain verified) — the implementation relies on the OS lock, not the file's existence. Through the operator's own path, `vk boot --endpoint <other> --state-dir <same>` prints `vkd (pid …) exited with exit code: 1 before it answered on …, saying: Error: state directory … is already open by another vkd …`, exits 1 at once, and leaves the serving daemon's record at 2 lines.

**B — the tail of the ledger deleted.** Record built to 3 events (`device.enrolled`, `boot`, `arch.mounted`), daemon gone, last two lines removed. Restart without `--force`: `WARN … the ledger on disk no longer contains the head this node last recorded: its tail was cut or rewritten recorded_seq=2 … found_seq=0`, `vkd booted ledger_ok=false ledger_len=1`, then `Error: the ledger chain in …\ledger does not verify (1 events): a line was rewritten, or the tail this node last recorded is gone; refusing to serve…`. With `--force`: serves, `status` `ledger_ok: false`, `ledger verify` `{"len":3,"ok":false}`; after a further append (`mount`) still `{"len":4,"ok":false}`; a later start *without* `--force` refuses again, and the `kv` row is unchanged (`ledger.head = {"seq":2,"hash":"sha256:30dbd9c6…"}`). A forced run does not heal the record.

### Per-finding verdicts

**C1 — two daemons on one state directory. Closed.**
`Store::open` (`crates/vk-store/src/lib.rs:77-92`) takes `StoreLock::acquire(state_dir/lock)` as its second act, before the master key, the database, the ledger (and so before the partial-line truncation) and before any ledger append; the only write ahead of it is the idempotent `private_dir` mkdir/chmod. The lock is `share_mode(0)` on Windows and `flock(LOCK_EX|LOCK_NB)` on Unix (`crates/vk-store/src/lock.rs:29-51`) — non-blocking, so a held directory fails at once rather than hanging. Release is by handle close only: the `File` is the last field of `StoreLock`, `_lock` is the last field of `Store` and documented as such (`lib.rs:64-66`), so it outlives the db/ledger/blobs; on `bail!`, on unwind and on `kill -9` the OS closes it, which `kill -9` + restart confirmed empirically on both platforms. `ERROR_SHARING_VIOLATION` (32) and `WouldBlock` are the two "someone holds it" cases and produce the named refusal; anything else is reported as a failure to take the lock, not as a second daemon. `vkd` (`crates/vkd/src/main.rs:51-66`) now binds the endpoint before `--auto-enroll-node` and `boot()`, so a daemon refused its endpoint appends nothing; `serve_on` takes the already-bound listener (`crates/vk-ipc/src/server.rs:15-25`). No other process opens a `Store` — `vk` is a pure client — so the lock costs no existing workflow. Tested in-process (`vk-store/src/lib.rs:203-218`, `lock.rs:86-101`) and e2e (`vk-cli/tests/smoke.rs`, `a_second_vkd_over_a_served_state_dir_is_refused_and_writes_nothing`).

**I1 — in-memory chain ahead of the disk. Closed** (push-then-rollback is observably equivalent here).
`LedgerFs::append` (`crates/vk-store/src/ledger_fs.rs:106-137`) still builds the event through `Ledger::append` — the contract has no other constructor and no `pop` — but on a failed `write_line` it calls `roll_back(e.seq)` and returns the error. The rollback is exact rather than approximate: `Ledger::append` computes `seq = events.len()` (`crates/vk-contracts/src/ledger.rs:147`), so `seq` is the new event's index, `Ledger` has exactly one field (`events`), and rebuilding from `events()[..seq]` reproduces the previous state bit for bit. `write_line` (`ledger_fs.rs:144-167`) records the length before the write and truncates back to it if `write_all`+`sync_data` fails, so the file has no half line either; a new segment is followed by a directory fsync on Unix (`sync_dir`, M15 closed in passing), and the per-line durability is `sync_data` (which flushes the size change an append needs). Panic window: nothing between the push and the rollback can panic — `serde_json::to_vec`, `metadata`, `write_all` and `sync_data` all return `Result` — and a panic there would poison the kernel mutex, which `lock()` reports as an error on every later dispatch (`server.rs:241-243`), i.e. the phantom would be unreachable rather than served. Covered by `a_failed_write_leaves_the_chain_unchanged_and_later_appends_verify` (read-only segment → error, `len` unchanged, file byte-identical, next append takes the freed seq, reopen verifies).

**I2 — a silently shortened record. Closed.**
Every append goes through `Store::append_event` (`vk-store/src/lib.rs:105-130`), which writes the segment line first and only then records `kv.ledger.head = {seq, hash}`; `RealKernel::log` is the kernel's only ledger writer and now calls it (`crates/vk-kernel/src/lib.rs:494-500`). `head_verdict` (`lib.rs:133-151`) compares the recorded head with `events()[seq]` by both seq and hash at open: shorter, or a different event at that seq, is `Diverged`; longer is `Intact`, which is exactly the shape a crash between the synced line and the head record leaves (tested); absent is `Unrecorded`, accepted once and recorded by the first append (tested with a legacy segment). `boot()` reports `ledger_ok = ledger_holds()` = chain **and** head (`vk-kernel/src/lib.rs:244`, `263-266`), and `boot.info` and `ledger.verify` report the same verdict rather than recomputing the chain alone (`server.rs:335`, `489-491`). A `Diverged` store never records a head again (`lib.rs:124-128`), which is what makes the verdict survive the `boot` event appended onto the cut chain and every later forced append — confirmed in reproduction B, three starts later, with the `kv` row still on the pre-cut seq. Residual (by design, and the review's own prescription): the witness lives in the same store, so restoring an older `vk.sqlite` with the ledger, or clearing that one row, resets it; an out-of-store witness and a `vk fsck` re-baseline remain SP1b items.

**I3 — SQLite durability. Closed.**
`crates/vk-store/src/db.rs:38-44`: `journal_mode=WAL` then `synchronous=FULL`, with the reason (a STOP row must be at least as durable as the ledger event that records it) in the comment. Asserted as `PRAGMA synchronous == 2` by a test in the same file, which passed on both platforms.

**I4 — content-addressed blobs verified on read. Closed.**
`seal`/`open` take associated data (`crates/vk-store/src/keys.rs:105-137`) and `put` passes the address itself, `hash.as_bytes()` — the exact `sha256:<64 hex>` bytes, not the hex part — as AAD (`blobs.rs:119-135`). `get` (`blobs.rs:152-174`) holds the answer to the address three times: the envelope must name it (`env.hash == hash`), the ciphertext must open under it, and the plaintext must re-derive `address(env.key_id, plaintext) == hash`. The re-derivation uses the envelope's `key_id`, but that field is not trusted blindly: a changed `key_id` selects a different DEK and the AEAD tag fails, so `key_id` is authenticated in effect. `alg` and `ciphertext_len` are written and never read. Integrity failures are a distinct error — not downcastable to `StorageError` — and the kernel maps them to `KernelError::Store`, keeping `NotFound`/`Shredded` for the real cases (`vk-kernel/src/lib.rs:468-482`). Shred still works (its test passed unchanged), and a full live task run through the daemon (plan → draft → release) produced the right plaintext in `exports/out/<hash12>.note`, so the AAD change did not break the read path. Covered by swapped `.bin`, swapped `.bin`+`.json` and one-byte-flip tests at store level and a swapped-artefact test at kernel level.

**I5 — Unix permissions. Closed for everything the ruling names.**
`private_dir` creates with `DirBuilder::mode(0o700)` and re-applies 0700 to a directory that already existed (`paths.rs:25-38`); `private_file_options()` gives every file the store creates `mode(0o600)` at birth and `restrict_file` tightens ones an older version left open (`paths.rs:40-70`). Applied to the state dir (`lib.rs:78`), the database plus its `-wal`/`-shm` after migrate (`db.rs:32-54`), ledger segments on open and on creation (`ledger_fs.rs:37`, `147`), the lock file (`lock.rs:48`), and the export root, each release destination and each released file (`tasks.rs:456-467`). Measured under WSL with `umask 022`: state dir `700` (including a pre-existing `755` one, tightened), `vk.sqlite`, `vk.sqlite-wal`, `vk.sqlite-shm`, `lock`, `ledger/seg-000000.jsonl` all `600`; the release test asserts `700`/`700`/`700`/`600` for root, `out`, `out/deep` and the file. On a DrvFS state dir where chmod is a no-op the calls still succeed, so no new startup failure there. Windows branches are `#[cfg(not(unix))]` no-ops and the Windows suite is unchanged. See N2 for what the ruling does not name.

**I6 — the task read surface. Closed.**
`task_row` is private and reached only through `task(&Ctx, id)`, which filters on `visible_to` — the *register's* label against the caller's clearance, the same rule as `read_register` (`crates/vk-kernel/src/tasks.rs:145-170`). `tasks(&Ctx)` filters the listing, `top(&Ctx)` uses it, and `ns::resolve` takes a `Ctx` so `/tasks` and `/tasks/<id>` hide what the caller is not cleared for (`ns.rs:32-59`). The three ways to reach a task by id are all behind the same read: `run_task_step` (`tasks.rs:299-303`) and `approval_subject` (`tasks.rs:188-191`) now go through `task(ctx, …)` and return `NotFound` — the row is not touched, asserted in the test — and `task.show`/`task.ls`/`top`/`ns.ls` pass a `Ctx` at the RPC edge (`server.rs:423-437`, `344-350`). `approve` names a subject hash and never a task, and that hash is only obtainable from `task.subject`, which is now gated; `stop` is scope-based. `ledger.tail` carries no goal — a `LedgerEvent` has `kind` and `payload_hash` and nothing else from the payload — which I confirmed live: `vk --json dmesg` after a task whose goal was "a visible goal" contains zero occurrences of it. Nothing is hidden from the CLI in SP1a: `ctx_for` still issues Personal clearance for every connection and `task.create` still pins `Label::bottom()` (`server.rs:292-299`, `397-406`), and a live run showed `vk ps`, `vk top`, `vk ls /tasks` and `vk ls /tasks/<id>` all returning the task and its goal. The new `ctx_for` calls in the read arms cannot disturb the presence ceremony: a proof on a method outside `takes_presence` is still refused before dispatch (`server.rs:321-323`), so those arms always see `None`.

### New findings (all Minor)

- **N1. A malformed `ledger.head` row makes the node unstartable, and `--force` cannot reach it.** `crates/vk-store/src/lib.rs:137-138`: `head_verdict` fails `Store::open` on a `ledger.head` value that does not parse. `--force` is only consulted after `boot()`, so a corrupted row (or a hand-edit) refuses every start with `malformed ledger.head record`, and nothing in the message says the row can be deleted. Same shape as the missing re-baseline path for a legitimately restored ledger. Fix: treat an unparseable head as `Unrecorded` with a `warn!`, or name the `kv` key and the remedy in the error.
- **N2. The payload tier keeps the umask mode.** `crates/vk-store/src/blobs.rs:28-29` (`keys/`, `shredded/` via `create_dir_all`), `:96` (the wrapped DEK), `:131-133` (`.bin`, `.json`), and `ledger/` itself (`ledger_fs.rs:29`). Measured `755` on the directories, and `std::fs::write` gives the files `644`. They are private only because the state directory above them is now `0700` — which is enforced on every open, so this is defence in depth rather than an exposure, but the wrapped DEKs are exactly the material the rest of I5 was tightened for. Fix: `private_dir` for the three blob directories and `private_file_options` for the three writes.
- **N3. `visible_to` swallows a store read error as "not found".** `crates/vk-kernel/src/tasks.rs:157-164`: `.ok().flatten()` maps a failed or undeserialisable `registers` read to "hidden", so a database fault makes tasks silently disappear from `ps`/`top`/`ls` instead of failing loudly (Ruling 8). Fail-closed for confidentiality, and `task_row` already had the same shape, but this puts a second swallowed read on every listing. Fix: distinguish "no such register" from a read error and surface the latter as `KernelError::Store`.
- **N4. DEKs are still wrapped without associated data.** `crates/vk-store/src/keys.rs:80-86`: `wrap`/`unwrap_dek` pass an empty AAD, so a `keys/<hex>.dek` file moved to another subject's name is not detected. The consequence is bounded — blobs become unreadable (an I4 integrity failure) rather than wrong, because the address stays subject-scoped — but a `shred` of subject A would then destroy subject B's key. Fix: bind `key_id` as AAD in `wrap`/`unwrap_dek` (a format change, still free today).

### Carried forward, not re-opened

- The envelope's `label` is unauthenticated and is the field `read_artefact` trusts for its I2 decision (`vk-kernel/src/lib.rs:468`); with the state directory now `0700`, editing it means being the owner, who is already "the human" in SP1a. Known, deferred to SP1b as the fix wave states.
- A refused start still appends its own `boot` event (Ruling 7): reproduction B grew the cut record from 1 to 4 lines across three refused/forced starts.
- `boot.info` still recomputes the whole chain per call (M13), now with the head check on top.
- The `%TEMP%\.tmp*` leak from `vk-ipc/tests/roundtrip.rs` on Windows is unchanged; the leaked directories now also contain a released `lock` file. Ten of them from this session's run were removed afterwards.

### Build and checks

Windows (MSVC, `CARGO_TARGET_DIR` outside OneDrive):

- `cargo test --workspace --no-fail-fast` → exit 0; every suite `test result: ok.`, summed **135 passed; 0 failed; 0 ignored**.
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0, no diagnostics; re-run from scratch in a clean target directory: `Finished dev profile [unoptimized + debuginfo] target(s) in 40.55s`, exit 0, zero `warning:`/`error:` lines.
- `cargo fmt --all -- --check` → exit 0, no output.

Linux (WSL Ubuntu, same worktree over `/mnt/c`, target dir on the WSL side):

- `cargo test --workspace --no-fail-fast` → exit 0, summed **141 passed; 0 failed** (the six extra are the `#[cfg(unix)]` mode and lock tests).

Afterwards: no `vkd` process running, no new `vk-*` temp directories; the worktree is clean at 2e546dc.

### Verdict

**All seven findings are closed and the fix introduces no new Critical or Important defect.** C1 and I2 were re-reproduced end to end and behave as Ruling 30 says; I1's push-then-rollback is observably equivalent to write-then-push given `seq == index` and `Ledger`'s single field; I3, I4, I5 and I6 are implemented where they had to be and tested at the level the finding was found at. The four new items are Minor and none of them blocks the merge.
