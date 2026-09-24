# SP1a fix-wave implementer report (commit 2e546dc)

Recovered on 2026-09-24 from the implementer's scratch folder (it had been written outside the SDD workspace). Companion to 2026-09-24-sp1a-final-review.md.

# SP1a fix wave — report (Ruling 30)

Branch `sp1-kernel`, base `a226059`, fix commit `2e546dc` ("fix(store,kernel,vkd): close the SP1a review's Critical and six Important findings"), pushed to `origin/sp1-kernel`.
Worktree `.worktrees/sp1-kernel`; `contracts/` untouched (`schema_drift` green on both platforms); no contract type, ledger event kind or CLI verb/flag changed; one new dependency edge (`libc`, Unix-only, `vk-store` — for `flock`), already in `Cargo.lock`.

Status: **DONE_WITH_CONCERNS** (all seven findings closed and tested on Windows and Linux; concerns are design notes for the re-review, listed at the end).

## Per finding

### C1 — single writer + boot ordering
- `crates/vk-store/src/lock.rs` (new, 100 lines): `StoreLock::acquire` opens `<state_dir>/lock` — Windows `share_mode(0)` (`lock.rs:33-36`), Unix `libc::flock(LOCK_EX | LOCK_NB)` on the open descriptor (`lock.rs:39-48`) — and keeps the `File` for the lock's lifetime. "Held by another" (`ERROR_SHARING_VIOLATION` 32 / `EWOULDBLOCK`, `lock.rs:56-65`) becomes `state directory <dir> is already open by another vkd: <lock file> is locked by another process; stop that daemon or choose another --state-dir` (`lock.rs:67-80`); any other error keeps the OS error with the lock path as context.
- `crates/vk-store/src/lib.rs:77-92` `Store::open`: `private_dir(state_dir)` then `StoreLock::acquire` **before** the master key, the db, the ledger or the blobs are opened — nothing is read or written by a refused open. `Store` holds `_lock` as its last field (`lib.rs:65-66`) so it is released last.
- `crates/vk-store/Cargo.toml`: `[target.'cfg(unix)'.dependencies] libc = "0.2"`.
- `crates/vkd/src/main.rs:60-84`: order is now open (lock) → bind endpoint (`os::bind`, `main.rs:73-75`) → auto-enrol → `boot()`. A daemon refused its endpoint therefore never enrols or appends. `vk_ipc::server::serve` was split: `serve(kernel, endpoint)` binds and delegates to the new `serve_on(kernel, listener)` (`crates/vk-ipc/src/server.rs:79-89`), which `vkd` calls with its pre-bound listener (`main.rs:123`).
- Tests:
  - `crates/vk-store/src/lock.rs:86` `lock::tests::a_second_lock_on_the_same_file_is_refused_until_the_first_is_dropped` — second `acquire` errs naming the lock file; succeeds after the first is dropped.
  - `crates/vk-store/src/lib.rs:183` `tests::a_state_directory_is_opened_by_one_store_at_a_time` — second `Store::open` on one dir errs naming `<dir>/lock` and "already open"; reopen after drop succeeds.
  - `crates/vk-cli/tests/smoke.rs:489` `a_second_vkd_over_a_served_state_dir_is_refused_and_writes_nothing` (e2e, real binaries): daemon A serving; daemon B on the same dir with its own endpoint exits non-zero, stderr names the lock file and "already open"; the on-disk segment line count is unchanged; nothing answers on B's endpoint; A still answers `status` with `ledger_ok: true` and `vk ledger verify --json` → `ok: true`; after A is killed, a third daemon on the same dir serves and verifies.
  - Output (Windows / Linux): `test lock::tests::a_second_lock_on_the_same_file_is_refused_until_the_first_is_dropped ... ok`, `test tests::a_state_directory_is_opened_by_one_store_at_a_time ... ok`, `test a_second_vkd_over_a_served_state_dir_is_refused_and_writes_nothing ... ok` on both.

### I1 — ledger append ordering
- `crates/vk-store/src/ledger_fs.rs:96-178`: `append` builds the event through the chain (the only place the contract's hash is computed), calls `write_line` (`:144-167`: serialise line + `\n`, open segment append-mode with `0600`, record the length, `write_all` + `sync_data`; on error `set_len(len_before)` so no partial line is left, then `Err` with the segment path) and on failure `roll_back(seq)` (`:171-178`) restores the chain to exactly what it was; only a synced line stays in memory. `Ledger` (vk-contracts) has no `pop`, so the rollback rebuilds the chain from the events before the phantom — see Deviations.
- Test `crates/vk-store/src/ledger_fs.rs:386` `ledger_fs::tests::a_failed_write_leaves_the_chain_unchanged_and_later_appends_verify`: segment made read-only (Windows attribute / Unix `0400`), append → `Err` naming `seg-000000.jsonl`; `chain().events().len()` and `len()` still 1, `verify()` true, file bytes unchanged; made writable again → next append takes `seq 1`; reopen → 2 events, verifies, tail is the later event. Output: `... ok` on both platforms.

### I2 — tail truncation detection
- `crates/vk-store/src/lib.rs:18` `LEDGER_HEAD = "ledger.head"`, `LedgerHead {seq, hash}` (`:21-33`), `HeadVerdict { Unrecorded | Intact | Diverged { recorded, found } }` (`:40-57`).
- `Store::append_event` (`lib.rs:105-131`) is the kernel's single append path (`crates/vk-kernel/src/lib.rs:497`): `LedgerFs::append` (synced) then `kv_set("ledger.head", {seq, hash})` — a plain autocommitted `kv` write like every other kv write. On a store whose verdict is `Diverged`, the head is deliberately **not** advanced, so the boot event appended onto a cut chain cannot make the next open call it intact.
- `head_verdict` (`lib.rs:133-152`) at `Store::open`: no record → `Unrecorded`; the event at `recorded.seq` present with `recorded.hash` → `Intact` (the chain may be longer — the crash window between segment sync and kv write); shorter, or a different event at that seq → `Diverged`.
- `crates/vk-kernel/src/lib.rs:232-241` `boot()` warns with the recorded/found seqs on `Diverged`; `ledger_ok = self.ledger_holds()` (`:262-265` = `verify() && !Diverged`). `boot.info` and `ledger.verify` over IPC use the same `ledger_holds()` (`crates/vk-ipc/src/server.rs:339, 471`) — the first version of the smoke test caught that `boot.info` recomputed `verify_chain()` alone and reported `true` under `--force` on the cut chain. `vkd`'s refusal text now says "a line was rewritten, or the tail this node last recorded is gone" (`main.rs:111-116`), still containing "ledger" and "--force".
- Tests:
  - `crates/vk-store/src/lib.rs:201` `every_append_records_the_head_and_a_cut_tail_is_found_on_reopen`: head recorded after each append; reopen `Intact`; last two lines cut → chain still `verify()`s but verdict `Diverged { recorded.seq 2, found.seq 0 }`; an append on the diverged store does not move the head → next open still `Diverged`.
  - `lib.rs:253` `the_head_is_held_to_its_hash_and_a_longer_chain_is_accepted`: an event appended behind the store's back (chain longer by one) → `Intact`; the tail replaced by a *consistently rehashed* different event via `Ledger::append` (chain verifies) → `Diverged`.
  - `lib.rs:317` `a_ledger_from_before_heads_were_recorded_is_accepted_and_then_recorded`: legacy record without `ledger.head` → `Unrecorded`, served, and the first append records seq 1.
  - `crates/vk-kernel/src/lib.rs:1084` `boot_reports_a_cut_tail_rather_than_trusting_the_shorter_chain`: boot + mount + STOP, last two lines deleted, reopen → `ledger_ok == false` while `verify_chain()` is true and the STOP still holds; a further reopen still reports `false`.
  - `crates/vk-cli/tests/smoke.rs:479` `vkd_refuses_to_serve_a_ledger_whose_tail_was_cut_unless_forced` (e2e; the refusal test was made generic over the damage, `smoke.rs:410`, and the tampered-line variant still runs as before): mount + stop, daemon killed, tail cut → new daemon exits non-zero with "ledger"/"--force"; `--force` serves with `status.ledger_ok == false` and `stopped_scopes == ["node"]`.
  - Output: all five `... ok` on Windows and Linux.

### I3 — durability
- `crates/vk-store/src/db.rs:44` `PRAGMA synchronous = FULL` (WAL kept), with the reason in a comment.
- Test `db.rs:193` `db::tests::commits_are_synced_on_every_transaction`: `PRAGMA synchronous` → `2`, `PRAGMA journal_mode` → `wal`. Output: `... ok` on both.

### I4 — blob integrity
- `crates/vk-store/src/keys.rs:105-140`: `seal(key, aad, plaintext)` / `open(key, aad, sealed)` take AEAD associated data (`chacha20poly1305::aead::Payload`); DEK wrapping passes empty AAD (format unchanged).
- `crates/vk-store/src/blobs.rs:119-123` `put` seals under `aad = address`; `address(key_id, plaintext)` (`:205-211`) is the one place the subject-scoped hash is computed. `get` (`:152-174`) now returns `anyhow::Result` and checks three things against the *requested* address: the envelope names it, the ciphertext opens under it as AAD, and the plaintext re-derives it; each failure is an "integrity" error that downcasts to no `StorageError`, while missing/shredded blobs still carry `StorageError::NotFound`/`Shredded` (same downcast convention `put` already used). `StorageError` is a contract type, so no `Integrity` variant was added.
- `crates/vk-kernel/src/lib.rs:473-484` `read_artefact` maps a `StorageError` to `KernelError::NotFound` and an integrity failure to `KernelError::Store("blob … failed its integrity check …")` (E_STORE over IPC) rather than "not found".
- Tests: `blobs.rs:340` `a_blob_swapped_with_another_of_the_same_subject_is_refused` (two `.bin` swapped → both `get`s fail with "integrity"; `.bin`+`.json` pairs swapped → both fail, message names the envelope; swapped back → both read); `blobs.rs:376` `a_ciphertext_with_one_byte_changed_is_refused` (byte 30 flipped → fails; restored → reads); `crates/vk-kernel/src/lib.rs:1537` `a_swapped_artefact_is_refused_as_a_store_failure_not_served_under_the_wrong_hash` (two artefacts of one task swapped → `read_artefact` is `Err(KernelError::Store(msg))` with "integrity" for both). Output: `... ok` on both platforms.

### I5 — Unix permissions
- `crates/vk-store/src/paths.rs:25-38` `private_dir` (create `0700` recursively and `set_permissions(0700)` on an existing dir; Windows `create_dir_all`), `:44-57` `private_file_options` (`mode(0o600)` on Unix), `:61-71` `restrict_file` (`chmod 0600`, no-op on Windows). `state_dir()` uses `private_dir` (`:16`); so does `Store::open` (`lib.rs:78`).
- `db.rs:32-36`: the SQLite file is created `0600` (empty file = empty database) and restricted before `Connection::open`, so SQLite's `-wal`/`-shm` inherit `0600`; both are also restricted explicitly after `migrate` when present (`:46-54`).
- `ledger_fs.rs:37` every existing segment restricted on open; new segments born `0600` (`:147-148`). Lock file `0600` (`lock.rs:30, 49-50`).
- `crates/vk-kernel/src/tasks.rs:460-471` release: export root and destination `private_dir` (0700), each released file created with `0600` and restricted after the write.
- Tests (Unix only, `/tmp` via `tempfile`): `crates/vk-store/src/lib.rs:352` `the_state_directory_and_the_files_in_it_are_private_to_the_owner` (dir chmod'ed 0755 and `vk.sqlite`, `-wal`, `-shm`, `lock`, segment chmod'ed 0644 between opens → after reopen dir `0700`, all five files `0600`); `crates/vk-kernel/src/tasks.rs:1114` `on_unix_a_release_leaves_only_owner_readable_directories_and_files` (export root pre-created 0755; after a release to `out/deep`: root, `out`, `out/deep` `0700`, released file `0600`). Output (Linux): both `... ok`; Windows: compiled out.

### I6 — I2 on task views
- `crates/vk-kernel/src/tasks.rs:147-170`: `task_row` (raw read, private), `visible_to(ctx, task)` (register label `flows_to` caller clearance; missing/unreadable register → hidden), `task(ctx, id)`; `tasks(ctx)` filters (`:270-280`); `top(ctx)` lists only visible tasks (`:482`); `run_task_step` and `approval_subject` read through `task(ctx, …)` (`:190, :301`) so a hidden task is `NotFound` and its row untouched. `crates/vk-kernel/src/ns.rs:29` `resolve(k, ctx, path)`: `/tasks` and `/tasks/<id>` filtered. `crates/vk-ipc/src/server.rs:362-437`: `ns.ls`, `task.show`, `task.ls`, `top` build the caller's `Ctx` via `ctx_for` (machine principal, the connection's clearance) — `task.show` on a hidden task is `E_NOT_FOUND`. `crates/vk-ipc/tests/roundtrip.rs:459-473` adjusted for the new signature.
- Test `crates/vk-kernel/src/tasks.rs:1019` `a_task_above_the_callers_clearance_is_absent_from_every_task_view`: a `Scope::Business` task and a bottom task created by a Personal-clearance caller; a `max_scope: Public` caller gets `task() == None`, `tasks()`/`top().tasks`/`/tasks` listing only the bottom task, `/tasks/<id>` → `NotFound`, `run_task_step` and `approval_subject` → `NotFound`; the cleared caller sees the task unchanged (row equal to the created one) in every view. Output: `... ok` on both platforms.

## Test runs

Windows (`cargo test --workspace --no-fail-fast`, exit 0):
```
vk-cli unit: test result: ok. 8 passed; 0 failed
vk-cli smoke: test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.42s
vk-contracts: test result: ok. 33 passed; examples_validate: 1 passed; schema_drift: 1 passed
vk-ipc unit: test result: ok. 3 passed; roundtrip: test result: ok. 8 passed
vk-kernel: test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.32s
vk-props: i1 2 passed; i2 2 passed; i3 1 passed; i4 4 passed
vk-store: test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s
vk-stub: test result: ok. 5 passed
```
Windows `cargo fmt --all -- --check`: exit 0. `cargo clippy --workspace --all-targets -- -D warnings`: exit 0, no diagnostics.

Linux / WSL2 Ubuntu (`cargo test --workspace --no-fail-fast`, exit 0):
```
vk-cli unit 8 passed; smoke: test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.62s
vk-contracts 33 passed; examples_validate 1; schema_drift 1
vk-ipc unit: test result: ok. 6 passed (the three Unix transport tests included); roundtrip 8 passed
vk-kernel: test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
vk-props: 2 / 2 / 1 / 4 passed
vk-store: test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
vk-stub 5 passed
```
Linux `cargo fmt --all -- --check`: exit 0. `cargo clippy --workspace --all-targets -- -D warnings`: exit 0, 0 warnings/errors.

## CI

GitHub Actions workflow `ci`, run id `35935832698` for head `2e546dc79e8487e9cf87ed4175921ff9fd415013` on `sp1-kernel` (polled with `curl` against the Actions API every 60 s; completed at poll 5, 01:58:22 local):
- `test (ubuntu-latest)` → success
- `test (windows-latest)` → success
- `test (macos-latest)` → success
- `sign` → success (scaffold step; no signing secret, as expected in SP1)

No failing step in any job. Run: https://github.com/EricLtx/VerticalAI/actions/runs/35935832698

## Minors fixed in passing
- M12: the "vkd booted" log line carries `master_key = <fingerprint>` (`crates/vkd/src/main.rs:96`; `BlobStore::master_fingerprint`, `blobs.rs:104-106`), so a replaced keyring entry is tellable from missing blobs.
- M15: a newly created ledger segment is followed by a directory fsync on Unix (`ledger_fs.rs:163-165, 204-215`; NTFS journals metadata, so no Windows equivalent).
- Both `#[allow(clippy::too_many_arguments)]` on the append functions now state their reason (the event's own seven fields in contract order). The only other `allow` is on the Windows-only test helper that clears the read-only attribute (`ledger_fs.rs`, reason stated: the lint guards a Unix mode widening).

## Deviations from the ruling's letter
- **I1 ordering**: the ruling says "serialise, write, fsync, and only then push". `Ledger` (a `vk-contracts` type, out of scope) is the only place the event hash is computed and it has no `pop`/`prepare`, so the event is computed by pushing and, on a failed write, rolled back by rebuilding the chain from the events before it (`roll_back`). Observably identical — no caller can see the chain between the push and the rollback (`&mut self`), and the test asserts `chain().len()` unchanged, later appends verify, reopen verifies. Adding a two-line `Ledger::pop` to `vk-contracts` would make the code literal; I did not touch that crate.
- **I2 head not advanced while diverged**: the ruling does not say what the boot event's own append should do to the record after a truncation is found; without this rule the second start would have reported `ledger_ok: true` (the recorded head would have become the cut chain + boot event). The head stays where it was until the chain contains it again (a backup restore) — the same "permanently marked" semantics tampering already has. Consequence: a `--force`d daemon on a cut record does not record heads for the events it appends (its record is already known not to hold).
- **I2 visibility**: `boot.info.ledger_ok` and `ledger.verify.ok` now report the boot verdict (chain **and** head) rather than a live `verify_chain()`, otherwise `vk status`/`vk ledger verify` would still have said "verifies" on a cut tail — exactly the review's reproduction. No CLI surface changed; the meaning of `ok` broadened to "the record holds".
- **I4 error kind**: `StorageError::Integrity` would change a contract type; `get` returns `anyhow::Result` with the integrity failure as its own error and `StorageError` downcastable (the convention `put` already used); the kernel maps it to `KernelError::Store`.
- **I5**: `private_dir` tightens a pre-existing directory to `0700` instead of refusing it (the ruling says "set explicitly after creation"; the review's suggestion was to refuse). No `umask(077)` at `vkd` start — every file the store writes is created with an explicit mode, and `vkd.log` (written by the CLI, out of scope) sits inside the `0700` state dir.
- **I6 scope**: besides the four views named, `run_task_step` and `approval_subject` also read through the checked `task(ctx, …)`, so a hidden task cannot be stepped, failed or probed for existence by a caller not cleared for it (every step reads the register, so nothing that could have succeeded is lost).

## Concerns for the re-review
1. Blob envelopes' `label` is not authenticated (not in the AAD, which the ruling fixed to the address only): someone with write access to `blobs/*.json` could lower a label and pass `read_artefact`'s I2 check. Same threat class as editing SQLite registers (which are plaintext) — noted, not fixed.
2. Existing SP1a dev stores: blobs sealed before this commit fail their AEAD check (no AAD) and read as `KernelError::Store` integrity failures; DEK files are unaffected (empty AAD kept). No production store exists yet.
3. The recorded head is a second copy of the truth inside the same store; an operator who restores a ledger backup *older* than the recorded head will keep getting `ledger_ok: false` until `ledger.head` is cleared by hand (no `vk` verb does that — `vk fsck`/recovery verbs are SP1b territory, per the review's recommendation 8).
4. On Unix, a daemon refused after binding (bad ledger, no `--force`) leaves its socket file behind as a stale socket; the existing live-vs-stale check removes it on the next bind, so behaviour is unchanged for callers, but it is a leftover the pre-change ordering did not create.
5. `roll_back` is O(n) in the ledger length on the (rare) failed-append path — fine at SP1a sizes (segments of 10 000), noted for when segments are many.
6. The Windows lock is released when the process object is torn down; a `vk boot` that kills a daemon by pid (`taskkill /F`) and immediately restarts could, in theory, race the handle release by microseconds. The e2e tests did not hit it (three consecutive full runs); `Daemon` in the tests reaps the child before reopening.

## Side effects on this machine
- Builds under `%USERPROFILE%\.cargo-target\verticalai-sp1` (Windows) and `~/.cargo-target/vk` (WSL) only; the worktree gained no untracked files besides this report (git-ignored).
- The tests' temp state directories leak on Windows (pre-existing deferred minor: handles still open when `TempDir` drops). I removed every `%TEMP%\.tmp*` directory that contained vk state (223, accumulated over several sessions, 47 from mine) and the `/tmp/vk-test-*` socket directories on WSL; a few created by the last confirmation runs were removed again at the end. No `vkd` process is left on either side (`tasklist` / `pgrep` clean).
- No default endpoint was ever bound and no keyring entry touched: every daemon ran on a `test_endpoint()` with file-backed keys in a temp dir.
