# The SP1 demo

A client proposal, written from a two-page brief by two models that have never
met, through one kernel register, approved by a human, released as a file —
and then run again with the two models' roles swapped, to show that the
register did not care which was which.

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo-sp1.ps1
```

That is the whole demo. It takes about twelve minutes and asks nothing of you
unless you run it with `-Approval passkey`, which is the variant where a person
holds the key.

The runs from 2026-09-25 are in `docs/demo/runs/2026-09-25/` — both orders, the
harness variant, the two proposals, the ledgers and the H1 verdict — so you can
read what it does before you spend the twelve minutes.

## What actually happens

| | |
|---|---|
| **Gemma** | `gemma4:e4b`, 8B, in an Ollama container **this kernel starts**, on loopback, capped at 12 GiB and 6 CPUs. `governed: yes`. Nothing about the call leaves the machine. |
| **Claude** | `claude-sonnet-5` to draft and `claude-opus-5` to judge, through the Claude Code installed on this machine, driven as a pure completion engine. `governed: no`, `locality: cloud`, `jurisdiction: US`. |
| **The brief** | `docs/demo/brief/acme-brief.md` — a fictional client brief from a fictional four-person food business. It is the task's *goal*, verbatim. |
| **The task** | `[Plan(A), Draft(B), Judge(B), Approve, Release out]`. |
| **The human** | `vk approve` signs a challenge **the kernel minted** for that task — never one the shell chose. That is invariant I1, and it is the only reason the artefact is allowed to leave. |
| **The file** | `<export_root>/out/<hash12>.proposal`, owner-only, plaintext, outside the encrypted tier. |

Then the same brief again, as a **new task with a new register**, with A and B
exchanged. Ten checks then ask whether H1 holds.

### H1: one register, either model in either role

The script does not take H1 on trust. It checks, from the shell alone:

1. Run 2 names both arches on **consecutive** steps (`plan`, then `draft`).
2. **Each of those two steps left a non-empty `decision` in the register**, and
   the draft's is not the plan's — and the same in run 1. This is the brief's
   own H1 check, and it is asserted, not inferred: `vk task show` reports per
   step how many decisions the register held once that step had run, how long
   the newest one is and its hash (Ruling 28). Metadata only — the text of a
   decision stays behind the register's label, where `harness.read_register` is
   the only verb that reaches it. Checks 4 and 5 then say the same thing a
   second way, from the other side, in the two models' own tokenizers.
3. Run 2's roles are the **swap** of run 1's.
4. Every inference step in both runs is `done`.
5. **The plan left a decision the drafter read (arch B).** This is the
   load-bearing one, and it is measured rather than asserted. Run 2's draft and
   run 1's plan are *the same arch* over *the same goal*; the only difference
   between the two prompts is the plan decision run 2's register carried into
   it. Prompt tokens are the arch's own count, so
   `run2.draft.tokens_in > run1.plan.tokens_in` is the local model saying, in
   its own tokenizer, that it read what the cloud model wrote into the IR.
6. **The plan left a decision the drafter read (arch A)** — the same claim in
   the other direction, in the cloud model's tokenizer:
   `run1.draft.tokens_in > run2.plan.tokens_in`.
7. **The draft left a decision the judge read**, the same way, in both runs.
8. **The draft decision is the file that was released.** A `Draft` step
   attaches `decisions.last()` byte for byte, which is why every released
   proposal begins `draft:`. A non-empty file is a non-empty decision.
9. **Run 1's register is not run 2's** — two ids.
10. **Run 1's decisions are absent from run 2's register** — two different
    artefacts, neither containing the other. The stronger statement, that each
    run released *exactly one new file*, is asserted per run as it happens
    rather than here: a `Release` step writes every artefact its register holds,
    so had anything of run 1's register been in run 2's, run 2 would have
    released two files and failed on the spot.

**On the recorded runs and check 2.** The runs in `runs/2026-09-25/` were made
before `task.show` reported `decisions`, so their `*-task.json` carries no such
field and their H1 block has nine checks, not ten. For those runs the claim rests
on checks 5–8 — the token deltas and the `draft:` prefix — which is the same
substance by a longer route. Every run from here carries the field, and the
per-step table prints it.

## Before you run it

- **Docker Desktop**, running. The script refuses early if the engine is not
  reachable.
- **The weights.** The container `vk-ollama` (image `ollama/ollama:0.33.3`,
  12 GiB, 6 CPUs) with `gemma4:e4b` — 9.6 GB — in its volume. The mount starts
  a stopped container and adopts it only when its image and *both* caps are
  exactly the ones asked for. To make one from nothing, `vk mount ollama
  --model gemma4:e4b` creates it and pulls the weights; that first pull is a
  download, not a demo.
- **Claude Code**, installed and logged in, with `claude` on the PATH
  (`claude --version` must answer). The calls run on **the founder's own
  subscription**: nothing is billed per call, and what the same calls would
  have cost on the meter is recorded beside them as `cost_list_usd`.
- **The binaries**, release-built:

  ```
  set CARGO_TARGET_DIR=%USERPROFILE%\.cargo-target\verticalai-sp1
  cargo build --release
  ```

  Building `vk-web` needs a **Windows-native Perl** (Strawberry Perl, or
  `OPENSSL_SRC_PERL` pointing at one) because the passkey verifier builds
  OpenSSL from source. See the repository README. Pass `-Bin <dir>` if the
  binaries are not under `%USERPROFILE%\.cargo-target\verticalai-sp1\release`.

The script takes nothing of yours. A fresh state directory under `%TEMP%`, a
master key and a node key in files (never the OS keyring), a private named
pipe, and an OS-chosen port for the passkey pages — so it can run beside the
daemon you already have on `\\.\pipe\vk-<you>` and port 7734 without touching
it. At the end it stops the daemon, stops the container and removes the state
directory.

## Options

```
scripts\demo-sp1.ps1 [-Roles gemma-plans|claude-plans|harness]
                     [-Model gemma4:e4b] [-Approval nodekey|passkey]
                     [-StateDir <dir>] [-Bin <dir>] [-Ctx 16384] [-Keep]
```

| | |
|---|---|
| `-Roles gemma-plans` | *(default)* run 1 Gemma plans, Claude drafts and judges; run 2 swapped. |
| `-Roles claude-plans` | the same two runs, started from the other end. |
| `-Roles harness` | one run, `[Plan(Gemma), Harness(claude-code), Judge(Gemma), Approve, Release]`. The middle step is an **agent** in the confined harness, not an arch: `vk task step` refuses it by name and `vk harness run` runs it. No swap and no H1 — a harness is not a role two models can trade. It needs `vk-mcp.exe` beside `vkd.exe` (a full `cargo build --release`), because a daemon will not launch a harness without its kernel channel. |
| `-Model gemma3:1b` | develop against this. It is small, fast and wrong, which is all a dry run needs. |
| `-Approval passkey` | the ceremony with Windows Hello instead of the node key. See below. |
| `-Keep` | leave the daemon, the container and the state directory up, to poke at: `$env:VK_ENDPOINT` is printed. |
| `-Ctx` | the window asked of Ollama. **Half of it is usable** (Ollama 0.33.3 truncates past that, so this node refuses instead), and the brief plus three decisions has to fit in that half — which is why the default is 16384 and not the 8192 a mount would otherwise take. |

## What you should see

Measured on the founder's machine (six CPUs to the container, weights already
pulled), 2026-09-25:

| | |
|---|---|
| boot and both mounts | ~5 s |
| one Gemma call | 145 s (the first, including the cold model load), then 191 s and 224 s as the register grows |
| one Claude call | 30 s (sonnet, 4.1k prompt tokens), 42 s (opus, 5.8k), 70 s (sonnet, 2.4k) |
| run with Gemma planning | 218 s — one local call, two cloud |
| run with Claude planning | 485 s — two local calls, one cloud |
| the pair, with the H1 check | ~12 min |

Three Claude calls over the pair, USD 0.23 at list price and nothing billed
(`cost_list_usd` in `*-top.json`). Nothing at all for the Gemma calls: a model
on this machine has no list price, so the record says `0.0` — the field is an
`f64`, not an optional — and the `vk top` *table* leaves the cell blank rather
than print a zero a reader could mistake for a measurement.

Each run prints its ledger tail, the file it released with its size and
SHA-256, and a per-step table: which arch ran it, the prompt tokens **the arch
itself counted**, what it left in the register, and how long the call took.
Then the ten H1 checks, then a summary. A failed H1 check fails the script.

## What this demo shows, and what it does not

It shows the mechanism. Two engines that share nothing — one in a container
this kernel caps, one on somebody else's servers — worked on one register,
in either order, and what came out was a file on disk that a human had to
approve before it was allowed to exist. Every call, every register write and
the release itself are on a hash chain that verifies.

It does not yet show the *craft*. `arch::lower` hands a model three things —
`ROLE: draft`, `GOAL: <the brief>`, and the decisions so far — and nothing at
all about what the role means. So both models read the plan decision as work
in progress and reacted to it rather than replacing it: in run 1 Claude
continued the plan, opening at "## 4."; in run 2 Gemma reviewed it and graded
it. Both are documents about the brief, both are real work, and neither is the
proposal a designer would send. That is a lowering problem, not a kernel one,
and there are two honest ways out of it: put the role instructions in
userland where the prompts belong (SP2), or — today, without touching
anything — write the instruction into the task's own goal, which is after all
where a task says what it wants. The demo deliberately does neither, so that
what you read in `runs/` is what the kernel does with a bare brief.

The harness run is the contrast, and it is worth running once for that reason
alone: `-Roles harness` gives the middle step to an agent that *is* instructed
("Read TASK.md, PLAN.md and BRIEF/. Write the proposal to OUT/proposal.md,
then call `vk_attach_artefact`…"), and out of the same brief and the same
local model's plan it writes an actual proposal — `01-harness-proposal.md`,
1 207 words, opening "# Proposal — Brand & Packaging System for Acme
Fermentation Co."

Two things that run exposes, in case they surprise you:

- **The judge after a harness step does not see what the harness wrote.**
  `arch::lower` renders the goal, constraints, evidence, decisions and open
  questions — not `artefacts`. A harness attaches its proposal to the
  register's *artefacts* and writes no decision, so the judge's prompt carries
  only the plan, and it judges the plan. In the arch path the draft *is* a
  decision, so the judge sees it.
- **A harness run's model usage was not in `vk top`** in the recorded runs.
  The harness is an agent, not an arch, so nothing bumped the per-arch
  counters: both Claude arches read `calls: 0` after a harness run, and the
  cost of the run was not on the screen that exists for cost. Fixed since
  (SP1b Task 8): a settled harness run records what its session spent, under
  the pseudo-arch `harness:claude-code`, so a fresh run shows it in `vk top`
  and `vk top --calls` names the step that spent it. The runs under
  `runs/2026-09-25/` predate that and still read `calls: 0`.

## What is recorded, and where

Under `docs/demo/runs/<date>/`, one set per run:

| file | what it is |
|---|---|
| `<n>-<order>-task.json` | `vk task show --json`: every step, its status, its **measured** `tokens` — the prompt as the arch counted it — and `decisions`, what each step left in the register (count, byte length, hash; never the text) |
| `<n>-<order>-top.json` | `vk top --json`: per arch, `calls`, `tokens_in`, `tokens_in_measured` and `cost_list_usd` |
| `<n>-<order>-dmesg.json` | `vk dmesg --json`: the whole chain, every event, with its hash and its payload hash |
| `<n>-<order>-dmesg.txt` | the last 40 events as `vk dmesg` prints them |
| `<n>-<order>-proposal.md` | the released artefact, byte for byte |
| `arches.json` | `vk ls /arches --json` after both mounts |
| `summary-<roles>.json` | the invocation's runs side by side: timings, tokens, hashes, the H1 verdict |

**Where the measured token counts live: `vk task show` and `vk top`, not
`vk dmesg`.** Two `infer` events go on the chain per model call — one when the
prompt leaves the kernel, one when the answer comes back — and the second's
payload carries `tokens_in`, `measured`, `cost_list_usd` and the arch's own
`details` (for Ollama: `prompt_eval_count`, `eval_count`, the container image
and both caps; for Claude Code: the input/cache/output token breakdown and the
API duration). But **the ledger commits to the hash of that payload, never to
the payload** — `payload_hash`, spec §3.9, "commits to ciphertext, never to
plaintext". So no number appears in `vk dmesg` and none can: what `dmesg` holds
is the *commitment* to it. The numbers themselves are read from
`vk task show` (per call) and `vk top` (per arch), which is where the saved
records carry them. Output tokens (`eval_count`, `output_tokens`) were inside
that hashed payload and on no read surface when these runs were recorded; a
per-call `usage` row now carries them (SP1b Task 8), so `vk task show` prints
an `OUT` column and `vk top --calls` a row per call. The saved
`*-task.json` and `*-top.json` predate it and have neither.

The per-call durations in the step table come off the chain rather than off
the script's clock: the two `infer` events of one call are stamped with the
wall clock of their own moment, and the difference is the call. (A step's
`started_ms` and `ended_ms` both come from the single `Ctx` the syscall was
given, so they are always equal — do not read a duration out of them.)

## The passkey ceremony, by hand

`-Approval passkey` is the variant no script can make on its own: it needs a
finger, a face or a PIN. The demo node is brand new, so it knows no passkey
yet and you enrol one first.

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo-sp1.ps1 -Approval passkey
```

1. The script boots the node, mounts both arches, and then stops and prints an
   **enrolment link** — `http://localhost:<port>/enroll?t=…`, on the port the
   OS gave this node, good for ten minutes, single use, for that page only.
2. Open it in Edge or Chrome. Press **Enrol with Windows Hello**. When the
   browser asks where to save the passkey, choose **This device**. Confirm with
   your PIN, fingerprint or face. The page prints `Enrolled passkey:…`.
3. The script sees it (`vk passkey ls`) and goes on. It runs the task to
   `waiting_human` — a few minutes — and then prints an **approval link**.
4. Open that one. It shows the task's goal and the hash of what you are about
   to approve. Press **Approve with Windows Hello** and confirm. What the
   authenticator signs is the challenge **the kernel minted**, with the WebAuthn
   challenge as its nonce; the daemon verifies the assertion in process against
   the passkey you enrolled, records the approval with `proof: webauthn` and
   the signed bytes beside it, and runs the step that was waiting. The shell
   prints `approved sha256:…`.
5. Then the second run, and a second approval link. Two ceremonies, two
   challenges, two nonces.

Things worth trying once, because they are the point:

- Open the same approval link again: **404**. Single use.
- Open `http://localhost:<port>/enroll` with no `?t=`: **404**. The pages open
  only from a link the daemon minted over its endpoint.
- Run `vk approve <task> --passkey` for a task that is not waiting: refused,
  and no link is minted.

`vk approve --passkey` waits fifteen minutes in the demo. If you miss it, the
script fails, the daemon and the container are stopped and the state directory
is removed; nothing is left behind and you start again.

## If something goes wrong

| | |
|---|---|
| `Docker's engine is not reachable` | start Docker Desktop and try again. |
| `image: it runs X, this mount asks for Y` | the `vk-ollama` container was made under other caps or another image. `vk mount ollama --model gemma4:e4b --recreate` replaces it and keeps the volume, so the weights are not downloaded again. |
| `arch <id> is starting; retry` | a container or a model load outran the mount. The task is untouched; run the script again. |
| `refusing rather than sending a mutilated prompt` | the brief plus the decisions no longer fit half the Ollama window. Raise `-Ctx`. |
| the script was killed mid-run | `tasklist /FI "IMAGENAME eq vkd.exe"` and `taskkill /F /PID <pid>`, then `docker stop vk-ollama`, then delete the `%TEMP%\vk-demo-*` directory the run printed. |

The adapter runs `claude` in one fixed empty directory under the state
directory (`claude-code-cwd`), so nothing accumulates per call. On the runs
recorded here `~/.claude/projects/` was byte-for-byte unchanged before and
after; if a future Claude Code does leave a `<mangled-cwd>/` directory there,
it is harmless and can be deleted.
