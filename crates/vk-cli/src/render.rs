//! What the syscalls' JSON looks like to a person: fixed-width tables and
//! label/value blocks. Nothing here talks to the kernel and nothing here
//! decides anything — `--json` prints the very same value unrendered, so this
//! module can never be the reason two callers disagree about what happened.
use serde_json::Value;
use std::path::Path;

/// A scalar as a cell: strings unquoted, null as a dash, anything else as its
/// compact JSON (so a surprise shape is shown rather than swallowed).
fn text(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// An arch's price per thousand prompt tokens, as its manifest states it.
///
/// Three outcomes and three glyphs, because they are three different things:
/// a number is a price, `-` is "nothing is billed" (a local model, a
/// subscription), and `?` is "this node has no price list for that arch" —
/// the Bedrock case, priced by AWS out of a table nobody here has read. A
/// `?` rendered as `0` would tell an operator their EU calls are free.
fn price(v: &Value) -> String {
    match v {
        Value::Null => "?".into(),
        _ => zeroless(v, |n| format!("{n:.4}")),
    }
}

/// A counter whose zero means "nothing was measured", shown as a dash rather
/// than as a number a reader could take for a measurement that came out at
/// zero. A missing or non-numeric field reads the same way.
fn zeroless(v: &Value, render: impl Fn(f64) -> String) -> String {
    match v.as_f64() {
        Some(n) if n != 0.0 => render(n),
        _ => "-".into(),
    }
}

/// `label  value` lines, labels padded to the widest.
fn fields(rows: &[(&str, String)]) -> String {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k:w$}  {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A header and its rows, every column as wide as its widest cell. No line
/// carries trailing whitespace: the last column is not padded, and a row whose
/// last cell is empty (an `approve` step has no detail) is trimmed rather than
/// left with the separator hanging off the end.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    let line = |cells: Vec<String>| {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c.clone()
                } else {
                    format!("{c:w$}", w = widths.get(i).copied().unwrap_or(0))
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = line(headers.iter().map(|h| (*h).to_string()).collect());
    for row in rows {
        out.push('\n');
        out.push_str(&line(row.clone()));
    }
    out
}

fn array<'a>(v: &'a Value, field: &str) -> &'a [Value] {
    v[field].as_array().map_or(&[], |a| a.as_slice())
}

/// A step's status: `"done"`, or the one-key object a `failed` status is.
fn step_status(v: &Value) -> String {
    match v {
        Value::Object(o) => o
            .iter()
            .next()
            .map(|(k, why)| format!("{k}: {}", text(why)))
            .unwrap_or_else(|| "-".into()),
        other => text(other),
    }
}

/// What this node is and what its boot sequence found. The two conditions a
/// person has to be told about — a chain that does not verify, an event lost
/// to a crash mid-append — are lines of their own, because a caller who reads
/// this screen has read everything the node will volunteer.
pub fn status(v: &Value) -> String {
    let chain = if v["ledger_ok"] == Value::Bool(true) {
        "verified"
    } else {
        "BROKEN"
    };
    // Set for this run only, by `record_forced_boot`: an operator overrode a
    // refusal, and the chain line is where a reader already looks for the
    // verdict it overrode.
    let forced = if v["forced"] == Value::Bool(true) {
        ", forced boot"
    } else {
        ""
    };
    let stopped = array(v, "stopped_scopes");
    let mut rows = vec![
        ("node", text(&v["node_id"])),
        ("state dir", text(&v["state_dir"])),
        ("export root", text(&v["export_root"])),
        ("arches", arch_count(v)),
        ("devices", text(&v["devices"])),
        // Where the passkey pages are, or that there are none: the person
        // who runs `vk passkey enroll` next should not have to guess.
        (
            "web",
            match v["web"].as_str() {
                Some(origin) => origin.to_string(),
                None => "none (vkd --web-port)".into(),
            },
        ),
        (
            "ledger",
            format!("{} events, chain {chain}{forced}", text(&v["ledger_len"])),
        ),
        (
            "policies",
            match v["policies_version"].as_str() {
                Some(version) => format!("version {version}"),
                // A node that has never booted: the boot sequence is what
                // writes the version down.
                None => "none recorded".into(),
            },
        ),
        (
            "stopped",
            if stopped.is_empty() {
                "nothing".into()
            } else {
                stopped.iter().map(text).collect::<Vec<_>>().join(", ")
            },
        ),
    ];
    if v["recovered_partial_line"] == Value::Bool(true) {
        rows.push((
            "recovered",
            "an unterminated last ledger line was dropped at boot".into(),
        ));
    }
    fields(&rows)
}

/// How many arches this node has, and how many of them cannot run (SP1b
/// ruling 14). A bare count would let `vk status` say "arches: 2" on a morning
/// when neither of them would answer a prompt — which is the morning somebody
/// most needs to be told.
fn arch_count(v: &Value) -> String {
    let total = text(&v["arches"]);
    let counted = |state: &str| {
        array(v, "arch_states")
            .iter()
            .filter(|a| a["state"] == Value::String(state.into()))
            .count()
    };
    let notes: Vec<String> = [
        ("unavailable", counted("unavailable")),
        ("starting", counted("starting")),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(what, n)| format!("{n} {what}"))
    .collect();
    if notes.is_empty() {
        total
    } else {
        format!("{total} ({})", notes.join(", "))
    }
}

/// The end of a daemon's log, quoted back at the person who started it.
///
/// A `vkd` that refuses to serve says why on its way out, into
/// `<state_dir>/vkd.log`, because it is detached and has no terminal. When the
/// shell that started it has to report the failure, the daemon's own last
/// words are the answer — naming a file to go and read is not.
///
/// The colour codes go: the subscriber writes them without knowing its output
/// is a file, and an operator should not have to see them to read the reason.
pub fn log_tail(contents: &str, lines: usize) -> String {
    let plain: Vec<String> = contents
        .lines()
        .map(uncoloured)
        .filter(|l| !l.trim().is_empty())
        .collect();
    plain[plain.len().saturating_sub(lines)..]
        .iter()
        .map(|l| format!("    {}", l.trim_end()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One line with its ANSI escape sequences removed.
fn uncoloured(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // CSI: `ESC [`, parameter and intermediate bytes, then a final byte in
        // `@`..=`~` that ends the sequence.
        if chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// A namespace entry. A directory is its listing; a ledger path is a dmesg
/// table; anything else is the object itself, which is what a reader of
/// `/arches/<id>` or `/tasks/<id>` came for.
pub fn ls(v: &Value) -> String {
    match v["type"].as_str() {
        Some("dir") => {
            let entries = array(v, "entries");
            if entries.is_empty() {
                "(empty)".into()
            } else {
                entries.iter().map(text).collect::<Vec<_>>().join("\n")
            }
        }
        Some("arches") => arches(&v["arches"]),
        Some("ledger_tail") => dmesg(&v["events"]),
        Some("task") => task(v),
        _ => serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()),
    }
}

/// `/arches`: what this node has mounted, and which of them would answer a
/// prompt right now (SP1b ruling 14). An unavailable arch is on the screen
/// with its reason, because it is the one an operator has to act on.
fn arches(v: &Value) -> String {
    let arches = v.as_array().map_or(&[][..], |a| a.as_slice());
    if arches.is_empty() {
        return "(no arch is mounted)".into();
    }
    let rows: Vec<Vec<String>> = arches
        .iter()
        .map(|a| {
            vec![
                text(&a["arch_id"]),
                text(&a["name"]),
                text(&a["state"]),
                a["reason"].as_str().unwrap_or("-").to_string(),
            ]
        })
        .collect();
    table(&["ARCH", "NAME", "STATE", "WHY"], &rows)
}

/// Tasks and how far each has got.
pub fn ps(v: &Value) -> String {
    let tasks = v.as_array().map_or(&[][..], |a| a.as_slice());
    if tasks.is_empty() {
        return "(no tasks)".into();
    }
    let rows = tasks
        .iter()
        .map(|t| {
            let steps = array(t, "steps");
            let done = steps.iter().filter(|s| s["status"] == "done").count();
            vec![
                text(&t["id"]),
                text(&t["status"]),
                format!("{done}/{}", steps.len()),
                text(&t["goal"]),
            ]
        })
        .collect::<Vec<_>>();
    table(&["TASK", "STATUS", "STEPS", "GOAL"], &rows)
}

/// The operator's screen: what the arches have cost, what the tasks are doing,
/// what is stopped and how long each business may act unattended.
pub fn top(v: &Value) -> String {
    let mut out = Vec::new();
    let arches: Vec<Vec<String>> = v["arches"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(id, s)| {
                    vec![
                        id.clone(),
                        // Would a prompt sent to it be answered? A dash for
                        // an arch that is no longer mounted — its counters
                        // outlive it — and `unavailable` for one whose engine
                        // this node could not bring back (Ruling 14).
                        v["states"][id].as_str().unwrap_or("-").to_string(),
                        // Is the inference a process this kernel started and
                        // capped? A dash for an arch that is no longer
                        // mounted: its counters outlive it, its governance
                        // does not (spec §3.3).
                        match v["governed"][id].as_bool() {
                            Some(true) => "yes".into(),
                            Some(false) => "no".into(),
                            None => "-".to_string(),
                        },
                        text(&s["calls"]),
                        text(&s["tokens_in"]),
                        // How much of TOKENS the arch itself counted. A dash
                        // where an arch reports no usage, so an estimate is
                        // never mistaken for a figure anyone could bill.
                        zeroless(&s["tokens_in_measured"], |n| format!("{n:.0}")),
                        zeroless(&s["cost_list_usd"], |c| format!("{c:.5}")),
                        // The manifest's own price tag, which is a different
                        // thing from the cost column beside it: that one is
                        // what the calls *did* cost, this is what the arch
                        // charges. `?` where the node has no price list for
                        // the arch — never `0`, which would read as free
                        // (Ruling 30).
                        price(&v["price_eur_per_1k"][id]),
                        text(&s["projected"]),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    out.push(if arches.is_empty() {
        "(no arch is mounted)".into()
    } else {
        table(
            &[
                "ARCH",
                "STATE",
                "GOVERNED",
                "CALLS",
                "TOKENS",
                "MEASURED",
                "COST (LIST USD)",
                "EUR/1K",
                "PROJECTED",
            ],
            &arches,
        )
    });
    // Why, under the table rather than in it: a reason is a sentence and a
    // sentence in a column makes every other column unreadable.
    if let Some(down) = v["unavailable"].as_object().filter(|m| !m.is_empty()) {
        for (id, why) in down {
            out.push(format!("{id} is unavailable: {}", text(why)));
        }
    }
    let tasks: Vec<Vec<String>> = v["tasks"]
        .as_object()
        .map(|m| m.iter().map(|(id, s)| vec![id.clone(), text(s)]).collect())
        .unwrap_or_default();
    if !tasks.is_empty() {
        out.push(table(&["TASK", "STATUS"], &tasks));
    }
    let stopped = array(v, "stopped_scopes");
    out.push(if stopped.is_empty() {
        "stopped scopes: none".into()
    } else {
        format!(
            "stopped scopes: {}",
            stopped.iter().map(text).collect::<Vec<_>>().join(", ")
        )
    });
    if let Some(liveness) = v["liveness"].as_object().filter(|m| !m.is_empty()) {
        let rows = liveness
            .iter()
            .map(|(b, exp)| vec![b.clone(), text(exp)])
            .collect::<Vec<_>>();
        out.push(table(&["BUSINESS", "UNATTENDED UNTIL (ms)"], &rows));
    }
    out.join("\n\n")
}

/// The ledger tail. Hashes are shown by their first 12 hex digits, which is
/// what a person compares; `--json` has them whole.
pub fn dmesg(v: &Value) -> String {
    let events = v.as_array().map_or(&[][..], |a| a.as_slice());
    if events.is_empty() {
        return "(no events)".into();
    }
    let rows = events
        .iter()
        .map(|e| {
            vec![
                text(&e["seq"]),
                text(&e["kind"]),
                text(&e["wall_ms"]),
                short(&text(&e["hash"])),
            ]
        })
        .collect::<Vec<_>>();
    table(&["SEQ", "KIND", "WALL_MS", "HASH"], &rows)
}

fn short(hash: &str) -> String {
    let hex = hash.trim_start_matches("sha256:");
    hex.get(..12).unwrap_or(hex).to_string()
}

/// One task: what it is, and every step with what it is waiting on. A release
/// step shows the path its artefacts are written to, resolved under the
/// kernel's export root by the caller (`release_paths`).
pub fn task(v: &Value) -> String {
    let head = fields(&[
        ("task", text(&v["id"])),
        ("goal", text(&v["goal"])),
        ("artefact", text(&v["artefact_type"])),
        ("status", text(&v["status"])),
        ("register", text(&v["register"])),
    ]);
    let steps = array(v, "steps");
    if steps.is_empty() {
        return head;
    }
    let mut releases = array(v, "release_paths").iter();
    let decisions = array(v, "decisions");
    let rows = steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let kind = &s["kind"];
            let detail = match kind["kind"].as_str() {
                Some("release") => releases
                    .next()
                    .map(text)
                    .unwrap_or_else(|| text(&kind["to_dir"])),
                Some("harness") => text(&kind["name"]),
                Some("approve") => String::new(),
                _ => text(&kind["arch_id"]),
            };
            vec![
                (i + 1).to_string(),
                text(&kind["kind"]),
                step_status(&s["status"]),
                text(&s["tokens"]),
                decisions_cell(decisions, i),
                detail,
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "{head}\n\n{}",
        table(
            &["#", "STEP", "STATUS", "TOKENS", "DECISIONS", "DETAIL"],
            &rows
        )
    )
}

/// What the register's `decisions` held once step `i` had run: `<count> (<n> B)`
/// — how many there were and how long the newest one is (Ruling 28). Never the
/// decision itself: `task.show` reports a count, a length and a hash, and the
/// text stays behind the register's label. A step that raises no decision, or a
/// step that has not run, gets a dash.
fn decisions_cell(decisions: &[Value], i: usize) -> String {
    decisions
        .iter()
        .find(|d| d["after_step"].as_u64() == Some(i as u64))
        .map(|d| format!("{} ({} B)", text(&d["count"]), text(&d["last_len_bytes"])))
        .unwrap_or_else(|| "-".into())
}

/// Where a task's release steps write, resolved under the kernel's export root.
pub fn release_paths(task: &Value, export_root: &str) -> Vec<String> {
    let root = Path::new(export_root);
    array(task, "steps")
        .iter()
        .map(|s| &s["kind"])
        .filter(|k| k["kind"] == "release")
        .filter_map(|k| k["to_dir"].as_str())
        .map(|dir| root.join(dir).display().to_string())
        .collect()
}

pub fn mounted(v: &Value) -> String {
    text(&v["arch_id"])
}

/// One arch, as `vk mount ollama` mounts it: what it is, the id every other
/// verb takes, and whether the kernel contains the process behind it — which
/// is the whole difference between a local model and a remote one, and the
/// first thing the person who just mounted it should see.
pub fn mounted_arch(v: &Value) -> String {
    let governed = match v["governed"].as_bool() {
        Some(true) => "yes",
        Some(false) => "no",
        None => "-",
    };
    let mut out = table(
        &["ARCH", "ID", "GOVERNED"],
        &[vec![
            text(&v["name"]),
            text(&v["arch_id"]),
            governed.to_string(),
        ]],
    );
    // Mounting an arch that is already there is a success, not a surprise —
    // and saying so is what keeps a person from re-running it harder
    // (Ruling 13).
    if v["already_mounted"] == Value::Bool(true) {
        out.push_str("\nalready mounted; this arch was left exactly as it was");
    }
    out
}

/// One arch per role, as `vk mount claude-code` mounts them: the role it is
/// for, what it is, and the id every other verb takes.
pub fn mounted_roles(v: &Value) -> String {
    let rows = ["draft", "judge"]
        .iter()
        .map(|role| {
            vec![
                (*role).to_string(),
                text(&v[role]["name"]),
                text(&v[role]["arch_id"]),
            ]
        })
        .collect::<Vec<_>>();
    table(&["ROLE", "ARCH", "ID"], &rows)
}

/// `vk secret set`: the name it was stored under, and nothing else. The
/// value is never rendered — not here, not anywhere.
pub fn secret_set(v: &Value) -> String {
    format!(
        "stored in this account's keyring as {}/{}",
        text(&v["service"]),
        text(&v["name"])
    )
}

pub fn stopped(v: &Value) -> String {
    format!("stopped; resume with: vk resume {}", text(&v["stop_id"]))
}

pub fn verified(v: &Value) -> String {
    let verdict = if v["ok"] == Value::Bool(true) {
        "verifies"
    } else {
        "DOES NOT VERIFY"
    };
    format!("{} events, chain {verdict}", text(&v["len"]))
}

pub fn booted(v: &Value) -> String {
    let where_ = format!(
        "on {} serving {}",
        text(&v["endpoint"]),
        text(&v["state_dir"])
    );
    // The node answers from the moment it says this; its arches may still be
    // being re-created behind it, and a step that names one of those is told
    // to retry rather than failed. Saying so here is what stops that reading
    // as a fault (Task 1b review, Important 1).
    let starting = match v["arches_starting"].as_u64().unwrap_or(0) {
        0 => String::new(),
        1 => "; 1 arch starting".into(),
        n => format!("; {n} arches starting"),
    };
    if v["already_running"] == Value::Bool(true) {
        format!("vkd is already running {where_}{starting}")
    } else {
        format!("vkd running (pid {}) {where_}{starting}", text(&v["pid"]))
    }
}

/// An approval is recorded, not applied: the step that was waiting for it only
/// moves when the task is stepped again, so say so.
pub fn approved(v: &Value) -> String {
    // The passkey page runs the step that was waiting, so the task has moved
    // on by the time this prints; the device-key ceremony records only, and
    // says what has to happen next.
    match v["status"].as_str() {
        Some(status) => format!(
            "approved {}\ntask {} is {status}",
            text(&v["subject_hash"]),
            text(&v["task_id"])
        ),
        None => format!(
            "approved {}\nrun `vk task step {} --all` to continue",
            text(&v["subject_hash"]),
            text(&v["task_id"])
        ),
    }
}

/// A link into the passkey pages, and what to do with it.
pub fn link(v: &Value) -> String {
    let url = text(&v["url"]);
    if v["waiting"] == Value::Bool(true) {
        format!("approve in the browser: {url}\nwaiting for the passkey…")
    } else if v["opened"] == Value::Bool(true) {
        format!("enrol in the browser (opened): {url}")
    } else {
        format!("enrol in the browser: {url}")
    }
}

/// `vk passkey ls`: one line per enrolled passkey.
pub fn passkeys(v: &Value) -> String {
    let rows = v
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    vec![
                        text(&p["device_id"]),
                        p["enrolled_ms"]
                            .as_u64()
                            .map(|ms| format!("{ms}"))
                            .unwrap_or_else(|| "-".into()),
                    ]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        "no passkey enrolled; run `vk passkey enroll`".into()
    } else {
        table(&["DEVICE", "ENROLLED (ms)"], &rows)
    }
}

/// For the calls whose whole answer is that they worked.
pub fn ok(_: &Value) -> String {
    "ok".into()
}

/// A `--dry-run` of `vk harness run`: the launch line and the `.mcp.json` it
/// would write, the token already redacted by the daemon.
pub fn harness_dry_run(v: &Value) -> String {
    let line = v["launch_line"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    let s = text(x);
                    if s.contains(' ') {
                        format!("\"{s}\"")
                    } else {
                        s
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| "-".into());
    format!(
        "dry run for task {}\nworkspace: {}\n\nlaunch line:\n{}\n\n.mcp.json:\n{}",
        text(&v["task_id"]),
        text(&v["workspace"]),
        line,
        text(&v["mcp_json"]),
    )
}

/// The result of a harness run: how it ended, whether the kernel contained it,
/// what it talked to, and the artefact it left.
pub fn harness_run(v: &Value) -> String {
    let connections = match v["connections"].as_array() {
        Some(a) if !a.is_empty() => a.iter().map(text).collect::<Vec<_>>().join(", "),
        _ => "(none observed)".into(),
    };
    let governed = if v["governed"] == Value::Bool(true) {
        "yes"
    } else {
        "no"
    };
    let mut rows = vec![
        ("task", text(&v["task_id"])),
        ("status", text(&v["status"])),
        ("exit", text(&v["exit"])),
        ("governed", governed.into()),
        ("egress", connections),
        ("samples", format!("{} (every 500 ms)", text(&v["samples"]))),
        ("duration", format!("{} ms", text(&v["duration_ms"]))),
        ("artefact", text(&v["artefact_hash"])),
    ];
    if let Some(err) = v["error"].as_str() {
        rows.push(("error", err.into()));
    }
    fields(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The three states of an arch's price, and the three glyphs that must
    /// stay distinct (Ruling 30). A `?` printed as `0` would tell an operator
    /// that an arch whose price this node does not know is free, which is the
    /// Bedrock case and is the whole reason the field is an `Option`.
    #[test]
    fn a_price_is_a_number_a_dash_for_free_or_a_question_mark_for_unknown() {
        // No price list for this arch: the manifest said `None`.
        assert_eq!(price(&Value::Null), "?");
        // Nothing is billed: a local model, or a subscription.
        assert_eq!(price(&json!(0.0)), "-");
        // A price, to four places, because these are thousandths of a euro.
        assert_eq!(price(&json!(0.0046)), "0.0046");
        assert_eq!(price(&json!(0.01)), "0.0100");
        // An arch with counters but no entry at all reads as unknown rather
        // than as free: `v["price_eur_per_1k"][id]` on a missing key is Null.
        assert_eq!(price(&json!({})["nope"]), "?");
    }

    /// And the column the operator actually reads carries them.
    #[test]
    fn vk_top_shows_the_manifests_price_beside_what_the_calls_cost() {
        let rendered = top(&json!({
            "arches": {
                "sha256:eu": {"calls": 0, "tokens_in": 0, "tokens_in_measured": 0,
                               "cost_list_usd": 0.0, "projected": 0},
                "sha256:us": {"calls": 2, "tokens_in": 100, "tokens_in_measured": 100,
                               "cost_list_usd": 0.5, "projected": 0},
            },
            "states": {"sha256:eu": "ready", "sha256:us": "ready"},
            "governed": {"sha256:eu": false, "sha256:us": false},
            // The EU arch is priced by AWS out of a list this node has not
            // read; the US one is in the table.
            "price_eur_per_1k": {"sha256:eu": null, "sha256:us": 0.0046},
            "tasks": {}, "stopped_scopes": [], "liveness": {},
        }));
        let eu = rendered
            .lines()
            .find(|l| l.starts_with("sha256:eu"))
            .expect("a row for the EU arch");
        assert!(
            eu.contains(" ? "),
            "the unknown price must read `?`: {eu:?}"
        );
        assert!(!eu.contains(" 0.0000 "), "and never as free: {eu:?}");
        let us = rendered
            .lines()
            .find(|l| l.starts_with("sha256:us"))
            .expect("a row for the US arch");
        assert!(us.contains("0.0046"), "{us:?}");
        assert!(rendered.contains("EUR/1K"), "{rendered}");
    }

    #[test]
    fn columns_are_as_wide_as_their_widest_cell_and_lines_do_not_trail() {
        let t = table(
            &["A", "LONGHEADER"],
            &[
                vec!["a-very-long-cell".into(), "x".into()],
                vec!["b".into(), "y".into()],
                // An `approve` step has no detail: the row must end at the
                // last cell that has something in it, not at the separator.
                vec!["c".into(), String::new()],
            ],
        );
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "A                 LONGHEADER");
        assert_eq!(lines[1], "a-very-long-cell  x");
        assert_eq!(lines[2], "b                 y");
        assert_eq!(lines[3], "c");
        for l in &lines {
            assert_eq!(*l, l.trim_end(), "trailing whitespace in {l:?}");
        }
    }

    /// What `vk status` volunteers about the boot sequence. The two bad
    /// conditions have to be visible without `--json`, and the good one must
    /// not read like a warning: a node with nothing wrong says so in words a
    /// person can stop reading at.
    #[test]
    fn status_says_what_boot_found() {
        let node = |ledger_ok, recovered, stopped: Value| {
            super::status(&json!({
                "node_id": "node-1", "state_dir": "S", "export_root": "E",
                "arches": 1, "devices": 2, "ledger_len": 18,
                "policies_version": "0",
                "ledger_ok": ledger_ok,
                "recovered_partial_line": recovered,
                "stopped_scopes": stopped,
            }))
        };

        // `label<pad>  value`, read back by label.
        let value = |rendered: &str, label: &str| {
            rendered
                .lines()
                .find_map(|l| l.split_once("  ").filter(|(k, _)| k.trim_end() == label))
                .map(|(_, v)| v.trim_start().to_string())
        };

        let healthy = node(true, false, json!([]));
        assert_eq!(
            value(&healthy, "ledger").as_deref(),
            Some("18 events, chain verified"),
            "{healthy}"
        );
        assert_eq!(value(&healthy, "stopped").as_deref(), Some("nothing"));
        assert_eq!(value(&healthy, "recovered"), None, "{healthy}");
        assert_eq!(
            value(&healthy, "devices").as_deref(),
            Some("2"),
            "{healthy}"
        );
        // The placeholder is reported, not hidden: the first real policy set
        // migrates from a version somebody can read.
        assert_eq!(
            value(&healthy, "policies").as_deref(),
            Some("version 0"),
            "{healthy}"
        );
        let unbooted = super::status(&json!({"node_id": "node-1", "ledger_len": 0}));
        assert_eq!(
            value(&unbooted, "policies").as_deref(),
            Some("none recorded"),
            "{unbooted}"
        );

        let damaged = node(false, true, json!(["node", "business:acme"]));
        assert_eq!(
            value(&damaged, "ledger").as_deref(),
            Some("18 events, chain BROKEN"),
            "{damaged}"
        );
        assert_eq!(
            value(&damaged, "stopped").as_deref(),
            Some("node, business:acme"),
            "{damaged}"
        );
        assert!(
            value(&damaged, "recovered")
                .is_some_and(|v| v.starts_with("an unterminated last ledger line")),
            "{damaged}"
        );
    }

    /// `record_forced_boot`'s marker, read back on the same line a person
    /// already checks for the chain's own verdict — not a separate row that
    /// a reader stopping at "ledger" would miss.
    #[test]
    fn status_marks_a_forced_boot_next_to_the_chain_line() {
        let value = |rendered: &str, label: &str| {
            rendered
                .lines()
                .find_map(|l| l.split_once("  ").filter(|(k, _)| k.trim_end() == label))
                .map(|(_, v)| v.trim_start().to_string())
        };
        let base = json!({
            "node_id": "node-1", "state_dir": "S", "export_root": "E",
            "arches": 0, "devices": 0, "ledger_len": 3,
            "policies_version": "0", "ledger_ok": false,
            "recovered_partial_line": false, "stopped_scopes": [],
        });

        let mut forced = base.clone();
        forced["forced"] = json!(true);
        assert_eq!(
            value(&super::status(&forced), "ledger").as_deref(),
            Some("3 events, chain BROKEN, forced boot"),
        );

        // Absent, exactly as every existing daemon's answer has it until it
        // rebuilds, reads no differently from an explicit `false`.
        assert_eq!(
            value(&super::status(&base), "ledger").as_deref(),
            Some("3 events, chain BROKEN"),
        );
        let mut not_forced = base.clone();
        not_forced["forced"] = json!(false);
        assert_eq!(
            value(&super::status(&not_forced), "ledger").as_deref(),
            Some("3 events, chain BROKEN"),
        );
    }

    /// What a detached daemon's last words look like when the shell that
    /// started it has to quote them: the reason, not the escape codes a
    /// subscriber wrote into a file it thought was a terminal.
    #[test]
    fn a_log_tail_is_the_reason_without_the_colour_codes() {
        let log = "\u{1b}[2m2026-09-23T22:03:16Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m vkd booted\n\
                   \n\
                   Error: the ledger chain does not verify: pass --force\n";
        assert_eq!(
            super::log_tail(log, 6),
            "    2026-09-23T22:03:16Z  INFO vkd booted\n\
             \x20   Error: the ledger chain does not verify: pass --force"
        );
        // Only the tail, and an empty log is not a panic.
        assert_eq!(
            super::log_tail(log, 1),
            "    Error: the ledger chain does not verify: pass --force"
        );
        assert_eq!(super::log_tail("", 4), "");
    }

    #[test]
    fn a_release_step_shows_where_it_writes() {
        let task = json!({
            "id": "task-1", "goal": "g", "artefact_type": "proposal",
            "status": "queued", "register": "reg-1",
            "steps": [
                {"kind": {"kind": "draft", "arch_id": "arch-9"}, "status": "done", "tokens": 12},
                {"kind": {"kind": "release", "to_dir": "out"}, "status": "pending", "tokens": 0},
            ],
        });
        let paths = release_paths(&task, "/exports");
        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("out"), "{paths:?}");

        let mut with_paths = task.clone();
        with_paths["release_paths"] = json!(paths);
        let rendered = super::task(&with_paths);
        assert!(rendered.contains("arch-9"), "{rendered}");
        assert!(rendered.contains(&paths[0]), "{rendered}");
        // Without them, the step still says where it was asked to write.
        assert!(super::task(&task).contains("out"));
    }

    /// Ruling 28: the per-step `decisions` summary is on the screen a person
    /// reads, not only in `--json`. A count and a length, never the text, and a
    /// dash for the steps that raised nothing.
    #[test]
    fn a_step_shows_what_it_left_in_the_register() {
        let task = json!({
            "id": "task-1", "goal": "g", "artefact_type": "proposal",
            "status": "waiting_human", "register": "reg-1",
            "steps": [
                {"kind": {"kind": "plan", "arch_id": "arch-a"}, "status": "done", "tokens": 1414},
                {"kind": {"kind": "draft", "arch_id": "arch-b"}, "status": "done", "tokens": 4108},
                {"kind": {"kind": "approve"}, "status": "waiting_human", "tokens": 0},
            ],
            "decisions": [
                {"after_step": 0, "count": 1, "last_len_bytes": 1847, "last_hash": "sha256:aa"},
                {"after_step": 1, "count": 2, "last_len_bytes": 4772, "last_hash": "sha256:bb"},
            ],
        });
        let rendered = super::task(&task);
        assert!(rendered.contains("DECISIONS"), "{rendered}");
        assert!(rendered.contains("1 (1847 B)"), "{rendered}");
        assert!(rendered.contains("2 (4772 B)"), "{rendered}");
        // The approve step raised nothing, so it claims nothing.
        assert!(
            rendered
                .lines()
                .any(|l| l.contains("approve") && l.contains('-')),
            "{rendered}"
        );
        // A task from a daemon that does not send the field still renders.
        let mut bare = task.clone();
        bare.as_object_mut().unwrap().remove("decisions");
        assert!(super::task(&bare).contains("arch-a"));
    }

    /// An unavailable arch is on every screen an operator reads, with its
    /// reason (SP1b ruling 14). The listing carries the column; `top` carries
    /// it too, and puts the sentence under the table where a sentence can be
    /// read without wrecking every other column.
    #[test]
    fn an_unavailable_arch_is_on_the_listing_and_on_the_operators_screen() {
        // Columns are padded to their widest cell, so a row is compared by its
        // cells rather than by the spacing between them.
        let cells = |rendered: &str, n: usize| -> Vec<String> {
            rendered
                .lines()
                .nth(n)
                .expect("that many lines")
                .split("  ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect()
        };
        let listing = json!({
            "type": "arches",
            "arches": [
                {"arch_id": "sha256:aaa", "name": "ollama/gemma3:1b", "state": "ready"},
                {"arch_id": "sha256:bbb", "name": "claude-code/claude-opus-5",
                 "state": "unavailable", "reason": "cannot run `claude --version`"},
            ],
        });
        let screen = super::ls(&listing);
        assert_eq!(cells(&screen, 0), ["ARCH", "NAME", "STATE", "WHY"]);
        assert_eq!(
            cells(&screen, 1),
            ["sha256:aaa", "ollama/gemma3:1b", "ready", "-"],
            "{screen}"
        );
        assert_eq!(
            cells(&screen, 2),
            [
                "sha256:bbb",
                "claude-code/claude-opus-5",
                "unavailable",
                "cannot run `claude --version`",
            ],
            "{screen}"
        );

        let top = json!({
            "arches": {"sha256:bbb": {"calls": 0, "tokens_in": 0, "tokens_in_measured": 0,
                                      "cost_list_usd": 0.0, "projected": 0}},
            "governed": {"sha256:bbb": true},
            "states": {"sha256:bbb": "unavailable"},
            "unavailable": {"sha256:bbb": "cannot run `claude --version`"},
            "tasks": {}, "stopped_scopes": [], "liveness": {},
        });
        let screen = super::top(&top);
        assert_eq!(cells(&screen, 0)[..3], ["ARCH", "STATE", "GOVERNED"]);
        assert_eq!(
            cells(&screen, 1)[..3],
            ["sha256:bbb", "unavailable", "yes"],
            "{screen}"
        );
        assert!(
            screen.contains("sha256:bbb is unavailable: cannot run `claude --version`"),
            "the reason belongs under the table, where a sentence fits:\n{screen}"
        );

        // An arch with counters but no state is one that has been unmounted
        // since: a dash, not a claim that it is ready.
        let unmounted = json!({
            "arches": {"sha256:ccc": {"calls": 3, "tokens_in": 9, "tokens_in_measured": 0,
                                      "cost_list_usd": 0.0, "projected": 0}},
            "governed": {}, "states": {}, "unavailable": {},
            "tasks": {}, "stopped_scopes": [], "liveness": {},
        });
        let screen = super::top(&unmounted);
        assert_eq!(cells(&screen, 1)[..3], ["sha256:ccc", "-", "-"], "{screen}");
    }

    /// `vk status` counts the arches a node has, and says how many of them
    /// would refuse a prompt — a bare "arches: 2" on a node where neither
    /// works is the number that gets somebody through a whole morning before
    /// they find out.
    #[test]
    fn status_says_how_many_arches_cannot_run() {
        // `label<pad>  value`, read back by label.
        let value = |rendered: &str, label: &str| {
            rendered
                .lines()
                .find_map(|l| l.split_once("  ").filter(|(k, _)| k.trim_end() == label))
                .map(|(_, v)| v.trim_start().to_string())
        };
        let node = |states: Value| {
            json!({
                "node_id": "n1", "state_dir": "/s", "export_root": "/s/exports",
                "arches": 2, "arch_states": states, "devices": 1, "ledger_len": 9,
                "ledger_ok": true, "forced": false, "recovered_partial_line": false,
                "stopped_scopes": [], "policies_version": "0",
            })
        };
        let all_up = node(json!([
            {"arch_id": "sha256:aaa", "state": "ready"},
            {"arch_id": "sha256:bbb", "state": "ready"},
        ]));
        assert_eq!(
            value(&super::status(&all_up), "arches").as_deref(),
            Some("2")
        );
        let one_down = node(json!([
            {"arch_id": "sha256:aaa", "state": "ready"},
            {"arch_id": "sha256:bbb", "state": "unavailable", "reason": "no engine"},
        ]));
        assert_eq!(
            value(&super::status(&one_down), "arches").as_deref(),
            Some("2 (1 unavailable)")
        );
    }
}
