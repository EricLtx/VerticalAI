//! What the syscalls' JSON looks like to a person: fixed-width tables and
//! label/value blocks. Nothing here talks to the kernel and nothing here
//! decides anything — `--json` prints the same values unrendered, so this
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

/// `label  value` lines, labels padded to the widest.
fn fields(rows: &[(&str, String)]) -> String {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k:w$}  {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A header and its rows, every column as wide as its widest cell. The last
/// column is not padded, so no line carries trailing spaces.
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

pub fn status(v: &Value) -> String {
    let chain = if v["ledger_ok"] == Value::Bool(true) {
        "verified"
    } else {
        "BROKEN"
    };
    fields(&[
        ("node", text(&v["node_id"])),
        ("state dir", text(&v["state_dir"])),
        ("export root", text(&v["export_root"])),
        ("arches", text(&v["arches"])),
        (
            "ledger",
            format!("{} events, chain {chain}", text(&v["ledger_len"])),
        ),
    ])
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
        Some("ledger_tail") => dmesg(&v["events"]),
        Some("task") => task(v),
        _ => serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()),
    }
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
                        text(&s["calls"]),
                        text(&s["tokens_in"]),
                        text(&s["projected"]),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    out.push(if arches.is_empty() {
        "(no arch has been called)".into()
    } else {
        table(&["ARCH", "CALLS", "TOKENS", "PROJECTED"], &arches)
    });
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
                detail,
            ]
        })
        .collect::<Vec<_>>();
    format!(
        "{head}\n\n{}",
        table(&["#", "STEP", "STATUS", "TOKENS", "DETAIL"], &rows)
    )
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
    if v["already_running"] == Value::Bool(true) {
        format!("vkd is already serving on {}", text(&v["endpoint"]))
    } else {
        format!(
            "vkd running (pid {}) on {}",
            text(&v["pid"]),
            text(&v["endpoint"])
        )
    }
}

/// For the calls whose whole answer is that they worked.
pub fn ok(_: &Value) -> String {
    "ok".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn columns_are_as_wide_as_their_widest_cell_and_lines_do_not_trail() {
        let t = table(
            &["A", "LONGHEADER"],
            &[
                vec!["a-very-long-cell".into(), "x".into()],
                vec!["b".into(), "y".into()],
            ],
        );
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "A                 LONGHEADER");
        assert_eq!(lines[1], "a-very-long-cell  x");
        assert_eq!(lines[2], "b                 y");
        assert!(lines.iter().all(|l| !l.ends_with(' ')), "{t}");
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
}
