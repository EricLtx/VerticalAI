//! Arch adapters (spec §3.7) and IR lowering/raising (spec §3.2).
use std::collections::BTreeSet;
use vk_contracts::arch::ArchManifest;
use vk_contracts::register::Register;

/// What an arch hands back from one call: the text, plus whatever that arch
/// measured about the call itself.
///
/// Only an arch that the provider tells can report the last two, so they are
/// optional and the mock leaves them unset (SP1b ruling 3). They exist because
/// the kernel's own numbers are estimates — `count_tokens` is a heuristic on
/// every adapter that has no tokenizer to ask — while these are what the call
/// actually was, and a record that can carry the measurement should not settle
/// for the guess. The kernel merges them into the `infer` event's payload, so
/// what the ledger commits to for a real call includes its measured cost and
/// token breakdown.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Completion {
    /// The completion itself — what `raise` puts back into the register.
    pub text: String,
    /// List-price equivalent in USD, as the provider reported it. Under a
    /// subscription nothing is billed per call, so this is what the same call
    /// would have cost on the meter, not a charge; the manifest's
    /// `cost_per_1k_tokens_eur` stays 0 and this is the honest number beside it.
    pub cost_list_usd: Option<f64>,
    /// Arch-specific measurements of the call (token breakdown, timings, the
    /// provider's own id for it). Free-form on purpose: it is payload, not a
    /// contract type, and every arch measures something different.
    pub details: Option<serde_json::Value>,
}

impl Completion {
    /// A completion from an arch that measured nothing — the text alone.
    pub fn text(text: impl Into<String>) -> Completion {
        Completion {
            text: text.into(),
            cost_list_usd: None,
            details: None,
        }
    }
}

pub trait ArchAdapter: Send + Sync {
    fn manifest(&self) -> &ArchManifest;
    /// Real context budget in tokens (I4'); adapters must report what is actually loaded.
    fn context_budget(&self) -> u32;
    fn count_tokens(&self, text: &str) -> u32;
    fn complete(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<Completion>;
}

pub struct MockAdapter {
    pub manifest: ArchManifest,
    pub budget: u32,
}

impl ArchAdapter for MockAdapter {
    fn manifest(&self) -> &ArchManifest {
        &self.manifest
    }
    fn context_budget(&self) -> u32 {
        self.budget
    }
    fn count_tokens(&self, text: &str) -> u32 {
        (text.len() / 4) as u32 + 1
    }
    fn complete(&self, prompt: &str, _max_tokens: u32) -> anyhow::Result<Completion> {
        let role = prompt
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("ROLE: ")
            .to_uppercase();
        let body: String = prompt.chars().take(200).collect();
        Ok(Completion::text(format!("{role}: {body}")))
    }
}

/// Lower a register into a prompt for `role` (plan | draft | judge). The role line
/// comes first so adapters and tests can recognise it.
pub fn lower(reg: &Register, role: &str) -> String {
    let mut s = format!("ROLE: {role}\nGOAL: {}\n", reg.goal);
    if !reg.constraints.is_empty() {
        s.push_str(&format!(
            "CONSTRAINTS:\n- {}\n",
            reg.constraints.join("\n- ")
        ));
    }
    for e in &reg.evidence {
        s.push_str(&format!("EVIDENCE ({:?}): {}\n", e.origin, e.content));
    }
    for d in &reg.decisions {
        s.push_str(&format!("DECISION: {d}\n"));
    }
    for q in &reg.open_questions {
        s.push_str(&format!("OPEN: {q}\n"));
    }
    s
}

/// One indivisible piece of a lowered prompt. A `CONSTRAINTS:` header owns the
/// `- ` lines under it, so a projection can never keep a bullet whose heading
/// it dropped.
struct Unit {
    text: String,
    lines: usize,
    rank: u8,
}

/// Priority of a prompt line: lower is kept first. `ROLE:`/`GOAL:` (rank 0) say
/// what the call *is* and are never dropped; evidence is the first thing to go.
fn rank_of(line: &str) -> u8 {
    if line.starts_with("ROLE:") || line.starts_with("GOAL:") {
        0
    } else if line.starts_with("DECISION:") {
        1
    } else if line.starts_with("CONSTRAINTS:") {
        2
    } else if line.starts_with("OPEN:") {
        3
    } else if line.starts_with("EVIDENCE") {
        4
    } else {
        5
    }
}

fn units_of(prompt: &str) -> Vec<Unit> {
    let lines: Vec<&str> = prompt.lines().collect();
    let mut units = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let rank = rank_of(lines[i]);
        let mut text = lines[i].to_string();
        let mut count = 1;
        if rank == 2 {
            while i + count < lines.len() && lines[i + count].starts_with("- ") {
                text.push('\n');
                text.push_str(lines[i + count]);
                count += 1;
            }
        }
        units.push(Unit {
            text,
            lines: count,
            rank,
        });
        i += count;
    }
    units
}

fn marker(dropped_lines: usize) -> String {
    format!("[PROJECTED: {dropped_lines} lines dropped]")
}

fn render(units: &[Unit], kept: &BTreeSet<usize>, marker_line: Option<&str>) -> String {
    let mut s = String::new();
    for i in kept {
        s.push_str(&units[*i].text);
        s.push('\n');
    }
    if let Some(m) = marker_line {
        s.push_str(m);
        s.push('\n');
    }
    s
}

/// Structural projection when the prompt exceeds the budget (I4'). The prompt is
/// rebuilt from whole lines in priority order — `ROLE:` and `GOAL:` always, then
/// decisions, constraints, open questions and last of all evidence — admitting a
/// unit only while `count` of the result stays within `budget_tokens`. Whatever
/// is left out is declared in a trailing `[PROJECTED: n lines dropped]` marker,
/// so a projection is never a silent truncation, and the surviving lines are
/// whole: this is not a byte-wise cut through the middle of the goal.
///
/// Returns `None` when the role and goal plus that marker already exceed the
/// budget. There is no honest prompt to send in that case and the caller must
/// refuse the inference (I4′) rather than send a mutilated one.
pub fn project(prompt: &str, budget_tokens: u32, count: &dyn Fn(&str) -> u32) -> Option<String> {
    if count(prompt) <= budget_tokens {
        return Some(prompt.to_string());
    }
    let units = units_of(prompt);
    let mut kept: BTreeSet<usize> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| u.rank == 0)
        .map(|(i, _)| i)
        .collect();

    // The marker's own size counts against the budget. Reserve the widest one
    // that can end up being printed, so admitting a unit can never be undone by
    // the marker growing a digit afterwards.
    let droppable: usize = units
        .iter()
        .enumerate()
        .filter(|(i, _)| !kept.contains(i))
        .map(|(_, u)| u.lines)
        .sum();
    let reserved = marker(droppable);

    if count(&render(&units, &kept, Some(&reserved))) > budget_tokens {
        return None;
    }
    let mut order: Vec<usize> = (0..units.len()).filter(|i| !kept.contains(i)).collect();
    order.sort_by_key(|i| (units[*i].rank, *i));
    for i in order {
        kept.insert(i);
        if count(&render(&units, &kept, Some(&reserved))) > budget_tokens {
            kept.remove(&i);
        }
    }
    let dropped: usize = units
        .iter()
        .enumerate()
        .filter(|(i, _)| !kept.contains(i))
        .map(|(_, u)| u.lines)
        .sum();
    Some(if dropped == 0 {
        render(&units, &kept, None)
    } else {
        render(&units, &kept, Some(&marker(dropped)))
    })
}

pub fn raise(reg: &mut Register, role: &str, output: &str) {
    match role {
        "plan" => reg.decisions.push(format!("plan: {}", output.trim())),
        "judge" => reg.open_questions.push(format!("judge: {}", output.trim())),
        _ => reg.decisions.push(format!("{role}: {}", output.trim())),
    }
}
