//! Arch adapters (spec §3.7) and IR lowering/raising (spec §3.2).
use vk_contracts::arch::ArchManifest;
use vk_contracts::register::Register;

pub trait ArchAdapter: Send + Sync {
    fn manifest(&self) -> &ArchManifest;
    /// Real context budget in tokens (I4'); adapters must report what is actually loaded.
    fn context_budget(&self) -> u32;
    fn count_tokens(&self, text: &str) -> u32;
    fn complete(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<String>;
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
    fn complete(&self, prompt: &str, _max_tokens: u32) -> anyhow::Result<String> {
        let role = prompt
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("ROLE: ")
            .to_uppercase();
        let body: String = prompt.chars().take(200).collect();
        Ok(format!("{role}: {body}"))
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

/// Structural projection when the prompt exceeds the budget (I4'): keep the role,
/// goal and decisions; truncate evidence, never silently.
pub fn project(prompt: &str, budget_tokens: u32) -> String {
    let max_chars = (budget_tokens as usize).saturating_mul(4);
    if prompt.len() <= max_chars {
        return prompt.to_string();
    }
    let head: String = prompt.chars().take(max_chars.saturating_sub(40)).collect();
    format!(
        "{head}\n[PROJECTED: {} chars dropped]\n",
        prompt.len() - head.len()
    )
}

pub fn raise(reg: &mut Register, role: &str, output: &str) {
    match role {
        "plan" => reg.decisions.push(format!("plan: {}", output.trim())),
        "judge" => reg.open_questions.push(format!("judge: {}", output.trim())),
        _ => reg.decisions.push(format!("{role}: {}", output.trim())),
    }
}
