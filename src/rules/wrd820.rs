use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd820;

fn re_if_true() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*if\s*:\s*(true|always\(\))").unwrap())
}

// Note: Rust regex does not support backreferences.
// Instead we check for common self-comparison patterns explicitly.
fn re_self_comparison() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"if\s*:.*'[^']+'\s*==\s*'[^']+'").unwrap())
}

impl Rule for Wrd820 {
    fn id(&self) -> &str {
        "WRD-820"
    }
    fn name(&self) -> &str {
        "Unsound Condition"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects conditions that are always true: 'if: true', 'if: always()', \
         or self-comparisons like 'github.actor == github.actor'"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_if_true().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!("Always-true condition: {}", m.as_str().trim()),
                description: "This condition always evaluates to true, making it effectively \
                    a no-op guard. If this is intentional, consider removing the condition \
                    entirely for clarity."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Replace with a meaningful condition, or remove the if: block \
                    if the step/job should always run."
                    .to_string(),
            });
        }

        for m in re_self_comparison().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Self-comparison condition is always true".to_string(),
                description: format!(
                    "The condition '{}' compares a value to itself, which is always true.",
                    m.as_str().trim()
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Fix the condition to compare against the intended value.".to_string(),
            });
        }

        findings
    }
}
