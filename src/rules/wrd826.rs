use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd826;

fn re_permissions_entry() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^(\s+)(contents|packages|actions|deployments|id-token|issues|pull-requests|statuses|security-events|checks|pages|discussions|repository-projects|attestations)\s*:\s*(read|write|none)"
        ).unwrap()
    })
}

impl Rule for Wrd826 {
    fn id(&self) -> &str {
        "WRD-826"
    }
    fn name(&self) -> &str {
        "Undocumented Permissions"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects permissions entries that lack an explanatory comment"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let lines: Vec<&str> = content.lines().collect();

        for m in re_permissions_entry().find_iter(content) {
            let line_num = line_number_at_offset(content, m.start());
            let line_idx = line_num.saturating_sub(1);

            // Check if this line has an inline comment
            let current_line = lines.get(line_idx).unwrap_or(&"");
            if current_line.contains('#') {
                continue;
            }

            // Check if the preceding line is a comment
            if line_idx > 0 {
                let prev_line = lines.get(line_idx - 1).unwrap_or(&"");
                if prev_line.trim_start().starts_with('#') {
                    continue;
                }
            }

            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!(
                    "Permission entry without documentation: {}",
                    current_line.trim()
                ),
                description: "This permissions entry has no comment explaining why the \
                    permission is required. Documenting permissions makes security \
                    reviews easier and helps future maintainers understand the \
                    intent behind each grant."
                    .to_string(),
                file: workflow.path.clone(),
                line: line_num,
                remediation: "Add a comment on the same line or the line above explaining \
                    why this permission is needed, e.g.:\n\
                    # Required to push Docker images\n\
                    packages: write"
                    .to_string(),
            });
        }

        findings
    }
}
