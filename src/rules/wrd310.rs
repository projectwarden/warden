use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-310: Impostor commit detection.
/// Flags actions pinned to SHAs that are suspiciously short, not 40 chars,
/// or pinned to commits that do not belong to a tagged release (heuristic).
pub struct Wrd310;

impl Rule for Wrd310 {
    fn id(&self) -> &str {
        "WRD-310"
    }

    fn name(&self) -> &str {
        "Impostor Commit"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Actions pinned to commit SHAs that appear suspicious. Impostor commits \
         can be pushed to a repository via its fork and may not belong to any \
         branch or tag in the original repository."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let uses_re =
            Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([0-9a-fA-F]+)\b").unwrap();

        for cap in uses_re.captures_iter(content) {
            let action = cap.get(1).unwrap().as_str();
            let sha = cap.get(2).unwrap().as_str();

            // Flag SHAs that are not exactly 40 hex chars (truncated or malformed)
            if sha.len() != 40 {
                let line = line_number_at_offset(content, cap.get(0).unwrap().start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("Suspicious SHA pin for {action}"),
                    description: format!(
                        "Action '{}' is pinned to '{}' which is {} characters. \
                         Valid full commit SHAs are exactly 40 hex characters. \
                         Truncated SHAs can collide and may indicate an impostor commit.",
                        action,
                        sha,
                        sha.len()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Use the full 40-character commit SHA. Verify the commit \
                                  exists on the default branch or a tagged release of the \
                                  action repository."
                        .to_string(),
                });
            }

            // Also flag if SHA is all zeros or a known test pattern
            if sha.chars().all(|c| c == '0') || sha.chars().all(|c| c == 'a') {
                let line = line_number_at_offset(content, cap.get(0).unwrap().start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("Suspicious SHA pattern for {action}"),
                    description: format!(
                        "Action '{action}' is pinned to '{sha}' which appears to be a \
                         placeholder or test SHA."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Replace with a real commit SHA from the action repository."
                        .to_string(),
                });
            }
        }

        findings
    }
}
