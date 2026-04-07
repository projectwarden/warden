use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-320: Unpinned third-party actions.
/// Detects actions using mutable tags (@v1, @v2, @main) instead of SHA pins.
/// GitHub-owned actions (actions/*, github/*) are medium severity;
/// third-party actions are high severity.
pub struct Wrd320;

const GITHUB_OWNED_PREFIXES: &[&str] = &["actions/", "github/"];

impl Rule for Wrd320 {
    fn id(&self) -> &str {
        "WRD-320"
    }

    fn name(&self) -> &str {
        "Unpinned Actions"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Third-party actions pinned to mutable tags instead of commit SHAs can be \
         silently replaced with malicious code via tag mutation."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Match uses: owner/repo@ref (not SHA-pinned)
        // SHA pins are 40 hex characters
        let uses_re = Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(\S+)").unwrap();
        let sha_re = Regex::new(r"^[0-9a-fA-F]{40}$").unwrap();

        for m in uses_re.captures_iter(content) {
            let action = m.get(1).unwrap().as_str();
            let ref_val = m.get(2).unwrap().as_str();

            // Skip if already SHA-pinned
            if sha_re.is_match(ref_val) {
                continue;
            }

            // Skip local actions (start with ./)
            if action.starts_with("./") {
                continue;
            }

            let is_github_owned = GITHUB_OWNED_PREFIXES
                .iter()
                .any(|prefix| action.starts_with(prefix));

            let severity = if is_github_owned { "medium" } else { "high" };

            let line = line_number_at_offset(content, m.get(0).unwrap().start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: severity.to_string(),
                title: format!("Unpinned action: {action}@{ref_val}"),
                description: format!(
                    "Action '{}' is pinned to tag/branch '{}' instead of a commit SHA. \
                     {} actions pinned to mutable refs can be silently replaced.",
                    action,
                    ref_val,
                    if is_github_owned {
                        "GitHub-owned"
                    } else {
                        "Third-party"
                    }
                ),
                file: workflow.path.clone(),
                line,
                remediation: format!(
                    "Pin '{action}' to a full commit SHA: {action}@<sha>. Use Dependabot or \
                     Renovate to keep pins updated."
                ),
            });
        }

        findings
    }
}
