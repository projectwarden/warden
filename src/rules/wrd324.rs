use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd324;

/// Branch names that are ambiguous when used as action refs.
const AMBIGUOUS_REFS: &[&str] = &["main", "master", "develop", "trunk", "dev", "HEAD"];

fn re_uses_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(\S+)").unwrap())
}

fn re_sha() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{40}$").unwrap())
}

fn re_version_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v\d").unwrap())
}

impl Rule for Wrd324 {
    fn id(&self) -> &str {
        "WRD-324"
    }
    fn name(&self) -> &str {
        "Ref Confusion"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions pinned to branch names (main, master, develop, etc.) \
         that are ambiguous and mutable"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for cap in re_uses_ref().captures_iter(content) {
            let action = cap.get(1).unwrap().as_str();
            let ref_val = cap.get(2).unwrap().as_str();

            // Skip SHA pins and version tags
            if re_sha().is_match(ref_val) || re_version_tag().is_match(ref_val) {
                continue;
            }

            if AMBIGUOUS_REFS.contains(&ref_val) {
                let line = line_number_at_offset(content, cap.get(0).unwrap().start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("Action pinned to branch ref: {action}@{ref_val}"),
                    description: format!(
                        "Action '{action}' is pinned to '{ref_val}', which is a mutable branch ref. \
                         This means the action code can change at any time without notice, \
                         making builds non-reproducible and vulnerable to supply chain attacks."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: format!(
                        "Pin '{action}' to a specific SHA or version tag instead of '{ref_val}'. \
                         Use Dependabot or Renovate to keep pins current."
                    ),
                });
            }
        }

        findings
    }
}
