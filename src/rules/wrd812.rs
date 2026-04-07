use serde_yaml::Value;

use super::{Finding, Rule};
use crate::scanner::Workflow;

/// WRD-812: Risky trigger uses default permissions.
pub struct Wrd812;

const RISKY_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "discussion_comment",
];

fn workflow_has_risky_trigger(parsed: &Value) -> Option<String> {
    let on = parsed.get("on")?;
    match on {
        Value::String(s) => {
            if RISKY_TRIGGERS.contains(&s.as_str()) {
                return Some(s.clone());
            }
        }
        Value::Sequence(seq) => {
            for v in seq {
                if let Some(s) = v.as_str() {
                    if RISKY_TRIGGERS.contains(&s) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        Value::Mapping(map) => {
            for (k, _v) in map {
                if let Some(s) = k.as_str() {
                    if RISKY_TRIGGERS.contains(&s) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    None
}

impl Rule for Wrd812 {
    fn id(&self) -> &str {
        "WRD-812"
    }
    fn name(&self) -> &str {
        "Risky Trigger Default Permissions"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Workflow uses a risky trigger (pull_request_target, workflow_run, issue_comment, \
         discussion_comment) without an explicit top-level permissions: block, inheriting \
         the repo default which may grant write access."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let parsed = &workflow.parsed;

        let Some(trigger) = workflow_has_risky_trigger(parsed) else {
            return findings;
        };

        let has_permissions = parsed.get("permissions").is_some();
        if has_permissions {
            return findings;
        }

        findings.push(Finding {
            rule_id: self.id().to_string(),
            severity: self.severity().to_string(),
            title: "Risky trigger uses default permissions".to_string(),
            description: format!(
                "Workflow is triggered by '{trigger}' but has no top-level permissions: block. \
                 It will inherit the repository default GITHUB_TOKEN permissions, which \
                 may be write-all, giving attacker-influenced runs excessive privileges."
            ),
            file: workflow.path.clone(),
            line: 1,
            remediation: "Add an explicit top-level `permissions:` block (e.g. \
                          `permissions: read-all`) to avoid inheriting the repo-default \
                          which may be write-all."
                .to_string(),
        });

        findings
    }
}
