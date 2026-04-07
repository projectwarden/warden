use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd321;

/// Known archived or deprecated GitHub Actions repos.
const ARCHIVED_ACTIONS: &[&str] = &[
    "actions/create-release",
    "actions/upload-release-asset",
    "peter-evans/slash-command-dispatch",
    "actions-rs/toolchain",
    "actions-rs/cargo",
    "actions-rs/clippy-check",
    "actions-rs/audit-check",
    "actions-rs/tarpaulin",
    "actions-ecosystem/action-add-labels",
    "aochmann/actions-download-artifact",
    "chrnorm/deployment-action",
    "elgohr/Publish-Docker-Github-Action",
];

fn re_uses_action() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(\S+)").unwrap())
}

impl Rule for Wrd321 {
    fn id(&self) -> &str {
        "WRD-321"
    }
    fn name(&self) -> &str {
        "Archived Action Reference"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects references to GitHub Actions from known archived or deprecated repositories"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_uses_action().captures_iter(content) {
            let action = m.get(1).unwrap().as_str();
            let action_lower = action.to_lowercase();

            if ARCHIVED_ACTIONS
                .iter()
                .any(|a| a.to_lowercase() == action_lower)
            {
                let line = line_number_at_offset(content, m.get(0).unwrap().start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("Archived action referenced: {action}"),
                    description: format!(
                        "Action '{action}' comes from a known archived or deprecated repository. \
                         Archived actions no longer receive security patches or bug fixes."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: format!(
                        "Replace '{action}' with an actively maintained alternative. \
                         Check the repo's README for migration guidance."
                    ),
                });
            }
        }

        findings
    }
}
