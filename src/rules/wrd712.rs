use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd712;

fn re_unsecure_commands() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*true").unwrap())
}

impl Rule for Wrd712 {
    fn id(&self) -> &str {
        "WRD-712"
    }
    fn name(&self) -> &str {
        "Insecure Commands"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects ACTIONS_ALLOW_UNSECURE_COMMANDS set to true, which re-enables \
         deprecated set-env and add-path workflow commands"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_unsecure_commands().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled".to_string(),
                description: "Setting ACTIONS_ALLOW_UNSECURE_COMMANDS to true re-enables the \
                    deprecated set-env and add-path commands, which are vulnerable to injection \
                    attacks via untrusted input."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use GITHUB_ENV / \
                    GITHUB_PATH files instead of the legacy commands."
                    .to_string(),
            });
        }

        findings
    }
}
