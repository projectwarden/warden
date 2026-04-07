use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-422: Debug logging enabled.
/// Detects ACTIONS_RUNNER_DEBUG or ACTIONS_STEP_DEBUG set to true, which can
/// expose secrets and sensitive data in logs.
pub struct Wrd422;

impl Rule for Wrd422 {
    fn id(&self) -> &str {
        "WRD-422"
    }

    fn name(&self) -> &str {
        "Debug Logging Enabled"
    }

    fn severity(&self) -> &str {
        "medium"
    }

    fn description(&self) -> &str {
        "ACTIONS_RUNNER_DEBUG or ACTIONS_STEP_DEBUG is enabled. Debug logging \
         can expose secrets and sensitive information in workflow logs."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let debug_re = Regex::new(
            r#"(?i)(ACTIONS_RUNNER_DEBUG|ACTIONS_STEP_DEBUG)\s*:\s*(?:true|'true'|"true")"#,
        )
        .unwrap();

        for m in debug_re.captures_iter(content) {
            let full = m.get(0).unwrap();
            let var_name = m.get(1).unwrap().as_str();
            let line = line_number_at_offset(content, full.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!("{var_name} is enabled"),
                description: format!(
                    "{var_name} is set to true. Debug mode logs additional information \
                     that may include secrets, tokens, and other sensitive data."
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Remove debug logging configuration or set it to false. \
                              Use repository-level debug settings only when needed for \
                              troubleshooting."
                    .to_string(),
            });
        }

        findings
    }
}
