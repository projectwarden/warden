use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-301: OIDC token trust boundary.
/// Detects id-token: write permission combined with pull_request_target or other
/// external triggers that could allow token theft.
pub struct Wrd301;

impl Rule for Wrd301 {
    fn id(&self) -> &str {
        "WRD-301"
    }

    fn name(&self) -> &str {
        "OIDC Trust Boundary Violation"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "id-token: write permission with external triggers (pull_request_target, \
         workflow_run, issue_comment) can allow attackers to obtain OIDC tokens \
         and access cloud resources."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Check for id-token: write
        let oidc_re = Regex::new(r"(?i)id-token\s*:\s*write").unwrap();
        let Some(oidc_match) = oidc_re.find(content) else {
            return findings;
        };

        let dangerous_triggers = [
            "pull_request_target",
            "workflow_run",
            "issue_comment",
            "issues",
            "discussion_comment",
            "repository_dispatch",
        ];

        for trigger in &dangerous_triggers {
            let trigger_re = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(trigger))).unwrap();
            if trigger_re.is_match(content) {
                let line = line_number_at_offset(content, oidc_match.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("OIDC token with {trigger} trigger"),
                    description: format!(
                        "This workflow requests id-token: write and uses the '{trigger}' trigger. \
                         An attacker may be able to obtain OIDC tokens to access cloud \
                         resources (AWS, GCP, Azure) configured to trust this repository."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Restrict OIDC token permissions to workflows triggered only \
                                  by trusted events (push, release). Add subject claim filters \
                                  in your cloud provider's OIDC configuration."
                        .to_string(),
                });
            }
        }

        findings
    }
}
