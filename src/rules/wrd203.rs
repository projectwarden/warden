use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-203: Cross-workflow privilege escalation via workflow_run.
/// Detects workflow_run watcher with write permissions that watches a pull_request
/// producer, enabling privilege escalation through artifact poisoning.
pub struct Wrd203;

impl Rule for Wrd203 {
    fn id(&self) -> &str {
        "WRD-203"
    }

    fn name(&self) -> &str {
        "Cross-Workflow Privilege Escalation"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "A workflow_run workflow with write permissions watching a pull_request \
         workflow can be exploited via artifact poisoning for privilege escalation."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Check for workflow_run trigger
        let wfr_re = Regex::new(r"(?i)workflow_run\s*:").unwrap();
        let Some(wfr_match) = wfr_re.find(content) else {
            return findings;
        };

        // Check if it has write permissions
        let write_perm_re = Regex::new(
            r"(?i)permissions\s*:[\s\S]*?(?:write|write-all|contents\s*:\s*write|pull-requests\s*:\s*write|issues\s*:\s*write)",
        )
        .unwrap();

        let has_write_perms = write_perm_re.is_match(content);

        // Check if it downloads artifacts without verification
        let downloads_artifacts = Regex::new(r"(?i)uses\s*:\s*actions/download-artifact")
            .unwrap()
            .is_match(content);

        if has_write_perms || downloads_artifacts {
            let line = line_number_at_offset(content, wfr_match.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "workflow_run with elevated permissions".to_string(),
                description: "This workflow_run workflow has write permissions or downloads \
                              artifacts. If the producing workflow is triggered by pull_request, \
                              an attacker can poison artifacts in a fork PR to escalate \
                              privileges."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation:
                    "Minimize permissions on workflow_run workflows. Validate artifact \
                              integrity before use. Avoid executing code from downloaded artifacts."
                        .to_string(),
            });
        }

        findings
    }
}
