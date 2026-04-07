use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd811;

fn re_workflow_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*workflow_run\s*:").unwrap())
}

fn re_download_artifact() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*actions/download-artifact").unwrap())
}

fn re_conclusion_check() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"conclusion\s*==\s*'success'").unwrap())
}

impl Rule for Wrd811 {
    fn id(&self) -> &str {
        "WRD-811"
    }
    fn name(&self) -> &str {
        "Artifact Injection"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects workflow_run triggers that download artifacts without verifying \
         the triggering workflow's conclusion"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_workflow_run = re_workflow_run().is_match(content);
        let has_conclusion_check = re_conclusion_check().is_match(content);

        if let Some(dl) = re_download_artifact().find(content) {
            if has_workflow_run && !has_conclusion_check {
                let line = line_number_at_offset(content, dl.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "workflow_run downloads artifacts without conclusion check".to_string(),
                    description: "A workflow_run trigger that downloads artifacts from the \
                    triggering workflow without checking conclusion == 'success' may \
                    process artifacts from failed or malicious runs."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Add a condition like \
                    'if: github.event.workflow_run.conclusion == 'success'' \
                    before downloading and using artifacts."
                        .to_string(),
                });
            }
        }

        findings
    }
}
