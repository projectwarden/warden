use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd833;

impl Rule for Wrd833 {
    fn id(&self) -> &str {
        "WRD-833"
    }
    fn name(&self) -> &str {
        "Anonymous Workflow Definition"
    }
    fn severity(&self) -> &str {
        "low"
    }
    fn description(&self) -> &str {
        "Detects workflow files missing a top-level 'name:' key"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let parsed = &workflow.parsed;

        if parsed.get("name").is_none() {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Workflow has no top-level name".to_string(),
                description: "This workflow file lacks a top-level 'name:' key. \
                    Without a name, the workflow appears as the filename in the \
                    GitHub Actions UI, making it harder to identify at a glance."
                    .to_string(),
                file: workflow.path.clone(),
                line: 1,
                remediation: "Add a descriptive 'name:' key at the top of the workflow file, \
                    e.g., 'name: CI Build and Test'."
                    .to_string(),
            });
        }

        findings
    }
}
