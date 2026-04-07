use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd711;

fn re_secrets_inherit() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*secrets\s*:\s*inherit\s*$").unwrap())
}

impl Rule for Wrd711 {
    fn id(&self) -> &str {
        "WRD-711"
    }
    fn name(&self) -> &str {
        "Secrets Inherit"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects 'secrets: inherit' in reusable workflow calls, which passes all \
         repository secrets to the called workflow"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_secrets_inherit().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "secrets: inherit passes all secrets to called workflow".to_string(),
                description: "Using 'secrets: inherit' forwards every secret in the calling \
                    repository to the reusable workflow. If that workflow is external or \
                    broadly scoped, secrets may be exposed unnecessarily."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Pass only the specific secrets the called workflow needs, e.g. \
                    secrets: { MY_TOKEN: ${{ secrets.MY_TOKEN }} }."
                    .to_string(),
            });
        }

        findings
    }
}
