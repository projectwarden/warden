use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-201: Fork checkout via pull_request_target.
/// Detects pull_request_target trigger combined with actions/checkout using
/// ref: ${{ github.event.pull_request.head.sha }} or head_ref, which checks out
/// untrusted fork code with write permissions.
pub struct Wrd201;

impl Rule for Wrd201 {
    fn id(&self) -> &str {
        "WRD-201"
    }

    fn name(&self) -> &str {
        "Dangerous Fork Checkout"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "pull_request_target with actions/checkout referencing the PR head checks out \
         untrusted fork code in a privileged context."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Must have pull_request_target trigger
        let prt_re = Regex::new(r"(?i)pull_request_target").unwrap();
        if !prt_re.is_match(content) {
            return findings;
        }

        // Look for actions/checkout with ref pointing to head.sha or head_ref
        let checkout_re = Regex::new(
            r"(?i)uses\s*:\s*actions/checkout@\S+[\s\S]*?ref\s*:\s*\$\{\{\s*(?:github\.event\.pull_request\.head\.sha|github\.head_ref|github\.event\.pull_request\.head\.ref)\s*\}\}",
        )
        .unwrap();

        for m in checkout_re.find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Fork checkout in pull_request_target workflow".to_string(),
                description: "actions/checkout checks out the PR head (fork code) in a \
                              pull_request_target workflow. This runs untrusted code with \
                              write permissions and access to secrets."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use pull_request instead of pull_request_target, or avoid \
                              checking out untrusted code. If checkout is necessary, do not \
                              run any build/test commands on the checked-out code."
                    .to_string(),
            });
        }

        findings
    }
}
