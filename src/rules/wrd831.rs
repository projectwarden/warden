use regex::Regex;
use std::sync::OnceLock;

use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd831;

fn re_push_or_pr_trigger() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*(push|pull_request)\s*:").unwrap())
}

impl Rule for Wrd831 {
    fn id(&self) -> &str {
        "WRD-831"
    }
    fn name(&self) -> &str {
        "Missing Concurrency Limits"
    }
    fn severity(&self) -> &str {
        "low"
    }
    fn description(&self) -> &str {
        "Detects workflows triggered by push or pull_request that lack a \
         concurrency block, which can lead to resource exhaustion"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let parsed = &workflow.parsed;

        let has_trigger = re_push_or_pr_trigger().is_match(content);
        let has_concurrency = parsed.get("concurrency").is_some();

        if has_trigger && !has_concurrency {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "No concurrency limits on push/PR workflow".to_string(),
                description: "This workflow is triggered by push or pull_request but \
                    does not define a 'concurrency:' block. Without concurrency limits, \
                    rapid pushes can queue many redundant runs, wasting runner resources."
                    .to_string(),
                file: workflow.path.clone(),
                line: 1,
                remediation: "Add a concurrency block to cancel in-progress runs on the \
                    same branch, e.g.:\n\
                    concurrency:\n  \
                      group: ${{ github.workflow }}-${{ github.ref }}\n  \
                      cancel-in-progress: true"
                    .to_string(),
            });
        }

        findings
    }
}
