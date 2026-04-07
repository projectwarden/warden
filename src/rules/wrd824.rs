use regex::Regex;
use std::sync::OnceLock;

use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd824;

fn re_write_all() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"permissions\s*:\s*write-all").unwrap())
}

// NOTE: a per-job-write-grant sub-check used to live here. It walked every
// `<scope>: write` line and emitted a "Potentially unnecessary write
// permission" finding for each. Without semantic analysis of whether the job
// actually needed the grant, the false-positive rate was too high to ship,
// drowning real findings. It has been removed; reintroduce only with proper
// per-job dataflow.

impl Rule for Wrd824 {
    fn id(&self) -> &str {
        "WRD-824"
    }
    fn name(&self) -> &str {
        "Excessive Permissions"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects `permissions: write-all` grants and workflows that omit a \
         top-level permissions block entirely (and therefore inherit the \
         repository default)."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let parsed = &workflow.parsed;

        // Check for permissions: write-all
        if let Some(m) = re_write_all().find(content) {
            let line = content[..m.start()].matches('\n').count() + 1;
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "permissions: write-all grants excessive access".to_string(),
                description: "Using write-all gives every scope write access. \
                    Prefer granting only the specific permissions needed."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Replace 'permissions: write-all' with specific scopes, \
                    e.g. contents: read, issues: write."
                    .to_string(),
            });
        }

        // Check for missing top-level permissions block
        if parsed.get("permissions").is_none() {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "No top-level permissions block defined".to_string(),
                description: "Without an explicit permissions block the workflow inherits \
                    the default token permissions, which may be overly broad."
                    .to_string(),
                file: workflow.path.clone(),
                line: 1,
                remediation: "Add a top-level 'permissions: {}' block (empty for read-only) \
                    and grant specific scopes per job as needed."
                    .to_string(),
            });
        }

        findings
    }
}
