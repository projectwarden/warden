use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd521;

fn re_pr_target_trigger() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*pull_request_target\s*:").unwrap())
}

fn re_dependabot_actor() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)dependabot|github\.actor\s*==\s*'dependabot").unwrap())
}

fn re_checkout_pr_head() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(actions/checkout.*\n(\s+with:\s*\n)?(\s+.*\n)*?\s+ref\s*:.*pull_request|github\.event\.pull_request\.head)").unwrap()
    })
}

fn re_run_scripts_from_pr() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)run\s*:\s*.*(\./|bash\s|sh\s|python\s|node\s|npm\s+(run|test|install)|yarn|make|cargo)").unwrap()
    })
}

impl Rule for Wrd521 {
    fn id(&self) -> &str {
        "WRD-521"
    }
    fn name(&self) -> &str {
        "Dependabot Insecure Execution"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects Dependabot-related workflows that may execute untrusted code \
         from pull requests via pull_request_target"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_pr_target = re_pr_target_trigger().is_match(content);
        if !has_pr_target {
            return findings;
        }

        let mentions_dependabot = re_dependabot_actor().is_match(content);
        if !mentions_dependabot {
            return findings;
        }

        // Check for checkout of PR head ref (dangerous with pull_request_target)
        if let Some(m) = re_checkout_pr_head().find(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Dependabot workflow checks out PR head in pull_request_target".to_string(),
                description: "This workflow uses pull_request_target and checks out the \
                    PR head ref. With pull_request_target, the workflow runs with \
                    write permissions and access to secrets. Checking out untrusted \
                    PR code in this context allows arbitrary code execution with \
                    elevated privileges."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Avoid checking out the PR head in pull_request_target \
                    workflows. If you must, run untrusted code in a separate \
                    unprivileged workflow triggered by pull_request instead."
                    .to_string(),
            });
        }

        // Check for running scripts (which execute from the checked-out code)
        if re_checkout_pr_head().is_match(content) {
            for m in re_run_scripts_from_pr().find_iter(content) {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Script execution in Dependabot pull_request_target workflow"
                        .to_string(),
                    description: "This pull_request_target workflow checks out PR code \
                        and runs scripts. An attacker could modify Dependabot PRs \
                        (or create PRs that match the conditions) to execute \
                        arbitrary code with write permissions."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Move script execution to a pull_request-triggered \
                        workflow (no write access). Use workflow_run to pass results \
                        back to the privileged context if needed."
                        .to_string(),
                });
            }
        }

        findings
    }
}
