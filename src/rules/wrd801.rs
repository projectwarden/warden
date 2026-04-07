use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd801;

fn re_pull_request_trigger() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*(pull_request|pull_request_target)\s*:").unwrap())
}

fn re_self_hosted() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"runs-on\s*:.*self-hosted").unwrap())
}

impl Rule for Wrd801 {
    fn id(&self) -> &str {
        "WRD-801"
    }
    fn name(&self) -> &str {
        "Self-Hosted Runner on PR"
    }
    fn severity(&self) -> &str {
        "critical"
    }
    fn description(&self) -> &str {
        "Detects pull_request triggers combined with self-hosted runners, \
         allowing untrusted PR code to execute on your infrastructure"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_pr_trigger = re_pull_request_trigger().is_match(content);
        if !has_pr_trigger {
            return findings;
        }

        for m in re_self_hosted().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Self-hosted runner used with pull_request trigger".to_string(),
                description: "Pull requests from forks can execute arbitrary code on \
                    self-hosted runners. Unlike GitHub-hosted runners, self-hosted runners \
                    are not ephemeral and may retain credentials, access internal networks, \
                    or persist malware between runs."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use GitHub-hosted runners for PR workflows, or restrict \
                    self-hosted runner access using runner groups with repository policies. \
                    Consider using pull_request_target with explicit checkout controls."
                    .to_string(),
            });
        }

        findings
    }
}
