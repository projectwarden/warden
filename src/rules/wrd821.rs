use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd821;

fn re_contains_user_input() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"contains\s*\(\s*github\.(event\.(issue|pull_request|comment)\.(title|body|labels)|head_ref|actor)"
        ).unwrap()
    })
}

impl Rule for Wrd821 {
    fn id(&self) -> &str {
        "WRD-821"
    }
    fn name(&self) -> &str {
        "Bypassable Contains Check"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects contains() checks on user-controlled input used as authorization \
         gates, which can be trivially bypassed"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_contains_user_input().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "contains() on user input used as gate".to_string(),
                description: format!(
                    "The pattern '{}...' uses contains() on user-controlled input. \
                     An attacker can include the expected substring in their input to \
                     bypass this check.",
                    m.as_str()
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Use a proper authorization mechanism instead of string matching \
                    on user-controlled input. Consider using team membership, CODEOWNERS, \
                    or GitHub's built-in permissions."
                    .to_string(),
            });
        }

        findings
    }
}
