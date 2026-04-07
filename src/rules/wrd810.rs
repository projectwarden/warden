use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd810;

fn re_auto_merge() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(auto-merge|auto.merge|merge.*automatically|gh\s+pr\s+merge\s+--auto)")
            .unwrap()
    })
}

fn re_auto_approve() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(gh\s+pr\s+review\s+--approve|auto.approv)").unwrap())
}

fn re_auth_check() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(github\.actor|github\.event\.sender|permission|team|CODEOWNERS|authorized)",
        )
        .unwrap()
    })
}

impl Rule for Wrd810 {
    fn id(&self) -> &str {
        "WRD-810"
    }
    fn name(&self) -> &str {
        "Confused Deputy"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects auto-merge or auto-approve patterns without proper authorization checks"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_auth = re_auth_check().is_match(content);

        for m in re_auto_merge().find_iter(content) {
            if !has_auth {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Auto-merge without authorization check".to_string(),
                    description: "The workflow performs automatic merging without apparent \
                        authorization checks. An attacker who can trigger this workflow \
                        could get unauthorized changes merged."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Add authorization checks (actor verification, team membership, \
                        or permission validation) before auto-merging."
                        .to_string(),
                });
            }
        }

        for m in re_auto_approve().find_iter(content) {
            if !has_auth {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Auto-approve without authorization check".to_string(),
                    description: "The workflow performs automatic PR approval without apparent \
                        authorization checks. This bypasses the code review requirement \
                        and could allow malicious changes to be approved."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Add authorization checks before auto-approving. Verify the \
                        PR author is a trusted bot or team member."
                        .to_string(),
                });
            }
        }

        findings
    }
}
