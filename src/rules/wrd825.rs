use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd825;

fn re_actor_bot_check() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"github\.actor\s*==\s*'(dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])'",
        )
        .unwrap()
    })
}

impl Rule for Wrd825 {
    fn id(&self) -> &str {
        "WRD-825"
    }
    fn name(&self) -> &str {
        "Spoofable Bot Check"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects if-conditions checking github.actor against bot names, \
         which can be spoofed by renaming a user account"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_actor_bot_check().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!("Spoofable bot identity check: {}", m.as_str()),
                description: "Checking github.actor against a bot name is unreliable because \
                    GitHub usernames can be changed to match bot names. An attacker could \
                    rename their account and trigger this condition."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Compare against the bot account's numeric `github.actor_id` \
                    instead of `github.actor`. Actor IDs are immutable, so an attacker \
                    cannot rename their account to match. `github.event.sender.type == 'Bot'` \
                    is also spoofable: any GitHub App can identify as a Bot, so it is \
                    not a sufficient gate either."
                    .to_string(),
            });
        }

        findings
    }
}
