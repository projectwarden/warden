use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd520;

fn re_daily_schedule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?m)interval\s*:\s*(daily|"daily")"#).unwrap())
}

fn re_groups() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s+groups\s*:").unwrap())
}

impl Rule for Wrd520 {
    fn id(&self) -> &str {
        "WRD-520"
    }
    fn name(&self) -> &str {
        "Dependabot Cooldown"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects Dependabot configurations with daily update schedules and no \
         grouping, which can flood PRs"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // This rule targets dependabot.yml files
        if !workflow.path.contains("dependabot") {
            return findings;
        }

        let daily_match = re_daily_schedule().find(content);
        let has_groups = re_groups().is_match(content);

        if let Some(m) = daily_match {
            if !has_groups {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Dependabot daily schedule without grouping".to_string(),
                    description: "Dependabot is configured with a daily update interval but \
                        no dependency groups. This can produce a high volume of individual \
                        PRs, overwhelming reviewers and CI resources."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Add dependency groups to batch related updates into fewer \
                        PRs, or reduce the schedule interval to weekly. Example:\n\
                        groups:\n  \
                          production-dependencies:\n    \
                            patterns: ['*']"
                        .to_string(),
                });
            }
        }

        findings
    }
}
