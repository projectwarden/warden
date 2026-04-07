use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd823;

fn re_actions_cache() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*actions/cache").unwrap())
}

fn re_release_trigger() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*(release|workflow_dispatch|push:\s*\n\s*tags)").unwrap())
}

fn re_elevated_perms() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(permissions\s*:\s*write-all|contents\s*:\s*write|packages\s*:\s*write|id-token\s*:\s*write)").unwrap()
    })
}

impl Rule for Wrd823 {
    fn id(&self) -> &str {
        "WRD-823"
    }
    fn name(&self) -> &str {
        "Cache Poisoning"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions/cache usage in release or elevated-permission workflows \
         where a poisoned cache could compromise builds"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_release = re_release_trigger().is_match(content);
        let has_elevated = re_elevated_perms().is_match(content);

        if !has_release && !has_elevated {
            return findings;
        }

        for m in re_actions_cache().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "actions/cache in release workflow with elevated permissions".to_string(),
                description: "Using actions/cache in a release or high-privilege workflow is \
                    risky. An attacker who poisons the cache via a PR build can inject \
                    malicious artifacts into the release pipeline."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use separate cache keys for PR and release workflows, or avoid \
                    restoring caches from untrusted branches in release builds. Consider \
                    using immutable artifacts instead of mutable caches."
                    .to_string(),
            });
        }

        findings
    }
}
