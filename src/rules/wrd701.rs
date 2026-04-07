use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd701;

fn re_tojson_secrets() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"toJSON\s*\(\s*secrets\s*\)").unwrap())
}

// NOTE: a `secrets.*` wildcard regex used to live here. GitHub Actions has no
// such expression syntax (you cannot iterate the secrets context via a glob),
// so the regex would only ever match the literal four-character substring
// inside YAML free-form text or comments. That produced false positives with
// no real signal. The wildcard variant has been removed; the only honest
// detection is `toJSON(secrets)`.

impl Rule for Wrd701 {
    fn id(&self) -> &str {
        "WRD-701"
    }
    fn name(&self) -> &str {
        "toJSON Secrets Exposure"
    }
    fn severity(&self) -> &str {
        "critical"
    }
    fn description(&self) -> &str {
        "Detects `toJSON(secrets)` patterns that serialize the entire secrets \
         context into a single value, potentially leaking all repository secrets."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_tojson_secrets().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "toJSON(secrets) exposes all secrets".to_string(),
                description: "Using toJSON(secrets) serializes every secret in the repository \
                    into a single string. If this value reaches logs, artifacts, or outputs, \
                    all secrets are compromised."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Reference individual secrets by name (e.g. secrets.MY_TOKEN) \
                    instead of dumping the entire secrets context."
                    .to_string(),
            });
        }

        findings
    }
}
