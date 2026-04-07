use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd713;

// The `regex` crate does not support lookahead. We match the full
// `key: value` form and post-filter the captured value in code.
fn re_username_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*username\s*:\s*([^\s#][^\n#]*)").unwrap())
}

fn re_password_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*password\s*:\s*([^\s#][^\n#]*)").unwrap())
}

fn is_secret_reference(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    v.starts_with("${{")
}

impl Rule for Wrd713 {
    fn id(&self) -> &str {
        "WRD-713"
    }
    fn name(&self) -> &str {
        "Hardcoded Credentials"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects hardcoded username or password values in container/services \
         credentials blocks instead of using secrets"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Look for credentials blocks by checking context
        let in_credentials_context = content.contains("credentials:");

        if !in_credentials_context {
            return findings;
        }

        for caps in re_username_value().captures_iter(content) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if is_secret_reference(value) {
                continue;
            }
            let m = caps.get(0).unwrap();
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Hardcoded username in credentials block".to_string(),
                description: "A username value is hardcoded instead of being sourced from a \
                    secret. This exposes the credential in the workflow file."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use a secret reference, e.g. \
                    username: ${{ secrets.REGISTRY_USERNAME }}."
                    .to_string(),
            });
        }

        for caps in re_password_value().captures_iter(content) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if is_secret_reference(value) {
                continue;
            }
            let m = caps.get(0).unwrap();
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Hardcoded password in credentials block".to_string(),
                description: "A password value is hardcoded instead of being sourced from a \
                    secret. This is a critical credential exposure."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use a secret reference, e.g. \
                    password: ${{ secrets.REGISTRY_PASSWORD }}."
                    .to_string(),
            });
        }

        findings
    }
}
