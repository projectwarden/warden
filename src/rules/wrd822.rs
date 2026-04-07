use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd822;

fn re_base64_secret() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)base64.*\$\{\{\s*secrets\.|echo\s+.*\$\{\{\s*secrets\..*\|\s*base64")
            .unwrap()
    })
}

fn re_char_split_secret() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(sed|tr|cut|fold|rev).*\$\{\{\s*secrets\.").unwrap())
}

fn re_file_write_secret() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\$\{\{\s*secrets\.[^}]+\}\}.*>>\s*\S+|echo.*\$\{\{\s*secrets\.[^}]+\}\}.*>\s*\S+",
        )
        .unwrap()
    })
}

impl Rule for Wrd822 {
    fn id(&self) -> &str {
        "WRD-822"
    }
    fn name(&self) -> &str {
        "Secret Redaction Bypass"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects patterns that bypass GitHub Actions secret redaction: base64 encoding, \
         character splitting, or file write then cat of secrets"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_base64_secret().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Secret base64-encoded to bypass redaction".to_string(),
                description: "Base64-encoding a secret produces output that does not match \
                    the original value, so GitHub Actions will not redact it from logs."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Avoid encoding secrets in ways that bypass redaction. If you \
                    need to encode a secret, ensure the output is not logged."
                    .to_string(),
            });
        }

        for m in re_char_split_secret().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Secret manipulated with text tools to bypass redaction".to_string(),
                description: "Using sed, tr, cut, fold, or rev on a secret can produce \
                    output that is not redacted by GitHub Actions."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Do not transform secrets with text-processing tools. \
                    Pass secrets directly to the tools that need them."
                    .to_string(),
            });
        }

        // Check for file-write-then-cat pattern
        let has_file_write = re_file_write_secret().is_match(content);
        if has_file_write {
            for m in re_file_write_secret().find_iter(content) {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Secret written to file (potential redaction bypass)".to_string(),
                    description: "Writing a secret to a file and later reading it with cat \
                        can bypass redaction if the file content is logged line by line."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Avoid writing secrets to files. If necessary, ensure the \
                        file is never logged or included in artifacts."
                        .to_string(),
                });
            }
        }

        findings
    }
}
