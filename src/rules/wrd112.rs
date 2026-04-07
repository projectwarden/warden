use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-112: GITHUB_ENV / GITHUB_PATH injection.
/// Detects attacker-controllable input being written to GITHUB_ENV or GITHUB_PATH.
pub struct Wrd112;

impl Rule for Wrd112 {
    fn id(&self) -> &str {
        "WRD-112"
    }

    fn name(&self) -> &str {
        "GITHUB_ENV/PATH Injection"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Writing attacker-controllable values to GITHUB_ENV or GITHUB_PATH allows \
         environment variable or PATH manipulation in subsequent steps."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Look for writes to GITHUB_ENV or GITHUB_PATH in run: blocks
        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let env_write_re =
            Regex::new(r">>?\s*\$(?:GITHUB_ENV|GITHUB_PATH)|\$\{GITHUB_ENV\}|\$\{GITHUB_PATH\}")
                .unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in env_write_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Write to GITHUB_ENV or GITHUB_PATH".to_string(),
                    description: format!(
                        "A run: block writes to GITHUB_ENV or GITHUB_PATH near '{}'. \
                         If the written value originates from attacker-controlled input, \
                         subsequent steps can be hijacked.",
                        m.as_str().trim()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Avoid writing attacker-controlled data to GITHUB_ENV or \
                                  GITHUB_PATH. Validate and sanitize values before writing."
                        .to_string(),
                });
            }
        }

        findings
    }
}
