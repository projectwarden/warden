use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-420: Secrets in run blocks.
/// Detects ${{ secrets.* }} interpolated directly in run: blocks instead of
/// being passed through environment variables.
pub struct Wrd420;

impl Rule for Wrd420 {
    fn id(&self) -> &str {
        "WRD-420"
    }

    fn name(&self) -> &str {
        "Secrets in Run Blocks"
    }

    fn severity(&self) -> &str {
        "medium"
    }

    fn description(&self) -> &str {
        "Secrets interpolated directly in run: blocks can leak through process \
         listings, shell history, and error messages. Pass them via environment \
         variables instead."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let secret_re = Regex::new(r"\$\{\{\s*secrets\.\w+").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in secret_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Secret directly in run: block".to_string(),
                    description: format!(
                        "Expression '{}' is interpolated directly in a run: block. \
                         Secrets in shell commands can leak through process tables, \
                         logs, and error messages.",
                        m.as_str()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Pass secrets through step-level environment variables: \
                                  env: MY_SECRET: ${{ secrets.TOKEN }}, then use $MY_SECRET \
                                  in the script."
                        .to_string(),
                });
            }
        }

        findings
    }
}
