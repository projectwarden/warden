use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-110: Composite action input injection.
/// Detects ${{ inputs.* }} in run: blocks of composite actions (action.yml / action.yaml).
pub struct Wrd110;

impl Rule for Wrd110 {
    fn id(&self) -> &str {
        "WRD-110"
    }

    fn name(&self) -> &str {
        "Composite Action Input Injection"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Composite action inputs interpolated directly in run: blocks allow injection \
         when the action is consumed with attacker-controlled values."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Only applies to composite actions
        let is_composite =
            workflow.path.ends_with("action.yml") || workflow.path.ends_with("action.yaml");
        if !is_composite {
            return findings;
        }

        // Verify it declares using: composite
        let using_re = Regex::new("(?i)using\\s*:\\s*['\"]?composite['\"]?").unwrap();
        if !using_re.is_match(content) {
            return findings;
        }

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let input_re = Regex::new(r"\$\{\{\s*inputs\.\w+").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in input_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Composite action input injection".to_string(),
                    description: format!(
                        "Expression '{}' is interpolated in a run: block of a composite action. \
                         If the input comes from attacker-controlled data, this enables injection.",
                        m.as_str()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation:
                        "Use an environment variable: env: INPUT_VAL: ${{ inputs.name }}, \
                                  then reference $INPUT_VAL in the shell script."
                            .to_string(),
                });
            }
        }

        findings
    }
}
