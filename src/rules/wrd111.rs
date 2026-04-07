use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-111: Dispatch input injection.
/// Detects workflow_dispatch inputs interpolated directly in run: blocks.
pub struct Wrd111;

impl Rule for Wrd111 {
    fn id(&self) -> &str {
        "WRD-111"
    }

    fn name(&self) -> &str {
        "Dispatch Input Injection"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "workflow_dispatch or repository_dispatch inputs interpolated in run: blocks \
         can be controlled by any user with push access, enabling command injection."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Check if workflow uses workflow_dispatch or repository_dispatch
        let has_dispatch = Regex::new(r"(?i)workflow_dispatch|repository_dispatch").unwrap();
        if !has_dispatch.is_match(content) {
            return findings;
        }

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let dispatch_input_re =
            Regex::new(r"\$\{\{\s*(?:github\.event\.inputs\.\w+|inputs\.\w+)").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in dispatch_input_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Dispatch input injection".to_string(),
                    description: format!(
                        "Expression '{}' is interpolated in a run: block. \
                         Dispatch inputs are user-controlled and can inject commands.",
                        m.as_str()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Pass dispatch inputs through environment variables instead of \
                                  direct interpolation."
                        .to_string(),
                });
            }
        }

        findings
    }
}
