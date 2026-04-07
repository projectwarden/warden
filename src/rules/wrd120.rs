use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-120: Step output injection.
/// Detects steps.*.outputs.* in run: blocks, which can be tainted if a previous
/// step set an output from attacker-controlled data.
pub struct Wrd120;

impl Rule for Wrd120 {
    fn id(&self) -> &str {
        "WRD-120"
    }

    fn name(&self) -> &str {
        "Step Output Injection"
    }

    fn severity(&self) -> &str {
        "medium"
    }

    fn description(&self) -> &str {
        "Step outputs interpolated in run: blocks may carry attacker-controlled data \
         if a prior step set the output from tainted input."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let step_output_re = Regex::new(r"\$\{\{\s*steps\.\w+\.outputs\.\w+").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in step_output_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Step output injection".to_string(),
                    description: format!(
                        "Expression '{}' in a run: block may be tainted if the originating \
                         step derived the output from attacker-controlled data.",
                        m.as_str()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Pass step outputs through environment variables. Validate or \
                                  sanitize outputs before use."
                        .to_string(),
                });
            }
        }

        findings
    }
}
