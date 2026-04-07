use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-421: Network exfiltration risk.
/// Detects curl/wget in run: blocks that also reference secrets, suggesting
/// possible data exfiltration.
pub struct Wrd421;

impl Rule for Wrd421 {
    fn id(&self) -> &str {
        "WRD-421"
    }

    fn name(&self) -> &str {
        "Network Exfiltration Risk"
    }

    fn severity(&self) -> &str {
        "medium"
    }

    fn description(&self) -> &str {
        "curl or wget commands in run: blocks that also reference secrets may \
         indicate credential exfiltration."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let net_cmd_re = Regex::new(r"(?i)\b(?:curl|wget|nc|ncat)\b").unwrap();
        let secret_re = Regex::new(r"(?i)\$\{\{\s*secrets\.\w+|(?:\$[A-Z_]*SECRET|\$[A-Z_]*TOKEN|\$[A-Z_]*KEY|\$[A-Z_]*PASSWORD)").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            let has_net_cmd = net_cmd_re.is_match(block_text);
            let has_secret = secret_re.is_match(block_text);

            if has_net_cmd && has_secret {
                for m in net_cmd_re.find_iter(block_text) {
                    let line = line_number_at_offset(content, block_start + m.start());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        title: "Network command with secrets reference".to_string(),
                        description: format!(
                            "A '{}' command appears in a run: block that also references \
                             secrets or credentials. This pattern can indicate exfiltration.",
                            m.as_str()
                        ),
                        file: workflow.path.clone(),
                        line,
                        remediation: "Review whether the network command needs access to \
                                      secrets. Consider using dedicated actions for API calls \
                                      instead of raw curl/wget with secrets."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
