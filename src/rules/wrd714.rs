use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd714;

fn re_curl_pipe() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(bash|sh|zsh|python|ruby|perl|node)").unwrap()
    })
}

impl Rule for Wrd714 {
    fn id(&self) -> &str {
        "WRD-714"
    }
    fn name(&self) -> &str {
        "Curl Pipe Bash"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Detects curl|bash, wget|sh, and similar patterns that execute remote \
         scripts without verification"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for m in re_curl_pipe().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Remote script executed via pipe to shell".to_string(),
                description: format!(
                    "Pattern '{}' downloads and immediately executes a remote script. \
                     A compromised server or MITM attack could inject malicious code.",
                    m.as_str().trim()
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Download the script first, verify its checksum or signature, \
                    then execute it. Or vendor the script into the repository."
                    .to_string(),
            });
        }

        findings
    }
}
