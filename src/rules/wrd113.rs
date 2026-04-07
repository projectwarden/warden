use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-113: Tainted reusable workflow inputs.
/// Detects attacker-controlled values (github.head_ref, github.event.* etc.) passed
/// as inputs to reusable workflows via workflow_call.
pub struct Wrd113;

const TAINTED_PATTERNS: &[&str] = &[
    "github.head_ref",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
];

impl Rule for Wrd113 {
    fn id(&self) -> &str {
        "WRD-113"
    }

    fn name(&self) -> &str {
        "Tainted Reusable Workflow Inputs"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Attacker-controlled values passed as inputs to reusable workflows can cause \
         injection if the called workflow interpolates them unsafely."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Look for uses: .*/...@... patterns (reusable workflow calls) nearby with: blocks
        // that pass tainted expressions.
        let with_block_re =
            Regex::new(r"(?i)uses\s*:\s*\S+/.+@\S+[\s\S]*?with\s*:([\s\S]*?)(?:\n\s{0,4}\w+:|$)")
                .unwrap();

        for cap in with_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for tainted in TAINTED_PATTERNS {
                let pattern = format!(r"\$\{{\{{?\s*{}", regex::escape(tainted));
                let re = Regex::new(&pattern).unwrap();

                for m in re.find_iter(block_text) {
                    let line = line_number_at_offset(content, block_start + m.start());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        title: format!("Tainted input passed to reusable workflow: {tainted}"),
                        description: format!(
                            "The attacker-controlled expression '{tainted}' is passed as input \
                             to a reusable workflow. If the callee interpolates it in a run: \
                             block, command injection is possible."
                        ),
                        file: workflow.path.clone(),
                        line,
                        remediation: "Sanitize or validate the value before passing it. \
                                      Ensure the called workflow uses environment variables \
                                      instead of direct interpolation."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
