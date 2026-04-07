use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-101: Expression injection in run: blocks.
/// Detects dangerous github.event.* / github.head_ref interpolations in run: steps.
pub struct Wrd101;

const TAINTED_EXPRESSIONS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.name",
    "github.event.commits.*.author.email",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.head_ref",
];

impl Rule for Wrd101 {
    fn id(&self) -> &str {
        "WRD-101"
    }

    fn name(&self) -> &str {
        "Expression Injection"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "Attacker-controlled GitHub context expressions interpolated in run: blocks \
         allow arbitrary command injection."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Build a regex that matches run: blocks (possibly multi-line via |)
        // then look for tainted expressions inside them.
        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full_match = cap.get(0).unwrap();
            let block_text = full_match.as_str();
            let block_start = full_match.start();

            for expr in TAINTED_EXPRESSIONS {
                // Match ${{ <expr> }} or ${{ <expr> with surrounding text }}
                let pattern = format!(r"\$\{{\{{?\s*{}", regex::escape(expr));
                let expr_re = Regex::new(&pattern).unwrap();

                for m in expr_re.find_iter(block_text) {
                    let line = line_number_at_offset(content, block_start + m.start());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        title: format!("Expression injection via {expr}"),
                        description: format!(
                            "The expression ${{{{ {expr} }}}} is interpolated in a run: block. \
                             An attacker can control this value and inject arbitrary commands."
                        ),
                        file: workflow.path.clone(),
                        line,
                        remediation: "Pass the value through an environment variable instead: \
                                      env: MY_VAR: ${{ <expr> }}, then use $MY_VAR in the script."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
