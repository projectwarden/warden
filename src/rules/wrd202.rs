use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-202: Build tool execution after fork checkout.
/// Detects pull_request_target + checkout of PR head + running build tools
/// (npm, pip, cargo, make, yarn, gradle, mvn, etc.) on untrusted code.
pub struct Wrd202;

const BUILD_COMMANDS: &[&str] = &[
    "npm", "npx", "yarn", "pnpm", "pip", "pip3", "cargo", "make", "cmake", "gradle", "gradlew",
    "mvn", "mvnw", "go build", "go run", "go test", "poetry", "bundle", "rake", "ant", "bazel",
    "pants", "sbt",
];

impl Rule for Wrd202 {
    fn id(&self) -> &str {
        "WRD-202"
    }

    fn name(&self) -> &str {
        "Build Tool Execution on Untrusted Code"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "pull_request_target workflow checks out fork code and executes build tools, \
         allowing arbitrary code execution with write permissions."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Must have pull_request_target
        let prt_re = Regex::new(r"(?i)pull_request_target").unwrap();
        if !prt_re.is_match(content) {
            return findings;
        }

        // Must check out PR head
        let checkout_head_re = Regex::new(
            r"(?i)uses\s*:\s*actions/checkout@\S+[\s\S]*?ref\s*:\s*\$\{\{.*(?:head\.sha|head_ref|head\.ref)",
        )
        .unwrap();
        if !checkout_head_re.is_match(content) {
            return findings;
        }

        // Find build commands in run: blocks
        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();

        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for cmd in BUILD_COMMANDS {
                let pattern = format!(r"(?i)\b{}\b", regex::escape(cmd));
                let cmd_re = Regex::new(&pattern).unwrap();

                for m in cmd_re.find_iter(block_text) {
                    let line = line_number_at_offset(content, block_start + m.start());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        title: format!("Build tool '{cmd}' executed on untrusted fork code"),
                        description: format!(
                            "The workflow uses pull_request_target, checks out the PR head, \
                             and runs '{cmd}'. An attacker can modify build scripts or config \
                             in their fork to execute arbitrary code with elevated privileges."
                        ),
                        file: workflow.path.clone(),
                        line,
                        remediation: "Do not run build commands on untrusted code in \
                                      pull_request_target workflows. Use pull_request trigger \
                                      instead, or run builds in a separate unprivileged workflow."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
