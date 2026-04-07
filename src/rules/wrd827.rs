use regex::Regex;
use std::sync::OnceLock;

use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd827;

/// Actions that duplicate functionality already present on GitHub-hosted runners.
const SUPERFLUOUS_ACTIONS: &[(&str, &str)] = &[
    (
        "actions/setup-node",
        "Node.js is pre-installed on all GitHub-hosted runners",
    ),
    (
        "actions/setup-python",
        "Python is pre-installed on all GitHub-hosted runners",
    ),
    (
        "actions/setup-java",
        "Java (Temurin) is pre-installed on all GitHub-hosted runners",
    ),
    (
        "actions/setup-go",
        "Go is pre-installed on all GitHub-hosted runners",
    ),
    (
        "actions/setup-dotnet",
        ".NET SDK is pre-installed on all GitHub-hosted runners",
    ),
    (
        "shivammathur/setup-php",
        "PHP is pre-installed on Ubuntu runners",
    ),
];

fn re_uses_action() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@").unwrap())
}

/// Per-action input names that satisfy "the user explicitly chose a version".
/// Indexed by the action's repo path (lowercased).
fn version_input_for(action_lower: &str) -> Option<&'static str> {
    match action_lower {
        "actions/setup-node" => Some("node-version"),
        "actions/setup-python" => Some("python-version"),
        "actions/setup-java" => Some("java-version"),
        "actions/setup-go" => Some("go-version"),
        "actions/setup-dotnet" => Some("dotnet-version"),
        "shivammathur/setup-php" => Some("php-version"),
        _ => None,
    }
}

impl Rule for Wrd827 {
    fn id(&self) -> &str {
        "WRD-827"
    }
    fn name(&self) -> &str {
        "Superfluous Actions"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects setup actions that may be unnecessary because the tool is \
         already pre-installed on GitHub-hosted runners"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let lines: Vec<&str> = content.lines().collect();

        // Per-action analysis: a workflow-wide presence of `python-version:`
        // must NOT suppress flagging a sibling `setup-node` step. Walk every
        // `uses:` line and only consider the version inputs that live inside
        // the same step block.
        for (i, line) in lines.iter().enumerate() {
            let Some(cap) = re_uses_action().captures(line) else {
                continue;
            };
            let action = cap.get(1).unwrap().as_str();
            let action_lower = action.to_lowercase();

            // Is this one of the superfluous actions we care about?
            let Some((_, reason)) = SUPERFLUOUS_ACTIONS
                .iter()
                .find(|(known, _)| action_lower == known.to_lowercase())
            else {
                continue;
            };

            // Determine what counts as an explicit version pin for this action.
            let Some(version_key) = version_input_for(&action_lower) else {
                // Unknown setup action; don't second-guess what justifies it.
                continue;
            };

            // Scan forward inside the same step block for the version input.
            // The step ends at the next line at the same or shallower indent
            // that starts a new step (`-` marker) or a sibling key.
            let uses_indent = line.len() - line.trim_start().len();
            let mut explicit_version = false;
            for next_line in lines.iter().skip(i + 1) {
                let trimmed = next_line.trim_end();
                if trimmed.is_empty() {
                    continue;
                }
                let indent = next_line.len() - next_line.trim_start().len();
                // A new step begins at the same indent with a `-` marker.
                let starts_new_step =
                    next_line.trim_start().starts_with('-') && indent <= uses_indent;
                if starts_new_step {
                    break;
                }
                // A sibling top-level key (jobs:, another job, ...) at <= the
                // step's container indent also ends the block.
                if indent < uses_indent {
                    break;
                }
                if trimmed.contains(version_key) {
                    // Cheap-but-correct check: the line literally mentions the
                    // input key (e.g. `node-version: '20'` or `node-version:`).
                    // We don't need a full YAML parse here.
                    let key_re = format!(r"(?m)^\s*{}\s*:", regex::escape(version_key));
                    if Regex::new(&key_re).unwrap().is_match(trimmed) {
                        explicit_version = true;
                        break;
                    }
                }
            }

            if explicit_version {
                continue;
            }

            let line_no = i + 1;
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!("Potentially superfluous action: {action}"),
                description: format!(
                    "Action '{action}' may be unnecessary. {reason}. If the default \
                     version is sufficient, the setup action adds overhead \
                     without benefit."
                ),
                file: workflow.path.clone(),
                line: line_no,
                remediation: format!(
                    "If you need a specific version, add a version input \
                     (e.g., node-version: '20'). Otherwise, consider removing \
                     '{action}' and using the pre-installed version."
                ),
            });
        }

        findings
    }
}
