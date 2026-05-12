use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

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

// ---------------------------------------------------------------------------
// V2: typed walk of every uses: step with a typed `with:` block. Skip steps
// whose `with:` includes the action-specific version key.
// ---------------------------------------------------------------------------

pub struct Wrd841;

fn superfluous_reason(uses: &str) -> Option<(&'static str, &'static str)> {
    let at = uses.split('@').next().unwrap_or(uses);
    let lower = at.to_ascii_lowercase();
    for (known, reason) in SUPERFLUOUS_ACTIONS {
        if lower == known.to_lowercase() {
            return Some((known, reason));
        }
    }
    None
}

impl Rule for Wrd841 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-841",
            name: "Superfluous Setup Action",
            default_severity: Severity::Info,
            description: "Detects setup actions that may be unnecessary because the tool is \
                          already pre-installed on GitHub-hosted runners.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        for (job_name, job) in &wf.jobs {
            if let crate::models::Job::Normal(j) = job {
                for (i, step) in j.steps.iter().enumerate() {
                    let crate::models::Step::Uses(u) = step else {
                        continue;
                    };
                    let Some((action, reason)) = superfluous_reason(&u.uses) else {
                        continue;
                    };
                    let action_lower = action.to_lowercase();
                    let Some(version_key) = version_input_for(&action_lower) else {
                        continue;
                    };

                    let has_version = u
                        .with
                        .as_ref()
                        .map(|m| m.contains_key(version_key))
                        .unwrap_or(false);
                    if has_version {
                        continue;
                    }

                    let span = ctx
                        .loaded
                        .spans
                        .get_str(&format!("jobs.{job_name}.steps[{i}].uses"))
                        .unwrap_or_else(default_span);
                    findings.push(RuleFinding {
                        rule_id: "WRD-841",
                        severity: Severity::Info,
                        title: format!("Potentially superfluous action: {action}"),
                        description: format!(
                            "Action '{action}' may be unnecessary. {reason}. If the default \
                             version is sufficient, the setup action adds overhead without \
                             benefit."
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: format!(
                            "If you need a specific version, add a version input (e.g., \
                             node-version: '20'). Otherwise, consider removing '{action}' and \
                             using the pre-installed version."
                        ),
                    });
                }
            }
        }
        findings
    }
}
