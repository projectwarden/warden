use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

/// Known archived or deprecated GitHub Actions repos.
const ARCHIVED_ACTIONS: &[&str] = &[
    "actions/create-release",
    "actions/upload-release-asset",
    "peter-evans/slash-command-dispatch",
    "actions-rs/toolchain",
    "actions-rs/cargo",
    "actions-rs/clippy-check",
    "actions-rs/audit-check",
    "actions-rs/tarpaulin",
    "actions-ecosystem/action-add-labels",
    "aochmann/actions-download-artifact",
    "chrnorm/deployment-action",
    "elgohr/Publish-Docker-Github-Action",
];

// ---------------------------------------------------------------------------
// V2: typed-model walk; compare each step's `uses:` action prefix (before `@`)
// against the archived list, case-insensitively.
// ---------------------------------------------------------------------------

pub struct Wrd331;

impl Rule for Wrd331 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-331",
            name: "Archived Action Reference",
            default_severity: Severity::Low,
            description: "Detects references to GitHub Actions from known archived or deprecated \
                          repositories.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                let action = match u.uses.split_once('@') {
                    Some((a, _)) => a,
                    None => u.uses.as_str(),
                };
                if action.starts_with("./") || action.starts_with("../") {
                    continue;
                }
                let action_lower = action.to_lowercase();
                if ARCHIVED_ACTIONS
                    .iter()
                    .any(|a| a.to_lowercase() == action_lower)
                {
                    let span = ctx
                        .loaded
                        .spans
                        .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                        .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                    findings.push(RuleFinding {
                        rule_id: "WRD-331",
                        severity: Severity::Low,
                        title: format!("Archived action referenced: {action}"),
                        description: format!(
                            "Action '{action}' comes from a known archived or deprecated \
                             repository. Archived actions no longer receive security patches \
                             or bug fixes."
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: format!(
                            "Replace '{action}' with an actively maintained alternative. \
                             Check the repo's README for migration guidance."
                        ),
                    });
                }
            }
        }

        findings
    }
}
