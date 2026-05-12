use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed-model walk over step `uses:` strings; parse `owner/repo@ref` and
// flag hex refs that aren't exactly 40 chars or that are placeholder patterns.
// ---------------------------------------------------------------------------

pub struct Wrd310;

/// Split a `uses:` value into (action, ref) if it has the `owner/repo@ref`
/// shape that this rule cares about. Returns None for local (`./...`) or
/// docker refs.
fn split_uses(uses: &str) -> Option<(&str, &str)> {
    if uses.starts_with("./") || uses.starts_with("../") || uses.starts_with("docker://") {
        return None;
    }
    let (action, ref_val) = uses.split_once('@')?;
    // Must look like owner/repo (at least one slash) and ref be non-empty.
    if !action.contains('/') || ref_val.is_empty() {
        return None;
    }
    Some((action, ref_val))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Rule for Wrd310 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-310",
            name: "Impostor Commit",
            default_severity: Severity::High,
            description: "Actions pinned to commit SHAs that appear suspicious. Impostor commits \
                          can be pushed to a repository via its fork and may not belong to any \
                          branch or tag in the original repository.",
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
                let Some((action, ref_val)) = split_uses(&u.uses) else {
                    continue;
                };
                // Only hex-looking refs; tag refs like v3 are WRD-311's job.
                if !is_hex(ref_val) {
                    continue;
                }

                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

                if ref_val.len() != 40 {
                    findings.push(RuleFinding {
                        rule_id: "WRD-310",
                        severity: Severity::High,
                        title: format!("Suspicious SHA pin for {action}"),
                        description: format!(
                            "Action '{}' is pinned to '{}' which is {} characters. \
                             Valid full commit SHAs are exactly 40 hex characters. \
                             Truncated SHAs can collide and may indicate an impostor commit.",
                            action,
                            ref_val,
                            ref_val.len()
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Use the full 40-character commit SHA. Verify the commit \
                                      exists on the default branch or a tagged release of the \
                                      action repository."
                            .to_string(),
                    });
                }

                if ref_val.chars().all(|c| c == '0') || ref_val.chars().all(|c| c == 'a') {
                    findings.push(RuleFinding {
                        rule_id: "WRD-310",
                        severity: Severity::High,
                        title: format!("Suspicious SHA pattern for {action}"),
                        description: format!(
                            "Action '{action}' is pinned to '{ref_val}' which appears to be a \
                             placeholder or test SHA."
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Replace with a real commit SHA from the action repository."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
