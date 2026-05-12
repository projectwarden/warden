use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

/// Branch names that are ambiguous when used as action refs.
const AMBIGUOUS_REFS: &[&str] = &["main", "master", "develop", "trunk", "dev", "HEAD"];

// ---------------------------------------------------------------------------
// V2: typed-model walk; for each `uses: owner/repo@ref` inspect the ref.
// SHA pins and version tags (vN...) are skipped; bare branch names like
// `main` or `HEAD` are flagged.
// ---------------------------------------------------------------------------

pub struct Wrd324;

fn is_sha40(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_version_tag(s: &str) -> bool {
    s.starts_with('v') && s.len() > 1 && s.as_bytes()[1].is_ascii_digit()
}

impl Rule for Wrd324 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-324",
            name: "Branch-Ref Action Pin",
            default_severity: Severity::Medium,
            description: "Detects actions pinned to branch names (main, master, develop, etc.) \
                          that are ambiguous and mutable.",
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
                if u.uses.starts_with("./") || u.uses.starts_with("../") {
                    continue;
                }
                let Some((action, ref_val)) = u.uses.split_once('@') else {
                    continue;
                };
                if !action.contains('/') {
                    continue;
                }
                if is_sha40(ref_val) || looks_like_version_tag(ref_val) {
                    continue;
                }
                if !AMBIGUOUS_REFS.contains(&ref_val) {
                    continue;
                }

                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-324",
                    severity: Severity::Medium,
                    title: format!("Action pinned to branch ref: {action}@{ref_val}"),
                    description: format!(
                        "Action '{action}' is pinned to '{ref_val}', which is a mutable \
                         branch ref. This means the action code can change at any time \
                         without notice, making builds non-reproducible and vulnerable to \
                         supply chain attacks."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: format!(
                        "Pin '{action}' to a specific SHA or version tag instead of \
                         '{ref_val}'. Use Dependabot or Renovate to keep pins current."
                    ),
                });
            }
        }

        findings
    }
}
