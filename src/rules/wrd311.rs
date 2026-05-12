use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

const GITHUB_OWNED_PREFIXES: &[&str] = &["actions/", "github/"];

// ---------------------------------------------------------------------------
// V2: typed-model walk; each `uses: owner/repo@ref` is inspected directly,
// no regex scan over the raw text. GitHub-owned actions stay medium-severity.
// ---------------------------------------------------------------------------

pub struct Wrd311;

fn is_sha40(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Rule for Wrd311 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-311",
            name: "Unpinned Third-Party Actions",
            default_severity: Severity::High,
            description: "Third-party actions pinned to mutable tags instead of commit SHAs can \
                          be silently replaced with malicious code via tag mutation.",
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

                // Skip local actions (./...).
                if u.uses.starts_with("./") || u.uses.starts_with("../") {
                    continue;
                }
                let Some((action, ref_val)) = u.uses.split_once('@') else {
                    continue;
                };
                if !action.contains('/') {
                    continue;
                }
                if is_sha40(ref_val) {
                    continue;
                }

                let is_github_owned = GITHUB_OWNED_PREFIXES
                    .iter()
                    .any(|prefix| action.starts_with(prefix));
                let severity = if is_github_owned {
                    Severity::Medium
                } else {
                    Severity::High
                };

                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

                findings.push(RuleFinding {
                    rule_id: "WRD-311",
                    severity,
                    title: format!("Unpinned action: {action}@{ref_val}"),
                    description: format!(
                        "Action '{}' is pinned to tag/branch '{}' instead of a commit SHA. \
                         {} actions pinned to mutable refs can be silently replaced.",
                        action,
                        ref_val,
                        if is_github_owned {
                            "GitHub-owned"
                        } else {
                            "Third-party"
                        }
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: format!(
                        "Pin '{action}' to a full commit SHA: {action}@<sha>. Use Dependabot or \
                         Renovate to keep pins updated."
                    ),
                });
            }
        }

        findings
    }
}
