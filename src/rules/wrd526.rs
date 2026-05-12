use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walks every `uses: actions/create-github-app-token@...` step and
// inspects the step's `with:` map for three specific misuse patterns that
// expand either the token's validity window or its blast radius:
//
//   1. skip-token-revoke: true       -> HIGH, token outlives the job.
//   2. no repositories: specified    -> MEDIUM, token scoped to every repo
//                                       the App can access (over-broad).
//   3. no permissions: specified     -> MEDIUM, token inherits every
//                                       permission the App was granted.
//
// Matches zizmor's github-app audit (https://docs.zizmor.sh/audits/) plus
// gives warden users a clear three-finding breakdown + per-slot severity
// so the worst offender (skip-token-revoke) shows up as HIGH in the
// scan summary instead of being averaged into the other two.
// ---------------------------------------------------------------------------

pub struct Wrd526;

fn is_create_app_token(uses: &str) -> bool {
    // accept common fork paths; action is canonically actions/create-github-app-token
    // but tj-actions/create-github-app-token@main was the reviewdog-era fork.
    let base = uses.split('@').next().unwrap_or(uses);
    base == "actions/create-github-app-token"
        || base == "tibdex/github-app-token"
        || base == "getsentry/action-github-app-token"
}

fn scalar_as_bool_true(v: &crate::models::ScalarOrExpr) -> bool {
    matches!(v, crate::models::ScalarOrExpr::String(s) if s.eq_ignore_ascii_case("true"))
}

impl Rule for Wrd526 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-526",
            name: "GitHub App Token Misuse",
            default_severity: Severity::Medium,
            description: "GitHub App installation tokens minted by \
                          actions/create-github-app-token (and common forks) should be \
                          scoped to the narrowest repositories + permissions the job \
                          needs, and should be revoked when the job ends. Skipping \
                          revocation or leaving the scope wide-open extends the blast \
                          radius of any log leak.",
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
                if !is_create_app_token(&u.uses) {
                    continue;
                }

                let step_path = format!("jobs.{job_name}.steps[{i}]");
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&step_path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

                let with = u.with.as_ref();

                // 1. skip-token-revoke: true (HIGH)
                if let Some(v) = with.and_then(|w| w.get("skip-token-revoke")) {
                    if scalar_as_bool_true(v) {
                        findings.push(RuleFinding {
                            rule_id: "WRD-526",
                            severity: Severity::High,
                            title: format!("GitHub App token revocation disabled ({})", u.uses),
                            description: "This step mints a GitHub App installation token with \
                                 skip-token-revoke: true, so the token stays valid \
                                 after the workflow run ends instead of being revoked \
                                 automatically. Any log leak, artifact upload, or env \
                                 spill during that window lets an attacker continue \
                                 using the token long after the job is gone."
                                .into(),
                            primary: span,
                            related: Vec::new(),
                            remediation: "Remove the skip-token-revoke input (or set it to \
                                 false) so the token is revoked at the end of the \
                                 job. Only disable revocation if a downstream job \
                                 must reuse the same token AND your logs / artifacts \
                                 are locked down."
                                .into(),
                        });
                    }
                }

                // 2. no repositories: specified (MEDIUM)
                let has_repositories = with
                    .map(|w| w.contains_key("repositories") || w.contains_key("repository"))
                    .unwrap_or(false);
                if !has_repositories {
                    findings.push(RuleFinding {
                        rule_id: "WRD-526",
                        severity: Severity::Medium,
                        title: format!(
                            "GitHub App token scoped to all installation repos ({})",
                            u.uses
                        ),
                        description: "This step mints a GitHub App installation token without a \
                             `repositories:` input, so the token is valid against every \
                             repository the GitHub App is installed in. If the token \
                             leaks, the attacker reaches every repository the App can \
                             touch, not just the one this job operates on."
                            .into(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Add `repositories: <this-repo>` (or a short list) to the \
                             step's `with:` block so the issued token is narrowly \
                             scoped to the repos this job actually needs."
                            .into(),
                    });
                }

                // 3. no permissions: specified (MEDIUM)
                let has_permissions = with.map(|w| w.contains_key("permissions")).unwrap_or(false);
                if !has_permissions {
                    findings.push(RuleFinding {
                        rule_id: "WRD-526",
                        severity: Severity::Medium,
                        title: format!(
                            "GitHub App token inherits all installation permissions ({})",
                            u.uses
                        ),
                        description: "This step mints a GitHub App installation token without a \
                             `permissions:` input, so the token inherits every \
                             permission the GitHub App was granted when it was \
                             installed. A compromised token then has every scope the \
                             App has, not just the ones this job needs."
                            .into(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Add a `permissions:` block to the step's `with:` (e.g. \
                             `permissions: |\\n  contents: read\\n  pull_requests: \
                             write`) so the minted token is least-privilege."
                            .into(),
                    });
                }
            }
        }

        findings
    }
}
