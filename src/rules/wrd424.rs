use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::expression::PathSeg;
use crate::models::Job;
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed-model + expression index. Walk jobs, and for any normal job with
// no `environment:` set, look for `secrets.*` expression occurrences under
// that job's path (excluding GITHUB_TOKEN). Emit one finding per job.
// ---------------------------------------------------------------------------

pub struct Wrd424;

fn secret_name_if_not_github_token(path: &[PathSeg]) -> Option<String> {
    if path.len() < 2 {
        return None;
    }
    match &path[0] {
        PathSeg::Root(r) if r == "secrets" => {}
        _ => return None,
    }
    let name = match &path[1] {
        PathSeg::Field(f) => f.clone(),
        PathSeg::IndexString(s) => s.clone(),
        _ => return None,
    };
    if name == "GITHUB_TOKEN" {
        return None;
    }
    Some(name)
}

impl Rule for Wrd424 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-424",
            name: "Secrets Used Without Environment Gate",
            default_severity: Severity::Medium,
            description: "A job references secrets (other than GITHUB_TOKEN) without declaring \
                          an `environment:`, so no required-reviewers or deployment protection \
                          rules gate the secret access.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else {
                continue;
            };
            if j.environment.is_some() {
                continue;
            }

            let job_prefix = format!("jobs.{job_name}.");
            let mut matched_secret: Option<String> = None;
            for occ in ctx.expressions.occurrences() {
                if !occ.path.starts_with(&job_prefix) {
                    continue;
                }
                let Some(ast) = occ.ast.as_ref() else {
                    continue;
                };
                for p in ast.all_paths() {
                    if let Some(name) = secret_name_if_not_github_token(&p) {
                        matched_secret = Some(name);
                        break;
                    }
                }
                if matched_secret.is_some() {
                    break;
                }
            }

            let Some(secret_name) = matched_secret else {
                continue;
            };

            let job_path = format!("jobs.{job_name}");
            let span = ctx
                .loaded
                .spans
                .get_str(&job_path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

            findings.push(RuleFinding {
                rule_id: "WRD-424",
                severity: Severity::Medium,
                title: "Job uses secrets without environment protection".into(),
                description: format!(
                    "Job '{job_name}' references secrets.{secret_name} but has no \
                     `environment:` key. Without an environment, secret access is not gated \
                     by deployment protection rules or required reviewers."
                ),
                primary: span,
                related: Vec::new(),
                remediation: "Add `environment: production` (or another protected environment) \
                              to this job so secret access requires environment protection \
                              rules / required reviewers."
                    .into(),
            });
        }

        findings
    }
}
