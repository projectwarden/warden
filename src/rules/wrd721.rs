use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::Job;
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk typed Reusable-call jobs and test `secrets` for the scalar
// "inherit". The legacy regex matches `secrets: inherit` anywhere in the
// file; this implementation only fires on the canonical job-level form.
// ---------------------------------------------------------------------------

pub struct Wrd721;

impl Rule for Wrd721 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-721",
            name: "Reusable Workflow Secrets Inherit",
            default_severity: Severity::Medium,
            description: "Detects 'secrets: inherit' in reusable workflow calls, which passes \
                          all repository secrets to the called workflow.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        for (job_name, job) in &wf.jobs {
            let Job::Reusable(r) = job else { continue };
            let Some(secrets) = &r.secrets else { continue };
            let is_inherit = match secrets {
                serde_yaml::Value::String(s) => s == "inherit",
                _ => false,
            };
            if !is_inherit {
                continue;
            }
            let path = format!("jobs.{job_name}.secrets");
            let span = ctx
                .loaded
                .spans
                .get_str(&path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            findings.push(RuleFinding {
                rule_id: "WRD-721",
                severity: Severity::Medium,
                title: "secrets: inherit passes all secrets to called workflow".to_string(),
                description: "Using 'secrets: inherit' forwards every secret in the calling \
                              repository to the reusable workflow. If that workflow is \
                              external or broadly scoped, secrets may be exposed \
                              unnecessarily."
                    .to_string(),
                primary: span,
                related: Vec::new(),
                remediation: "Pass only the specific secrets the called workflow needs, e.g. \
                              secrets: { MY_TOKEN: ${{ secrets.MY_TOKEN }} }."
                    .to_string(),
            });
        }

        findings
    }
}
