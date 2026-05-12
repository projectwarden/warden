use crate::models::{Job, PermissionLevel, Permissions};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed-model lookup of permissions (top-level + per-job). If any grant
// `id-token: write` AND the workflow's triggers include any of the external /
// attacker-reachable event names, emit one finding per matched trigger.
// ---------------------------------------------------------------------------

pub struct Wrd301;

const DANGEROUS_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion_comment",
    "repository_dispatch",
];

fn grants_id_token_write(p: &Permissions) -> bool {
    if p.is_write_all() {
        return true;
    }
    if let Some(scopes) = p.scopes() {
        if let Some(level) = scopes.get("id-token") {
            return *level == PermissionLevel::Write;
        }
    }
    false
}

impl Rule for Wrd301 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-301",
            name: "OIDC Trust Boundary Violation",
            default_severity: Severity::Critical,
            description: "id-token: write permission with external triggers \
                          (pull_request_target, workflow_run, issue_comment) can allow \
                          attackers to obtain OIDC tokens and access cloud resources.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;

        let mut oidc_path: Option<String> = None;
        if let Some(p) = &wf.permissions {
            if grants_id_token_write(p) {
                oidc_path = Some("permissions".to_string());
            }
        }
        if oidc_path.is_none() {
            for (job_name, job) in &wf.jobs {
                let perms = match job {
                    Job::Normal(j) => j.permissions.as_ref(),
                    Job::Reusable(j) => j.permissions.as_ref(),
                };
                if let Some(p) = perms {
                    if grants_id_token_write(p) {
                        oidc_path = Some(format!("jobs.{job_name}.permissions"));
                        break;
                    }
                }
            }
        }

        let Some(oidc_path) = oidc_path else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for trigger in DANGEROUS_TRIGGERS {
            if !wf.on.mentions(trigger) {
                continue;
            }
            let span = ctx
                .loaded
                .spans
                .get_str(&oidc_path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            findings.push(RuleFinding {
                rule_id: "WRD-301",
                severity: Severity::Critical,
                title: format!("OIDC token with {trigger} trigger"),
                description: format!(
                    "This workflow requests id-token: write and uses the '{trigger}' trigger. \
                     An attacker may be able to obtain OIDC tokens to access cloud resources \
                     (AWS, GCP, Azure) configured to trust this repository."
                ),
                primary: span,
                related: Vec::new(),
                remediation: "Restrict OIDC token permissions to workflows triggered only by \
                              trusted events (push, release). Add subject claim filters in \
                              your cloud provider's OIDC configuration."
                    .into(),
            });
        }
        findings
    }
}
