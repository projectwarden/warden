use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, PermissionLevel, Permissions, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed check for release/workflow_dispatch triggers + write-granting
// permissions + actions/cache usage.
// ---------------------------------------------------------------------------

pub struct Wrd823;

fn has_write_grant(p: &Permissions) -> bool {
    if p.is_write_all() {
        return true;
    }
    if let Some(scopes) = p.scopes() {
        return scopes.values().any(|v| *v == PermissionLevel::Write);
    }
    false
}

fn triggers_push_tags(wf: &crate::models::Workflow) -> bool {
    if let crate::models::On::Map(m) = &wf.on {
        if let Some(Some(cfg)) = m.get("push") {
            if cfg.tags.is_some() {
                return true;
            }
        }
    }
    false
}

impl Rule for Wrd823 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-823",
            name: "Cache Poisoning Risk",
            default_severity: Severity::Medium,
            description: "Detects actions/cache usage in release or elevated-permission \
                          workflows where a poisoned cache could compromise builds.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;

        let has_release_trigger = wf.on.mentions("release")
            || wf.on.mentions("workflow_dispatch")
            || triggers_push_tags(wf);

        let has_elevated = wf
            .permissions
            .as_ref()
            .map(has_write_grant)
            .unwrap_or(false)
            || wf.jobs.values().any(|job| {
                if let Job::Normal(j) = job {
                    j.permissions.as_ref().map(has_write_grant).unwrap_or(false)
                } else {
                    false
                }
            });

        if !has_release_trigger && !has_elevated {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                for (i, step) in j.steps.iter().enumerate() {
                    if let Step::Uses(u) = step {
                        if u.uses.starts_with("actions/cache") {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("jobs.{job_name}.steps[{i}].uses"))
                                .unwrap_or_else(default_span);
                            findings.push(RuleFinding {
                                rule_id: "WRD-823",
                                severity: Severity::Medium,
                                title: "actions/cache in release workflow with elevated \
                                        permissions"
                                    .into(),
                                description: "Using actions/cache in a release or \
                                              high-privilege workflow is risky. An attacker \
                                              who poisons the cache via a PR build can inject \
                                              malicious artifacts into the release pipeline."
                                    .into(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Use separate cache keys for PR and release \
                                              workflows, or avoid restoring caches from \
                                              untrusted branches in release builds. Consider \
                                              using immutable artifacts instead of mutable \
                                              caches."
                                    .into(),
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}
