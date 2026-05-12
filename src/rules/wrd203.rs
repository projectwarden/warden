use crate::models::{Job, PermissionLevel, Permissions, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: trigger must be `workflow_run`. Flag when the workflow grants any write
// permission (bulk write-all or any per-scope `: write`) OR uses
// `actions/download-artifact`.
// ---------------------------------------------------------------------------

pub struct Wrd203;

fn has_any_write(p: &Permissions) -> bool {
    if p.is_write_all() {
        return true;
    }
    if let Some(scopes) = p.scopes() {
        return scopes.values().any(|lvl| *lvl == PermissionLevel::Write);
    }
    false
}

impl Rule for Wrd203 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-203",
            name: "Cross-Workflow Privilege Escalation",
            default_severity: Severity::Critical,
            description: "A workflow_run workflow with write permissions watching a \
                          pull_request workflow can be exploited via artifact poisoning for \
                          privilege escalation.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        if !wf.on.mentions("workflow_run") {
            return Vec::new();
        }

        let has_write_perms = wf.permissions.as_ref().map(has_any_write).unwrap_or(false);

        let mut downloads_artifacts = false;
        for job in wf.jobs.values() {
            let Job::Normal(j) = job else { continue };
            for step in &j.steps {
                if let Step::Uses(u) = step {
                    if u.uses.starts_with("actions/download-artifact") {
                        downloads_artifacts = true;
                        break;
                    }
                }
            }
            if downloads_artifacts {
                break;
            }
        }

        if !has_write_perms && !downloads_artifacts {
            return Vec::new();
        }

        let span = ctx
            .loaded
            .spans
            .get_str("on")
            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
        vec![RuleFinding {
            rule_id: "WRD-203",
            severity: Severity::Critical,
            title: "workflow_run with elevated permissions".into(),
            description: "This workflow_run workflow has write permissions or downloads \
                          artifacts. If the producing workflow is triggered by pull_request, \
                          an attacker can poison artifacts in a fork PR to escalate privileges."
                .into(),
            primary: span,
            related: Vec::new(),
            remediation: "Minimize permissions on workflow_run workflows. Validate artifact \
                          integrity before use. Avoid executing code from downloaded artifacts."
                .into(),
        }]
    }
}
