use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed lookup of `on:` triggers + top-level `permissions:` field.
// ---------------------------------------------------------------------------

pub struct Wrd812;

const RISKY_TRIGGERS_V2: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion_comment",
    "repository_dispatch",
];

impl Rule for Wrd812 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-812",
            name: "Risky Trigger Without Permissions Block",
            default_severity: Severity::High,
            description: "Workflow uses a risky trigger without an explicit top-level \
                          permissions: block, inheriting the repo default which may grant \
                          write access.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;

        let Some(trigger) = RISKY_TRIGGERS_V2
            .iter()
            .copied()
            .find(|t| wf.on.mentions(t))
        else {
            return Vec::new();
        };

        if wf.permissions.is_some() {
            return Vec::new();
        }

        let span = ctx
            .loaded
            .spans
            .get_str("on")
            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
        vec![RuleFinding {
            rule_id: "WRD-812",
            severity: Severity::High,
            title: "Risky trigger uses default permissions".into(),
            description: format!(
                "Workflow is triggered by '{trigger}' but has no top-level permissions: \
                 block. It will inherit the repository default GITHUB_TOKEN permissions, \
                 which may be write-all, giving attacker-influenced runs excessive \
                 privileges."
            ),
            primary: span,
            related: Vec::new(),
            remediation: "Add an explicit top-level `permissions:` block (e.g. \
                          `permissions: read-all`) to avoid inheriting the repo-default \
                          which may be write-all."
                .into(),
        }]
    }
}
