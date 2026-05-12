use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct Wrd843;

impl Rule for Wrd843 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-843",
            name: "Missing Workflow Name",
            default_severity: Severity::Info,
            description: "Detects workflow files missing a top-level 'name:' key.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        if ctx.loaded.workflow.name.is_some() {
            return Vec::new();
        }
        vec![RuleFinding {
            rule_id: "WRD-843",
            severity: Severity::Info,
            title: "Workflow has no top-level name".into(),
            description: "This workflow file lacks a top-level 'name:' key. Without a name, \
                          the workflow appears as the filename in the GitHub Actions UI, \
                          making it harder to identify at a glance."
                .into(),
            primary: Span::new(0, 0, 1, 1, 1, 1),
            related: Vec::new(),
            remediation: "Add a descriptive 'name:' key at the top of the workflow file, \
                          e.g., 'name: CI Build and Test'."
                .into(),
        }]
    }
}
