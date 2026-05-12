use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct Wrd842;

impl Rule for Wrd842 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-842",
            name: "Missing Concurrency Limits",
            default_severity: Severity::Info,
            description: "Push and pull_request workflows without a concurrency: block let \
                          parallel runs of the same workflow stomp on each other.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        if wf.concurrency.is_some() {
            return Vec::new();
        }
        if !wf.on.mentions("push") && !wf.on.mentions("pull_request") {
            return Vec::new();
        }
        let span = ctx
            .loaded
            .spans
            .get_str("on")
            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
        vec![RuleFinding {
            rule_id: "WRD-842",
            severity: Severity::Info,
            title: "Workflow lacks a concurrency block".into(),
            description: "push / pull_request workflows without `concurrency:` allow multiple \
                          runs of the same workflow on the same ref to interleave."
                .into(),
            primary: span,
            related: Vec::new(),
            remediation: "Add `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, \
                          cancel-in-progress: true }`."
                .into(),
        }]
    }
}
