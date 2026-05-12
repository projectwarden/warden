use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// NOTE: a per-job-write-grant sub-check used to live here. It walked every
// `<scope>: write` line and emitted a "Potentially unnecessary write
// permission" finding for each. Without semantic analysis of whether the job
// actually needed the grant, the false-positive rate was too high to ship,
// drowning real findings. It has been removed; reintroduce only with proper
// per-job dataflow.

// ---------------------------------------------------------------------------
// V2 implementation: typed-model lookup of `permissions:`, no regex required.
// ---------------------------------------------------------------------------

pub struct Wrd824;

impl Rule for Wrd824 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-824",
            name: "Excessive Permissions Or Missing Block",
            default_severity: Severity::Medium,
            description: "Detects `permissions: write-all` grants and workflows that omit a \
                          top-level permissions block entirely.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        match &wf.permissions {
            Some(p) if p.is_write_all() => {
                let span = ctx
                    .loaded
                    .spans
                    .get_str("permissions")
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-824",
                    severity: Severity::Medium,
                    title: "permissions: write-all grants excessive access".into(),
                    description: "Using write-all gives every scope write access. Prefer \
                                  granting only the specific permissions needed."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Replace 'permissions: write-all' with specific scopes, e.g. \
                                  contents: read, issues: write."
                        .into(),
                });
            }
            None => {
                findings.push(RuleFinding {
                    rule_id: "WRD-824",
                    severity: Severity::Medium,
                    title: "No top-level permissions block defined".into(),
                    description: "Without an explicit permissions block the workflow inherits \
                                  the default token permissions, which may be overly broad."
                        .into(),
                    primary: Span::new(0, 0, 1, 1, 1, 1),
                    related: Vec::new(),
                    remediation: "Add a top-level 'permissions: {}' block (empty for \
                                  read-only) and grant specific scopes per job as needed."
                        .into(),
                });
            }
            _ => {}
        }

        findings
    }
}
