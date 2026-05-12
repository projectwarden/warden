use crate::expression::PathSeg;
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct Wrd111;

impl Rule for Wrd111 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-111",
            name: "Untrusted Input Injection",
            default_severity: Severity::High,
            description: "workflow_dispatch, repository_dispatch, or workflow_call inputs \
                          interpolated in run: blocks can be controlled by an external caller \
                          (push user, dispatch API client, or upstream workflow) and injected \
                          into the shell.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let on = &ctx.loaded.workflow.on;
        // workflow_call callees read caller-supplied inputs.* in their run
        // blocks; although the caller is another workflow rather than a push
        // user, the input is still externally controlled from the callee's
        // point of view and produces the same injection surface. The fixer
        // (fix_expression_injection) already rewrites these, so suppressing
        // the finding here would cause the "fixes proposed / no findings"
        // parity drift that tripped the 2026-04-23 audit.
        if !on.mentions("workflow_dispatch")
            && !on.mentions("repository_dispatch")
            && !on.mentions("workflow_call")
        {
            return Vec::new();
        }

        // Source label for the finding title so the caller sees which
        // trigger family applies; helps triage in multi-trigger workflows.
        let source = if on.mentions("workflow_call") {
            "workflow_call"
        } else if on.mentions("workflow_dispatch") {
            "workflow_dispatch"
        } else {
            "repository_dispatch"
        };

        let mut findings = Vec::new();
        for occ in ctx.expressions.occurrences() {
            if !occ.path.ends_with(".run") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                if matches!(path.first(), Some(PathSeg::Root(r)) if r == "inputs") {
                    let field_span = ctx
                        .loaded
                        .spans
                        .get_str(&occ.path)
                        .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                    let actual_line = field_span.start_line + occ.line_offset_in_field;
                    let span = Span::new(
                        field_span.byte_start,
                        field_span.byte_end,
                        actual_line,
                        field_span.start_col,
                        actual_line,
                        field_span.end_col,
                    );
                    findings.push(RuleFinding {
                        rule_id: "WRD-111",
                        severity: Severity::High,
                        title: format!("{source} input interpolated in run: block"),
                        description: format!(
                            "An `inputs.*` value from {source} is read inside a run: block. \
                             Externally-supplied inputs interpolated into the shell can be \
                             crafted to inject arbitrary commands."
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Pass inputs through an `env:` mapping and reference \
                                      the environment variable inside the script instead of \
                                      `${{ inputs.* }}` directly."
                            .into(),
                    });
                    break;
                }
            }
        }
        findings
    }
}
