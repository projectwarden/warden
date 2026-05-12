use crate::expression::{path_to_string, PathSeg};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed model + expression parser. Detects `secrets.*` interpolations
// anywhere inside a run: block, including ones wrapped in `format(...)` or
// other function calls that the legacy regex misses.
// ---------------------------------------------------------------------------

pub struct Wrd440;

fn path_is_secrets(path: &[PathSeg]) -> bool {
    matches!(path.first(), Some(PathSeg::Root(r)) if r == "secrets") && path.len() >= 2
}

impl Rule for Wrd440 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-440",
            name: "Secret Reference Inventory",
            default_severity: Severity::Info,
            description: "Secrets interpolated directly in run: blocks can leak through process \
                          listings, shell history, and error messages. Pass them via environment \
                          variables instead.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();

        for occ in ctx.expressions.occurrences() {
            if !occ.path.ends_with(".run") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                if !path_is_secrets(&path) {
                    continue;
                }
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
                let pretty = path_to_string(&path);
                findings.push(RuleFinding {
                    rule_id: "WRD-440",
                    severity: Severity::Info,
                    title: "Secret directly in run: block".into(),
                    description: format!(
                        "Expression ${{{{ {pretty} }}}} is interpolated directly in a run: \
                         block. Secrets in shell commands can leak through process tables, \
                         logs, and error messages."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Pass secrets through step-level environment variables: \
                                  env: MY_SECRET: ${{ secrets.TOKEN }}, then use $MY_SECRET \
                                  in the script."
                        .into(),
                });
            }
        }

        findings
    }
}
