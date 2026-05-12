use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::expression::{Expr, PathSeg};
use crate::yamlpath::Span;

// NOTE: a `secrets.*` wildcard regex used to live here. GitHub Actions has no
// such expression syntax (you cannot iterate the secrets context via a glob),
// so the regex would only ever match the literal four-character substring
// inside YAML free-form text or comments. That produced false positives with
// no real signal. The wildcard variant has been removed; the only honest
// detection is `toJSON(secrets)`.

pub struct Wrd701;

fn calls_tojson_secrets(e: &Expr) -> bool {
    match e {
        Expr::Call(name, args) => {
            if name.eq_ignore_ascii_case("toJSON") && args.len() == 1 {
                if let Some(path) = args[0].as_path() {
                    if matches!(path.first(), Some(PathSeg::Root(r)) if r == "secrets") {
                        return true;
                    }
                }
            }
            args.iter().any(calls_tojson_secrets)
        }
        Expr::Unary(_, inner) => calls_tojson_secrets(inner),
        Expr::Binary(_, l, r) => calls_tojson_secrets(l) || calls_tojson_secrets(r),
        Expr::Field(inner, _) | Expr::Star(inner) => calls_tojson_secrets(inner),
        Expr::Index(a, b) => calls_tojson_secrets(a) || calls_tojson_secrets(b),
        _ => false,
    }
}

impl Rule for Wrd701 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-701",
            name: "toJSON(secrets) Exposure",
            default_severity: Severity::Critical,
            description: "toJSON(secrets) serializes the entire secrets context, exposing \
                          every secret to anywhere the result is interpolated.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for occ in ctx.expressions.occurrences() {
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            if !calls_tojson_secrets(ast) {
                continue;
            }
            let field_span = ctx
                .loaded
                .spans
                .get_str(&occ.path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            let actual_line = field_span.start_line + occ.line_offset_in_field;
            findings.push(RuleFinding {
                rule_id: "WRD-701",
                severity: Severity::Critical,
                title: "toJSON(secrets) serializes all secrets".into(),
                description: "toJSON(secrets) returns a JSON string containing every secret \
                              available to this workflow. Wherever this is interpolated, the \
                              entire secrets context is exposed."
                    .into(),
                primary: Span::new(
                    field_span.byte_start,
                    field_span.byte_end,
                    actual_line,
                    field_span.start_col,
                    actual_line,
                    field_span.end_col,
                ),
                related: Vec::new(),
                remediation: "Reference specific secrets by name (`${{ secrets.MY_SECRET }}`) \
                              instead of serializing the whole context."
                    .into(),
            });
        }
        findings
    }
}
