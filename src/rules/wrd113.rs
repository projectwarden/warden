use crate::expression::{matches_pattern, path_to_string, PathSeg};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

const TAINTED_PATTERNS: &[&str] = &[
    "github.head_ref",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
];

// ---------------------------------------------------------------------------
// V2: walks parsed expression occurrences at `.with.` paths and path-matches
// each extracted context read against the same TAINTED_PATTERNS list as V1.
// Handles wrappers (format(), contains(), etc.) that the regex misses.
// ---------------------------------------------------------------------------

pub struct Wrd113;

fn path_is_tainted_113(path: &[PathSeg]) -> bool {
    TAINTED_PATTERNS
        .iter()
        .any(|pat| matches_pattern(path, pat))
}

impl Rule for Wrd113 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-113",
            name: "Tainted Reusable Workflow Inputs",
            default_severity: Severity::High,
            description: "Attacker-controlled values passed as inputs to reusable workflows can \
                          cause injection if the called workflow interpolates them unsafely.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for occ in ctx.expressions.occurrences() {
            // Only consider expressions inside a reusable-call `with:` block.
            // Layout: `jobs.<name>.with.<key>` (reusable call at job level).
            if !occ.path.contains(".with.") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                if !path_is_tainted_113(&path) {
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
                    rule_id: "WRD-113",
                    severity: Severity::High,
                    title: format!("Tainted input passed to reusable workflow: {pretty}"),
                    description: format!(
                        "The attacker-controlled expression '{pretty}' is passed as input to a \
                         reusable workflow. If the callee interpolates it in a run: block, \
                         command injection is possible."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Sanitize or validate the value before passing it. Ensure the \
                                  called workflow uses environment variables instead of direct \
                                  interpolation."
                        .to_string(),
                });
            }
        }

        findings
    }
}
