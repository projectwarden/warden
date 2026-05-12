use crate::expression::{is_tainted, path_to_string};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

/// The canonical list of attacker-controlled GitHub context expressions.
/// Both WRD-101 (the scanner) and `fix::fix_expression_injection` (the fixer)
/// consume this so they fire on the same set of expressions. Without this
/// shared source of truth the fixer would rewrite expressions the scanner
/// considers safe, producing surprise extras in `warden fix --pr` output.
pub const TAINTED_EXPRESSIONS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.name",
    "github.event.commits.*.author.email",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.head_ref",
];

// ---------------------------------------------------------------------------
// V2: typed model + real expression parser + byte-exact spans.
//
// Catches tainted-source reads that the legacy regex misses, including ones
// wrapped in `format(...)`, `contains(...)`, or other function calls.
// ---------------------------------------------------------------------------

pub struct Wrd101;

impl Rule for Wrd101 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-101",
            name: "Expression Injection",
            default_severity: Severity::Critical,
            description: "Attacker-controlled GitHub context expressions interpolated in run: \
                 blocks allow arbitrary command injection.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for occ in ctx.expressions.occurrences() {
            // Only run: blocks are exploitable for command injection.
            if !occ.path.ends_with(".run") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                if !is_tainted(&path) {
                    continue;
                }
                let field_span = ctx
                    .loaded
                    .spans
                    .get_str(&occ.path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                // The actual interpolation may be N lines into a `run: |`
                // block scalar. Add the field-relative line offset so the
                // primary span points at the offending line, not the run:
                // header (which is what makes inline ignore comments work).
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
                    rule_id: "WRD-101",
                    severity: Severity::Critical,
                    title: format!("Expression injection via {pretty}"),
                    description: format!(
                        "The expression ${{{{ {pretty} }}}} is interpolated in a run: \
                         block. An attacker can control this value and inject \
                         arbitrary commands."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Pass the value through an environment variable instead: \
                                  env: MY_VAR: ${{ <expr> }}, then use $MY_VAR in the \
                                  script."
                        .to_string(),
                });
            }
        }

        findings
    }
}
