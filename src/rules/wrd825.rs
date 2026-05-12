use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::expression::{BinaryOp, Expr, Literal, PathSeg};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk parsed expressions in `if:` fields, look for
// `github.actor == 'dependabot[bot]'` shape comparisons.
// ---------------------------------------------------------------------------

pub struct Wrd825;

const SPOOFABLE_BOT_NAMES: &[&str] = &["dependabot[bot]", "renovate[bot]", "github-actions[bot]"];

fn is_github_actor(e: &Expr) -> bool {
    if let Some(path) = e.as_path() {
        return matches!(
            path.as_slice(),
            [PathSeg::Root(r), PathSeg::Field(f)]
                if r == "github" && f == "actor"
        );
    }
    false
}

fn is_bot_string(e: &Expr) -> Option<&str> {
    if let Expr::Literal(Literal::String(s)) = e {
        if SPOOFABLE_BOT_NAMES.contains(&s.as_str()) {
            return Some(s.as_str());
        }
    }
    None
}

fn find_spoofable_check(e: &Expr) -> Option<String> {
    if let Expr::Binary(BinaryOp::Eq, l, r) = e {
        if is_github_actor(l) {
            if let Some(name) = is_bot_string(r) {
                return Some(format!("github.actor == '{name}'"));
            }
        }
        if is_github_actor(r) {
            if let Some(name) = is_bot_string(l) {
                return Some(format!("github.actor == '{name}'"));
            }
        }
    }
    match e {
        Expr::Binary(_, l, r) => find_spoofable_check(l).or_else(|| find_spoofable_check(r)),
        Expr::Unary(_, inner) => find_spoofable_check(inner),
        Expr::Call(_, args) => args.iter().find_map(find_spoofable_check),
        Expr::Field(inner, _) | Expr::Star(inner) => find_spoofable_check(inner),
        Expr::Index(a, b) => find_spoofable_check(a).or_else(|| find_spoofable_check(b)),
        _ => None,
    }
}

impl Rule for Wrd825 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-825",
            name: "Spoofable Bot Identity Check",
            default_severity: Severity::Medium,
            description: "Detects if-conditions checking github.actor against bot names, \
                          which can be spoofed by renaming a user account.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for occ in ctx.expressions.occurrences() {
            if !occ.path.ends_with(".if") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            let Some(matched) = find_spoofable_check(ast) else {
                continue;
            };
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
                rule_id: "WRD-825",
                severity: Severity::Medium,
                title: format!("Spoofable bot identity check: {matched}"),
                description: "Checking github.actor against a bot name is unreliable because \
                              GitHub usernames can be changed to match bot names. An attacker \
                              could rename their account and trigger this condition."
                    .into(),
                primary: span,
                related: Vec::new(),
                remediation: "Compare against the bot account's numeric `github.actor_id` \
                              instead of `github.actor`. Actor IDs are immutable, so an \
                              attacker cannot rename their account to match. \
                              `github.event.sender.type == 'Bot'` is also spoofable: any \
                              GitHub App can identify as a Bot, so it is not a sufficient gate \
                              either."
                    .into(),
            });
        }
        findings
    }
}
