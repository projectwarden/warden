use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;
use regex::Regex;
use std::sync::OnceLock;

// Note: Rust regex does not support backreferences.
// Instead we check for common self-comparison patterns explicitly.

pub struct Wrd830;

#[derive(Debug)]
enum Unsound {
    AlwaysTrue(&'static str),
    AlwaysFalse(&'static str),
    Tautological(&'static str),
}

fn re_expr_wrap() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*\$\{\{\s*(.*?)\s*\}\}\s*$").unwrap())
}

// rust-regex has no backreferences, so single- and double-quoted literal
// forms are matched by separate regexes with distinct capture groups.
fn re_literal_contains_sq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^contains\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)$"#).unwrap())
}
fn re_literal_contains_dq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^contains\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)$"#).unwrap())
}
fn re_literal_starts_with_sq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^startsWith\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)$"#).unwrap())
}
fn re_literal_starts_with_dq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^startsWith\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)$"#).unwrap())
}
fn re_literal_ends_with_sq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^endsWith\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)$"#).unwrap())
}
fn re_literal_ends_with_dq() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^endsWith\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)$"#).unwrap())
}

fn extract_literal_pair<'a>(s: &'a str, sq: &Regex, dq: &Regex) -> Option<(&'a str, &'a str)> {
    let caps = sq.captures(s).or_else(|| dq.captures(s))?;
    let haystack = caps.get(1)?.as_str();
    let needle = caps.get(2)?.as_str();
    Some((haystack, needle))
}

/// Check the body of the if-expression (with `${{ }}` stripped if present)
/// against the known-unsound shapes.
fn classify_core(body: &str) -> Option<Unsound> {
    let s = body.trim();

    // Always-true / always-false literals.
    if s.eq_ignore_ascii_case("true") {
        return Some(Unsound::AlwaysTrue("if: true"));
    }
    if s.eq_ignore_ascii_case("false") {
        return Some(Unsound::AlwaysFalse("if: false"));
    }
    if s.eq_ignore_ascii_case("always()") {
        return Some(Unsound::AlwaysTrue("if: always()"));
    }

    // Obvious self-equalities.
    if s == "1 == 1" || s == "'a' == 'a'" || s == "true == true" {
        return Some(Unsound::Tautological("self-comparison (always true)"));
    }
    if s == "1 == 0" || s == "'a' == 'b'" || s == "true == false" {
        return Some(Unsound::AlwaysFalse("literal inequality (always false)"));
    }

    // Literal contains / startsWith / endsWith: the answer is known at
    // parse time and makes the gate effectively a constant.
    if let Some((haystack, needle)) =
        extract_literal_pair(s, re_literal_contains_sq(), re_literal_contains_dq())
    {
        if haystack.contains(needle) {
            return Some(Unsound::Tautological(
                "contains() over two literals (always true)",
            ));
        }
        return Some(Unsound::AlwaysFalse(
            "contains() over two literals (always false)",
        ));
    }
    if let Some((haystack, needle)) =
        extract_literal_pair(s, re_literal_starts_with_sq(), re_literal_starts_with_dq())
    {
        if haystack.starts_with(needle) {
            return Some(Unsound::Tautological(
                "startsWith() over two literals (always true)",
            ));
        }
        return Some(Unsound::AlwaysFalse(
            "startsWith() over two literals (always false)",
        ));
    }
    if let Some((haystack, needle)) =
        extract_literal_pair(s, re_literal_ends_with_sq(), re_literal_ends_with_dq())
    {
        if haystack.ends_with(needle) {
            return Some(Unsound::Tautological(
                "endsWith() over two literals (always true)",
            ));
        }
        return Some(Unsound::AlwaysFalse(
            "endsWith() over two literals (always false)",
        ));
    }

    None
}

fn is_unsound(if_text: &str) -> Option<Unsound> {
    let s = if_text.trim();
    // Strip an outer `${{ ... }}` wrapper so `${{ true }}` / `${{ false }}`
    // are caught the same as a bare `true`/`false`.
    if let Some(caps) = re_expr_wrap().captures(s) {
        let inner = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(c) = classify_core(inner) {
            return Some(c);
        }
    }
    classify_core(s)
}

impl Rule for Wrd830 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-830",
            name: "Unsound If-Condition",
            default_severity: Severity::Low,
            description: "An `if:` condition whose value is constant at parse time is dead \
                          code at best and a bypass of intended gating at worst. Covers \
                          always-true, always-false, and tautological / contradictory \
                          calls to contains() / startsWith() / endsWith() over literals.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let mut emit = |path: &str, cls: &Unsound| {
            let (kind, description) = match cls {
                Unsound::AlwaysTrue(k) => (
                    *k,
                    "This condition always evaluates to TRUE, defeating any gating the \
                     author intended. The step/job runs every time."
                        .to_string(),
                ),
                Unsound::AlwaysFalse(k) => (
                    *k,
                    "This condition always evaluates to FALSE, so the step/job is dead \
                     code and will never execute. Either remove it or rewrite the \
                     condition."
                        .to_string(),
                ),
                Unsound::Tautological(k) => (
                    *k,
                    "This condition is tautological: its value is known at parse time \
                     and does not depend on any runtime input. Either remove it or \
                     rewrite it so it actually gates behavior."
                        .to_string(),
                ),
            };
            let span = ctx
                .loaded
                .spans
                .get_str(path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            findings.push(RuleFinding {
                rule_id: "WRD-830",
                severity: Severity::Low,
                title: format!("Unsound condition: {kind}"),
                description,
                primary: span,
                related: Vec::new(),
                remediation: "Remove the condition entirely (it adds no gate), or \
                              replace it with a check that actually depends on runtime \
                              inputs (github.*, inputs.*, env.*, steps.*.outputs.*)."
                    .into(),
            });
        };
        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                if let Some(if_) = &j.if_ {
                    if let Some(cls) = is_unsound(if_) {
                        emit(&format!("jobs.{job_name}.if"), &cls);
                    }
                }
                for (i, step) in j.steps.iter().enumerate() {
                    let if_ = match step {
                        Step::Run(r) => r.if_.as_deref(),
                        Step::Uses(u) => u.if_.as_deref(),
                        Step::Other(_) => None,
                    };
                    if let Some(if_) = if_ {
                        if let Some(cls) = is_unsound(if_) {
                            emit(&format!("jobs.{job_name}.steps[{i}].if"), &cls);
                        }
                    }
                }
            }
        }
        findings
    }
}
