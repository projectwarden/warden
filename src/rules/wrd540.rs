use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

fn re_daily_schedule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?m)interval\s*:\s*(daily|"daily")"#).unwrap())
}

fn re_groups() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s+groups\s*:").unwrap())
}

// ---------------------------------------------------------------------------
// V2: path-gate on "dependabot" in ctx.loaded.path, then raw-text scan for
// daily interval schedule. dependabot.yml reaches rules via a stub workflow,
// so we skip the is_stub gate and check the path instead.
// ---------------------------------------------------------------------------

pub struct Wrd540;

impl Rule for Wrd540 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-540",
            name: "Dependabot Daily Without Grouping",
            default_severity: Severity::Info,
            description: "Detects Dependabot configurations with daily update schedules and no \
                          grouping, which can flood PRs",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if !ctx.loaded.path.to_string_lossy().contains("dependabot") {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let raw = &ctx.loaded.raw;

        let Some(m) = re_daily_schedule().find(raw) else {
            return findings;
        };
        if re_groups().is_match(raw) {
            return findings;
        }

        let line = line_number_at_offset(raw, m.start());
        let span = Span::new(m.start(), m.end(), line, 1, line, 1);
        findings.push(RuleFinding {
            rule_id: "WRD-540",
            severity: Severity::Info,
            title: "Dependabot daily schedule without grouping".into(),
            description: "Dependabot is configured with a daily update interval but no \
                          dependency groups. This can produce a high volume of individual PRs, \
                          overwhelming reviewers and CI resources."
                .into(),
            primary: span,
            related: Vec::new(),
            remediation: "Add dependency groups to batch related updates into fewer PRs, or \
                          reduce the schedule interval to weekly. Example:\n\
                          groups:\n  \
                            production-dependencies:\n    \
                              patterns: ['*']"
                .into(),
        });

        findings
    }
}
