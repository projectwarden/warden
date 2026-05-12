use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: same comment-aware raw-text walk over the loaded workflow's raw lines.
// Comments are not preserved in the typed model so this stays text-driven.
// ---------------------------------------------------------------------------

pub struct Wrd840;

fn re_permissions_entry_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^(\s+)(contents|packages|actions|deployments|id-token|issues|pull-requests|statuses|security-events|checks|pages|discussions|repository-projects|attestations)\s*:\s*(read|write|none)"
        ).unwrap()
    })
}

impl Rule for Wrd840 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-840",
            name: "Undocumented Permissions",
            default_severity: Severity::Info,
            description: "Detects permissions entries that lack an explanatory comment.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let content = &ctx.loaded.raw;
        let lines: Vec<&str> = content.lines().collect();

        for m in re_permissions_entry_v2().find_iter(content) {
            let line_num = content[..m.start()].matches('\n').count() + 1;
            let line_idx = line_num.saturating_sub(1);

            let current_line = lines.get(line_idx).unwrap_or(&"");
            if current_line.contains('#') {
                continue;
            }

            if line_idx > 0 {
                let prev_line = lines.get(line_idx - 1).unwrap_or(&"");
                if prev_line.trim_start().starts_with('#') {
                    continue;
                }
            }

            let col =
                (m.start() - content[..m.start()].rfind('\n').map(|n| n + 1).unwrap_or(0)) + 1;
            let span = Span::new(
                m.start(),
                m.end(),
                line_num,
                col,
                line_num,
                col + (m.end() - m.start()),
            );
            findings.push(RuleFinding {
                rule_id: "WRD-840",
                severity: Severity::Info,
                title: format!(
                    "Permission entry without documentation: {}",
                    current_line.trim()
                ),
                description: "This permissions entry has no comment explaining why the \
                              permission is required. Documenting permissions makes security \
                              reviews easier and helps future maintainers understand the \
                              intent behind each grant."
                    .into(),
                primary: span,
                related: Vec::new(),
                remediation: "Add a comment on the same line or the line above explaining why \
                              this permission is needed, e.g.:\n\
                              # Required to push Docker images\n\
                              packages: write"
                    .into(),
            });
        }
        findings
    }
}
