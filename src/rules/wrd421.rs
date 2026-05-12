use regex::Regex;

use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: scan ShellIndex occurrences' script text for curl/wget/nc plus secret
// references. Uses the pre-collected script text so we don't have to redo the
// run-block regex.
// ---------------------------------------------------------------------------

pub struct Wrd421;

fn net_cmd_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:curl|wget|nc|ncat)\b").unwrap())
}

fn secret_ref_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\$\{\{\s*secrets\.\w+|(?:\$[A-Z_]*SECRET|\$[A-Z_]*TOKEN|\$[A-Z_]*KEY|\$[A-Z_]*PASSWORD)",
        )
        .unwrap()
    })
}

impl Rule for Wrd421 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-421",
            name: "Network Call Touches Secret",
            default_severity: Severity::Medium,
            description: "curl or wget commands in run: blocks that also reference secrets may \
                          indicate credential exfiltration.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();

        for occ in ctx.shell.occurrences() {
            let script = &occ.script;
            if !net_cmd_re().is_match(script) || !secret_ref_re().is_match(script) {
                continue;
            }
            let field_span = ctx
                .loaded
                .spans
                .get_str(&occ.path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            for m in net_cmd_re().find_iter(script) {
                let line_offset = script[..m.start()].matches('\n').count();
                let actual_line = field_span.start_line + line_offset;
                let span = Span::new(
                    field_span.byte_start,
                    field_span.byte_end,
                    actual_line,
                    field_span.start_col,
                    actual_line,
                    field_span.end_col,
                );
                findings.push(RuleFinding {
                    rule_id: "WRD-421",
                    severity: Severity::Medium,
                    title: "Network command with secrets reference".into(),
                    description: format!(
                        "A '{}' command appears in a run: block that also references \
                         secrets or credentials. This pattern can indicate exfiltration.",
                        m.as_str()
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Review whether the network command needs access to secrets. \
                                  Consider using dedicated actions for API calls instead of raw \
                                  curl/wget with secrets."
                        .into(),
                });
            }
        }

        findings
    }
}
