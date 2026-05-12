use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

fn re_curl_pipe() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(bash|sh|zsh|python|ruby|perl|node)").unwrap()
    })
}

// ---------------------------------------------------------------------------
// V2: scan parsed shell scripts. Narrows the regex to `run:` bodies only,
// avoiding false positives in comments or `name:` fields that the legacy
// full-file match would catch.
// ---------------------------------------------------------------------------

pub struct Wrd714;

impl Rule for Wrd714 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-714",
            name: "Curl Pipe Bash",
            default_severity: Severity::High,
            description: "Detects curl|bash, wget|sh, and similar patterns that execute remote \
                          scripts without verification.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        #[cfg(feature = "shell-analysis")]
        {
            let mut findings = Vec::new();
            for occ in ctx.shell.occurrences() {
                for m in re_curl_pipe().find_iter(&occ.script) {
                    let span = ctx
                        .loaded
                        .spans
                        .get_str(&occ.path)
                        .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                    let offset_line = occ.script[..m.start()].matches('\n').count();
                    let actual_line = span.start_line + offset_line;
                    let line_span = Span::new(
                        span.byte_start,
                        span.byte_end,
                        actual_line,
                        span.start_col,
                        actual_line,
                        span.end_col,
                    );
                    findings.push(RuleFinding {
                        rule_id: "WRD-714",
                        severity: Severity::High,
                        title: "Remote script executed via pipe to shell".to_string(),
                        description: format!(
                            "Pattern '{}' downloads and immediately executes a remote script. \
                             A compromised server or MITM attack could inject malicious code.",
                            m.as_str().trim()
                        ),
                        primary: line_span,
                        related: Vec::new(),
                        remediation: "Download the script first, verify its checksum or \
                                      signature, then execute it. Or vendor the script into \
                                      the repository."
                            .to_string(),
                    });
                }
            }
            findings
        }
        #[cfg(not(feature = "shell-analysis"))]
        {
            let _ = ctx;
            Vec::new()
        }
    }
}
