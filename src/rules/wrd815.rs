use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk ShellIndex occurrences, apply the same secret-bypass regexes to
// each parsed run script. Keyed off the step's run: span so findings point
// at the right step.
// ---------------------------------------------------------------------------

pub struct Wrd815;

fn re_base64_secret_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)base64.*\$\{\{\s*secrets\.|echo\s+.*\$\{\{\s*secrets\..*\|\s*base64")
            .unwrap()
    })
}

fn re_char_split_secret_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(sed|tr|cut|fold|rev).*\$\{\{\s*secrets\.").unwrap())
}

fn re_file_write_secret_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\$\{\{\s*secrets\.[^}]+\}\}.*>>\s*\S+|echo.*\$\{\{\s*secrets\.[^}]+\}\}.*>\s*\S+",
        )
        .unwrap()
    })
}

impl Rule for Wrd815 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-815",
            name: "Secret Redaction Bypass",
            default_severity: Severity::High,
            description: "Detects patterns that bypass GitHub Actions secret redaction: \
                          base64 encoding, character splitting, or file-write then cat of \
                          secrets.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        for occ in ctx.shell.occurrences() {
            let script = &occ.script;
            let span = ctx
                .loaded
                .spans
                .get_str(&occ.path)
                .unwrap_or_else(default_span);

            if re_base64_secret_v2().is_match(script) {
                findings.push(RuleFinding {
                    rule_id: "WRD-815",
                    severity: Severity::High,
                    title: "Secret base64-encoded to bypass redaction".into(),
                    description: "Base64-encoding a secret produces output that does not match \
                                  the original value, so GitHub Actions will not redact it \
                                  from logs."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Avoid encoding secrets in ways that bypass redaction. If you \
                                  need to encode a secret, ensure the output is not logged."
                        .into(),
                });
            }

            if re_char_split_secret_v2().is_match(script) {
                findings.push(RuleFinding {
                    rule_id: "WRD-815",
                    severity: Severity::High,
                    title: "Secret manipulated with text tools to bypass redaction".into(),
                    description: "Using sed, tr, cut, fold, or rev on a secret can produce \
                                  output that is not redacted by GitHub Actions."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Do not transform secrets with text-processing tools. Pass \
                                  secrets directly to the tools that need them."
                        .into(),
                });
            }

            if re_file_write_secret_v2().is_match(script) {
                findings.push(RuleFinding {
                    rule_id: "WRD-815",
                    severity: Severity::High,
                    title: "Secret written to file (potential redaction bypass)".into(),
                    description: "Writing a secret to a file and later reading it with cat \
                                  can bypass redaction if the file content is logged line by \
                                  line."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Avoid writing secrets to files. If necessary, ensure the \
                                  file is never logged or included in artifacts."
                        .into(),
                });
            }
        }
        findings
    }
}
