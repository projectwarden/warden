use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: tree-sitter-bash detection of writes to GitHub special files.
// Eliminates the legacy regex's false positive on quoted strings that merely
// *mention* `>> $GITHUB_ENV` (e.g. `echo 'string with $GITHUB_ENV in it'`).
// ---------------------------------------------------------------------------

pub struct Wrd112;

impl Rule for Wrd112 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-112",
            name: "GITHUB_ENV/PATH Write Sink",
            default_severity: Severity::High,
            description: "Writing attacker-controllable values to GITHUB_ENV or GITHUB_PATH \
                          allows environment variable or PATH manipulation in subsequent steps.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for occ in ctx.shell.occurrences() {
            #[cfg(feature = "shell-analysis")]
            for w in &occ.special_writes {
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&occ.path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-112",
                    severity: Severity::High,
                    title: format!("Write to ${}", w.file.name()),
                    description: format!(
                        "A run: block writes to ${0}. If the written value originates from \
                         attacker-controlled input, subsequent steps can be hijacked.",
                        w.file.name()
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: format!(
                        "Avoid writing attacker-controlled data to ${0}. Validate and \
                         sanitize values before writing.",
                        w.file.name()
                    ),
                });
            }
            #[cfg(not(feature = "shell-analysis"))]
            let _ = occ;
        }
        findings
    }
}
