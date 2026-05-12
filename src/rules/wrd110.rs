use regex::Regex;

use crate::rules::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: composite action.yml files do not deserialize as `models::Workflow`
// (they use `runs:`, not `jobs:`), so they always arrive as stubs. We gate
// on the file path, then scan `ctx.loaded.raw` for `${{ inputs.X }}` patterns
// inside `run:` blocks, mirroring the legacy behavior with span-aware output.
// ---------------------------------------------------------------------------

pub struct Wrd110;

impl Rule for Wrd110 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-110",
            name: "Composite Action Input Injection",
            default_severity: Severity::High,
            description: "Composite action inputs interpolated directly in run: blocks allow \
                          injection when the action is consumed with attacker-controlled values.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let path_str = ctx.loaded.path.to_string_lossy();
        if !path_str.ends_with("action.yml") && !path_str.ends_with("action.yaml") {
            return Vec::new();
        }

        let content = &ctx.loaded.raw;

        // Verify it declares using: composite.
        let using_re = Regex::new("(?i)using\\s*:\\s*['\"]?composite['\"]?").unwrap();
        if !using_re.is_match(content) {
            return Vec::new();
        }

        let run_block_re =
            Regex::new(r"(?i)\brun\s*:\s*[|>]?[ \t]*\n?([\s\S]*?)(?:\n\s*\w+:|$)").unwrap();
        let input_re = Regex::new(r"\$\{\{\s*inputs\.\w+").unwrap();

        let mut findings = Vec::new();
        for cap in run_block_re.captures_iter(content) {
            let full = cap.get(0).unwrap();
            let block_text = full.as_str();
            let block_start = full.start();

            for m in input_re.find_iter(block_text) {
                let line = line_number_at_offset(content, block_start + m.start());
                let byte_start = block_start + m.start();
                let byte_end = block_start + m.end();
                let span = Span::new(byte_start, byte_end, line, 1, line, 1);
                findings.push(RuleFinding {
                    rule_id: "WRD-110",
                    severity: Severity::High,
                    title: "Composite action input injection".into(),
                    description: format!(
                        "Expression '{}' is interpolated in a run: block of a composite action. \
                         If the input comes from attacker-controlled data, this enables injection.",
                        m.as_str()
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation:
                        "Use an environment variable: env: INPUT_VAL: ${{ inputs.name }}, \
                                  then reference $INPUT_VAL in the shell script."
                            .into(),
                });
            }
        }

        findings
    }
}
