use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

fn re_pr_target_trigger() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*pull_request_target\s*:").unwrap())
}

fn re_dependabot_actor() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)dependabot|github\.actor\s*==\s*'dependabot").unwrap())
}

fn re_checkout_pr_head() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(actions/checkout.*\n(\s+with:\s*\n)?(\s+.*\n)*?\s+ref\s*:.*pull_request|github\.event\.pull_request\.head)").unwrap()
    })
}

fn re_run_scripts_from_pr() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)run\s*:\s*.*(\./|bash\s|sh\s|python\s|node\s|npm\s+(run|test|install)|yarn|make|cargo)").unwrap()
    })
}

// ---------------------------------------------------------------------------
// V2: path-gate on "dependabot" in the loaded path, raw-text scans mirroring
// the legacy regexes. Like WRD-540, this targets dependabot.yml which reaches
// rules via a stub workflow.
// ---------------------------------------------------------------------------

pub struct Wrd521;

impl Rule for Wrd521 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-521",
            name: "Dependabot PR Untrusted Execution",
            default_severity: Severity::Medium,
            description: "Detects Dependabot-related workflows that may execute untrusted code \
                          from pull requests via pull_request_target",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if !ctx.loaded.path.to_string_lossy().contains("dependabot") {
            return Vec::new();
        }
        let raw = &ctx.loaded.raw;
        let mut findings = Vec::new();

        if !re_pr_target_trigger().is_match(raw) {
            return findings;
        }
        if !re_dependabot_actor().is_match(raw) {
            return findings;
        }

        if let Some(m) = re_checkout_pr_head().find(raw) {
            let line = line_number_at_offset(raw, m.start());
            let span = Span::new(m.start(), m.end(), line, 1, line, 1);
            findings.push(RuleFinding {
                rule_id: "WRD-521",
                severity: Severity::Medium,
                title: "Dependabot workflow checks out PR head in pull_request_target".into(),
                description: "This workflow uses pull_request_target and checks out the PR head \
                              ref. With pull_request_target, the workflow runs with write \
                              permissions and access to secrets. Checking out untrusted PR code \
                              in this context allows arbitrary code execution with elevated \
                              privileges."
                    .into(),
                primary: span,
                related: Vec::new(),
                remediation: "Avoid checking out the PR head in pull_request_target workflows. \
                              If you must, run untrusted code in a separate unprivileged \
                              workflow triggered by pull_request instead."
                    .into(),
            });
        }

        if re_checkout_pr_head().is_match(raw) {
            for m in re_run_scripts_from_pr().find_iter(raw) {
                let line = line_number_at_offset(raw, m.start());
                let span = Span::new(m.start(), m.end(), line, 1, line, 1);
                findings.push(RuleFinding {
                    rule_id: "WRD-521",
                    severity: Severity::Medium,
                    title: "Script execution in Dependabot pull_request_target workflow".into(),
                    description: "This pull_request_target workflow checks out PR code and runs \
                                  scripts. An attacker could modify Dependabot PRs (or create \
                                  PRs that match the conditions) to execute arbitrary code with \
                                  write permissions."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Move script execution to a pull_request-triggered workflow \
                                  (no write access). Use workflow_run to pass results back to \
                                  the privileged context if needed."
                        .into(),
                });
            }
        }

        findings
    }
}
