use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk uses/run steps for auto-merge/auto-approve patterns, regex the
// raw content for auth hints.
// ---------------------------------------------------------------------------

pub struct Wrd810;

fn re_auto_merge_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(auto-merge|auto\.merge|merge.*automatically|gh\s+pr\s+merge\s+--auto)")
            .unwrap()
    })
}

fn re_auto_approve_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(gh\s+pr\s+review\s+--approve|auto\.approv)").unwrap())
}

fn re_auth_check_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(github\.actor|github\.event\.sender|permission|team|CODEOWNERS|authorized)",
        )
        .unwrap()
    })
}

impl Rule for Wrd810 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-810",
            name: "Auto-Merge Without Authorization",
            default_severity: Severity::High,
            description: "Detects auto-merge or auto-approve patterns without proper \
                          authorization checks.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let raw = &ctx.loaded.raw;
        let has_auth = re_auth_check_v2().is_match(raw);
        if has_auth {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                for (i, step) in j.steps.iter().enumerate() {
                    let step_path = format!("jobs.{job_name}.steps[{i}]");
                    let (text, field_suffix) = match step {
                        Step::Uses(u) => (u.uses.as_str(), "uses"),
                        Step::Run(r) => (r.run.as_str(), "run"),
                        Step::Other(_) => continue,
                    };
                    let field_path = format!("{step_path}.{field_suffix}");
                    if re_auto_merge_v2().is_match(text) {
                        let span = ctx
                            .loaded
                            .spans
                            .get_str(&field_path)
                            .unwrap_or_else(default_span);
                        findings.push(RuleFinding {
                            rule_id: "WRD-810",
                            severity: Severity::High,
                            title: "Auto-merge without authorization check".into(),
                            description: "The workflow performs automatic merging without \
                                          apparent authorization checks. An attacker who can \
                                          trigger this workflow could get unauthorized changes \
                                          merged."
                                .into(),
                            primary: span,
                            related: Vec::new(),
                            remediation: "Add authorization checks (actor verification, team \
                                          membership, or permission validation) before \
                                          auto-merging."
                                .into(),
                        });
                    }
                    if re_auto_approve_v2().is_match(text) {
                        let span = ctx
                            .loaded
                            .spans
                            .get_str(&field_path)
                            .unwrap_or_else(default_span);
                        findings.push(RuleFinding {
                            rule_id: "WRD-810",
                            severity: Severity::High,
                            title: "Auto-approve without authorization check".into(),
                            description: "The workflow performs automatic PR approval without \
                                          apparent authorization checks. This bypasses the code \
                                          review requirement and could allow malicious changes \
                                          to be approved."
                                .into(),
                            primary: span,
                            related: Vec::new(),
                            remediation: "Add authorization checks before auto-approving. \
                                          Verify the PR author is a trusted bot or team member."
                                .into(),
                        });
                    }
                }
            }
        }
        findings
    }
}
