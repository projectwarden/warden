use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk typed `if:` fields on jobs and steps, regex-match contains() on
// user-controlled GitHub context values.
// ---------------------------------------------------------------------------

pub struct Wrd816;

fn re_contains_user_input_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"contains\s*\(\s*github\.(event\.(issue|pull_request|comment)\.(title|body|labels)|head_ref|actor|event\.sender\.login)"
        ).unwrap()
    })
}

impl Rule for Wrd816 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-816",
            name: "Bypassable Contains Authorization",
            default_severity: Severity::High,
            description: "Detects contains() checks on user-controlled input used as \
                          authorization gates, which can be trivially bypassed.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        let scan = |path: String, text: &str, findings: &mut Vec<RuleFinding>| {
            if let Some(m) = re_contains_user_input_v2().find(text) {
                let span = ctx.loaded.spans.get_str(&path).unwrap_or_else(default_span);
                findings.push(RuleFinding {
                    rule_id: "WRD-816",
                    severity: Severity::High,
                    title: "contains() on user input used as gate".into(),
                    description: format!(
                        "The pattern '{}...' uses contains() on user-controlled input. An \
                         attacker can include the expected substring in their input to bypass \
                         this check.",
                        m.as_str()
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Use a proper authorization mechanism instead of string \
                                  matching on user-controlled input. Consider using team \
                                  membership, CODEOWNERS, or GitHub's built-in permissions."
                        .into(),
                });
            }
        };

        for (job_name, job) in &wf.jobs {
            match job {
                Job::Normal(j) => {
                    if let Some(if_) = &j.if_ {
                        scan(format!("jobs.{job_name}.if"), if_, &mut findings);
                    }
                    for (i, step) in j.steps.iter().enumerate() {
                        let if_ = match step {
                            Step::Run(r) => r.if_.as_deref(),
                            Step::Uses(u) => u.if_.as_deref(),
                            Step::Other(_) => None,
                        };
                        if let Some(if_) = if_ {
                            scan(format!("jobs.{job_name}.steps[{i}].if"), if_, &mut findings);
                        }
                    }
                }
                Job::Reusable(r) => {
                    if let Some(if_) = &r.if_ {
                        scan(format!("jobs.{job_name}.if"), if_, &mut findings);
                    }
                }
            }
        }
        findings
    }
}
