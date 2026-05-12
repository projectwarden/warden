use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed check for workflow_run trigger + download-artifact steps, with a
// raw-text fallback for the conclusion check.
// ---------------------------------------------------------------------------

pub struct Wrd811;

fn re_conclusion_check_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"conclusion\s*==\s*'success'").unwrap())
}

impl Rule for Wrd811 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-811",
            name: "Artifact Download Without Conclusion Check",
            default_severity: Severity::High,
            description: "Detects workflow_run triggers that download artifacts without \
                          verifying the triggering workflow's conclusion.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        if !wf.on.mentions("workflow_run") {
            return Vec::new();
        }
        let has_conclusion_check = re_conclusion_check_v2().is_match(&ctx.loaded.raw);
        if has_conclusion_check {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                for (i, step) in j.steps.iter().enumerate() {
                    if let Step::Uses(u) = step {
                        if u.uses.starts_with("actions/download-artifact") {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("jobs.{job_name}.steps[{i}].uses"))
                                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                            findings.push(RuleFinding {
                                rule_id: "WRD-811",
                                severity: Severity::High,
                                title: "workflow_run downloads artifacts without conclusion check"
                                    .into(),
                                description: "A workflow_run trigger that downloads artifacts \
                                              from the triggering workflow without checking \
                                              conclusion == 'success' may process artifacts from \
                                              failed or malicious runs."
                                    .into(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Add a condition like \
                                              'if: github.event.workflow_run.conclusion == \
                                              'success'' before downloading and using artifacts."
                                    .into(),
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}
