use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed walk over jobs.*.steps[*]. We only consider workflows triggered by
// `pull_request_target`, then flag `actions/checkout@*` steps whose `with.ref`
// resolves to the PR head (sha / ref / github.head_ref).
// ---------------------------------------------------------------------------

pub struct Wrd201;

fn ref_is_pr_head(ref_value: &str) -> bool {
    let s = ref_value.trim();
    s.contains("github.event.pull_request.head.sha")
        || s.contains("github.event.pull_request.head.ref")
        || s.contains("github.head_ref")
}

impl Rule for Wrd201 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-201",
            name: "Dangerous Fork Checkout",
            default_severity: Severity::Critical,
            description: "pull_request_target with actions/checkout referencing the PR head \
                          checks out untrusted fork code in a privileged context.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        if !wf.on.mentions("pull_request_target") {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                if !u.uses.starts_with("actions/checkout@") {
                    continue;
                }
                let Some(with) = &u.with else { continue };
                let Some(ref_val) = with.get("ref") else {
                    continue;
                };
                let ref_str = ref_val.as_str_owned();
                if !ref_is_pr_head(&ref_str) {
                    continue;
                }
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-201",
                    severity: Severity::Critical,
                    title: "Fork checkout in pull_request_target workflow".into(),
                    description: "actions/checkout checks out the PR head (fork code) in a \
                                  pull_request_target workflow. This runs untrusted code with \
                                  write permissions and access to secrets."
                        .into(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Use pull_request instead of pull_request_target, or avoid \
                                  checking out untrusted code. If checkout is necessary, do not \
                                  run any build/test commands on the checked-out code."
                        .into(),
                });
            }
        }
        findings
    }
}
