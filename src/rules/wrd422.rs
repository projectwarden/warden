use crate::models::Job;
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct Wrd422;

fn debug_env_set(
    env: &std::collections::BTreeMap<String, crate::models::EnvValue>,
) -> Option<&'static str> {
    for key in &["ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"] {
        if let Some(v) = env.get(*key) {
            let s = v.as_str_owned();
            if s.eq_ignore_ascii_case("true") || s == "1" {
                return Some(key);
            }
        }
    }
    None
}

impl Rule for Wrd422 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-422",
            name: "Step/Runner Debug Enabled",
            default_severity: Severity::Medium,
            description: "ACTIONS_RUNNER_DEBUG or ACTIONS_STEP_DEBUG enabled in committed YAML \
                          can expose secrets and sensitive data in workflow logs.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let mut emit = |path: &str, var: &str| {
            let span = ctx
                .loaded
                .spans
                .get_str(path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            findings.push(RuleFinding {
                rule_id: "WRD-422",
                severity: Severity::Medium,
                title: format!("{var} enabled in committed workflow"),
                description: format!(
                    "{var} causes the runner to print verbose diagnostic output, which can \
                     include masked secrets in some scenarios. Enable on-demand via the \
                     'Re-run with debug logging' UI button instead."
                ),
                primary: span,
                related: Vec::new(),
                remediation: format!("Remove {var} from the workflow file."),
            });
        };
        if let Some(env) = &wf.env {
            if let Some(var) = debug_env_set(env) {
                emit("env", var);
            }
        }
        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                if let Some(env) = &j.env {
                    if let Some(var) = debug_env_set(env) {
                        emit(&format!("jobs.{job_name}.env"), var);
                    }
                }
                for (i, step) in j.steps.iter().enumerate() {
                    let env = match step {
                        crate::models::Step::Run(r) => r.env.as_ref(),
                        crate::models::Step::Uses(u) => u.env.as_ref(),
                        crate::models::Step::Other(_) => None,
                    };
                    if let Some(env) = env {
                        if let Some(var) = debug_env_set(env) {
                            emit(&format!("jobs.{job_name}.steps[{i}].env"), var);
                        }
                    }
                }
            }
        }
        findings
    }
}
