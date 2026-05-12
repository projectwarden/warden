use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::Job;
use crate::yamlpath::Span;

pub struct Wrd712;

fn env_says_true(
    env: &std::collections::BTreeMap<String, crate::models::EnvValue>,
    key: &str,
) -> bool {
    env.get(key)
        .map(|v| {
            let s = v.as_str_owned();
            s.eq_ignore_ascii_case("true") || s == "1"
        })
        .unwrap_or(false)
}

impl Rule for Wrd712 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-712",
            name: "Insecure Commands Allowed",
            default_severity: Severity::High,
            description: "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables the deprecated workflow \
                          command syntax (set-env, add-path) used in legacy injection attacks.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let key = "ACTIONS_ALLOW_UNSECURE_COMMANDS";

        let mut emit = |path: &str| {
            let span = ctx
                .loaded
                .spans
                .get_str(path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            findings.push(RuleFinding {
                rule_id: "WRD-712",
                severity: Severity::High,
                title: "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled".into(),
                description: "This setting re-enables the deprecated `set-env` and `add-path` \
                              workflow commands. They were removed in 2020 because attacker \
                              output to stdout could escalate to environment variable / PATH \
                              control."
                    .into(),
                primary: span,
                related: Vec::new(),
                remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS. Use the modern \
                              GITHUB_ENV / GITHUB_PATH files instead."
                    .into(),
            });
        };

        if let Some(env) = &wf.env {
            if env_says_true(env, key) {
                emit("env");
            }
        }
        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                if let Some(env) = &j.env {
                    if env_says_true(env, key) {
                        emit(&format!("jobs.{job_name}.env"));
                    }
                }
                for (i, step) in j.steps.iter().enumerate() {
                    let step_env = match step {
                        crate::models::Step::Run(r) => r.env.as_ref(),
                        crate::models::Step::Uses(u) => u.env.as_ref(),
                        crate::models::Step::Other(_) => None,
                    };
                    if let Some(env) = step_env {
                        if env_says_true(env, key) {
                            emit(&format!("jobs.{job_name}.steps[{i}].env"));
                        }
                    }
                }
            }
        }
        findings
    }
}
