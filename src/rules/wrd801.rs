use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::Job;
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed lookup of the `on:` triggers and `runs-on:` per job.
// ---------------------------------------------------------------------------

pub struct Wrd801;

fn runs_on_mentions_self_hosted(v: &serde_yaml::Value) -> bool {
    match v {
        serde_yaml::Value::String(s) => s.contains("self-hosted"),
        serde_yaml::Value::Sequence(seq) => seq.iter().any(|x| {
            x.as_str()
                .map(|s| s.contains("self-hosted"))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

impl Rule for Wrd801 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-801",
            name: "Self-Hosted Runner on PR",
            default_severity: Severity::Critical,
            description: "Detects pull_request triggers combined with self-hosted runners, \
                          allowing untrusted PR code to execute on your infrastructure.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let has_pr = wf.on.mentions("pull_request") || wf.on.mentions("pull_request_target");
        if !has_pr {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                if let Some(runs_on) = &j.runs_on {
                    if runs_on_mentions_self_hosted(runs_on) {
                        let span = ctx
                            .loaded
                            .spans
                            .get_str(&format!("jobs.{job_name}.runs-on"))
                            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                        findings.push(RuleFinding {
                            rule_id: "WRD-801",
                            severity: Severity::Critical,
                            title: "Self-hosted runner used with pull_request trigger".into(),
                            description: "Pull requests from forks can execute arbitrary code on \
                                          self-hosted runners. Unlike GitHub-hosted runners, \
                                          self-hosted runners are not ephemeral and may retain \
                                          credentials, access internal networks, or persist \
                                          malware between runs."
                                .into(),
                            primary: span,
                            related: Vec::new(),
                            remediation: "Use GitHub-hosted runners for PR workflows, or \
                                          restrict self-hosted runner access using runner groups \
                                          with repository policies. Consider using \
                                          pull_request_target with explicit checkout controls."
                                .into(),
                        });
                    }
                }
            }
        }
        findings
    }
}
