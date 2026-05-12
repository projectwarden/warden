use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{EnvValue, Job, Step};
use crate::yamlpath::Span;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// V2: CodeQLEAKED class (CVE-2025-24362). When ACTIONS_STEP_DEBUG=true or
// ACTIONS_RUNNER_DEBUG=true is set at workflow / job / step level AND
// actions/upload-artifact runs in the same job, the debug artifact includes
// a dump of every env var in the runner process, which routinely includes a
// live GITHUB_TOKEN. Anyone with repo read can download the artifact inside
// the retention window.
//
// Sources:
//   - https://github.com/github/codeql-action/security/advisories/GHSA-vqf5-2xx6-9wfm
//   - https://www.praetorian.com/blog/codeqleaked-public-secrets-exposure-leads-to-supply-chain-attack-on-github-codeql/
// ---------------------------------------------------------------------------

pub struct Wrd715;

fn env_sets_debug_flag(env: Option<&BTreeMap<String, EnvValue>>) -> Option<&'static str> {
    let env = env?;
    for (k, v) in env {
        let ku = k.to_ascii_uppercase();
        if ku == "ACTIONS_STEP_DEBUG" || ku == "ACTIONS_RUNNER_DEBUG" {
            let s = v.as_str_owned();
            let sl = s.to_ascii_lowercase();
            // `true`, `"true"`, numeric 1, expression that yields true — we
            // accept any non-"false" non-empty value as "debug on" to err
            // toward the finding. False negatives here are worse than false
            // positives.
            if sl != "false" && sl != "0" && !sl.is_empty() {
                return Some(if ku == "ACTIONS_STEP_DEBUG" {
                    "ACTIONS_STEP_DEBUG"
                } else {
                    "ACTIONS_RUNNER_DEBUG"
                });
            }
        }
    }
    None
}

impl Rule for Wrd715 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-715",
            name: "Debug Artifact Env Exposure",
            default_severity: Severity::High,
            description: "A workflow / job / step sets ACTIONS_STEP_DEBUG or \
                          ACTIONS_RUNNER_DEBUG and the same job uploads an \
                          artifact. The debug dump includes every env var in \
                          the runner process (including GITHUB_TOKEN), which is \
                          then retrievable by anyone with repo read. This is the \
                          CodeQLEAKED pattern (CVE-2025-24362).",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        // Workflow-level env debug flag, if present, applies to every job.
        let wf_flag = env_sets_debug_flag(wf.env.as_ref());

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            let job_flag = env_sets_debug_flag(j.env.as_ref());

            // Scan steps for both (a) an upload-artifact step and (b) a
            // step-level debug flag.
            let mut uploads_path: Option<String> = None;
            let mut step_flag: Option<(&'static str, String)> = None;

            for (i, step) in j.steps.iter().enumerate() {
                match step {
                    Step::Uses(u) => {
                        if u.uses.starts_with("actions/upload-artifact@") {
                            uploads_path = Some(format!("jobs.{job_name}.steps[{i}]"));
                        }
                        if let Some(flag) = env_sets_debug_flag(u.env.as_ref()) {
                            step_flag = Some((flag, format!("jobs.{job_name}.steps[{i}]")));
                        }
                    }
                    Step::Run(r) => {
                        if let Some(flag) = env_sets_debug_flag(r.env.as_ref()) {
                            step_flag = Some((flag, format!("jobs.{job_name}.steps[{i}]")));
                        }
                    }
                    Step::Other(_) => {}
                }
            }

            let Some(upload_path) = uploads_path else {
                continue;
            };

            // The debug flag can come from any of three scopes; pick the
            // most-local one for the span (step > job > workflow).
            let flag_info: Option<(&'static str, String, &'static str)> =
                if let Some((flag, path)) = step_flag {
                    Some((flag, path, "step env"))
                } else if let Some(flag) = job_flag {
                    Some((flag, format!("jobs.{job_name}"), "job env"))
                } else if let Some(flag) = wf_flag {
                    Some((flag, "env".to_string(), "workflow env"))
                } else {
                    None
                };

            let Some((flag_name, flag_span_path, scope_label)) = flag_info else {
                continue;
            };

            let span = ctx
                .loaded
                .spans
                .get_str(&flag_span_path)
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            let upload_span = ctx.loaded.spans.get_str(&upload_path);
            let related: Vec<(Span, String)> = upload_span
                .map(|s| vec![(s, "actions/upload-artifact step".to_string())])
                .unwrap_or_default();

            findings.push(RuleFinding {
                rule_id: "WRD-715",
                severity: Severity::High,
                title: format!(
                    "{flag_name} enabled ({scope_label}) with artifact upload in same job"
                ),
                description: format!(
                    "{flag_name} is set to true in {scope_label}, and the \
                     same job ('{job_name}') runs actions/upload-artifact. \
                     Debug mode writes every env var (including \
                     GITHUB_TOKEN) into the runner's debug dump, which the \
                     upload step can inadvertently include. Anyone with \
                     repo read can then download the artifact and extract \
                     a live token. This is the CodeQLEAKED pattern \
                     (CVE-2025-24362)."
                ),
                primary: span,
                related,
                remediation: "Remove the ACTIONS_STEP_DEBUG / \
                              ACTIONS_RUNNER_DEBUG flag from your workflow \
                              (the repo-level `Re-run with debug logging` \
                              checkbox already scopes debug output to logs, \
                              not artifacts). If you must run with debug, \
                              pin upload-artifact to a narrow path list that \
                              excludes the runner's temp directory, and \
                              rotate any GITHUB_TOKEN that could have been \
                              uploaded."
                    .to_string(),
            });
        }

        findings
    }
}
