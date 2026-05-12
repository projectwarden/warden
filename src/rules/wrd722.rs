use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Container, Job};
use crate::yamlpath::Span;

// The `regex` crate does not support lookahead. We match the full
// `key: value` form and post-filter the captured value in code.

// ---------------------------------------------------------------------------
// V2: walks typed Job::Normal container/services. Only inspects values under
// `credentials:`, so the legacy regex's false positives on unrelated
// username/password keys go away.
// ---------------------------------------------------------------------------

pub struct Wrd722;

fn is_secret_ref_v2(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    v.starts_with("${{")
}

impl Rule for Wrd722 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-722",
            name: "Hardcoded Container Credentials",
            default_severity: Severity::Medium,
            description: "Detects hardcoded username or password values in container/services \
                          credentials blocks instead of using secrets.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };

            // Job-level `container:`.
            if let Some(Container::Detailed(detailed)) = &j.container {
                if let Some(creds) = &detailed.credentials {
                    let base = format!("jobs.{job_name}.container.credentials");
                    if let Some(u) = &creds.username {
                        if !is_secret_ref_v2(u) {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("{base}.username"))
                                .unwrap_or_else(default_span);
                            findings.push(RuleFinding {
                                rule_id: "WRD-722",
                                severity: Severity::Medium,
                                title: "Hardcoded username in credentials block".to_string(),
                                description: "A username value is hardcoded instead of being \
                                              sourced from a secret. This exposes the credential \
                                              in the workflow file."
                                    .to_string(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Use a secret reference, e.g. \
                                              username: ${{ secrets.REGISTRY_USERNAME }}."
                                    .to_string(),
                            });
                        }
                    }
                    if let Some(p) = &creds.password {
                        if !is_secret_ref_v2(p) {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("{base}.password"))
                                .unwrap_or_else(default_span);
                            findings.push(RuleFinding {
                                rule_id: "WRD-722",
                                severity: Severity::Medium,
                                title: "Hardcoded password in credentials block".to_string(),
                                description: "A password value is hardcoded instead of being \
                                              sourced from a secret. This is a critical \
                                              credential exposure."
                                    .to_string(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Use a secret reference, e.g. \
                                              password: ${{ secrets.REGISTRY_PASSWORD }}."
                                    .to_string(),
                            });
                        }
                    }
                }
            }

            // Job-level `services:` map.
            if let Some(services) = &j.services {
                for (svc_name, svc) in services {
                    let Container::Detailed(detailed) = svc else {
                        continue;
                    };
                    let Some(creds) = &detailed.credentials else {
                        continue;
                    };
                    let base = format!("jobs.{job_name}.services.{svc_name}.credentials");
                    if let Some(u) = &creds.username {
                        if !is_secret_ref_v2(u) {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("{base}.username"))
                                .unwrap_or_else(default_span);
                            findings.push(RuleFinding {
                                rule_id: "WRD-722",
                                severity: Severity::Medium,
                                title: "Hardcoded username in credentials block".to_string(),
                                description: "A username value is hardcoded instead of being \
                                              sourced from a secret. This exposes the credential \
                                              in the workflow file."
                                    .to_string(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Use a secret reference, e.g. \
                                              username: ${{ secrets.REGISTRY_USERNAME }}."
                                    .to_string(),
                            });
                        }
                    }
                    if let Some(p) = &creds.password {
                        if !is_secret_ref_v2(p) {
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&format!("{base}.password"))
                                .unwrap_or_else(default_span);
                            findings.push(RuleFinding {
                                rule_id: "WRD-722",
                                severity: Severity::Medium,
                                title: "Hardcoded password in credentials block".to_string(),
                                description: "A password value is hardcoded instead of being \
                                              sourced from a secret. This is a critical \
                                              credential exposure."
                                    .to_string(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Use a secret reference, e.g. \
                                              password: ${{ secrets.REGISTRY_PASSWORD }}."
                                    .to_string(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
