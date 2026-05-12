use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk typed env, with, and name fields (NOT run scripts) for base64
// decode ops or long base64-looking literal strings. Uses the typed model so
// we do not need the heuristic is_in_run_block check from V1.
// ---------------------------------------------------------------------------

pub struct Wrd817;

fn re_base64_string_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap())
}

fn re_encoded_payload_v2() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(base64\s*-d|base64\s+--decode|\batob\b|Buffer\.from\([^)]+,\s*['"]base64['"])"#,
        )
        .unwrap()
    })
}

fn scan_string_for_obfuscation<F>(path: &str, text: &str, mut emit: F)
where
    F: FnMut(&str, &str, String),
{
    if re_encoded_payload_v2().is_match(text) {
        emit(
            path,
            "Decode operation in non-run context",
            "A base64 decode or similar operation appears in an env: or with: block. This is \
             unusual and may indicate an attempt to obfuscate malicious content."
                .into(),
        );
    }
    for m in re_base64_string_v2().find_iter(text) {
        // Skip apparent SHA pins (exactly 40 chars) // same policy as V1.
        if m.as_str().len() == 40 {
            continue;
        }
        emit(
            path,
            "Possible encoded payload in workflow metadata",
            format!(
                "A long base64-like string ({} chars) was found outside a run: block. This may \
                 indicate obfuscated content.",
                m.as_str().len()
            ),
        );
        break;
    }
}

impl Rule for Wrd817 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-817",
            name: "Base64 Payload in Workflow YAML",
            default_severity: Severity::High,
            description: "Detects base64-encoded strings or decode operations in non-run \
                          contexts (env blocks, with: inputs, step names).",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        let mut raw_hits: Vec<(String, &'static str, String)> = Vec::new();
        let mut emit = |path: &str, title: &str, description: String| {
            raw_hits.push((path.to_string(), title_to_static(title), description));
        };

        if let Some(env) = &wf.env {
            for (k, v) in env {
                let path = format!("env.{k}");
                scan_string_for_obfuscation(&path, &v.as_str_owned(), &mut emit);
            }
        }
        if let Some(name) = &wf.name {
            scan_string_for_obfuscation("name", name, &mut emit);
        }

        for (job_name, job) in &wf.jobs {
            if let Job::Normal(j) = job {
                if let Some(env) = &j.env {
                    for (k, v) in env {
                        let path = format!("jobs.{job_name}.env.{k}");
                        scan_string_for_obfuscation(&path, &v.as_str_owned(), &mut emit);
                    }
                }
                for (i, step) in j.steps.iter().enumerate() {
                    let step_path = format!("jobs.{job_name}.steps[{i}]");
                    match step {
                        Step::Uses(u) => {
                            if let Some(name) = &u.name {
                                scan_string_for_obfuscation(
                                    &format!("{step_path}.name"),
                                    name,
                                    &mut emit,
                                );
                            }
                            if let Some(with) = &u.with {
                                for (k, v) in with {
                                    let p = format!("{step_path}.with.{k}");
                                    scan_string_for_obfuscation(&p, &v.as_str_owned(), &mut emit);
                                }
                            }
                            if let Some(env) = &u.env {
                                for (k, v) in env {
                                    let p = format!("{step_path}.env.{k}");
                                    scan_string_for_obfuscation(&p, &v.as_str_owned(), &mut emit);
                                }
                            }
                        }
                        Step::Run(r) => {
                            if let Some(name) = &r.name {
                                scan_string_for_obfuscation(
                                    &format!("{step_path}.name"),
                                    name,
                                    &mut emit,
                                );
                            }
                            if let Some(env) = &r.env {
                                for (k, v) in env {
                                    let p = format!("{step_path}.env.{k}");
                                    scan_string_for_obfuscation(&p, &v.as_str_owned(), &mut emit);
                                }
                            }
                        }
                        Step::Other(_) => {}
                    }
                }
            }
        }

        for (path, title, description) in raw_hits {
            let span = ctx.loaded.spans.get_str(&path).unwrap_or_else(default_span);
            findings.push(RuleFinding {
                rule_id: "WRD-817",
                severity: Severity::High,
                title: title.into(),
                description,
                primary: span,
                related: Vec::new(),
                remediation: "Review the encoded content. If it is legitimate, add a comment \
                              explaining what it contains and why it is encoded."
                    .into(),
            });
        }
        findings
    }
}

/// Map the two finding titles into &'static str without allocating.
fn title_to_static(t: &str) -> &'static str {
    if t.starts_with("Decode") {
        "Decode operation in non-run context"
    } else {
        "Possible encoded payload in workflow metadata"
    }
}
