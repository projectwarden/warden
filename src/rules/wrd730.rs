use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walks typed Uses steps. Severity tiering:
//
//   pre-v6 checkout + leaky sink        HIGH (tj-actions class exploit)
//   pre-v6 checkout, no sink in workflow MEDIUM (was LOW; real-world blast
//                                             radius includes Red Hat, Google,
//                                             AWS. Latent until a sink is added.)
//   v6+ checkout + leaky sink           LOW (v6+ stores token in $RUNNER_TEMP;
//                                            hardening recommended as defense in
//                                            depth)
//   v6+ checkout, no sink               LOW (hardening only)
//
// Sink detection covers four `uses:` steps: actions/upload-artifact,
// docker/build-push-action (build context copies .git/ by default),
// softprops/action-gh-release (uploads workspace tarballs to a public release),
// and actions/cache (the workspace path can wrap .git/ depending on config).
// ---------------------------------------------------------------------------

pub struct Wrd730;

/// Extract the version tag after `actions/checkout@` if it is a `vN` tag.
/// Returns None for SHA pins or other tag shapes (conservative: treated as
/// pre-v6 so we do not silently downgrade a real finding).
fn checkout_major_version(uses: &str) -> Option<u32> {
    let rest = uses.strip_prefix("actions/checkout@")?;
    // Accept `v6`, `v6.1.0`, `v10`, etc. Reject SHA pins (40-char hex).
    let tag = rest.split('#').next().unwrap_or(rest);
    let after_v = tag.strip_prefix('v')?;
    let major_str: String = after_v.chars().take_while(|c| c.is_ascii_digit()).collect();
    if major_str.is_empty() {
        return None;
    }
    major_str.parse::<u32>().ok()
}

/// An action ref whose presence in the workflow elevates a persisted-token
/// to a real leak vector, not just a hardening hint. The list matches the
/// sinks flagged in the 2026 incident-history audit: any public-surface
/// upload / image-publish / release that might carry the workspace (and
/// therefore its embedded `.git/config`) outside the runner.
fn is_leaky_sink_uses(uses: &str) -> bool {
    let base = uses.split('@').next().unwrap_or(uses);
    matches!(
        base,
        "actions/upload-artifact"
            | "docker/build-push-action"
            | "softprops/action-gh-release"
            | "actions/cache"
            | "actions/cache/save"
    )
}

fn leaky_sink_name(wf: &crate::models::Workflow) -> Option<String> {
    for job in wf.jobs.values() {
        if let Job::Normal(j) = job {
            for step in &j.steps {
                if let Step::Uses(u) = step {
                    if is_leaky_sink_uses(&u.uses) {
                        return Some(u.uses.split('@').next().unwrap_or(&u.uses).to_string());
                    }
                }
            }
        }
    }
    None
}

impl Rule for Wrd730 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-730",
            name: "Persisted Credentials Uploaded",
            default_severity: Severity::Low,
            description: "Detects actions/checkout without persist-credentials: false. By \
                          default, actions/checkout persists the GITHUB_TOKEN on disk after \
                          cloning. Below v6 it's written to .git/config inside the workspace; \
                          v6+ moved it to $RUNNER_TEMP.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let leaky_sink = leaky_sink_name(wf);
        let mut findings = Vec::new();

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                if !u.uses.starts_with("actions/checkout@") {
                    continue;
                }

                // Check the `with.persist-credentials` value.
                let pc_value = u
                    .with
                    .as_ref()
                    .and_then(|w| w.get("persist-credentials"))
                    .map(|v| v.as_str_owned());
                let has_false = matches!(pc_value.as_deref(), Some("false"));
                if has_false {
                    continue;
                }

                let major = checkout_major_version(&u.uses);
                let is_v6_plus = matches!(major, Some(v) if v >= 6);
                let active_exploit = leaky_sink.is_some() && !is_v6_plus;

                let (severity, title, description): (Severity, String, String) = if active_exploit {
                    let sink = leaky_sink.as_deref().unwrap_or("upload sink");
                    (
                        Severity::High,
                        "Checkout without persist-credentials: false in artifact workflow"
                            .to_string(),
                        format!(
                            "actions/checkout below v6 stores the GITHUB_TOKEN in \
                             .git/config inside the workspace. This workflow also \
                             includes `{sink}`, which can carry the workspace (or a \
                             path that includes .git/) outside the runner. If the \
                             upload is public or downloadable by an attacker, the \
                             token leaks. This is the tj-actions / reviewdog / \
                             Artipacked attack pattern (Red Hat, Google, AWS affected)."
                        ),
                    )
                } else if leaky_sink.is_some() {
                    let sink = leaky_sink.as_deref().unwrap_or("upload sink");
                    (
                        Severity::Low,
                        "Checkout v6+ without persist-credentials: false (hardening)".to_string(),
                        format!(
                            "actions/checkout v6+ stores the token in $RUNNER_TEMP \
                             rather than .git/config, which is safer against a \
                             workspace-wrapping `{sink}`. Setting persist-credentials: \
                             false is still recommended as defense in depth, in case a \
                             future change uploads $RUNNER_TEMP directly."
                        ),
                    )
                } else if is_v6_plus {
                    (
                        Severity::Low,
                        "Checkout v6+ without persist-credentials: false (hardening)".to_string(),
                        "actions/checkout v6+ stores the token in $RUNNER_TEMP rather than \
                         .git/config, so there is no active exploit path here. Setting \
                         persist-credentials: false is still recommended as defense in \
                         depth: a future change that adds an upload/release/docker-push \
                         step pointing at $RUNNER_TEMP would otherwise immediately leak \
                         the token."
                            .to_string(),
                    )
                } else {
                    // Pre-v6 checkout, no sink today. Bumped LOW -> MEDIUM
                    // because the exploit path is one step away (add any of
                    // upload-artifact / docker-build-push / gh-release / cache),
                    // and the real-world Artipacked disclosures showed teams
                    // regularly miss this until it's already being uploaded.
                    (
                        Severity::Medium,
                        "Checkout without persist-credentials: false (latent leak)".to_string(),
                        "actions/checkout below v6 stores the GITHUB_TOKEN in \
                         .git/config inside the workspace by default. No upload \
                         sink is present in this workflow today, so there is no \
                         active exploit path, but any future change that adds an \
                         upload-artifact, docker/build-push-action, \
                         softprops/action-gh-release, or actions/cache step would \
                         immediately leak the token. Disclosed instances of this \
                         bug (Artipacked, 2024) have affected Red Hat, Google, and \
                         AWS. Set persist-credentials: false as the safe default."
                            .to_string(),
                    )
                };

                let span_path = format!("jobs.{job_name}.steps[{i}]");
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&span_path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-730",
                    severity,
                    title,
                    description,
                    primary: span,
                    related: Vec::new(),
                    remediation: "Add 'persist-credentials: false' to the actions/checkout \
                                  step. `warden fix --apply` will do this for you \
                                  automatically."
                        .to_string(),
                });
            }
        }

        findings
    }
}
