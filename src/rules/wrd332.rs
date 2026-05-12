use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};

fn re_version_comment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Accepts the common SHA-pin comment formats:
    //   # v1.2.3            (semver tag)
    //   # 1.2.3             (bare semver)
    //   # stable / nightly / beta   (toolchain channels, e.g. dtolnay/rust-toolchain)
    //   # main / master / latest    (named refs, less ideal but common)
    RE.get_or_init(|| {
        Regex::new(r"#\s*(?:v?\d+(?:\.\d+)*|stable|nightly|beta|main|master|latest)").unwrap()
    })
}

// ---------------------------------------------------------------------------
// V2: typed-model walk for each `uses:` whose ref is a 40-char SHA, THEN
// inspect the raw source line for that step because serde strips YAML
// comments before we ever see the model. Without peeking at the raw text
// we could not detect "# v4.1.0" style version pins.
// ---------------------------------------------------------------------------

pub struct Wrd332;

fn is_sha40(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Rule for Wrd332 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-332",
            name: "SHA Pin Missing Version Comment",
            default_severity: Severity::Low,
            description: "Detects actions pinned to a SHA without a version comment, suggesting \
                          the pin may be stale or untracked.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;
        let raw = &ctx.loaded.raw;

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                let Some((action, ref_val)) = u.uses.split_once('@') else {
                    continue;
                };
                if !is_sha40(ref_val) {
                    continue;
                }

                // Look up the span of the `uses:` value directly. The step
                // span (the whole mapping) starts at the first key which is
                // usually `name:`, not `uses:`; using it would slice the
                // wrong line and miss trailing `# v1.2.3` comments.
                let uses_span = match ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}].uses"))
                {
                    Some(s) => s,
                    None => continue,
                };
                let step_span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or(uses_span);

                // Read the line that contains `uses:`. Walk back from the
                // value span's start to the line start, then forward to the
                // next newline.
                let value_start = uses_span.byte_start.min(raw.len());
                let line_start = raw[..value_start].rfind('\n').map(|p| p + 1).unwrap_or(0);
                let line_end = raw[value_start..]
                    .find('\n')
                    .map(|n| value_start + n)
                    .unwrap_or(raw.len());
                let line_str = &raw[line_start..line_end];

                if re_version_comment().is_match(line_str) {
                    continue;
                }

                findings.push(RuleFinding {
                    rule_id: "WRD-332",
                    severity: Severity::Low,
                    title: format!("SHA pin without version comment: {action}"),
                    description: format!(
                        "Action '{}' is pinned to SHA '{}' but lacks a version comment \
                         (e.g., '# v4.1.0'). Without a comment, it is difficult to tell \
                         which release the SHA corresponds to or whether the pin is \
                         outdated.",
                        action,
                        &ref_val[..12]
                    ),
                    primary: step_span,
                    related: Vec::new(),
                    remediation: format!(
                        "Add a version comment after the SHA pin: {}@{} # v<version>. This \
                         aids auditability and makes Dependabot/Renovate updates easier to \
                         review.",
                        action,
                        &ref_val[..12]
                    ),
                });
            }
        }

        findings
    }
}
