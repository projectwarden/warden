use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};

// ---------------------------------------------------------------------------
// V2: typed-model walk for each `uses:` with a vN-style tag ref, then re-read
// the raw source line for the step to recover the `# vX.Y.Z` trailing comment
// (serde strips YAML comments before we see the typed model).
// ---------------------------------------------------------------------------

pub struct Wrd333;

fn re_comment_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"#\s*v([\d]+(?:\.[\d]+)*)").unwrap())
}

fn re_ref_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^v([\d]+(?:\.[\d]+)*)$").unwrap())
}

impl Rule for Wrd333 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-333",
            name: "Ref Version Mismatch",
            default_severity: Severity::Low,
            description: "Detects actions where a literal version tag (e.g. `@v3`) disagrees \
                          with the inline `# vX.Y.Z` comment, indicating a partial or \
                          copy-pasted version bump.",
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

                let Some(ref_cap) = re_ref_version().captures(ref_val) else {
                    continue;
                };
                let ref_version = ref_cap.get(1).unwrap().as_str();

                // Peek at the raw source line because serde discards YAML
                // comments; the `# vX.Y.Z` trailing comment is only visible
                // in the raw bytes.
                let step_span = match ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                {
                    Some(s) => s,
                    None => continue,
                };
                let start = step_span.byte_start.min(raw.len());
                let end_of_line = raw[start..]
                    .find('\n')
                    .map(|n| start + n)
                    .unwrap_or(raw.len());
                let step_slice = &raw[start..end_of_line];
                let uses_line_start = step_slice.find("uses").map(|o| start + o).unwrap_or(start);
                let uses_line_end = raw[uses_line_start..]
                    .find('\n')
                    .map(|n| uses_line_start + n)
                    .unwrap_or(raw.len());
                let line_str = &raw[uses_line_start..uses_line_end];

                let Some(comment_cap) = re_comment_version().captures(line_str) else {
                    continue;
                };
                let comment_version = comment_cap.get(1).unwrap().as_str();

                let ref_major = ref_version.split('.').next().unwrap_or("");
                let comment_major = comment_version.split('.').next().unwrap_or("");

                if ref_major != comment_major {
                    findings.push(RuleFinding {
                        rule_id: "WRD-333",
                        severity: Severity::Low,
                        title: format!(
                            "Version mismatch for {action}: ref v{ref_version} vs comment v{comment_version}"
                        ),
                        description: format!(
                            "Action '{action}' references @v{ref_version} but the inline \
                             comment says v{comment_version}. This inconsistency may \
                             indicate a copy-paste error or a partially completed version \
                             bump."
                        ),
                        primary: step_span,
                        related: Vec::new(),
                        remediation: "Update the comment to match the actual ref, or update \
                                      the ref to match the intended version."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
