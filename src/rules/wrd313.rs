use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

// (pattern, severity, reason)
// TODO: load from .warden.toml
const DENYLIST: &[(&str, &str, &str)] = &[
    // tj-actions/changed-files v1..v44 supply-chain incident
    (
        r"^tj-actions/changed-files@v([1-9]|[1-3][0-9]|4[0-4])(\..*)?$",
        "high",
        "tj-actions/changed-files supply-chain incident (v1..v44)",
    ),
    // reviewdog/action-setup@v1 compromised range
    (
        r"^reviewdog/action-setup@v1(\..*)?$",
        "high",
        "reviewdog/action-setup@v1 compromised range",
    ),
    // EOL checkout
    (
        r"^actions/checkout@v1(\..*)?$",
        "medium",
        "actions/checkout@v1 is EOL",
    ),
    (
        r"^actions/checkout@v2(\..*)?$",
        "medium",
        "actions/checkout@v2 is EOL",
    ),
    // dawidd6/action-download-artifact below patched version (pre v6)
    (
        r"^dawidd6/action-download-artifact@v[1-5](\..*)?$",
        "medium",
        "dawidd6/action-download-artifact below patched version",
    ),
    // aquasecurity/trivy-action pre-fix (example: before 0.20.0 — keep as coarse tag match)
    (
        r"^aquasecurity/trivy-action@(0\.(?:[0-9]|1[0-9])(\..*)?|master)$",
        "medium",
        "aquasecurity/trivy-action before fixed release",
    ),
];

fn compiled_denylist() -> &'static Vec<(Regex, &'static str, &'static str)> {
    static LIST: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    LIST.get_or_init(|| {
        DENYLIST
            .iter()
            .map(|(pat, sev, reason)| (Regex::new(pat).unwrap(), *sev, *reason))
            .collect()
    })
}

// ---------------------------------------------------------------------------
// V2: typed-model walk over step `uses:` strings and match against the
// denylist, same per-entry severity mapping as the legacy rule.
// ---------------------------------------------------------------------------

pub struct Wrd313;

fn sev_from_str(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

impl Rule for Wrd313 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-313",
            name: "Denylisted Action Reference",
            default_severity: Severity::High,
            description: "Uses an action reference that is on warden's hardcoded denylist due to \
                          a known security incident or EOL status.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                // Strip any surrounding quotes that might have survived in the
                // typed value (defensive; serde will usually strip them).
                let raw = u.uses.as_str().trim_matches(|c| c == '\'' || c == '"');
                for (re, sev, reason) in compiled_denylist().iter() {
                    if re.is_match(raw) {
                        let span = ctx
                            .loaded
                            .spans
                            .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                        findings.push(RuleFinding {
                            rule_id: "WRD-313",
                            severity: sev_from_str(sev),
                            title: format!("Forbidden action: {raw}"),
                            description: format!(
                                "Action '{raw}' matches warden's denylist: {reason}."
                            ),
                            primary: span,
                            related: Vec::new(),
                            remediation: "This action ref is in warden's denylist due to a \
                                          known security incident or EOL status. Pin to a \
                                          known-good SHA or migrate to an alternative."
                                .to_string(),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}
