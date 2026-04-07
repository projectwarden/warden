use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-326: Forbidden action uses (denylist of known-bad/EOL refs).
pub struct Wrd326;

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

fn re_uses() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)uses\s*:\s*([^\s#]+)").unwrap())
}

fn compiled_denylist() -> &'static Vec<(Regex, &'static str, &'static str)> {
    static LIST: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    LIST.get_or_init(|| {
        DENYLIST
            .iter()
            .map(|(pat, sev, reason)| (Regex::new(pat).unwrap(), *sev, *reason))
            .collect()
    })
}

impl Rule for Wrd326 {
    fn id(&self) -> &str {
        "WRD-326"
    }
    fn name(&self) -> &str {
        "Forbidden Action Uses"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn description(&self) -> &str {
        "Uses an action reference that is on warden's hardcoded denylist due to a known \
         security incident or EOL status."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for cap in re_uses().captures_iter(content) {
            let full = cap.get(0).unwrap();
            let raw = cap
                .get(1)
                .unwrap()
                .as_str()
                .trim_matches(|c| c == '\'' || c == '"');

            for (re, sev, reason) in compiled_denylist().iter() {
                if re.is_match(raw) {
                    let line = line_number_at_offset(content, full.start());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: sev.to_string(),
                        title: format!("Forbidden action: {raw}"),
                        description: format!("Action '{raw}' matches warden's denylist: {reason}."),
                        file: workflow.path.clone(),
                        line,
                        remediation: "This action ref is in warden's denylist due to a \
                                      known security incident or EOL status. Pin to a \
                                      known-good SHA or migrate to an alternative."
                            .to_string(),
                    });
                    break;
                }
            }
        }

        findings
    }
}
