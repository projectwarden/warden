use regex::Regex;
use std::sync::OnceLock;

use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd322;

fn re_sha_pin() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([0-9a-fA-F]{40})").unwrap()
    })
}

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

impl Rule for Wrd322 {
    fn id(&self) -> &str {
        "WRD-322"
    }
    fn name(&self) -> &str {
        "Stale Action SHA Pin"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions pinned to a SHA without a version comment, \
         suggesting the pin may be stale or untracked"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Iterate enumerated lines so the reported line number always matches
        // the actual match site (a previous implementation called
        // `content.find(line_str)` which returns the FIRST occurrence and
        // mis-reports duplicates).
        for (i, line_str) in content.lines().enumerate() {
            if let Some(cap) = re_sha_pin().captures(line_str) {
                let action = cap.get(1).unwrap().as_str();
                let sha = cap.get(2).unwrap().as_str();

                // Check if the same line has a version comment like "# v4.1.0"
                if !re_version_comment().is_match(line_str) {
                    let line = i + 1;
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        title: format!("SHA pin without version comment: {action}"),
                        description: format!(
                            "Action '{}' is pinned to SHA '{}' but lacks a version \
                             comment (e.g., '# v4.1.0'). Without a comment, it is \
                             difficult to tell which release the SHA corresponds to \
                             or whether the pin is outdated.",
                            action,
                            &sha[..12]
                        ),
                        file: workflow.path.clone(),
                        line,
                        remediation: format!(
                            "Add a version comment after the SHA pin: \
                             {}@{} # v<version>. This aids auditability and \
                             makes Dependabot/Renovate updates easier to review.",
                            action,
                            &sha[..12]
                        ),
                    });
                }
            }
        }

        findings
    }
}
