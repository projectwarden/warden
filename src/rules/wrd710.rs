use regex::Regex;
use std::sync::OnceLock;

use super::{Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd710;

fn re_checkout() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*actions/checkout").unwrap())
}

fn re_persist_creds_false() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"persist-credentials\s*:\s*false").unwrap())
}

fn re_upload_artifact() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*actions/upload-artifact").unwrap())
}

fn re_checkout_v6_or_higher() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches actions/checkout@v6, v7, ..., v99 (tag form). SHA pins are
        // not version-detectable from YAML, so they fall through to the
        // conservative path.
        Regex::new(r"uses\s*:\s*actions/checkout@v([6-9]|[1-9][0-9])").unwrap()
    })
}

impl Rule for Wrd710 {
    fn id(&self) -> &str {
        "WRD-710"
    }
    fn name(&self) -> &str {
        "Artipacked"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions/checkout without persist-credentials: false when artifacts \
         are uploaded. Below checkout v6, the token is stored in .git/config and \
         leaks via uploaded workspaces. v6+ moved it to $RUNNER_TEMP, which is safer \
         but explicit persist-credentials: false is still the recommended hardening."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_upload = re_upload_artifact().is_match(content);
        if !has_upload {
            return findings;
        }

        // Find each checkout step that lacks persist-credentials: false
        for m in re_checkout().find_iter(content) {
            let checkout_pos = m.start();
            // Look ahead in the next ~300 chars for persist-credentials: false
            // and to detect the version pinned on this specific step.
            let lookahead_end = (checkout_pos + 300).min(content.len());
            let snippet = &content[checkout_pos..lookahead_end];

            if re_persist_creds_false().is_match(snippet) {
                continue;
            }

            let is_v6_plus = re_checkout_v6_or_higher().is_match(snippet);
            let line = content[..checkout_pos].matches('\n').count() + 1;

            let (severity, title, description) = if is_v6_plus {
                (
                    "low",
                    "Checkout v6+ without persist-credentials: false (hardening)",
                    "actions/checkout v6+ stores the token in $RUNNER_TEMP rather \
                     than .git/config, so a plain workspace upload no longer leaks \
                     it. Setting persist-credentials: false is still recommended as \
                     defense in depth.",
                )
            } else {
                (
                    "high",
                    "Checkout without persist-credentials: false in artifact workflow",
                    "actions/checkout below v6 stores the GITHUB_TOKEN in \
                     .git/config. If the workspace is uploaded as an artifact the \
                     token is exfiltrated to anyone who can download the artifact.",
                )
            };

            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: severity.to_string(),
                title: title.to_string(),
                description: description.to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Add 'persist-credentials: false' to the actions/checkout step, \
                    or ensure the .git directory and $RUNNER_TEMP are excluded from \
                    uploaded artifacts."
                    .to_string(),
            });
        }

        findings
    }
}
