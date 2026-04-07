use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd323;

fn re_tag_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"uses\s*:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@v([\d]+(?:\.[\d]+)*).*#\s*v([\d]+(?:\.[\d]+)*)"
        ).unwrap()
    })
}

impl Rule for Wrd323 {
    fn id(&self) -> &str {
        "WRD-323"
    }
    fn name(&self) -> &str {
        "Ref Version Mismatch"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions where a literal version tag (e.g. `@v3`) disagrees \
         with the inline `# vX.Y.Z` comment, indicating a partial or \
         copy-pasted version bump."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Case: uses: owner/repo@v3 # v4  (tag ref with mismatched comment)
        for cap in re_tag_ref().captures_iter(content) {
            let action = cap.get(1).unwrap().as_str();
            let ref_version = cap.get(2).unwrap().as_str();
            let comment_version = cap.get(3).unwrap().as_str();

            // Compare major versions at minimum
            let ref_major = ref_version.split('.').next().unwrap_or("");
            let comment_major = comment_version.split('.').next().unwrap_or("");

            if ref_major != comment_major {
                let line = line_number_at_offset(content, cap.get(0).unwrap().start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!(
                        "Version mismatch for {action}: ref v{ref_version} vs comment v{comment_version}"
                    ),
                    description: format!(
                        "Action '{action}' references @v{ref_version} but the inline comment says v{comment_version}. \
                         This inconsistency may indicate a copy-paste error or a \
                         partially completed version bump."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Update the comment to match the actual ref, or \
                        update the ref to match the intended version."
                        .to_string(),
                });
            }
        }

        findings
    }
}
