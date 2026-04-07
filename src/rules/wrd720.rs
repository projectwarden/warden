use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd720;

/// Matches Docker image references like "image: foo/bar:tag". The `regex`
/// crate does not support lookahead, so we capture the value and post-filter
/// in code to skip any value containing `@sha256:`.
fn re_image_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*image\s*:\s*([^\s#][^\n#]*)").unwrap())
}

impl Rule for Wrd720 {
    fn id(&self) -> &str {
        "WRD-720"
    }
    fn name(&self) -> &str {
        "Unpinned Docker Images"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects container or services image references that are not pinned \
         to a specific @sha256: digest"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let parsed = &workflow.parsed;

        // Only flag if the workflow actually uses container or services
        let has_container_section = parsed
            .get("jobs")
            .and_then(|jobs| {
                jobs.as_mapping().map(|m| {
                    m.values()
                        .any(|job| job.get("container").is_some() || job.get("services").is_some())
                })
            })
            .unwrap_or(false);

        if !has_container_section {
            return findings;
        }

        for caps in re_image_value().captures_iter(content) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            if value.contains("@sha256:") {
                continue;
            }
            let m = caps.get(0).unwrap();
            let line = line_number_at_offset(content, m.start());
            let image_ref = m.as_str().trim();
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: format!("Unpinned Docker image: {image_ref}"),
                description: "Docker images referenced by tag (e.g. :latest, :v1) can be \
                    replaced with a compromised version. Pinning by digest ensures \
                    immutability."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Pin the image to a sha256 digest, e.g. \
                    image: node:18@sha256:abcdef..."
                    .to_string(),
            });
        }

        findings
    }
}
