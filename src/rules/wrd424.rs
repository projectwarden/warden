use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-424: Job uses secrets without environment protection.
pub struct Wrd424;

fn re_secret_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)").unwrap())
}

impl Rule for Wrd424 {
    fn id(&self) -> &str {
        "WRD-424"
    }
    fn name(&self) -> &str {
        "Secrets Used Outside Environment Scope"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "A job references secrets (other than GITHUB_TOKEN) without declaring an \
         `environment:`, so no required-reviewers or deployment protection rules gate \
         the secret access."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Some(jobs) = workflow.parsed.get("jobs").and_then(|v| v.as_mapping()) else {
            return findings;
        };

        for (job_name_v, job_v) in jobs {
            let job_name = job_name_v.as_str().unwrap_or("<unknown>");
            let Some(job_map) = job_v.as_mapping() else {
                continue;
            };

            // Has environment?
            if job_map.contains_key(serde_yaml::Value::String("environment".into())) {
                continue;
            }

            // Serialize the job back to YAML and scan for secrets.*
            let job_yaml = match serde_yaml::to_string(job_v) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut matched_secret: Option<String> = None;
            for cap in re_secret_ref().captures_iter(&job_yaml) {
                let name = cap.get(1).unwrap().as_str();
                if name == "GITHUB_TOKEN" {
                    continue;
                }
                matched_secret = Some(name.to_string());
                break;
            }

            let Some(secret_name) = matched_secret else {
                continue;
            };

            // Best-effort line number: locate the job key in the raw content.
            let needle = format!("{job_name}:");
            let line = workflow
                .content
                .find(&needle)
                .map(|o| line_number_at_offset(&workflow.content, o))
                .unwrap_or(1);

            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Job uses secrets without environment protection".to_string(),
                description: format!(
                    "Job '{job_name}' references secrets.{secret_name} but has no `environment:` key. \
                     Without an environment, secret access is not gated by deployment \
                     protection rules or required reviewers."
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Add `environment: production` (or another protected \
                              environment) to this job so secret access requires \
                              environment protection rules / required reviewers."
                    .to_string(),
            });
        }

        findings
    }
}
