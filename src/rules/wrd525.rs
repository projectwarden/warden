use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd525;

fn re_pypi_publish() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*pypa/gh-action-pypi-publish").unwrap())
}

fn re_id_token_write() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)id-token\s*:\s*write").unwrap())
}

fn re_npm_publish_with_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)npm\s+publish.*NPM_TOKEN|NODE_AUTH_TOKEN\s*:\s*\$\{\{\s*secrets\.(NPM_TOKEN|NODE_AUTH_TOKEN)").unwrap()
    })
}

fn re_pypi_token_secret() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\$\{\{\s*secrets\.(PYPI_TOKEN|PYPI_API_TOKEN|PYPI_PASSWORD)").unwrap()
    })
}

impl Rule for Wrd525 {
    fn id(&self) -> &str {
        "WRD-525"
    }
    fn name(&self) -> &str {
        "Use Trusted Publishing"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects PyPI/npm publish workflows using stored API tokens instead of \
         OIDC trusted publishing"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        let has_id_token = re_id_token_write().is_match(content);

        // Check PyPI publish without OIDC
        if re_pypi_publish().is_match(content) && !has_id_token {
            for m in re_pypi_publish().find_iter(content) {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "PyPI publish without trusted publishing (OIDC)".to_string(),
                    description: "pypa/gh-action-pypi-publish is used without \
                        'id-token: write' permission. Trusted publishing via OIDC is \
                        more secure than long-lived API tokens because it eliminates \
                        stored secrets entirely."
                        .to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Configure trusted publishing on PyPI and add \
                        'id-token: write' to permissions. Remove any PYPI_TOKEN secrets. \
                        See https://docs.pypi.org/trusted-publishers/"
                        .to_string(),
                });
            }
        }

        // Check PyPI token secrets even without the action
        for m in re_pypi_token_secret().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "PyPI API token stored as secret".to_string(),
                description: "A PyPI API token is referenced as a repository secret. \
                    Trusted publishing via OIDC eliminates the need for stored tokens."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Migrate to trusted publishing (OIDC) and remove the \
                    stored PyPI token. See https://docs.pypi.org/trusted-publishers/"
                    .to_string(),
            });
        }

        // Check npm publish with token
        for m in re_npm_publish_with_token().find_iter(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "npm publish using stored token".to_string(),
                description: "npm publish uses a stored NPM_TOKEN or NODE_AUTH_TOKEN \
                    secret. Consider using npm provenance with OIDC for a more \
                    secure publishing flow."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Use 'npm publish --provenance' with OIDC (id-token: write) \
                    instead of stored tokens. See https://docs.npmjs.com/generating-provenance-statements"
                    .to_string(),
            });
        }

        findings
    }
}
