use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-302: Known vulnerable actions.
/// Detects usage of GitHub Actions with known security vulnerabilities.
pub struct Wrd302;

struct VulnerableAction {
    /// Regex pattern to match the action reference in uses: directives.
    pattern: &'static str,
    /// Human-readable name of the vulnerable action.
    action_name: &'static str,
    /// Description of the vulnerability.
    description: &'static str,
    /// Suggested fix.
    remediation: &'static str,
}

const VULNERABLE_ACTIONS: &[VulnerableAction] = &[
    VulnerableAction {
        pattern: r"(?i)tj-actions/changed-files@v(?:[1-9]|[1-3][0-9]|4[0-4])\b",
        action_name: "tj-actions/changed-files (pre-v45)",
        description: "tj-actions/changed-files versions before v45 were compromised in a \
                      supply chain attack (March 2024). The action was modified to dump \
                      CI/CD secrets to workflow logs.",
        remediation: "Update to tj-actions/changed-files@v45 or later, or pin to a \
                      verified SHA after the fix.",
    },
    VulnerableAction {
        pattern: r"(?i)tj-actions/eslint-changed-files@v(?:[1-9]|1[0-9]|2[0-3])\b",
        action_name: "tj-actions/eslint-changed-files (pre-v24)",
        description: "tj-actions/eslint-changed-files was also compromised in the \
                      tj-actions supply chain attack.",
        remediation: "Update to the latest version or pin to a verified SHA.",
    },
    VulnerableAction {
        pattern: r"(?i)reviewdog/action-setup@v1\b",
        action_name: "reviewdog/action-setup@v1",
        description: "reviewdog/action-setup v1 was compromised to inject malicious code \
                      into CI pipelines.",
        remediation: "Update to a patched version or pin to a verified commit SHA.",
    },
    VulnerableAction {
        pattern: r"(?i)reviewdog/action-[a-z]+@v1\b",
        action_name: "reviewdog/action-* @v1",
        description: "reviewdog actions at v1 may be affected by the reviewdog supply chain \
                      compromise. Multiple reviewdog actions were backdoored.",
        remediation: "Update all reviewdog actions to patched versions or pin to verified SHAs.",
    },
    VulnerableAction {
        pattern: r"(?i)github/codeql-action/(?:init|analyze|upload-sarif)@v2\b",
        action_name: "github/codeql-action@v2",
        description: "github/codeql-action@v2 is deprecated and no longer receives security \
                      updates. Node.js 16 runtime is end-of-life.",
        remediation: "Upgrade to github/codeql-action@v3 or later.",
    },
    VulnerableAction {
        pattern: r"(?i)actions/upload-artifact@v[12]\b",
        action_name: "actions/upload-artifact@v1 or v2",
        description: "actions/upload-artifact v1 and v2 are deprecated. They use Node.js 12 \
                      runtime which is end-of-life and have known path traversal issues.",
        remediation: "Upgrade to actions/upload-artifact@v4 or later.",
    },
    VulnerableAction {
        pattern: r"(?i)actions/download-artifact@v[12]\b",
        action_name: "actions/download-artifact@v1 or v2",
        description: "actions/download-artifact v1 and v2 are deprecated with known issues \
                      including artifact confusion vulnerabilities.",
        remediation: "Upgrade to actions/download-artifact@v4 or later.",
    },
    VulnerableAction {
        pattern: r"(?i)ossf/scorecard-action@v1\b",
        action_name: "ossf/scorecard-action@v1",
        description: "ossf/scorecard-action@v1 uses a deprecated Node.js runtime and has \
                      known issues.",
        remediation: "Upgrade to ossf/scorecard-action@v2 or later.",
    },
    VulnerableAction {
        pattern: r"(?i)peter-evans/create-pull-request@v[1-4]\b",
        action_name: "peter-evans/create-pull-request (old versions)",
        description: "Older versions of peter-evans/create-pull-request have known issues \
                      with token handling that could lead to privilege escalation.",
        remediation: "Upgrade to the latest version and pin to a verified commit SHA.",
    },
    VulnerableAction {
        pattern: r"(?i)peaceiris/actions-gh-pages@v[12]\b",
        action_name: "peaceiris/actions-gh-pages@v1 or v2",
        description: "peaceiris/actions-gh-pages v1 and v2 are deprecated and use outdated \
                      Node.js runtimes.",
        remediation: "Upgrade to peaceiris/actions-gh-pages@v4 or later.",
    },
];

impl Rule for Wrd302 {
    fn id(&self) -> &str {
        "WRD-302"
    }

    fn name(&self) -> &str {
        "Known Vulnerable Action"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "Workflow uses a GitHub Action with known security vulnerabilities or \
         that was involved in a supply chain compromise."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for vuln in VULNERABLE_ACTIONS {
            let re = match Regex::new(vuln.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(content) {
                let line = line_number_at_offset(content, m.start());
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("Known vulnerable action: {}", vuln.action_name),
                    description: vuln.description.to_string(),
                    file: workflow.path.clone(),
                    line,
                    remediation: vuln.remediation.to_string(),
                });
            }
        }

        findings
    }
}
