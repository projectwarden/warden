use regex::Regex;

use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

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

// ---------------------------------------------------------------------------
// V2: typed-model walk over `jobs.*.steps[*].uses` and match each `uses` string
// against the VULNERABLE_ACTIONS regex catalog. No free-text scan, no false
// matches on commented-out lines or strings that happen to mention the ref.
// ---------------------------------------------------------------------------

pub struct Wrd302;

impl Rule for Wrd302 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-302",
            name: "Known Vulnerable Action",
            default_severity: Severity::Critical,
            description: "Workflow uses a GitHub Action with known security vulnerabilities or \
                          that was involved in a supply chain compromise.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        let compiled: Vec<(Regex, &VulnerableAction)> = VULNERABLE_ACTIONS
            .iter()
            .filter_map(|v| Regex::new(v.pattern).ok().map(|r| (r, v)))
            .collect();

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                for (re, vuln) in &compiled {
                    if re.is_match(&u.uses) {
                        let span = ctx
                            .loaded
                            .spans
                            .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                        findings.push(RuleFinding {
                            rule_id: "WRD-302",
                            severity: Severity::Critical,
                            title: format!("Known vulnerable action: {}", vuln.action_name),
                            description: vuln.description.to_string(),
                            primary: span,
                            related: Vec::new(),
                            remediation: vuln.remediation.to_string(),
                        });
                    }
                }
            }
        }

        findings
    }
}
