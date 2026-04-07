use crate::rules::{Finding, Rule, Workflow};
use regex::Regex;
use std::sync::OnceLock;

/// WRD-325: Actions that download external binaries at runtime,
/// bypassing SHA-pin protection. Even with the action pinned to a
/// commit SHA, the action's internal code may fetch unverified
/// binaries from external sources at runtime.
pub struct Wrd325;

fn re_runtime_fetch_actions() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)uses:\s*['"]?(?:aquasecurity/trivy-action|snyk/actions|securecodewarrior/github-action|anchore/scan-action|zaproxy/action-|bearer/bearer-action|bridgecrewio/checkov-action|returntocorp/semgrep-action|trufflesecurity/trufflehog)@"#
        ).unwrap()
    })
}

fn re_setup_actions() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)uses:\s*['"]?(?:actions/setup-node|actions/setup-python|actions/setup-go|actions/setup-java|actions/setup-dotnet|ruby/setup-ruby|denoland/setup-deno|astral-sh/setup-uv|oven-sh/setup-bun)@"#
        ).unwrap()
    })
}

impl Rule for Wrd325 {
    fn id(&self) -> &str {
        "WRD-325"
    }
    fn name(&self) -> &str {
        "Runtime Binary Fetch"
    }
    /// Default severity for the rule. Note that `check()` emits per-finding
    /// severities: HIGH for runtime-fetch security tooling (Trivy, Snyk,
    /// Semgrep, etc.) and MEDIUM for first-party setup actions whose
    /// downloads come from trusted upstreams. The trait method returns the
    /// MEDIUM default for catalog/listing purposes only.
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects actions known to download external binaries at runtime. \
         SHA-pinning the action does not protect against compromised \
         upstream binaries or install scripts fetched during execution."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for (line_num, line) in content.lines().enumerate() {
            if re_runtime_fetch_actions().is_match(line) {
                let action = line.trim().trim_start_matches("- ");
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: "high".to_string(),
                    title: format!("Action fetches external binary at runtime: {}", action.trim().chars().take(60).collect::<String>()),
                    description: "This action downloads a binary from an external source during execution. \
                         Even if the action reference is SHA-pinned, the downloaded binary is not \
                         verified against the pin. A compromised upstream release or install script \
                         can execute malicious code in your workflow. Consider using a container-based \
                         alternative or verifying downloaded binaries against known checksums.".to_string(),
                    file: workflow.path.clone(),
                    line: line_num + 1,
                    remediation: "Verify that the action pins its internal downloads to specific \
                        versions and checksums. Consider using official container images with \
                        digest pins instead of setup actions that curl binaries at runtime.".to_string(),
                });
            }

            // Setup actions are lower severity since they download from trusted sources
            // (nodejs.org, python.org, etc.) but still worth noting
            if re_setup_actions().is_match(line) {
                let action = line.trim().trim_start_matches("- ");
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: "medium".to_string(),
                    title: format!(
                        "Setup action downloads binary at runtime: {}",
                        action.trim().chars().take(60).collect::<String>()
                    ),
                    description:
                        "This setup action downloads a tool binary from an external source. \
                         The binary is fetched at runtime, not captured by the action SHA pin. \
                         While these typically download from trusted first-party sources, the \
                         download is not verified against the action's commit hash."
                            .to_string(),
                    file: workflow.path.clone(),
                    line: line_num + 1,
                    remediation: "Consider using pre-built container images with the tools \
                        already installed, or verify that the action validates downloaded \
                        binary checksums."
                        .to_string(),
                });
            }
        }

        findings
    }
}
