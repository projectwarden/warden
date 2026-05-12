use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: typed-model walk over step `uses:` values. Each `uses:` owner/repo ref
// is checked against the two curated prefix lists: security tooling that
// fetches binaries (HIGH) and first-party setup actions (MEDIUM).
// ---------------------------------------------------------------------------

pub struct Wrd345;

/// Runtime-binary-fetch security tooling (HIGH). Must appear as the action
/// prefix (before `@`).
const RUNTIME_FETCH_PREFIXES: &[&str] = &[
    "aquasecurity/trivy-action",
    "snyk/actions",
    "securecodewarrior/github-action",
    "anchore/scan-action",
    "zaproxy/action-",
    "bearer/bearer-action",
    "bridgecrewio/checkov-action",
    "returntocorp/semgrep-action",
    "trufflesecurity/trufflehog",
];

/// First-party setup actions that fetch binaries (MEDIUM).
const SETUP_PREFIXES: &[&str] = &[
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-go",
    "actions/setup-java",
    "actions/setup-dotnet",
    "ruby/setup-ruby",
    "denoland/setup-deno",
    "astral-sh/setup-uv",
    "oven-sh/setup-bun",
];

fn matches_prefix(action: &str, list: &[&str]) -> bool {
    let lower = action.to_lowercase();
    list.iter().any(|p| lower.starts_with(p))
}

impl Rule for Wrd345 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-345",
            name: "Runtime Binary Fetch",
            default_severity: Severity::Info,
            description: "Detects actions known to download external binaries at runtime. \
                          SHA-pinning the action does not protect against compromised upstream \
                          binaries or install scripts fetched during execution. \
                          Demoted to Info in v2.0.0: the scanner cannot reliably distinguish \
                          a legitimate setup action (setup-go, setup-python) from a \
                          compromised one by static analysis, so this rule inventories \
                          the risk surface rather than asserting an exploit.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let wf = &ctx.loaded.workflow;

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                let action = match u.uses.split_once('@') {
                    Some((a, _)) => a,
                    None => u.uses.as_str(),
                };
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

                let label: String = u.uses.chars().take(60).collect();

                if matches_prefix(action, RUNTIME_FETCH_PREFIXES) {
                    findings.push(RuleFinding {
                        rule_id: "WRD-345",
                        severity: Severity::Info,
                        title: format!("Action fetches external binary at runtime: {label}"),
                        description: "This action downloads a binary from an external source \
                                      during execution. Even if the action reference is \
                                      SHA-pinned, the downloaded binary is not verified against \
                                      the pin. A compromised upstream release or install script \
                                      can execute malicious code in your workflow. Consider \
                                      using a container-based alternative or verifying downloaded \
                                      binaries against known checksums."
                            .to_string(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Verify that the action pins its internal downloads to \
                                      specific versions and checksums. Consider using official \
                                      container images with digest pins instead of setup actions \
                                      that curl binaries at runtime."
                            .to_string(),
                    });
                } else if matches_prefix(action, SETUP_PREFIXES) {
                    findings.push(RuleFinding {
                        rule_id: "WRD-345",
                        severity: Severity::Info,
                        title: format!("Setup action downloads binary at runtime: {label}"),
                        description:
                            "This setup action downloads a tool binary from an external source. \
                             The binary is fetched at runtime, not captured by the action SHA \
                             pin. While these typically download from trusted first-party \
                             sources, the download is not verified against the action's commit \
                             hash."
                                .to_string(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Consider using pre-built container images with the tools \
                                      already installed, or verify that the action validates \
                                      downloaded binary checksums."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
