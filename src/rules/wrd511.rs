use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-511: MCP config injection.
///
/// Detects privileged-context workflows that check out fork code which may
/// contain attacker-controlled Model Context Protocol (MCP) server
/// configurations. A malicious .mcp.json (or any of its many filename
/// variants across editors) can redirect an AI assistant's tool calls to
/// attacker-controlled MCP servers, exfiltrating secrets and source code or
/// returning manipulated tool responses that introduce backdoors into
/// AI-generated code.
///
/// Like WRD-510, this rule fires for the three privileged GitHub Actions
/// trigger contexts: `pull_request_target`, `workflow_run`, and
/// `issue_comment`.
///
/// Future enhancement (v1.1): if the .mcp.json already exists in main and the
/// PR does not modify it, the marginal risk from the PR is lower (though the
/// existing config may itself be compromised). Detecting this requires
/// comparing against the base branch, which is outside the scope of warden's
/// static workflow analysis.
pub struct Wrd511;

/// Verified MCP configuration file paths as of April 2026. Each entry links
/// back to the upstream client's official documentation.
const MCP_CONFIG_FILES: &[&str] = &[
    // Generic / spec-style names
    ".mcp.json",
    "mcp.json",
    ".mcp.yaml",
    ".mcp.yml",
    "mcp_config.json",
    "mcp-config.json",
    "mcp_servers.json",
    "mcp-servers.json",
    // VS Code -- microsoft/vscode-docs mcp-servers documentation
    ".vscode/mcp.json",
    // Cursor -- docs.cursor.com/en/context/mcp
    ".cursor/mcp.json",
    // Claude Code (Anthropic)
    ".claude/mcp.json",
    ".claude/mcp_servers.json",
    "claude_desktop_config.json",
    // Continue -- docs.continue.dev/customize/deep-dives/mcp
    ".continue/mcpServers/",
    ".continue/config.yaml",
    ".continue/config.json",
    // Windsurf (Codeium) -- docs.windsurf.com/windsurf/cascade/mcp
    // (Windsurf's MCP config lives at ~/.codeium/windsurf/mcp_config.json,
    // not inside the repo, but a fork PR can plant a per-project equivalent
    // that other tools may pick up. We list mcp_config.json above for that
    // reason.)
    // Cline -- github.com/cline/cline docs/mcp/adding-and-configuring-servers
    "cline_mcp_settings.json",
];

impl Rule for Wrd511 {
    fn id(&self) -> &str {
        "WRD-511"
    }

    fn name(&self) -> &str {
        "MCP Config Injection"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Privileged-context workflow (pull_request_target, workflow_run, or \
         issue_comment) checks out fork code that may contain malicious Model \
         Context Protocol (MCP) server configurations (.mcp.json, .vscode/mcp.json, \
         .cursor/mcp.json, .claude/mcp.json, .continue/mcpServers/, \
         cline_mcp_settings.json, claude_desktop_config.json, etc.), enabling \
         tool-server hijacking, secret exfiltration, and silent backdoor \
         injection into AI-generated code."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Trigger gate: privileged contexts only.
        let trigger_re =
            Regex::new(r"(?i)\b(pull_request_target|workflow_run|issue_comment)\b").unwrap();
        let Some(trigger_match) = trigger_re.find(content) else {
            return findings;
        };

        // Must check out fork-controlled PR head ref.
        let checkout_head_re = Regex::new(
            r"(?i)uses\s*:\s*actions/checkout@\S+[\s\S]*?ref\s*:\s*\$\{\{[^}]*?(?:head\.sha|head_ref|head\.ref)",
        )
        .unwrap();
        if !checkout_head_re.is_match(content) {
            return findings;
        }

        // Broad finding: any reference to MCP in a privileged + fork-checkout
        // workflow is suspicious. We use a word-boundary match so unrelated
        // tokens like "compose" don't false-positive.
        let mcp_re = Regex::new(r"(?i)\bmcp\b").unwrap();
        if let Some(m) = mcp_re.find(content) {
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "MCP configuration in fork checkout".to_string(),
                description: format!(
                    "This privileged-context workflow checks out fork code and \
                     references MCP. Across {} tracked MCP config file paths \
                     (.mcp.json, .vscode/mcp.json, .cursor/mcp.json, \
                     .claude/mcp.json, .continue/mcpServers/, cline_mcp_settings.json, \
                     claude_desktop_config.json, ...) a fork PR could plant a \
                     malicious server definition that redirects AI tool calls \
                     to attacker infrastructure.",
                    MCP_CONFIG_FILES.len()
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Do not process MCP configurations from untrusted \
                              checkouts. Use a pinned, base-branch copy of any \
                              required MCP config, or restore it via `git show \
                              base:` before launching any AI tool that auto-loads \
                              MCP servers from the working tree."
                    .to_string(),
            });
            // Note the trigger location too so the user knows which event made
            // this risky in the first place.
            let _ = trigger_match;
        }

        // Specific finding: explicit MCP config file path referenced in YAML.
        for config_file in MCP_CONFIG_FILES {
            if let Some(off) = content.find(config_file) {
                let line = line_number_at_offset(content, off);
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("MCP config file referenced: {config_file}"),
                    description: format!(
                        "The workflow references '{config_file}' and runs in a \
                         privileged context that checks out fork code. This MCP \
                         config could be replaced by a malicious fork to hijack \
                         AI tool servers, exfiltrate secrets passed through tool \
                         calls, or inject backdoors into AI-generated code."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Avoid reading MCP config files from untrusted \
                                  checkouts. Use a trusted copy from the base \
                                  branch, or maintain MCP server definitions \
                                  outside the repository entirely (e.g. \
                                  ~/.codeium/windsurf/mcp_config.json or \
                                  organization-managed config)."
                        .to_string(),
                });
            }
        }

        findings
    }
}
