use regex::Regex;

use crate::models::{Job, Step};
use crate::rules::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

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

// ---------------------------------------------------------------------------
// V2: typed-model gating for triggers + checkout ref, raw-text scan for MCP
// references and known MCP config file paths.
// ---------------------------------------------------------------------------

pub struct Wrd511;

const PRIVILEGED_TRIGGERS_511: &[&str] = &["pull_request_target", "workflow_run", "issue_comment"];

fn mentions_fork_head_511(ref_value: &str) -> bool {
    let lower = ref_value.to_ascii_lowercase();
    lower.contains("head.sha") || lower.contains("head_ref") || lower.contains("head.ref")
}

fn checkout_fork_step_511(wf: &crate::models::Workflow) -> bool {
    for job in wf.jobs.values() {
        let Job::Normal(j) = job else {
            continue;
        };
        for step in &j.steps {
            if let Step::Uses(u) = step {
                if !u.uses.starts_with("actions/checkout@") {
                    continue;
                }
                if let Some(with) = &u.with {
                    if let Some(ref_v) = with.get("ref") {
                        if mentions_fork_head_511(&ref_v.as_str_owned()) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

impl Rule for Wrd511 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-511",
            name: "MCP Config Injection",
            default_severity: Severity::High,
            description: "Privileged-context workflow (pull_request_target, workflow_run, or \
                          issue_comment) checks out fork code that may contain malicious Model \
                          Context Protocol (MCP) server configurations (.mcp.json, \
                          .vscode/mcp.json, .cursor/mcp.json, .claude/mcp.json, \
                          .continue/mcpServers/, cline_mcp_settings.json, \
                          claude_desktop_config.json, etc.), enabling tool-server hijacking, \
                          secret exfiltration, and silent backdoor injection into AI-generated \
                          code.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        let has_priv_trigger = PRIVILEGED_TRIGGERS_511.iter().any(|t| wf.on.mentions(t));
        if !has_priv_trigger {
            return findings;
        }
        if !checkout_fork_step_511(wf) {
            return findings;
        }

        let raw = &ctx.loaded.raw;

        let mcp_re = Regex::new(r"(?i)\bmcp\b").unwrap();
        if let Some(m) = mcp_re.find(raw) {
            let line = line_number_at_offset(raw, m.start());
            let span = Span::new(m.start(), m.end(), line, 1, line, 1);
            findings.push(RuleFinding {
                rule_id: "WRD-511",
                severity: Severity::High,
                title: "MCP configuration in fork checkout".into(),
                description: format!(
                    "This privileged-context workflow checks out fork code and references MCP. \
                     Across {} tracked MCP config file paths (.mcp.json, .vscode/mcp.json, \
                     .cursor/mcp.json, .claude/mcp.json, .continue/mcpServers/, \
                     cline_mcp_settings.json, claude_desktop_config.json, ...) a fork PR could \
                     plant a malicious server definition that redirects AI tool calls to \
                     attacker infrastructure.",
                    MCP_CONFIG_FILES.len()
                ),
                primary: span,
                related: Vec::new(),
                remediation: "Do not process MCP configurations from untrusted checkouts. Use \
                              a pinned, base-branch copy of any required MCP config, or \
                              restore it via `git show base:` before launching any AI tool \
                              that auto-loads MCP servers from the working tree."
                    .into(),
            });
        }

        for config_file in MCP_CONFIG_FILES {
            if let Some(off) = raw.find(config_file) {
                let line = line_number_at_offset(raw, off);
                let span = Span::new(off, off + config_file.len(), line, 1, line, 1);
                findings.push(RuleFinding {
                    rule_id: "WRD-511",
                    severity: Severity::High,
                    title: format!("MCP config file referenced: {config_file}"),
                    description: format!(
                        "The workflow references '{config_file}' and runs in a privileged \
                         context that checks out fork code. This MCP config could be replaced \
                         by a malicious fork to hijack AI tool servers, exfiltrate secrets \
                         passed through tool calls, or inject backdoors into AI-generated code."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Avoid reading MCP config files from untrusted checkouts. Use \
                                  a trusted copy from the base branch, or maintain MCP server \
                                  definitions outside the repository entirely (e.g. \
                                  ~/.codeium/windsurf/mcp_config.json or organization-managed \
                                  config)."
                        .into(),
                });
            }
        }

        findings
    }
}
