use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walks each run: block via ctx.shell.occurrences() and flags the
// specific "--dangerously-skip-permissions / --yolo / --trust-all-tools"
// flag shapes that AI coding-assistant CLIs expose. Matches the pivot
// pattern from the Nx s1ngularity supply-chain attack (2025-08), where
// the post-exploitation step was to spawn a local Claude/Gemini/Codex
// CLI with permission-skipping flags to enumerate dev secrets from the
// user's filesystem.
//
// Default severity MEDIUM (per CHANGELOG.md convention: 510s = AI tooling
// hardening). Escalated to HIGH when the workflow trigger is
// pull_request_target / workflow_run / issue_comment, since those
// contexts give an external caller influence over the run (i.e. the exact
// Nx-s1ngularity shape).
//
// Sources:
//   - https://nx.dev/blog/s1ngularity-postmortem
//   - https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html
// ---------------------------------------------------------------------------

pub struct Wrd522;

fn re_ai_danger_flags() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match common AI-agent CLIs followed by permission-bypass flags.
        // We match broadly so the flag order doesn't matter; the flag is
        // the strong signal, the binary name is the context.
        Regex::new(
            r"(?i)\b(claude(?:-code)?|cursor(?:-agent)?|gemini|codex|aider|continue|cline)\b[^\n]*?(--dangerously-skip-permissions|--yolo|--trust-all-tools|--full-auto|-y\b|--unsafe|--no-confirm)",
        )
        .unwrap()
    })
}

fn escalated_trigger(wf: &crate::models::Workflow) -> bool {
    let on = &wf.on;
    on.mentions("pull_request_target")
        || on.mentions("workflow_run")
        || on.mentions("issue_comment")
}

impl Rule for Wrd522 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-522",
            name: "AI Agent Permission Bypass Flags",
            default_severity: Severity::Medium,
            description: "Detects run: blocks that invoke an AI coding-agent CLI \
                          (claude, cursor-agent, gemini, codex, aider, continue, \
                          cline) with a permission-bypass flag (--dangerously-skip-\
                          permissions, --yolo, --trust-all-tools, --full-auto, -y, \
                          --unsafe, --no-confirm). This is the post-exploitation \
                          primitive used by the Nx s1ngularity npm supply-chain \
                          attack (2025-08) to enumerate dev secrets from a victim's \
                          filesystem.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }

        #[cfg(feature = "shell-analysis")]
        {
            let mut findings = Vec::new();
            let wf = &ctx.loaded.workflow;
            let escalate = escalated_trigger(wf);

            for occ in ctx.shell.occurrences() {
                let script = &occ.script;
                let Some(m) = re_ai_danger_flags().find(script) else {
                    continue;
                };
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&occ.path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                let offset_line = script[..m.start()].matches('\n').count();
                let actual_line = span.start_line + offset_line;
                let line_span = Span::new(
                    span.byte_start,
                    span.byte_end,
                    actual_line,
                    span.start_col,
                    actual_line,
                    span.end_col,
                );

                let severity = if escalate {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let title = if escalate {
                    "AI agent permission-bypass flag on externally-triggered workflow"
                } else {
                    "AI agent permission-bypass flag in run block"
                };

                findings.push(RuleFinding {
                    rule_id: "WRD-522",
                    severity,
                    title: title.to_string(),
                    description: format!(
                        "Pattern `{}` invokes an AI coding-agent CLI with a \
                         permission-bypass flag. If an attacker can influence \
                         the files the agent reads (a malicious PR, a poisoned \
                         npm install hook, a crafted issue comment), the agent \
                         will execute the attacker's tool calls without \
                         prompting. This is the exact pivot used by the Nx \
                         s1ngularity attack (August 2025) to enumerate \
                         developer secrets.{}",
                        m.as_str().trim(),
                        if escalate {
                            " This workflow runs on an externally-triggerable \
                              event (pull_request_target / workflow_run / \
                              issue_comment), so the blast radius is immediate."
                        } else {
                            ""
                        }
                    ),
                    primary: line_span,
                    related: Vec::new(),
                    remediation: "Remove the permission-bypass flag and let the \
                                  agent prompt per tool call, OR constrain the \
                                  agent's workspace so there is no secret material \
                                  or outbound-network capability in reach, OR move \
                                  the step to a workflow that is not externally \
                                  triggerable (plain push on trusted branches only)."
                        .to_string(),
                });
            }
            findings
        }
        #[cfg(not(feature = "shell-analysis"))]
        {
            let _ = ctx;
            Vec::new()
        }
    }
}
