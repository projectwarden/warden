use regex::Regex;

use crate::models::{Job, Step};
use crate::rules::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

/// WRD-510: AI config poisoning.
///
/// Detects privileged-context workflows that check out fork code which may
/// contain attacker-controlled AI assistant configuration files (CLAUDE.md,
/// .cursorrules, AGENTS.md, .github/copilot-instructions.md, etc.). When such
/// a config file is read by an AI tool running in the privileged context, the
/// attacker's instructions become trusted prompts to the model.
///
/// The rule fires for the three privileged trigger contexts that GitHub
/// Actions exposes: `pull_request_target`, `workflow_run`, and
/// `issue_comment`. Each one can run with repository write tokens and access
/// to secrets while evaluating fork-controlled content.
///
/// Verified AI assistant configuration file paths as of April 2026. Each entry
/// links back to the upstream tool's official documentation.
///
/// The list deliberately includes both the file name and its containing
/// directory where applicable, so a workflow that touches the directory (e.g.
/// `cp -r .claude/ ./trusted/`) is detected just as well as one that touches
/// the file directly.
const AI_CONFIG_FILES: &[&str] = &[
    // Claude Code (Anthropic) -- docs.claude.com/en/docs/claude-code/memory
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    ".claude/rules/",
    ".claude/",
    // Cross-tool agent instructions (OpenAI, Cursor, Codex, Windsurf, Aider, Cline)
    // -- agents.md, github/openai/codex, docs.windsurf.com
    "AGENTS.md",
    "agents.md",
    // Cursor -- docs.cursor.com/en/context/rules
    ".cursorrules",
    ".cursorignore",
    ".cursorindexingignore",
    ".cursor/rules/",
    ".cursor/",
    // GitHub Copilot (VS Code) -- microsoft/vscode-docs custom-instructions.md
    ".github/copilot-instructions.md",
    "copilot-instructions.md",
    ".github/instructions/",
    ".github/prompts/",
    // Windsurf (Codeium) -- docs.windsurf.com/windsurf/cascade/memories
    ".windsurf/rules/",
    ".windsurf/",
    ".windsurfrules",
    // Cline -- github.com/cline/cline docs/customization/cline-rules.mdx
    ".clinerules/",
    ".clinerules",
    // Aider -- aider.chat/docs/config/aider_conf.html
    ".aider.conf.yml",
    ".aider.model.settings.yml",
    ".aider.model.metadata.json",
    "CONVENTIONS.md",
    // Continue -- docs.continue.dev/customize/deep-dives/rules
    ".continue/rules/",
    ".continue/",
    // Gemini CLI (Google) -- github/google-gemini/gemini-cli docs/cli/gemini-md.md
    "GEMINI.md",
    ".gemini/GEMINI.md",
    ".gemini/",
    // OpenAI Codex CLI -- github/openai/codex docs/agents_md.md
    ".codex/",
];

/// AI tool name patterns. Used to fire the broader "checkout-and-uses-AI"
/// finding even when no specific config file path is referenced in the
/// workflow YAML, since the AI tool may discover and read config files at
/// runtime from its current working directory.
const AI_TOOL_NAMES: &str = "(?i)(?:claude[-_ ]?code|claude\\.md|cursor|copilot|aider|\
                             continue\\.dev|continuedev|windsurf|cline|codeium|\
                             gemini[-_ ]?cli|gemini\\.md|junie|qodo|coderabbit|sourcery|\
                             sweep|codex[-_ ]cli|openai/codex)";

// ---------------------------------------------------------------------------
// V2: typed-model gating for triggers + checkout ref, plus raw-text scan for
// AI tool names and known AI config file paths.
// ---------------------------------------------------------------------------

pub struct Wrd510;

const PRIVILEGED_TRIGGERS: &[&str] = &["pull_request_target", "workflow_run", "issue_comment"];

fn mentions_fork_head(ref_value: &str) -> bool {
    let lower = ref_value.to_ascii_lowercase();
    lower.contains("head.sha") || lower.contains("head_ref") || lower.contains("head.ref")
}

fn checkout_fork_step(wf: &crate::models::Workflow) -> bool {
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
                        if mentions_fork_head(&ref_v.as_str_owned()) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

impl Rule for Wrd510 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-510",
            name: "AI Config Poisoning",
            default_severity: Severity::High,
            description: "Privileged-context workflow (pull_request_target, workflow_run, or \
                          issue_comment) checks out fork code that may contain poisoned AI \
                          assistant configuration files (CLAUDE.md, AGENTS.md, .cursorrules, \
                          .github/copilot-instructions.md, .windsurf/rules/, .clinerules, \
                          .continue/rules/, GEMINI.md, .aider.conf.yml, CONVENTIONS.md, etc.), \
                          enabling prompt injection attacks against any AI coding assistant \
                          that reads these files at runtime.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        let has_priv_trigger = PRIVILEGED_TRIGGERS.iter().any(|t| wf.on.mentions(t));
        if !has_priv_trigger {
            return findings;
        }
        if !checkout_fork_step(wf) {
            return findings;
        }

        let raw = &ctx.loaded.raw;
        let top_span = ctx
            .loaded
            .spans
            .get_str("on")
            .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

        let ai_tool_re = Regex::new(AI_TOOL_NAMES).unwrap();
        if ai_tool_re.is_match(raw) {
            findings.push(RuleFinding {
                rule_id: "WRD-510",
                severity: Severity::High,
                title: "AI config poisoning via privileged trigger + fork checkout".into(),
                description: format!(
                    "This privileged-context workflow checks out fork code and appears to \
                     invoke AI tooling. A malicious PR could plant or modify any of {} known \
                     AI assistant configuration files (CLAUDE.md, AGENTS.md, .cursorrules, \
                     .github/copilot-instructions.md, .windsurf/rules/, .clinerules, \
                     .continue/rules/, GEMINI.md, .aider.conf.yml, .codex/, CONVENTIONS.md, \
                     ...) which the AI tool will then read as trusted instructions.",
                    AI_CONFIG_FILES.len()
                ),
                primary: top_span,
                related: Vec::new(),
                remediation: "Do not check out fork code in privileged workflows that invoke \
                              AI tools. If checkout is necessary, run the AI step in a \
                              separate unprivileged pull_request workflow, or explicitly \
                              remove all AI configuration files from the checked-out tree \
                              before invoking the AI."
                    .into(),
            });
        }

        for config_file in AI_CONFIG_FILES {
            if let Some(off) = raw.find(config_file) {
                let line = line_number_at_offset(raw, off);
                let span = Span::new(off, off + config_file.len(), line, 1, line, 1);
                findings.push(RuleFinding {
                    rule_id: "WRD-510",
                    severity: Severity::High,
                    title: format!("AI config file referenced: {config_file}"),
                    description: format!(
                        "The workflow references '{config_file}' and runs in a privileged \
                         context that checks out fork code. A fork PR could replace or modify \
                         this file with attacker-controlled prompts that the AI tool will \
                         subsequently treat as trusted instructions."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Do not read AI configuration files from untrusted checkouts. \
                                  Use a pinned, base-branch copy, or restore the file from \
                                  `git show base:` before invoking any AI tool."
                        .into(),
                });
            }
        }

        findings
    }
}
