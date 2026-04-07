use regex::Regex;

use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

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
/// Future enhancement (v1.1): if the AI config file already exists in main
/// and the PR does not modify it, the risk is lower. Detecting this requires
/// comparing the PR diff against the base branch, which is outside the scope
/// of warden's static workflow analysis.
pub struct Wrd510;

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

impl Rule for Wrd510 {
    fn id(&self) -> &str {
        "WRD-510"
    }

    fn name(&self) -> &str {
        "AI Config Poisoning"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "Privileged-context workflow (pull_request_target, workflow_run, or \
         issue_comment) checks out fork code that may contain poisoned AI \
         assistant configuration files (CLAUDE.md, AGENTS.md, .cursorrules, \
         .github/copilot-instructions.md, .windsurf/rules/, .clinerules, \
         .continue/rules/, GEMINI.md, .aider.conf.yml, CONVENTIONS.md, etc.), \
         enabling prompt injection attacks against any AI coding assistant \
         that reads these files at runtime."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Trigger gate: at least one privileged trigger context must be
        // present. We accept the three contexts that can carry repo write
        // permissions while evaluating fork-controlled content.
        //
        // - pull_request_target  // classic fork-PR risk
        // - workflow_run         // parent workflow re-uses fork artifacts
        // - issue_comment        // slash-command bots check out fork branches
        let trigger_re =
            Regex::new(r"(?i)\b(pull_request_target|workflow_run|issue_comment)\b").unwrap();
        let Some(trigger_match) = trigger_re.find(content) else {
            return findings;
        };

        // Must check out PR head ref. We accept the three common ways the
        // PR head is referenced in actions/checkout config: head.sha, head_ref
        // and head.ref.
        let checkout_head_re = Regex::new(
            r"(?i)uses\s*:\s*actions/checkout@\S+[\s\S]*?ref\s*:\s*\$\{\{[^}]*?(?:head\.sha|head_ref|head\.ref)",
        )
        .unwrap();
        if !checkout_head_re.is_match(content) {
            return findings;
        }

        // Broad finding: workflow uses an AI tool by name. The tool will
        // typically read its config files at runtime from cwd, so just having
        // the AI tool present in a fork-checkout context is enough to fire.
        let ai_tool_re = Regex::new(AI_TOOL_NAMES).unwrap();
        if ai_tool_re.is_match(content) {
            let line = line_number_at_offset(content, trigger_match.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "AI config poisoning via privileged trigger + fork checkout".to_string(),
                description: format!(
                    "This privileged-context workflow checks out fork code and appears \
                     to invoke AI tooling. A malicious PR could plant or modify any of \
                     {} known AI assistant configuration files \
                     (CLAUDE.md, AGENTS.md, .cursorrules, .github/copilot-instructions.md, \
                     .windsurf/rules/, .clinerules, .continue/rules/, GEMINI.md, \
                     .aider.conf.yml, .codex/, CONVENTIONS.md, ...) which the AI tool \
                     will then read as trusted instructions.",
                    AI_CONFIG_FILES.len()
                ),
                file: workflow.path.clone(),
                line,
                remediation: "Do not check out fork code in privileged workflows that \
                              invoke AI tools. If checkout is necessary, run the AI step \
                              in a separate unprivileged pull_request workflow, or \
                              explicitly remove all AI configuration files from the \
                              checked-out tree before invoking the AI."
                    .to_string(),
            });
        }

        // Specific finding: workflow YAML directly references one of the
        // tracked AI config file paths. This catches scripts that explicitly
        // cat / cp / move config files into the trusted area.
        for config_file in AI_CONFIG_FILES {
            if let Some(off) = content.find(config_file) {
                let line = line_number_at_offset(content, off);
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: format!("AI config file referenced: {config_file}"),
                    description: format!(
                        "The workflow references '{config_file}' and runs in a privileged \
                         context that checks out fork code. A fork PR could replace or \
                         modify this file with attacker-controlled prompts that the AI \
                         tool will subsequently treat as trusted instructions."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Do not read AI configuration files from untrusted \
                                  checkouts. Use a pinned, base-branch copy, or restore \
                                  the file from `git show base:` before invoking any AI \
                                  tool."
                        .to_string(),
                });
            }
        }

        findings
    }
}
