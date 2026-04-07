# AI Security Rules (500s)

These rules cover AI-related risks and CI/CD automation hygiene. The 510s address AI configuration poisoning via fork-checkout in privileged workflow contexts. The 520s cover Dependabot security and trusted publishing patterns.

---

## WRD-510: AI Config Poisoning

**Severity:** High

**What it detects:** Privileged-context workflows (`pull_request_target`, `workflow_run`, or `issue_comment`) that check out fork code and either invoke an AI coding assistant or reference an AI assistant's configuration file by path. A malicious PR can plant or modify any of these files; when the privileged workflow runs an AI tool, the tool reads the attacker-controlled file as trusted instructions and the attacker effectively controls the model running in your CI environment.

**Tracked AI configuration file paths (verified against upstream docs as of April 2026):**

| Tool | Files / directories |
| --- | --- |
| Claude Code (Anthropic) | `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md`, `.claude/rules/`, `.claude/` |
| Cursor | `.cursorrules`, `.cursorignore`, `.cursorindexingignore`, `.cursor/rules/`, `.cursor/` |
| GitHub Copilot (VS Code) | `.github/copilot-instructions.md`, `copilot-instructions.md`, `.github/instructions/`, `.github/prompts/` |
| Cross-tool agents standard | `AGENTS.md`, `agents.md` (read by Codex CLI, Cursor, Windsurf, Aider, Cline, VS Code Copilot) |
| Windsurf (Codeium) | `.windsurf/rules/`, `.windsurf/`, `.windsurfrules` (legacy) |
| Cline | `.clinerules/`, `.clinerules` |
| Aider | `.aider.conf.yml`, `.aider.model.settings.yml`, `.aider.model.metadata.json`, `CONVENTIONS.md` |
| Continue | `.continue/rules/`, `.continue/` |
| Gemini CLI (Google) | `GEMINI.md`, `.gemini/GEMINI.md`, `.gemini/` |
| OpenAI Codex CLI | `.codex/`, `AGENTS.md` |

In addition, the rule fires whenever a privileged + fork-checkout workflow invokes any of these tools by name even if no specific config file is referenced in the YAML, since the tool will discover and read the config files at runtime from its working directory.

**Vulnerable:**

```yaml
on: pull_request_target  # also workflow_run and issue_comment

jobs:
  review:
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/ai-review-action@v1
```

**Remediation:** Do not process AI config files from untrusted fork checkouts. Run the AI step in a separate unprivileged `pull_request` workflow, or remove all AI configuration files from the checked-out tree before invoking the AI.

---

## WRD-511: MCP Config Injection

**Severity:** High

**What it detects:** Privileged-context workflows (`pull_request_target`, `workflow_run`, or `issue_comment`) that check out fork code and reference Model Context Protocol (MCP) server configuration. A malicious PR can plant a `.mcp.json` (or one of its many editor-specific filename variants) that redirects AI tool calls to attacker-controlled MCP servers. Those servers can then exfiltrate secrets passed through tool calls, return manipulated results that introduce backdoors into AI-generated code, or execute arbitrary commands on the runner.

**Tracked MCP configuration file paths (verified against upstream docs as of April 2026):**

| Source | Files |
| --- | --- |
| Generic / spec-style | `.mcp.json`, `mcp.json`, `.mcp.yaml`, `.mcp.yml`, `mcp_config.json`, `mcp-config.json`, `mcp_servers.json`, `mcp-servers.json` |
| VS Code | `.vscode/mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Claude Code / Claude Desktop | `.claude/mcp.json`, `.claude/mcp_servers.json`, `claude_desktop_config.json` |
| Continue | `.continue/mcpServers/`, `.continue/config.yaml`, `.continue/config.json` |
| Cline | `cline_mcp_settings.json` |

**Vulnerable:**

```yaml
on: pull_request_target  # also workflow_run and issue_comment

jobs:
  analyze:
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: mcp-tool analyze .
```

**Remediation:** Do not process MCP configurations from untrusted checkouts. Use pinned, repository-owned MCP configs from the base branch, or maintain MCP server definitions outside the repository entirely (e.g. user-level `~/.codeium/windsurf/mcp_config.json` or organization-managed config).

---

## WRD-520: Dependabot Cooldown

**Severity:** Medium

**What it detects:** Dependabot configurations (`dependabot.yml`) with daily update schedules but no dependency grouping. This can produce a high volume of individual PRs, overwhelming reviewers and CI resources.

**Vulnerable:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: daily
```

**Remediation:** Add dependency groups to batch related updates into fewer PRs, or reduce the schedule interval to weekly.

```yaml
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: daily
    groups:
      production-dependencies:
        patterns: ['*']
```

---

## WRD-521: Dependabot Insecure Execution

**Severity:** Medium

**What it detects:** Dependabot-related workflows that use `pull_request_target` and check out the PR head ref. With `pull_request_target`, the workflow runs with write permissions and access to secrets. Checking out untrusted PR code in this context allows arbitrary code execution with elevated privileges.

**Vulnerable:**

```yaml
on: pull_request_target

jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
```

**Remediation:** Avoid checking out the PR head in `pull_request_target` workflows. If you must, run untrusted code in a separate unprivileged workflow triggered by `pull_request` instead.

---

## WRD-525: Use Trusted Publishing

**Severity:** Medium

**What it detects:** PyPI publish workflows using stored API tokens (`PYPI_TOKEN`, `PYPI_API_TOKEN`, `PYPI_PASSWORD`) or npm publish workflows using `NPM_TOKEN` instead of OIDC-based trusted publishing. Trusted publishing is more secure because it eliminates stored secrets entirely.

**Vulnerable:**

```yaml
- uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_TOKEN }}
```

**Remediation:** Configure PyPI Trusted Publishing and add `id-token: write` to permissions. Remove stored API token secrets.

```yaml
permissions:
  id-token: write

steps:
  - uses: pypa/gh-action-pypi-publish@release/v1
    # No password needed with Trusted Publishing
```

See [PyPI Trusted Publishers docs](https://docs.pypi.org/trusted-publishers/) for setup.
