# AI Security Rules (500s)

These rules cover AI-related risks and CI/CD automation hygiene. The 510s address AI configuration poisoning via fork-checkout in privileged workflow contexts. The 520s cover Dependabot security and trusted publishing patterns. WRD-540 surfaces a Dependabot scheduling hygiene signal.

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

## WRD-521: Dependabot PR Untrusted Execution

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

## WRD-525: Long-Lived Publish Token In Use

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

---

## WRD-522: AI Agent Permission Bypass Flags

**Severity:** Medium (High when the trigger is `pull_request_target`, `workflow_run`, or `issue_comment`)

**What it detects:** `run:` blocks that invoke an AI coding-agent CLI (`claude`, `cursor-agent`, `gemini`, `codex`, `aider`, `continue`, `cline`) with a permission-bypass flag (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, `--full-auto`, `-y`, `--unsafe`, `--no-confirm`). This is the exact post-exploitation pivot used by the Nx `s1ngularity` npm supply-chain attack in August 2025 to enumerate developer secrets from the victim's filesystem without prompting.

Escalates to High when the workflow trigger is externally controllable, because in that case an attacker (via a PR, an issue comment, or a workflow_run dispatch) can influence what the agent reads.

**Vulnerable:**

```yaml
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: |
          claude --dangerously-skip-permissions --prompt "$PROMPT"
```

**Remediation:** remove the bypass flag and let the agent prompt per tool call, or constrain the agent's workspace so there is no secret material / outbound-network capability in reach, or move the step to a workflow that is not externally triggerable.

Nobody else in the GitHub Actions static-analysis space currently detects this pattern.

---

## WRD-526: GitHub App Token Misuse

**Severity:** Medium (High for `skip-token-revoke: true`)

**What it detects:** Workflows using `actions/create-github-app-token` (or common forks: `tibdex/github-app-token`, `getsentry/action-github-app-token`) with one or more of three misconfigurations that extend the token's validity window or its blast radius:

1. `skip-token-revoke: true` (High). The token is not revoked at the end of the job, so it stays valid long after the workflow run ends; any log leak during that window lets an attacker keep using it.
2. No `repositories:` specified (Medium). The minted token is valid against every repo the GitHub App is installed in, not just the one this job operates on.
3. No `permissions:` specified (Medium). The token inherits every permission the GitHub App was granted at install time.

**Vulnerable:**

```yaml
- uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_PRIVATE_KEY }}
    skip-token-revoke: true
```

**Remediation:** Specify `repositories:` (narrow), specify `permissions:` (least-privilege), and let revocation run by default.

```yaml
- uses: actions/create-github-app-token@v1
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_PRIVATE_KEY }}
    repositories: this-repo
    permissions: |
      contents: read
      pull_requests: write
```

---

## WRD-527: Registry Publish Without Trusted Publishing

**Severity:** Medium

**What it detects:** Complements WRD-525 (PyPI + npm) by flagging the same class of long-lived-publish-token use against Cargo (crates.io) and RubyGems. Both registries shipped OIDC-based trusted publishing in late 2025, so using a stored `CARGO_REGISTRY_TOKEN`, `CRATES_IO_TOKEN`, `GEM_HOST_API_KEY`, or `RUBYGEMS_API_KEY` is now the legacy path. Also catches `cargo publish` and `gem push` directly inside a `run:` block.

**Vulnerable:**

```yaml
- run: cargo publish --token $TOKEN
  env:
    TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

**Remediation:** Configure the registry's OIDC trusted-publisher flow, add `permissions: id-token: write`, and remove the stored token secret. See crates.io's "trusted publishing" docs and RubyGems' OIDC guide.

---

## WRD-540: Dependabot Daily Without Grouping

**Severity:** Info

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
