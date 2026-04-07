# Changelog

All notable changes to warden are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.0.0 // 2026-04-07

First public release of warden. Static analyzer + auto-fixer for GitHub
Actions workflows, written in Rust, single static binary, zero runtime
dependencies.

### Detection

- 53 detection rules across 8 attack classes:
  - **1xx Injection** // expression injection in `run:` blocks, composite
    action input injection, `workflow_dispatch` input injection,
    `GITHUB_ENV`/`GITHUB_PATH` writes, tainted reusable-workflow inputs,
    step-output taint propagation
  - **2xx Triggers** // dangerous fork checkout, build-tool execution on
    untrusted code, cross-workflow privilege escalation
  - **3xx Supply chain** // OIDC trust boundaries, known-vulnerable actions,
    impostor commits, unpinned actions (with severity dampening for
    `actions/*` and `github/*`), archived/stale/version-mismatched/branch-pinned
    refs, runtime binary fetch, denylisted action incidents, and **composite
    or Docker action internal unpinned refs** (transitive pinning hygiene)
  - **4xx Permissions** // secrets in run blocks, network exfiltration,
    debug logging, secrets used outside `environment:` scope
  - **5xx AI security** // AI assistant config poisoning across the broadest
    published catalog of any GHA scanner: 30+ verified file paths covering
    Claude Code, Cursor, GitHub Copilot, Aider, Continue, Windsurf, Cline,
    Gemini CLI, OpenAI Codex CLI, and the cross-tool `AGENTS.md` standard.
    MCP config injection across 16 verified `.mcp.json`-style file paths
    spanning every major MCP-aware editor. Both rules also fire across
    `pull_request_target`, `workflow_run`, and `issue_comment` privileged
    triggers, not just `pull_request_target`. Plus Dependabot cooldown /
    insecure execution and trusted publishing enforcement.
  - **6xx Steganography** // unicode bidi / zero-width / homoglyph payloads,
    IOC pattern matching against known C2 / reverse-shell / exfil patterns
  - **7xx Integrity** // toJSON secrets exposure, artipacked, secrets-inherit,
    insecure commands, hardcoded credentials, curl-pipe-bash, unpinned
    container/services images
  - **8xx Logic** // self-hosted runner on PR triggers, confused deputy on
    auto-merge, artifact injection via `workflow_run`, risky-trigger default
    permissions, unsound conditions, bypassable contains() checks, secret
    redaction bypass, cache poisoning in release workflows, excessive
    permissions, spoofable bot identity checks, undocumented permissions,
    superfluous setup actions, obfuscation in non-`run:` contexts, missing
    concurrency limits, anonymous workflow definitions

### Auto-fix

`warden fix` operates in **plan mode by default** (terraform-style) //
nothing on disk changes unless you pass `--apply`. The fixer covers:

- SHA pinning of `uses:` refs from tags via the GitHub Git API
- Lifting `${{ expression }}` interpolations into `env:` blocks to neutralize
  script injection
- Adding `persist-credentials: false` to `actions/checkout` steps
- Inserting a least-privilege top-level `permissions:` block when missing
- Inserting a `concurrency:` block to prevent overlapping runs

`warden fix --pr owner/repo --apply` pushes a branch with the fixes and
opens a pull request. Add `--prepare-only` to skip the PR creation and
return a GitHub compare URL instead, so you click "Create pull request"
yourself.

### Subcommands

- `warden scan <target>` // scan a local path or `owner/repo` GitHub slug
- `warden score <target>` // 0-100 security score with diminishing-returns
  per-severity penalties
- `warden fix <target>` // plan / apply auto-fixes (see above)
- `warden upstream <path>` // resolve a project's dependency manifests
  (`package.json`, `requirements.txt`, `Pipfile.lock`, `go.mod`, `Cargo.toml`)
  back to their source repos and scan each one's upstream workflows with
  the full 53-rule detector. Supports `--depth 2` for shallow transitive
  walks and `--concurrency N` for parallel scanning.
- `warden rules` // print all detection rules grouped by category
- `warden` (no args) // launches an interactive guided menu in a TTY

### Output formats

- `--format console` (default) // colorized terminal output, capped at the
  20 most severe findings with a "top rules by count" summary so a single
  noisy systemic issue doesn't drown out the actually-critical findings;
  `--all` removes the cap
- `--format json` // structured output for tooling
- `--format sarif` // SARIF 2.1.0 for GitHub Code Scanning upload
- `--format markdown` // collapsible markdown summary suitable for posting
  as a PR comment
- Live progress events on stderr via `--progress` (NDJSON, one event per
  workflow file)

### Configuration

- `.warden.toml` walks upward from the scan target for per-project rule
  disabling and severity overrides
- `--fail-on critical|high|medium|low|none` controls the CI exit code

### Distribution

- Static binaries for `linux-x86_64`, `linux-aarch64`, `macos-x86_64`,
  `macos-aarch64`, `windows-x86_64`
- Multi-arch Docker image at `ghcr.io/projectwarden/warden:1.0.0`
- Cargo: `cargo install wardenscan`
- GitHub Action: `projectwarden/warden@v1` (Docker action with `path`,
  `fail-on`, and `format` inputs)

### Dogfooding

All GitHub Actions in warden's own CI and release workflows are pinned to
40-char commit SHAs. Warden's self-scan runs on every CI build and must
exit clean above the high-severity threshold.
