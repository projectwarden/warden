# CLI Reference

Warden is invoked as `warden`. Every subcommand supports `--help`, and the
top-level binary supports `--help` and `--version`.

```
warden <COMMAND> [OPTIONS]
```

Run `warden` with no arguments inside a TTY to launch the interactive guided
menu. In CI or when stdin is piped, the binary instead prints top-level help.

## Top-Level Flags

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |
| `--help`, `-h` | Print help |

There are no global `--no-color`, `--quiet`, `--verbose`, or `--config` flags.
Subcommand-specific flags are documented below.

---

## warden scan

Scan workflows for security vulnerabilities.

```
warden scan <TARGET> [OPTIONS]
```

`<TARGET>` may be:

- A local path (`.`, `./my-project`, a single `.yml` file). When given a
  directory, warden looks for `.github/workflows/*.yml` and `*.yaml`.
- A GitHub `owner/repo` slug (e.g. `cli/cli`, `aquasecurity/trivy`). Workflows
  are fetched via the GitHub API.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--format <FORMAT>` | `console` | Output format: `console`, `json`, `sarif`, `markdown` (alias: `pr-comment`) |
| `--fail-on <SEVERITY>` | `high` | Minimum severity that causes a non-zero exit: `critical`, `high`, `medium`, `low`, `none` |
| `--github-token <TOKEN>` | none | GitHub token for API calls. Also reads `GITHUB_TOKEN` env var |
| `--progress` | off | Emit NDJSON progress events on stderr (one per workflow) |
| `--all` | off | Print every finding instead of capping the console view at 20 |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` threshold |
| `1` | One or more findings at or above the threshold |
| `2` | Input or runtime error (file not found, invalid YAML, network error, ...) |

### Examples

```bash
# Scan the current project
warden scan .

# Scan a public repo
warden scan cli/cli

# Write SARIF for GitHub Code Scanning
warden scan . --format sarif > results.sarif

# Fail CI only on critical findings
warden scan . --fail-on critical

# Print every finding (no top-20 cap)
warden scan pytorch/pytorch --all

# Stream NDJSON scan progress on stderr
warden scan . --progress
```

---

## warden score

Compute a 0-100 security score for the workflows in `<TARGET>`.

```
warden score <TARGET> [OPTIONS]
```

`<TARGET>` accepts the same forms as `warden scan` (local path or
`owner/repo`).

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--format <FORMAT>` | `console` | Output format: `console`, `json`, `sarif`, `markdown` |
| `--fail-on <SEVERITY>` | `high` | Minimum severity that causes a non-zero exit |
| `--github-token <TOKEN>` | none | GitHub token for API calls. Also reads `GITHUB_TOKEN` env var |

### Examples

```bash
# Score the current project
warden score .

# JSON output for dashboards
warden score aquasecurity/trivy --format json

# Score a public repo
warden score cli/cli
```

---

## warden fix

Compute and apply automatic fixes for common workflow security issues
(unpinned actions, expression injection, missing permissions, ...).

```
warden fix <PATH> [OPTIONS]
```

`<PATH>` may be a local workflow file, a directory, or a GitHub `owner/repo`
slug.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | off | Apply the fixes by writing files (without `--apply`, runs in plan mode and prints changes only) |
| `--format <FORMAT>` | `console` | `console` prints colored output and writes files to disk (unless `--apply`); `json` emits structured output and never touches disk |
| `--github-token <TOKEN>` | none | GitHub token for API calls. Also reads `GITHUB_TOKEN` env var |
| `--pr <OWNER/REPO>` | none | Open a pull request with the computed fixes against `OWNER/REPO`. Requires a token with `contents:write` and `pull-requests:write` |
| `--branch <NAME>` | `warden/auto-fix-<unix-ts>` | Branch name to create for the PR |
| `--prepare-only` | off | Push the branch but do not call the GitHub API to create the PR; instead, print a compare URL |

### Examples

```bash
# Show fixable issues without writing
warden fix .              # plan only (default)
warden fix . --apply      # actually write changes

# Apply fixes in place
warden fix .github/workflows/ci.yml

# Compute fixes for a remote repo and emit JSON (no disk writes)
warden fix cli/cli --format json

# Open a pull request with the computed fixes
GITHUB_TOKEN=ghp_... warden fix . --pr myorg/myrepo

# Push the branch but do not open the PR; print a compare URL instead
warden fix . --pr myorg/myrepo --prepare-only
```

---

## warden upstream

Resolve a project's direct (and optionally depth-2) dependencies back to their
source repositories on GitHub, then run warden's full rule set against each
one's workflows.

```
warden upstream [PATH] [OPTIONS]
```

`PATH` defaults to `.`. Manifest discovery is non-recursive (project root
only) and currently understands `package.json`, `requirements.txt`,
`Pipfile.lock`, `go.mod`, and `Cargo.toml`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--concurrency <N>` | `8` | Number of dep repos to scan in parallel |
| `--format <FORMAT>` | `console` | Output format: `console`, `json`, `sarif`, `markdown` |
| `--fail-on <SEVERITY>` | `high` | Minimum severity that causes a non-zero exit |
| `--depth <N>` | `1` | Dependency walk depth (`1` = direct deps only, `2` = also deps-of-deps) |
| `--github-token <TOKEN>` | none | GitHub token for API calls. Also reads `GITHUB_TOKEN` env var |

### Examples

```bash
# Audit the current project's direct dependencies
warden upstream .

# Scan upstream + deps-of-deps
warden upstream . --depth 2

# Crank concurrency for a fast scan with a token
GITHUB_TOKEN=ghp_... warden upstream . --concurrency 16

# JSON output for the dashboard
warden upstream . --format json
```

---

## warden rules

List all detection rules grouped by severity.

```
warden rules
```

This subcommand takes no flags. It prints every registered rule's `ID`,
`SEVERITY`, and `NAME`, sorted by ID.

### Example

```bash
warden rules
```

---

## Configuration File (.warden.toml)

Warden walks from the scan target up to the filesystem root looking for a
`.warden.toml`. If found, it loads two fields:

```toml
# Suppress specific rules
disabled_rules = ["WRD-710", "WRD-826"]

# Override severities
[severity_overrides]
"WRD-322" = "low"
```

`disabled_rules` removes those rule IDs from the scan entirely.
`severity_overrides` lets you reclassify a rule's findings before the
`--fail-on` threshold is applied. Severity values must be one of `critical`,
`high`, `medium`, or `low`.

There are no `[scan]`, `[ignore]`, `[ignore.file]`, `[severity]`, or `[score]`
tables; warden v1.0 does not support per-file suppression, category filters,
or score thresholds in the config file.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub token for API calls (equivalent to `--github-token` on every subcommand) |

Warden v1.0 does not read any other env vars.
