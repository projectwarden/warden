# warden

GitHub Actions security scanner. 59 detection rules across 8 attack classes (injection, triggers, supply chain, permissions, AI security, steganography, integrity, logic). Single static binary, zero runtime dependencies, auto-fix engine, JSON / SARIF / Markdown output.

**v2.0.0**: rebuilt on a typed, span-aware analyzer foundation with cross-step taint propagation (`StepOutputProvenance`), tree-sitter shell parsing, a real `${{ ... }}` expression parser, inline `# warden: ignore[WRD-XXX]` directives, and recalibrated rule severities. See [CHANGELOG.md](CHANGELOG.md).

## Install

```sh
cargo install wardenscan
```

Or grab a binary from [releases](https://github.com/projectwarden/warden/releases),
or use the Docker image at `ghcr.io/projectwarden/warden:latest`.

## Quick start

```sh
# Scan the current project's .github/workflows/
warden scan .

# Scan a public GitHub repo
warden scan cli/cli

# Get a 0-100 security score
warden score .

# JSON output (for tooling)
warden scan . --format json

# SARIF for GitHub Code Scanning
warden scan . --format sarif > results.sarif

# Fail CI on high+ findings
warden scan . --fail-on high

# List all 53 detection rules
warden rules
```

Bare `./warden` (no args) launches an interactive guided menu in a TTY.

## GitHub Action

Drop warden into any workflow:

```yaml
- uses: projectwarden/warden@e4f665f5171ef446d79cc5c268af6606d78aaf04  # v2.0.0
  with:
    path: '.'
    fail-on: high        # critical | high | medium | low | none
    format: markdown     # console | json | sarif | markdown
```

Don't write the workflow file by hand. Use `warden add-action` to generate a properly-pinned, properly-permissioned `.github/workflows/warden.yml` for you:

```sh
warden add-action --print              # print to stdout
warden add-action                      # write to current repo
warden add-action --pr myorg/myrepo --apply   # open a PR (returns a compare URL)
```

The generated workflow scans clean against warden's own ruleset (verified by an integration test on every build).

### Post a PR comment with findings

See `examples/workflow-with-warden.yml` for a complete workflow that runs
warden on every PR and posts a collapsible markdown summary as a comment:

```yaml
- name: Run warden
  run: |
    docker run --rm -v "$PWD":/src -w /src ghcr.io/projectwarden/warden:latest \
      scan . --format markdown --fail-on none > warden-report.md || true

- uses: peter-evans/create-or-update-comment@e8674b075228eee787fea43ef493e45ece1004c9  # v5.0.0
  if: github.event_name == 'pull_request'
  with:
    issue-number: ${{ github.event.pull_request.number }}
    body-path: warden-report.md
    edit-mode: replace
```

## Auto-fix (plan / apply)

`warden fix` runs in **plan mode by default**: it prints exactly what
would change without touching any file. This is the same model as
`terraform plan` / `terraform apply`: the safe thing is the default, and
writes require explicit opt-in.

```sh
# Plan: print fixable issues, no writes
warden fix .

# Apply: actually rewrite files in place
warden fix . --apply

# Plan a PR: resolve fixes but do not push or open anything
warden fix . --pr owner/repo

# Apply a PR: push a branch and return a compare URL (click `Create pull request`)
GITHUB_TOKEN=ghp_... warden fix . --pr owner/repo --apply --prepare-only

# Apply a PR: push branch AND open the PR for you
GITHUB_TOKEN=ghp_... warden fix . --pr owner/repo --apply
```

The auto-fixer covers SHA pinning of `uses:` refs, `${{ expression }}` to
`env:` rewriting (neutralizes script injection), `persist-credentials: false`
on `actions/checkout`, top-level `permissions:` insertion, and `concurrency:`
block insertion.

## Configuration (`.warden.toml`)

Drop a `.warden.toml` at your repo root to tune warden per-project:

```toml
# Disable specific rules entirely.
disabled_rules = ["WRD-710", "WRD-826"]

# Override the severity reported for a given rule.
[severity_overrides]
"WRD-322" = "low"
```

Warden walks upward from the scan target looking for `.warden.toml`; the
first one found wins. See `docs/src/configuration.md` for details.

## Scanning upstream dependencies

`warden upstream` walks your project's dependency manifests
(`package.json`, `requirements.txt`, `Pipfile.lock`, `go.mod`, `Cargo.toml`),
resolves each direct dependency back to its source repository on GitHub, and
runs warden's full 53-rule detector against the workflow files in each of
those upstream repos. This surfaces CI/CD vulnerabilities in your supply
chain, not just in your own workflows.

```sh
# Audit direct dependencies
warden upstream .

# Also look one level deeper (deps-of-deps)
warden upstream . --depth 2

# Parallelize and output JSON
warden upstream . --concurrency 8 --format json > audit.json
```

Set `GITHUB_TOKEN` (or `--github-token`) before running; the unauthenticated
GitHub API quota is 60 req/hr, you will hit it on a real project.

## Docker

```sh
docker run --rm -v "$PWD":/repo ghcr.io/projectwarden/warden scan /repo
```

## Architecture

warden is a single-binary Rust crate (`wardenscan`), with a bin target at `src/main.rs` and a library surface at `src/lib.rs`. The pieces worth knowing:

- `src/scanner/` loads `.github/workflows/*.yml` off disk (or off GitHub via `warden scan owner/repo`) and parses each file into a `LoadedWorkflow` carrying byte-exact span information.
- `src/rules/` holds one source file per detection (`wrd101.rs`, `wrd110.rs`, ...). Each file defines a struct that implements the `Rule` trait declared in `src/rules/api.rs`.
- `src/rules/api.rs` defines `AuditCtx`, the per-workflow context handed to every rule. It bundles the parsed workflow, a pre-built `ExprIndex` of `${{ ... }}` expressions, tree-sitter shell ASTs, an inline-ignore map, and the cross-step taint `StepOutputProvenance`.
- `all_rules()` in `src/rules/api.rs` is the registry; the `tests/rule_meta_test.rs` suite asserts that every `src/rules/wrdNNN.rs` maps one-to-one to a registered rule with a matching `meta.id`.
- `src/output/` lowers each `RuleFinding` to the plain `Finding` consumed by the console, JSON, SARIF, and Markdown formatters.

Data flow: workflow YAML goes through `scanner::load_local` into a `LoadedWorkflow`, which is wrapped in an `AuditCtx` and handed to every rule returned by `all_rules()`; each rule yields `RuleFinding`s with byte-exact `Span`s, which are lowered via `RuleFinding::into_legacy` and serialized by one of the formatters in `src/output/` (JSON, SARIF, Markdown, or the default console renderer).

The full rule catalog lives under [`docs/src/rules/`](docs/src/rules/), organized by attack class (`injection.md`, `triggers.md`, `supply-chain.md`, `permissions.md`, `ai-security.md`, `steganography.md`, `integrity.md`, `logic.md`).

## License

MIT
