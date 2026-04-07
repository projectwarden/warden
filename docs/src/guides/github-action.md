# GitHub Action

The warden GitHub Action runs workflow security scanning as part of your CI pipeline. It scans all workflows in the repository and optionally fails the build based on finding severity.

## Basic Usage

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  warden:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - uses: projectwarden/warden@v1
        with:
          path: .github/workflows
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | No | `.` | Path to scan. May be a directory or a single workflow file |
| `fail-on` | No | `high` | Minimum severity that causes a non-zero exit: `critical`, `high`, `medium`, `low`, `none` |
| `format` | No | `console` | Output format: `console`, `json`, `sarif`, `markdown` |

## Outputs

| Output | Description |
|--------|-------------|
| `results-json` | JSON findings payload for downstream steps. Populate by running warden with `format: json` and capturing stdout into `$GITHUB_OUTPUT` (see example below) |

## Failing on Severity

Set `fail-on` to control which severity level causes the action to exit non-zero:

```yaml
- uses: projectwarden/warden@v1
  with:
    fail-on: critical   # only fail on critical findings
```

```yaml
- uses: projectwarden/warden@v1
  with:
    fail-on: medium     # fail on medium, high, and critical
```

```yaml
- uses: projectwarden/warden@v1
  with:
    fail-on: none       # never fail (reporting only)
```

## SARIF Upload

To upload results to GitHub Code Scanning, run warden a second time with
`format: sarif` and capture its stdout into a file the upload-sarif action
can read:

```yaml
- uses: projectwarden/warden@v1
  with:
    fail-on: none   # let Code Scanning handle enforcement

- name: Re-run warden as SARIF
  run: |
    warden scan . --format sarif > warden.sarif

- uses: github/codeql-action/upload-sarif@c10b8064de6f491fea524254123dbe5e09572f13  # v4.35.1
  if: always()
  with:
    sarif_file: warden.sarif
```

See the [SARIF guide](./sarif.md) for full details.

## Using with Pull Request Annotations

When running on a pull request, warden annotations appear inline on the diff:

```yaml
name: Workflow Security

on:
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write  # required for annotations
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - uses: projectwarden/warden@v1
        with:
          fail-on: high
```

## Configuration File

Place a `.warden.toml` in the repository root (or any parent of the scan
target) to suppress rules or override severities. The config has just two
fields:

```toml
# Suppress specific rules
disabled_rules = ["WRD-710", "WRD-826"]

# Override severities
[severity_overrides]
"WRD-322" = "low"
```

`disabled_rules` removes those rule IDs from the scan. `severity_overrides`
reclassifies a rule's findings before the `fail-on` threshold is applied.
Severity values must be one of `critical`, `high`, `medium`, or `low`.

## Pinning the Action

Always pin the warden action to a specific commit SHA:

```yaml
- uses: projectwarden/warden@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v1.2.0
```

Do not use `@main` or `@v1` (mutable tags). See [WRD-320](../rules/supply-chain.md#wrd-320-unpinned-actions).

## Example: Full Security Gate Workflow

The action's only output is `results-json`, which holds the JSON findings
payload for downstream steps. The example below runs warden once for the
gate (console output, fail on high) and then re-runs warden in `json` and
`sarif` formats so we can both upload SARIF to Code Scanning and parse
findings via `actions/github-script`.

```yaml
name: Workflow Security Gate

on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: "0 8 * * 1"  # weekly Monday scan

jobs:
  scan:
    name: Scan workflows
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # for SARIF upload

    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2

      - name: Run warden (gate)
        uses: projectwarden/warden@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v1.2.0
        with:
          path: .
          fail-on: high

      - name: Re-run warden as SARIF
        if: always()
        run: warden scan . --format sarif > results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@c10b8064de6f491fea524254123dbe5e09572f13  # v4.35.1
        with:
          sarif_file: results.sarif

      - name: Re-run warden as JSON for downstream consumption
        if: always()
        id: warden_json
        run: |
          warden scan . --format json --fail-on none > findings.json
          {
            echo 'findings<<__WARDEN_EOF__'
            cat findings.json
            echo
            echo '__WARDEN_EOF__'
          } >> "$GITHUB_OUTPUT"

      - name: Summarize findings
        if: always()
        uses: actions/github-script@v7
        env:
          FINDINGS_JSON: ${{ steps.warden_json.outputs.findings }}
        with:
          script: |
            const data = JSON.parse(process.env.FINDINGS_JSON || '{}');
            const findings = data.findings || [];
            core.summary
              .addHeading('Warden findings')
              .addRaw(`Total: ${findings.length}`)
              .write();
```
