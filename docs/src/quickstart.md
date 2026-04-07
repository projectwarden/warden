# Quick Start

Three commands cover the core workflow.

## 1. Scan a repository

```bash
warden scan /path/to/repo
```

Warden walks `.github/workflows/` and reports findings to stdout in text format. Exit code is non-zero when any finding meets or exceeds the configured threshold.

```
WRD-101 [CRITICAL] script-injection: Unsanitized github.event.pull_request.title in run step
  File: .github/workflows/ci.yml
  Line: 42
  Step: Build and test
```

Scan only a specific workflow file:

```bash
warden scan .github/workflows/ci.yml
```

Output as SARIF (for GitHub Code Scanning upload):

```bash
warden scan /path/to/repo --format sarif -o results.sarif
```

## 2. Score a repository

```bash
warden score /path/to/repo
```

Produces an aggregate security score (0-100) based on finding severity and count. Useful for tracking improvement over time or enforcing a minimum score in CI.

```
Security Score: 74/100
  Critical: 0
  High:     2
  Medium:   5
  Low:      3
```

Set a failing threshold:

```bash
warden score /path/to/repo --min-score 80
```

## 3. List rules

```bash
warden rules
```

Lists all 53 detection rules with ID, severity, name, and a one-line description.

```
WRD-101  CRITICAL  script-injection                  Untrusted input interpolated into run step
WRD-110  HIGH      composite-input-injection         Composite action input interpolated in run step
...
```

Filter by category:

```bash
warden rules --category injection
```

Filter by severity:

```bash
warden rules --severity critical
```

## Next Steps

- Browse the [Rules Reference](./rules/index.md) for full rule documentation
- Set up the [GitHub Action](./guides/github-action.md) for continuous scanning
- Integrate [SARIF output](./guides/sarif.md) with GitHub Code Scanning
- See all flags in the [CLI Reference](./reference/cli.md)
