# SARIF Output

Warden supports outputting findings in SARIF (Static Analysis Results Interchange Format) 2.1.0. SARIF integrates with GitHub Code Scanning to show security alerts in the Security tab and inline on pull request diffs.

## Generating SARIF

### CLI

```bash
warden scan /path/to/repo --format sarif -o results.sarif
```

Or write to stdout and redirect:

```bash
warden scan /path/to/repo --format sarif > results.sarif
```

### Docker

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/projectwarden/warden:latest \
  scan /repo --format sarif -o /repo/results.sarif
```

### GitHub Action

```yaml
- uses: projectwarden/warden@e4f665f5171ef446d79cc5c268af6606d78aaf04  # v2.0.0
  with:
    format: sarif
    output-file: results.sarif
```

## Uploading to GitHub Code Scanning

Use the `github/codeql-action/upload-sarif` action to upload results. The `security-events: write` permission is required.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2

      - name: Run warden
        run: warden scan . --format sarif -o results.sarif

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@c10b8064de6f491fea524254123dbe5e09572f13  # v4.35.1
        if: always()
        with:
          sarif_file: results.sarif
          category: warden
```

The `if: always()` condition ensures results are uploaded even if warden exits non-zero (due to findings). Without it, findings would prevent the upload.

## Viewing Results

After upload, results appear in three places:

1. **Security tab**: `github.com/<org>/<repo>/security/code-scanning` shows all open alerts with rule details and remediation guidance.

2. **Pull request checks**: Alerts introduced by a PR are shown as inline annotations on the diff, with the rule name and description.

3. **API**: Query programmatically via `GET /repos/{owner}/{repo}/code-scanning/alerts`.

## Dismissing Alerts

Alerts can be dismissed in the GitHub UI with a reason (false positive, won't fix, used in tests). Dismissals are tracked in the audit log. Dismissed alerts are not re-opened unless the same finding reappears in a new commit.

## SARIF Schema Details

Warden's SARIF output includes:

- `runs[].tool.driver.name`: `warden`
- `runs[].tool.driver.version`: current warden version
- `runs[].tool.driver.rules`: all 53 rule definitions with `id`, `name`, `shortDescription`, `fullDescription`, `helpUri`, and `properties.tags`
- `runs[].results[].ruleId`: e.g. `WRD-101`
- `runs[].results[].level`: `error` (critical/high), `warning` (medium), `note` (low)
- `runs[].results[].locations`: file path and line number
- `runs[].results[].message`: human-readable description with context

## Filtering by Severity in SARIF

SARIF `level` mapping:

| Warden severity | SARIF level |
|-----------------|-------------|
| Critical | `error` |
| High | `error` |
| Medium | `warning` |
| Low | `note` |

GitHub Code Scanning's default alert filter shows `error` and `warning`. Low (`note`) findings are visible but not shown by default.

## Multi-repo Scanning

To scan multiple repositories and aggregate results:

```bash
#!/bin/bash
for repo in org/repo1 org/repo2 org/repo3; do
  gh repo clone "$repo" "/tmp/$repo"
  warden scan "/tmp/$repo" --format sarif -o "/tmp/${repo//\//-}.sarif"
done
```

Upload each SARIF file to the corresponding repository using the GitHub API:

```bash
gh api repos/org/repo1/code-scanning/sarifs \
  -f sarif="$(base64 -w0 /tmp/org-repo1.sarif)" \
  -f ref="refs/heads/main" \
  -f commitSha="$(git -C /tmp/org/repo1 rev-parse HEAD)"
```

## Offline SARIF Viewers

To view SARIF results without uploading to GitHub:

- [SARIF Viewer VS Code extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- [SARIF Web Viewer](https://microsoft.github.io/sarif-web-component/)
- `jq` for quick inspection:

```bash
jq '.runs[0].results[] | {rule: .ruleId, file: .locations[0].physicalLocation.artifactLocation.uri, line: .locations[0].physicalLocation.region.startLine, message: .message.text}' results.sarif
```
