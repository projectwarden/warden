# Integrity Rules (700s)

Integrity rules cover secret exposure, credential leakage, command safety, and Docker image pinning. These rules ensure that workflow configurations do not inadvertently compromise secrets or weaken the build pipeline.

---

## WRD-701: toJSON(secrets) Exposure

**Severity:** Critical

**What it detects:** `toJSON(secrets)` or `secrets.*` patterns that expose the entire secrets context. If this value reaches logs, artifacts, or outputs, all repository secrets are compromised.

**Vulnerable:**

```yaml
- run: echo '${{ toJSON(secrets) }}'
```

**Remediation:** Reference individual secrets by name (e.g., `secrets.MY_TOKEN`) instead of dumping the entire secrets context.

---

## WRD-712: Insecure Commands Allowed

**Severity:** High

**What it detects:** `ACTIONS_ALLOW_UNSECURE_COMMANDS` set to `true`, which re-enables the deprecated `set-env` and `add-path` workflow commands. These legacy commands are vulnerable to injection attacks via untrusted input.

**Vulnerable:**

```yaml
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
```

**Remediation:** Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS` and use `GITHUB_ENV` / `GITHUB_PATH` files instead of the legacy commands.

---

## WRD-714: Curl Pipe Bash

**Severity:** High

**What it detects:** `curl | bash`, `wget | sh`, and similar patterns that download and immediately execute remote scripts in `run:` blocks. A compromised server or MITM attack could inject malicious code.

**Vulnerable:**

```yaml
- run: curl https://get.example.com/install.sh | bash
```

**Remediation:** Download the script first, verify its checksum or signature, then execute.

```yaml
- run: |
    curl -Lo install.sh https://get.example.com/install.sh
    echo "expectedsha256sum  install.sh" | sha256sum -c
    bash install.sh
```

---

## WRD-721: Reusable Workflow Secrets Inherit

**Severity:** Medium

**What it detects:** `secrets: inherit` in reusable workflow calls, which passes every secret in the calling repository to the called workflow. If that workflow is external or broadly scoped, secrets may be exposed unnecessarily.

**Vulnerable:**

```yaml
jobs:
  build:
    uses: some-org/shared/.github/workflows/build.yml@main
    secrets: inherit
```

**Remediation:** Pass only the specific secrets the called workflow needs.

```yaml
jobs:
  build:
    uses: some-org/shared/.github/workflows/build.yml@main
    secrets:
      npm-token: ${{ secrets.NPM_TOKEN }}
```

---

## WRD-722: Hardcoded Container Credentials

**Severity:** Medium

**What it detects:** Hardcoded `username` or `password` values in container/services credentials blocks instead of secret references. This exposes credentials in the workflow file.

**Vulnerable:**

```yaml
jobs:
  test:
    services:
      db:
        image: postgres
        credentials:
          username: admin
          password: supersecret123
```

**Remediation:** Use secret references for credentials.

```yaml
credentials:
  username: ${{ secrets.REGISTRY_USERNAME }}
  password: ${{ secrets.REGISTRY_PASSWORD }}
```

---

## WRD-723: Unpinned Docker Image

**Severity:** Medium

**What it detects:** Container or services `image:` references that are not pinned to a specific `@sha256:` digest. Docker image tags are mutable and can be replaced with compromised versions.

**Vulnerable:**

```yaml
jobs:
  test:
    container:
      image: node:18
    services:
      redis:
        image: redis:7
```

**Remediation:** Pin images to a sha256 digest.

```yaml
container:
  image: node:18@sha256:a1b2c3d4e5f6...
```

---

## WRD-715: Debug Artifact Env Exposure

**Severity:** High

**What it detects:** `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG` set to true (at workflow, job, or step scope) together with `actions/upload-artifact` in the same job. Debug mode writes every env var in the runner process (including `GITHUB_TOKEN`) into the runner's debug dump; if the upload step inadvertently copies the runner temp directory, anyone with repo read can download the artifact and extract a live token. This is the CodeQLEAKED pattern ([CVE-2025-24362](https://github.com/github/codeql-action/security/advisories/GHSA-vqf5-2xx6-9wfm)).

**Vulnerable:**

```yaml
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make
      - uses: actions/upload-artifact@v4
        with:
          path: .
```

**Remediation:** Remove the `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG` env entry; GitHub's "Re-run with debug logging" checkbox gives you the same verbose logs without writing them into an artifact. If you genuinely need the debug output to be uploaded, narrow the upload path to exclude `$RUNNER_TEMP` and rotate any `GITHUB_TOKEN` that could have been exposed.

---

## WRD-730: Persisted Credentials Uploaded

**Severity:** Low

**What it detects:** `actions/checkout` without `persist-credentials: false` in workflows that also upload artifacts. When `persist-credentials` is true (the default), the GITHUB_TOKEN is stored in `.git/config`. If the `.git` directory is included in an uploaded artifact, the token can be extracted.

**Vulnerable:**

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
  # persist-credentials defaults to true
- run: make build
- uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f  # v7.0.0
  with:
    name: build-output
    path: .
```

**Remediation:** Add `persist-credentials: false` to the checkout step, or ensure the `.git` directory is excluded from uploaded artifacts.

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
  with:
    persist-credentials: false
```
