# Trigger Rules (200s)

Dangerous trigger configurations expose workflows to attacks from untrusted contributors. The `pull_request_target` event is particularly hazardous because it runs in the context of the base repository with full access to secrets, even when triggered by a fork.

---

## WRD-201: Dangerous Fork Checkout

**Severity:** Critical

**What it detects:** A workflow triggered by `pull_request_target` that checks out the pull request's head code (via `ref: ${{ github.event.pull_request.head.sha }}` or `github.head_ref`), combining privileged execution context with attacker-controlled code.

**Vulnerable:**

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
```

This pattern is known as a "pwn request." An attacker submits a PR that modifies `npm test` or `package.json` scripts and gains code execution with the base repository's secrets.

**Remediation:** Use `pull_request` instead of `pull_request_target`, or avoid checking out untrusted code. If checkout is necessary, do not run any build/test commands on the checked-out code.

```yaml
# Unprivileged workflow: runs fork code, no secrets
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - run: npm install && npm test
```

---

## WRD-202: Build Tool Execution on Untrusted Code

**Severity:** Critical

**What it detects:** A `pull_request_target` workflow that checks out the PR head and then executes build tools (npm, pip, cargo, make, yarn, gradle, mvn, go, poetry, etc.) on the untrusted code. This is a more specific variant of WRD-201 that looks for actual build commands.

**Vulnerable:**

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: npm install && npm test
```

An attacker can modify build scripts, `package.json` lifecycle hooks, or `Makefile` targets in their fork to execute arbitrary code with elevated privileges.

**Remediation:** Split into two workflows. Run build tools only in unprivileged `pull_request` workflows. Use `workflow_run` for privileged operations that do not run fork code.

---

## WRD-203: Cross-Workflow Privilege Escalation

**Severity:** Critical

**What it detects:** A `workflow_run`-triggered workflow with write permissions or that downloads artifacts. If the producing workflow is triggered by `pull_request`, an attacker can poison artifacts in a fork PR to escalate privileges.

**Vulnerable:**

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

permissions:
  contents: write

jobs:
  publish:
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - run: ./deploy.sh $(cat artifact/target.txt)
```

**Remediation:** Minimize permissions on `workflow_run` workflows. Validate artifact integrity before use. Check `github.event.workflow_run.conclusion` and fork status before processing.

```yaml
jobs:
  publish:
    if: github.event.workflow_run.conclusion == 'success'
    steps:
      - name: Check workflow origin
        run: |
          if [[ "${{ github.event.workflow_run.head_repository.fork }}" == "true" ]]; then
            echo "Refusing artifact from fork" && exit 1
          fi
```
