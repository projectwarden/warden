# Logic Rules (800s)

Logic rules catch workflow design flaws, insecure conditionals, permission misuse, and configuration mistakes that do not fall into the other categories.

---

## WRD-801: Self-Hosted Runner on PR

**Severity:** Critical

**What it detects:** `pull_request` or `pull_request_target` triggers combined with `runs-on: self-hosted`. Pull requests from forks can execute arbitrary code on self-hosted runners. Unlike GitHub-hosted runners, self-hosted runners are not ephemeral and may retain credentials, access internal networks, or persist malware between runs.

**Vulnerable:**

```yaml
on: pull_request

jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - run: make build
```

**Remediation:** Use GitHub-hosted runners for PR workflows, or restrict self-hosted runner access using runner groups with repository policies.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
```

---

## WRD-810: Confused Deputy

**Severity:** High

**What it detects:** Auto-merge or auto-approve patterns (`gh pr merge --auto`, `gh pr review --approve`) without proper authorization checks (actor verification, team membership, or permission validation). An attacker who can trigger the workflow could get unauthorized changes merged.

**Vulnerable:**

```yaml
- run: gh pr merge --auto --squash "$PR_URL"
```

**Remediation:** Add authorization checks (actor verification, team membership, or permission validation) before auto-merging or auto-approving.

---

## WRD-811: Artifact Injection

**Severity:** High

**What it detects:** `workflow_run` triggers that download artifacts using `actions/download-artifact` without checking `conclusion == 'success'` on the triggering workflow. Artifacts from failed or malicious runs may be processed.

**Vulnerable:**

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - run: ./deploy.sh
```

**Remediation:** Add a condition to check the triggering workflow's conclusion before downloading and using artifacts.

```yaml
jobs:
  deploy:
    if: github.event.workflow_run.conclusion == 'success'
```

---

## WRD-812: Risky Trigger Default Permissions

**Severity:** High

**What it detects:** A workflow uses one of the risky triggers (`pull_request_target`, `workflow_run`, `issue_comment`, `discussion_comment`) but has no top-level `permissions:` block. With no explicit permissions, the workflow inherits the repository default `GITHUB_TOKEN` scopes, which on many older repos is `write-all`. Combined with an attacker-controlled trigger, that gives a forked PR or third-party comment effectively write access to the repo.

The rule checks the parsed YAML for an `on:` key matching any of the risky triggers (string, list, or mapping forms) and a top-level `permissions:` key. If a risky trigger is present and `permissions:` is missing, it emits a finding at line 1 of the workflow.

**Vulnerable:**

```yaml
on: pull_request_target   # WRD-812: no top-level permissions block

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - run: ./scripts/triage.sh
```

**Remediation:** Add an explicit minimal `permissions:` block at the top of the workflow. `permissions: read-all` is the safest baseline for risky triggers; grant individual write scopes only on the specific jobs that need them.

```yaml
on: pull_request_target

permissions: read-all   # explicit baseline; jobs can opt into writes individually

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - run: ./scripts/triage.sh
```

---

## WRD-820: Unsound Condition

**Severity:** Medium

**What it detects:** Conditions that are always true: `if: true`, `if: always()`, or self-comparisons. These make the condition a no-op guard.

**Vulnerable:**

```yaml
- if: always()
  run: ./security-scan.sh
```

**Remediation:** Replace with a meaningful condition, or remove the `if:` block if the step should always run.

---

## WRD-821: Bypassable Contains Check

**Severity:** Medium

**What it detects:** `contains()` checks on user-controlled input (`github.event.issue.title`, `github.event.pull_request.body`, `github.head_ref`, `github.actor`, etc.) used as authorization gates. An attacker can include the expected substring in their input to bypass the check.

**Vulnerable:**

```yaml
- if: contains(github.event.comment.body, '/deploy')
  run: ./deploy.sh
```

**Remediation:** Use proper authorization mechanisms instead of string matching on user-controlled input. Consider team membership, CODEOWNERS, or GitHub's built-in permissions.

---

## WRD-822: Secret Redaction Bypass

**Severity:** Medium

**What it detects:** Patterns that bypass GitHub Actions secret redaction in logs: base64-encoding secrets, manipulating secrets with text tools (`sed`, `tr`, `cut`, `fold`, `rev`), or writing secrets to files then reading them back. The transformed output is not masked by GitHub Actions.

**Vulnerable:**

```yaml
- run: echo "${{ secrets.API_KEY }}" | base64
```

**Remediation:** Avoid encoding or transforming secrets in ways that bypass redaction. Pass secrets directly to the tools that need them. Never echo or log transformed secret values.

---

## WRD-823: Cache Poisoning

**Severity:** Medium

**What it detects:** `actions/cache` usage in release or elevated-permission workflows (those with `write-all`, `contents: write`, `packages: write`, or `id-token: write`). An attacker who poisons the cache via a PR build can inject malicious artifacts into the release pipeline.

**Vulnerable:**

```yaml
on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  release:
    steps:
      - uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7  # v5.0.4
        with:
          key: deps-${{ hashFiles('**/package-lock.json') }}
      - run: npm ci && npm run build
```

**Remediation:** Use separate cache keys for PR and release workflows. Avoid restoring caches from untrusted branches in release builds. Consider using immutable artifacts instead of mutable caches.

---

## WRD-824: Excessive Permissions

**Severity:** Medium

**What it detects:** `permissions: write-all` grants, missing top-level `permissions:` blocks (which inherit potentially broad defaults), and unnecessary write permission entries at the job level.

**Vulnerable:**

```yaml
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

**Remediation:** Add an explicit `permissions:` block. Grant only the specific scopes needed. Use `permissions: {}` for read-only or no-token workflows.

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

---

## WRD-825: Spoofable Bot Check

**Severity:** Medium

**What it detects:** `if:` conditions checking `github.actor` against bot names like `dependabot[bot]`, `renovate[bot]`, or `github-actions[bot]`. GitHub usernames can be changed to match bot names, so an attacker could rename their account to trigger the condition.

**Vulnerable:**

```yaml
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    steps:
      - run: gh pr merge --auto
```

**Remediation:** Use `github.event.sender.type == 'Bot'` or verify the app installation ID instead of checking the actor name.

---

## WRD-826: Undocumented Permissions

**Severity:** Medium

**What it detects:** Permission entries (e.g., `contents: write`, `packages: write`) that lack an explanatory comment. Documenting permissions makes security reviews easier and helps future maintainers understand the intent behind each grant.

**Vulnerable:**

```yaml
permissions:
  contents: write
  packages: write
  id-token: write
```

**Remediation:** Add a comment on the same line or the line above explaining why each permission is needed.

```yaml
permissions:
  contents: write   # Required to push release tags
  packages: write   # Required to push Docker images
  id-token: write   # Required for OIDC authentication to AWS
```

---

## WRD-827: Superfluous Actions

**Severity:** Medium

**What it detects:** Setup actions (e.g., `actions/setup-node`, `actions/setup-python`, `actions/setup-go`) used without specifying a version input. These tools are pre-installed on GitHub-hosted runners, so the setup action adds overhead without benefit if the default version is sufficient.

**Vulnerable:**

```yaml
- uses: actions/setup-node@53b83947a5a98c8d113130e565377fae1a50d02f  # v6.3.0
- run: node --version
```

**Remediation:** If you need a specific version, add a version input (e.g., `node-version: '20'`). Otherwise, consider removing the setup action and using the pre-installed version.

```yaml
- uses: actions/setup-node@53b83947a5a98c8d113130e565377fae1a50d02f  # v6.3.0
  with:
    node-version: '20'
```

---

## WRD-828: Obfuscation in Workflow

**Severity:** Medium

**What it detects:** Base64 decode operations (`base64 -d`, `atob`, `Buffer.from(..., 'base64')`) appearing in non-`run:` contexts (env blocks, `with:` inputs). This is unusual and may indicate an attempt to obfuscate malicious content.

**Vulnerable:**

```yaml
env:
  PAYLOAD: $(echo "bWFsaWNpb3Vz" | base64 -d)
```

**Remediation:** If base64 encoding is necessary for legitimate data (certificates, binary config), move the decode into a `run:` block with clear documentation explaining its purpose.

---

## WRD-833: Anonymous Workflow Definition

**Severity:** Low

**What it detects:** Two patterns:

1. Actions pinned to branch names like `@main` or `@master` instead of a commit SHA or version tag. Branch tips change with every commit, making builds non-reproducible.
2. Workflow files missing a top-level `name:` key. Without a name, the workflow appears as the filename in the GitHub Actions UI.

**Vulnerable:**

```yaml
# Missing name:
on: push
jobs:
  build:
    steps:
      - uses: some-org/action@main
```

**Remediation:** Pin actions to full commit SHAs. Add a descriptive `name:` key at the top of workflow files.

```yaml
name: CI Build

on: push
jobs:
  build:
    steps:
      - uses: some-org/action@a1b2c3d4e5f6...  # v1.2.0
```

---

## WRD-831: Missing Concurrency Limits

**Severity:** Low

**What it detects:** Workflows triggered by `push` or `pull_request` that do not define a `concurrency:` block. Without concurrency limits, rapid pushes can queue many redundant runs, wasting runner resources.

**Vulnerable:**

```yaml
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

**Remediation:** Add a concurrency block to cancel in-progress runs on the same branch.

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```
