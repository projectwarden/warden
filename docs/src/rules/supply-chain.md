# Supply Chain Rules (300s)

Supply chain attacks target the actions and tools a workflow depends on. OIDC trust boundaries, known-vulnerable actions, mutable references, and unverified third-party code are the primary attack surfaces.

---

## WRD-301: OIDC Trust Boundary Violation

**Severity:** Critical

**What it detects:** `id-token: write` permission combined with external triggers (`pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion_comment`, `repository_dispatch`). An attacker who can trigger the workflow may obtain OIDC tokens to access cloud resources (AWS, GCP, Azure) configured to trust the repository.

**Vulnerable:**

```yaml
on: pull_request_target

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@ec61189d14ec14c8efccab744f656cffd0e33f37  # v6.1.0
```

**Remediation:** Restrict OIDC token permissions to workflows triggered only by trusted events (push, release). Add subject claim filters in your cloud provider's OIDC configuration.

---

## WRD-302: Known Vulnerable Action

**Severity:** Critical

**What it detects:** Usage of GitHub Actions with known security vulnerabilities, including compromised actions (tj-actions/changed-files pre-v45, reviewdog supply chain attack), deprecated actions with EOL runtimes (actions/upload-artifact@v1/v2, github/codeql-action@v2), and other known-bad versions.

**Vulnerable:**

```yaml
- uses: tj-actions/changed-files@v39
- uses: actions/upload-artifact@v2
- uses: github/codeql-action/analyze@v2
```

**Remediation:** Update to patched versions or pin to verified SHAs after the fix. Check action repositories for security advisories.

---

## WRD-310: Impostor Commit

**Severity:** High

**What it detects:** Actions pinned to commit SHAs that appear suspicious: truncated SHAs (not exactly 40 hex characters), all-zero SHAs, or placeholder patterns. Impostor commits can be pushed to a repository via its fork and may not belong to any branch or tag in the original repository.

**Vulnerable:**

```yaml
- uses: some-org/some-action@abcdef1
```

**Remediation:** Use the full 40-character commit SHA. Verify the commit exists on the default branch or a tagged release of the action repository.

---

## WRD-320: Unpinned Actions

**Severity:** Medium (promoted to High for third-party actions)

**What it detects:** Actions referenced by mutable tags (e.g., `@v1`, `@v2.3`) rather than a full-length commit SHA. Tag contents can change without notice. Third-party actions are promoted to high severity; GitHub-owned actions (`actions/*`, `github/*`) remain medium.

**Vulnerable:**

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
- uses: some-org/some-action@v2
```

**Remediation:** Pin every action to a specific commit SHA. Use a comment to document the version.

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
- uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v2.1.0
```

---

## WRD-321: Archived Action Reference

**Severity:** Medium

**What it detects:** References to GitHub Actions from known archived or deprecated repositories (e.g., `actions/create-release`, `actions-rs/toolchain`, `actions-rs/cargo`). Archived actions no longer receive security patches.

**Vulnerable:**

```yaml
- uses: actions-rs/toolchain@v1
```

**Remediation:** Replace with an actively maintained alternative. Check the repository README for migration guidance.

---

## WRD-322: Stale Action SHA Pin

**Severity:** Medium

**What it detects:** Actions pinned to a SHA without a version comment (e.g., `# v4.1.0`). Without a comment, it is difficult to tell which release the SHA corresponds to or whether the pin is outdated.

**Vulnerable:**

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

**Remediation:** Add a version comment after the SHA pin for auditability and easier Dependabot/Renovate reviews.

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
```

---

## WRD-323: Ref Version Mismatch

**Severity:** Medium

**What it detects:** Actions where the tag ref disagrees with the inline version comment. For example, `@v3 # v4` indicates a copy-paste error or partially completed version bump.

**Vulnerable:**

```yaml
- uses: actions/checkout@v3  # v4.0.0
```

**Remediation:** Update the comment to match the actual ref, or update the ref to match the intended version.

---

## WRD-324: Ref Confusion

**Severity:** Medium

**What it detects:** Actions pinned to branch names (`main`, `master`, `develop`, `dev`, `trunk`, `HEAD`) that are mutable and change with every commit. Builds using branch refs are non-reproducible and vulnerable to supply chain attacks.

**Vulnerable:**

```yaml
- uses: some-org/some-action@main
```

**Remediation:** Pin to a full commit SHA or version tag. Use Dependabot or Renovate to keep pins current.

---

## WRD-325: Runtime Binary Fetch

**Severity:** Medium

**What it detects:** Actions known to download external binaries at runtime (security scanners like Trivy, Snyk, Bearer, Semgrep, and language setup actions). Even if the action reference is SHA-pinned, the downloaded binary is not verified against the pin. A compromised upstream release can execute malicious code.

**Vulnerable:**

```yaml
- uses: aquasecurity/trivy-action@a1b2c3d4...
- uses: actions/setup-node@a1b2c3d4...
```

**Remediation:** Consider using container-based alternatives or verifying downloaded binaries against known checksums. For setup actions, specify a version input so the setup is intentional.

---

## WRD-326: Forbidden Action Uses

**Severity:** High (some entries are Medium, see below)

**What it detects:** Action references that match warden's hardcoded denylist of known-bad or end-of-life action versions. The denylist currently includes:

- `tj-actions/changed-files@v1` through `@v44` (supply-chain compromise) // high
- `reviewdog/action-setup@v1` (compromised range) // high
- `actions/checkout@v1` and `@v2` (EOL) // medium
- `dawidd6/action-download-artifact@v1` through `@v5` (pre-patch) // medium
- `aquasecurity/trivy-action@0.x` and `@master` (pre-fix) // medium

The line number reported by the finding always points at the matching `uses:` line in the workflow.

**Vulnerable:**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - uses: tj-actions/changed-files@v44                                 # WRD-326
      - uses: reviewdog/action-setup@v1                                    # WRD-326
      - uses: actions/checkout@v1                                          # WRD-326
```

**Remediation:** Pin to a known-good commit SHA after the fix, upgrade to a maintained successor (e.g. `actions/checkout@v4` or later for the EOL entries), or migrate to an alternative action. Re-running `warden scan` after the bump verifies the denylist match has cleared.

```yaml
- uses: tj-actions/changed-files@cbda684547adc8c052d50711417e5b03b5ea3247  # v46.0.5
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd          # v6.0.2
```

---

## WRD-327: Composite Action Internal Unpinned References

**Severity:** High

**What it detects:** A workflow references a composite or Docker action at a full 40-character commit SHA, but that upstream action's own `action.yml` at that commit contains `uses:` steps (or a `docker://` image) that are not themselves SHA-pinned. SHA-pinning the outer action does not protect against tag mutation in its internal dependencies, so a compromise of an inner `actions/checkout@v4` (or similar) silently propagates into every downstream consumer.

Warden fetches the `action.yml` for every SHA-pinned `uses:` in the workflow via the GitHub Contents API (`action.yml` first, then `action.yaml`), walks `runs.steps[*].uses` for composite actions or `runs.image` for Docker actions, and flags any reference whose ref is not a 40-char hex SHA (or, for Docker images, does not contain `@sha256:`). The scan caches results per `{owner}/{repo}@{sha}` and caps at 10 distinct outer actions per workflow so large monorepos do not hammer the GitHub API. Without a `GITHUB_TOKEN` the rule still runs but is bound by the 60 req/hr unauthenticated quota; network errors are silently skipped (set `WARDEN_DEBUG=1` to see them on stderr).

The line number reported by the finding always points at the **outer** `uses:` line in your workflow, since that is the only file you control.

**Vulnerable outer workflow (you):**

```yaml
# .github/workflows/ci.yml
- uses: myorg/myaction@4f86b85a2eac07a7d4ec52a29d1c3c9c3f5f5f5f  # looks correctly pinned
```

**Vulnerable upstream `myorg/myaction/action.yml` at that SHA:**

```yaml
name: myaction
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4       # unpinned, tag-mutable
    - uses: third-party/setup@main    # unpinned, branch-ref
```

**Remediation:** Either fork `myorg/myaction`, pin all of its internal actions to SHAs, and use your fork, or switch to an alternative action whose `action.yml` only references SHA-pinned dependencies. Upstream maintainers can address this by pinning all internal `uses:` references in their `action.yml`.
