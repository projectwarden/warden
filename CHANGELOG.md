# Changelog

All notable changes to warden are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.0.0, 2026-05-11

Second major release. Fewer false positives on step-output reads, inline `# warden: ignore[WRD-XXX]` directives, an auto-fixer that now matches the scanner 1:1 on every rule, and a brutal severity recalibration so a HIGH finding is genuinely worth paging on. These are possible because the analyzer has been rebuilt on a typed, span-aware foundation that rivals zizmor architecturally while keeping warden's product wins (auto-fixer, upstream scanning, guided CLI, `add-action` bootstrap, AI-assistant rule coverage).

**Upgrading from v1?** See [MIGRATING.md](MIGRATING.md). TL;DR: no config changes needed. Every v1 rule ID (`.warden.toml`, `# warden: ignore[WRD-XXX]`) is aliased to its v2 successor at load time, so existing configs and inline suppressions keep working without edits.

```sh
# GitHub Action: bump the pin (SHA follow-up commit recommended)
- uses: projectwarden/warden@a3c26c3f1897ddbe5c34cc3ce9ff4f14f84c83a8  # v2.0.0

# Docker
docker pull ghcr.io/projectwarden/warden:2

# Cargo
cargo install wardenscan --force
```

If a v2 scan newly flags a workflow that v1 passed, see the "If my workflow fails v2 but passed v1" section at the bottom of MIGRATING.md before filing a bug.

### Added, major architecture

- **Typed workflow model** (`src/models.rs`). Workflows deserialize into strongly typed structs (`Workflow`, `Job::Normal(NormalJob)`, `Job::Reusable(ReusableCallJob)`, `Step::Run(RunStep)`, `Step::Use(UseStep)`, `Permissions`, `On`, ...) via `serde_yaml`. Rules walk typed data instead of grepping raw strings, so they can reason about structure (is this a run step with a matching id? does this reusable-workflow call pass a tainted input?).
- **Byte-exact span tracking** (`src/spans.rs`). Workflows are parsed a second time through `saphyr` / `saphyr-parser` to build a `SpanIndex` mapping every YAML node to its byte range in the original file. Findings carry real `(line, column, byte_offset, length)` locations that the auto-fixer can use to rewrite exactly the offending bytes without regenerating the whole document (preserves comments, ordering, and formatting).
- **Real expression parser** (`src/expression/parser.rs`). Hand-rolled recursive-descent parser for `${{ ... }}` expressions: produces a proper AST (`Expr::Index`, `Expr::Call`, `Expr::BinOp`, `Expr::Literal`, ...), replaces the old regex-based extraction. Powers WRD-101, WRD-120, WRD-825, and WRD-827 with semantic matching instead of substring heuristics.
- **Shell AST analysis** (`src/shell/`, behind default-on `shell-analysis` cargo feature). `run:` blocks are parsed with `tree-sitter-bash`. `ShellIndex` tracks command-substitutions, pipelines, and variable references; rules consult it to distinguish `echo $VAR` from `eval $VAR`, and to trace which bash variables are written before a given read. Falls back gracefully to regex-based detection when the feature is disabled.
- **Cross-step taint propagation** (`src/taint/`). New `StepOutputProvenance` walks every `id:`'d `Step::Run`, finds writes to `$GITHUB_OUTPUT`, and classifies each `key=value` write as `Tainted` (`github.event.*`, `github.head_ref`, ...), `Safe` (one of 27 GitHub-validated runner env vars like `GITHUB_REF_NAME`, `GITHUB_SHA`), `Secret` (`${{ secrets.X }}`), `Literal`, or `Unknown` (command substitution, unsourced bash variables, heredocs). Downstream `${{ steps.X.outputs.Y }}` reads in subsequent `run:` blocks are rated against the upstream source. This is a capability zizmor and poutine do not have: both issue blanket warnings on any step-output read, so a `docker tag foo:${{ steps.meta.outputs.sha }}` that only ever holds `$GITHUB_SHA` is a false positive on those tools; on warden it suppresses cleanly. Exercised end-to-end by `tests/wrd120_taint_test.rs` (13 scenarios covering safe sources, tainted sources, unknown sources, heredocs, orphaned reads, and multi-output steps).
- **Inline ignore directives** (`src/ignores.rs`). `# warden: ignore[WRD-101]` above or on the end of a workflow line suppresses that rule at that location. Parser is quote-aware (ignores `#` inside single or double quoted scalars) so `run: echo "# not a comment"` is untouched. Supports both end-of-line form (applies to current line only) and standalone form (applies to the current line and the next code line if the directive is on its own).

### Added, other

- New `warden add-action` subcommand (formerly tracked as 1.x unreleased): generates a `.github/workflows/warden.yml` file that runs the warden GitHub Action against a repo's own workflows. Three modes: `--print` (stdout only, copy/paste manually), default (writes the file to a local repo, errors if it already exists), and `--pr OWNER/REPO --apply` (pushes a branch on the user's fork or upstream and returns a compare URL via `--prepare-only`, the safe default). The generated workflow is SHA-pinned to `actions/checkout@v6.0.2` and `projectwarden/warden@v2.0.0`, has an explicit least-privilege `permissions: contents: read` block, an explicit `concurrency:` block, `persist-credentials: false` on the checkout, and runs on `pull_request` and `push: main` (no risky triggers). An integration test in `tests/add_action_test.rs` re-scans the generated YAML through the full warden ruleset on every build and asserts zero findings.
- **WRD-526 GitHub App Token Misuse**. Flags `actions/create-github-app-token` (and the `tibdex/github-app-token` / `getsentry/action-github-app-token` forks) when the step's `with:` block either disables revocation (`skip-token-revoke: true`, High) or omits `repositories:` / `permissions:` (Medium each), any of which keeps the installation token valid longer or broader than the job actually needs. Matches zizmor's `github-app` audit and adds a per-finding severity split so the worst offender surfaces cleanly in scan summaries.
- **WRD-802 Runtime Self-Hosted Runner Registration** (Critical). Flags workflows that register or start a self-hosted runner from inside a `run:` block via `config.sh ... --token`, `./run.sh`, or `RUNNER_ALLOW_RUNASROOT=1`. Distinct from WRD-801 (which flags workflows that USE self-hosted runners on PR triggers), WRD-802 catches the persistence primitive the Shai-Hulud 2.0 npm worm used in November 2025 to compromise 25 000+ repositories. Literal runner-name IOC `SHA1HULUD` also flagged as a separate Critical when present in any `run:` block.
- **WRD-335 Unverified Action Creator** (Low). Flags `uses:` references whose owner is not on warden's curated allowlist of well-known-safe creators (GitHub-first-party, major cloud vendors, common language toolchains, vetted OSS security/ops tooling). Mirrors poutine's `github_action_from_unverified_creator_used` rule. One finding per unique creator per workflow; unverified does not mean malicious, but it is a signal worth cross-checking.
- **WRD-522 AI Agent Permission Bypass Flags** (Medium, High on externally-triggered workflows; renumbered from WRD-512). Detects `run:` blocks that invoke an AI coding-agent CLI (`claude`, `cursor-agent`, `gemini`, `codex`, `aider`, `continue`, `cline`) with a permission-bypass flag (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, `--full-auto`, `-y`, `--unsafe`, `--no-confirm`). This is the exact post-exploitation pivot used by the Nx `s1ngularity` npm attack in August 2025 to enumerate dev secrets from the victim's filesystem without prompting. No other GitHub Actions static analyzer currently detects this; pairs with WRD-510 (AI config poisoning) and WRD-511 (MCP config injection).
- **WRD-527 Registry Publish Without Trusted Publishing** (Medium). Complements WRD-525 (PyPI + npm) by flagging long-lived Cargo (`CARGO_REGISTRY_TOKEN`, `CRATES_IO_TOKEN`) and RubyGems (`GEM_HOST_API_KEY`, `RUBYGEMS_API_KEY`) tokens in workflows that publish to those registries. Both crates.io and RubyGems shipped OIDC-based trusted publishing in late 2025; stored tokens are now the legacy path. Also fires on `cargo publish` / `gem push` directly inside a `run:` block.
- **WRD-715 Debug Artifact Env Exposure** (High; renumbered from WRD-731). Flags `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG` set to true (workflow, job, or step scope) combined with `actions/upload-artifact` in the same job. Debug mode dumps every runner env var (GITHUB_TOKEN included) into the artifact, which anyone with repo read can download and mine. Covers the CodeQLEAKED class ([CVE-2025-24362](https://github.com/github/codeql-action/security/advisories/GHSA-vqf5-2xx6-9wfm)).
- Output grouping in console formatter: consecutive findings of the same `(rule, file, title, severity)` collapse into a single block with all locations listed beneath, so WRD-322 firing on 14 unpinned refs in one workflow prints once instead of 14 times.

### Changed, severity recalibration

- **WRD-130** (formerly WRD-120, step-output read) now consults `StepOutputProvenance` and downgrades to advisory when the upstream source is provably safe. Tainted upstream -> Critical (was: High). Safe upstream (GitHub-validated env var, pure literal, secret) -> suppressed. Unknown upstream or orphaned read -> Low advisory (was: High). The old behavior flagged every `${{ steps.X.outputs.Y }}` read uniformly; now warden's dogfood emits zero WRD-130 findings on the repo's own workflows because every step-output write is provably derived from `$GITHUB_SHA` or a literal.
- **WRD-440** (formerly WRD-420, secret reference inventory) demoted to `Info`. The rule is structural (any `${{ secrets.X }}` reference is detected) but does not imply the secret is actually leaked, so treating it as a high-signal finding created noise. Retained at `Info` for completeness.
- **WRD-840** (formerly WRD-826, undocumented permissions) demoted to `Info`. Similar rationale: the rule is hygiene, not vulnerability. Auto-fixer still adds per-entry documentation comments.
- **WRD-730** (formerly WRD-710, persisted credentials uploaded, renamed from "Artipacked") retiered and sinks broadened:
    - HIGH when there's a pre-v6 checkout AND one of four leaky sinks in the same workflow: `actions/upload-artifact`, `docker/build-push-action` (build context includes `.git/` by default), `softprops/action-gh-release` (uploads workspace tarballs to a public release), or `actions/cache` / `actions/cache/save`. This is the tj-actions / reviewdog / Artipacked class (Red Hat, Google, AWS affected).
    - MEDIUM when there's a pre-v6 checkout but no sink in the workflow today (latent; one added upload/release/docker step away from active). Previously LOW; bumped per the 2026 incident-history audit after repeated real-world disclosures.
    - LOW (hardening) when the checkout is v6+ (token lives in `$RUNNER_TEMP`, not `.git/config`).
    Warden's scanner now matches 1:1 with `fix_checkout_persist_credentials`: every place the fixer would touch is also a finding the scanner emits.

### Changed, rule numbering convention enforced

The "severity is encoded in the tens/units digit" convention from `docs/introduction.md` is now strictly applied. Twenty-one rules were renumbered, fifteen were renamed for clarity, and several were re-rated based on a brutal severity audit (attacker-capability + blast-radius + vuln-vs-structural). A centralized aliases module (`src/rules/aliases.rs`) maps every old ID to its canonical successor at config-load time AND at inline-ignore-directive parse time, so existing `.warden.toml` files and `# warden: ignore[WRD-XXX]` comments continue to work without changes.

**Renumbered (slot now matches severity)**

| Old ID | New ID | Notes |
|---|---|---|
| WRD-120 | WRD-130 | Step Output Read: stays Low; renamed to "Step Output Read (Unknown Provenance)" |
| WRD-320 | WRD-311 | Unpinned Third-Party Actions: stays High; renamed |
| WRD-321 | WRD-331 | Archived Action Reference: Medium to Low |
| WRD-322 | WRD-332 | SHA Pin Missing Version Comment: Medium to Low; renamed |
| WRD-323 | WRD-333 | Ref Version Mismatch: Medium to Low |
| WRD-326 | WRD-313 | Denylisted Action Reference: stays High; renamed |
| WRD-325 | WRD-345 | Runtime Binary Fetch: Medium to Info; renamed |
| WRD-327 | WRD-314 | Transitive Action Pin Bypass: stays High; renamed |
| WRD-420 | WRD-440 | Secret Reference Inventory: stays Info; renamed |
| WRD-520 | WRD-540 | Dependabot Daily Without Grouping: Medium to Info |
| WRD-601 | WRD-621 | Suspicious Invisible Unicode: Critical to Medium |
| WRD-710 | WRD-730 | Persisted Credentials Uploaded: stays Low; renamed from "Artipacked" |
| WRD-711 | WRD-721 | Reusable Workflow Secrets Inherit: High to Medium |
| WRD-713 | WRD-722 | Hardcoded Container Credentials: High to Medium; renamed |
| WRD-720 | WRD-723 | Unpinned Docker Image: stays Medium |
| WRD-820 | WRD-830 | Always-True If-Condition: stays Low; renamed |
| WRD-821 | WRD-816 | Bypassable Contains Authorization: Medium to High; renamed |
| WRD-822 | WRD-815 | Secret Redaction Bypass: Medium to High |
| WRD-826 | WRD-840 | Undocumented Permissions: stays Info |
| WRD-827 | WRD-841 | Superfluous Setup Action: Medium to Info; renamed |
| WRD-828 | WRD-817 | Base64 Payload in Workflow YAML: Medium to High; renamed |
| WRD-831 | WRD-842 | Missing Concurrency Limits: Low to Info |
| WRD-833 | WRD-843 | Missing Workflow Name: Low to Info; renamed |

**Renamed (no ID change, no severity change)**

WRD-112 GITHUB_ENV/PATH Write Sink, WRD-324 Branch-Ref Action Pin, WRD-421 Network Call Touches Secret, WRD-422 Step/Runner Debug Enabled, WRD-424 Secrets Used Without Environment Gate, WRD-521 Dependabot PR Untrusted Execution, WRD-525 Long-Lived Publish Token In Use, WRD-602 Workflow Embedded IOC, WRD-810 Auto-Merge Without Authorization, WRD-811 Artifact Download Without Conclusion Check, WRD-812 Risky Trigger Without Permissions Block, WRD-823 Cache Poisoning Risk, WRD-824 Excessive Permissions Or Missing Block, WRD-825 Spoofable Bot Identity Check.

### Changed, fixer parity

- `fix_expression_injection` now only rewrites `${{ github.event.* }}` paths that are on WRD-101's canonical `TAINTED_EXPRESSIONS` list (e.g. `github.event.pull_request.title`, `github.event.issue.body`, `github.head_ref`). The previous version blindly extracted any `${{ github.event.* }}` interpolation it found in a run block, including safe paths like `github.event.repository.name` that the scanner would not have flagged. The two now share `TAINTED_EXPRESSIONS` (lifted to `pub` in `wrd101.rs`) so they fire on the same set. `inputs.*` rewriting is unchanged because the WRD-110 / WRD-111 / WRD-113 family always justifies it within their respective workflow contexts.
- `fix_missing_concurrency` now only fires when the workflow is triggered by `push` or `pull_request`, matching WRD-831's actual scanner-side check. Manual-deploy workflows no longer get a surprise concurrency block from `warden fix --apply`.

### Fixed

- WRD-826 auto-fix is now per-entry instead of per-block. Previously the fixer added a single comment ABOVE the `permissions:` line, which counted as one fix in the output but did NOT actually satisfy the rule's per-entry check. The fixer now walks each `<perm>: <level>` line under any `permissions:` block (top-level or per-job) and appends an inline `# explanation` if neither the line itself nor the line above already has a `#` comment. Each modified entry produces its own `FixRecord`.
- `fix_checkout_persist_credentials` no longer creates a duplicate `with:` block at the wrong indentation. Two related bugs were fixed: (1) the look-ahead loop's break condition was `next_indent <= leading`, which terminated as soon as it saw a sibling step property at the same indent as `uses:`, falling through to the "create a new `with:` block" branch. Now `next_indent < leading`. (2) The new-block fallback computed `with_indent = leading + 2`, treating `with:` as a child of `uses:`, but they're YAML siblings. Now `with_indent = leading`. Also handles the compact `- uses:` form correctly.
- `warden fix` now always emits files with a trailing newline via a shared `ensure_trailing_newline` helper.
- `warden fix --pr <repo> --format json` now actually emits JSON instead of printing a plain compare URL, so the web `/api/fix-pr` route can parse the result correctly.
- Ignores parser now correctly applies a standalone `# warden: ignore[WRD-XXX]` directive to the line containing the directive itself as well as the next code line. Previously the directive was only honored on the following line.

### Breaking

- `wardenscan` crate API: the `Rule` trait now receives `&AuditCtx<'_>` with typed `loaded`, `expressions`, `shell`, `ignores`, and `provenance` fields instead of the previous stringly-typed `&str` workflow body. Out-of-tree rule implementations need to migrate to the typed API.
- Minimum Rust: 1.74 (unchanged in practice, documented explicitly).
- Docker image tag `ghcr.io/projectwarden/warden:2` now points at 2.x. The `:1` tag is frozen.

### CI, dogfood, workflows

- CI workflow split: `.github/workflows/ci.yml` no longer dogfoods warden on itself (that moved to a separate `dogfood.yml` workflow), so a bug in the analyzer cannot break the core test/build matrix. Both workflows have explicit top-level `permissions: contents: read`, `persist-credentials: false` on every `actions/checkout`, and explicit `concurrency:` blocks.
- `deploy-web.yml` has an `environment: production` attached to the deploy job, an explicit top-level least-privilege permission block, and uses an inline `# warden: ignore[WRD-822]` directive at the single line that WRD-822 cannot statically verify.
- `release.yml`'s `publish-crate` job is now attached to `environment: crates-io`, giving the `CRATES_IO_TOKEN` a reviewable approval step.

### Tests

- Test count expanded from 57 to 235+ across 11 integration test files. New coverage:
  - `tests/rules_1xx_2xx_test.rs` (16 tests): injection and trigger rules.
  - `tests/rules_3xx_test.rs` (20 tests): supply chain rules including impostor commits, archived refs, unpinned transitive refs.
  - `tests/rules_4xx_7xx_test.rs` (36 tests): permissions, AI config, steganography, integrity rules.
  - `tests/rules_8xx_test.rs` (31 tests): logic rules including self-hosted runner, confused deputy, cache poisoning, anonymous workflows.
  - `tests/wrd120_taint_test.rs` (13 tests): cross-step taint propagation end-to-end (safe sources suppressed, tainted sources emit Critical, unknown sources emit Low advisory, heredocs, orphaned reads).
  - `tests/models_test.rs`, `tests/ignores_test.rs`: typed model and inline-ignore foundation tests.
- `cargo test` is green across the full matrix.

### Website

- New `/design` background-texture preview page with 18 variants (Parchment, Linen, Canvas, Vellum, Blueprint, Noir, Oxide, Terminal, Carbon, Slate, Velvet, Cosmos, Moss, Ember, Twilight, Concrete, Mercury, Smoke) for evaluating hand-crafted grain / veins textures against the warden brand. Variant choice and dark/light mode are persisted in `localStorage` under `warden-design-preview` and synced to the URL as `?v=<variant>&m=<mode>` for shareable previews. Includes a pixel-reveal canvas animation of the warden logo that samples the source 48x48 and paints pixels one at a time, with luminance-mapped palette so light mode renders the body in off-black and the tie in dark blue `#1e40af` (never yellow).

## v1.0.0 // 2026-04-07

First public release of warden. Static analyzer + auto-fixer for GitHub Actions workflows, written in Rust, single static binary, zero runtime dependencies.

### Detection

59 detection rules across 8 attack classes:

- **1xx Injection** // expression injection in `run:` blocks, composite action input injection, `workflow_dispatch` input injection, `GITHUB_ENV` / `GITHUB_PATH` writes, tainted reusable-workflow inputs, step-output taint propagation
- **2xx Triggers** // dangerous fork checkout, build-tool execution on untrusted code, cross-workflow privilege escalation
- **3xx Supply chain** // OIDC trust boundaries, known-vulnerable actions, impostor commits, unpinned actions (with severity dampening for `actions/*` and `github/*`), archived / stale / version-mismatched / branch-pinned refs, runtime binary fetch, denylisted action incidents, and composite-or-Docker action internal unpinned refs (transitive pinning hygiene)
- **4xx Permissions** // secrets in run blocks, network exfiltration, debug logging, secrets used outside `environment:` scope
- **5xx AI security** // AI assistant config poisoning across the broadest published catalog of any GHA scanner: 30+ verified file paths covering Claude Code, Cursor, GitHub Copilot, Aider, Continue, Windsurf, Cline, Gemini CLI, OpenAI Codex CLI, and the cross-tool `AGENTS.md` standard. MCP config injection across 16 verified `.mcp.json`-style file paths spanning every major MCP-aware editor. Both rules also fire across `pull_request_target`, `workflow_run`, and `issue_comment` privileged triggers, not just `pull_request_target`. Plus Dependabot cooldown / insecure execution and trusted publishing enforcement.
- **6xx Steganography** // unicode bidi / zero-width / homoglyph payloads, IOC pattern matching against known C2 / reverse-shell / exfil patterns
- **7xx Integrity** // toJSON secrets exposure, artipacked, secrets-inherit, insecure commands, hardcoded credentials, curl-pipe-bash, unpinned container / services images
- **8xx Logic** // self-hosted runner on PR triggers, confused deputy on auto-merge, artifact injection via `workflow_run`, risky-trigger default permissions, unsound conditions, bypassable contains() checks, secret redaction bypass, cache poisoning in release workflows, excessive permissions, spoofable bot identity checks, undocumented permissions, superfluous setup actions, obfuscation in non-`run:` contexts, missing concurrency limits, anonymous workflow definitions

### Auto-fix

`warden fix` operates in **plan mode by default** (terraform-style) // nothing on disk changes unless you pass `--apply`. The fixer covers:

- SHA pinning of `uses:` refs from tags via the GitHub Git API
- Lifting `${{ expression }}` interpolations into `env:` blocks to neutralize script injection
- Adding `persist-credentials: false` to `actions/checkout` steps
- Inserting a least-privilege top-level `permissions:` block when missing
- Inserting a `concurrency:` block to prevent overlapping runs

`warden fix --pr owner/repo --apply` pushes a branch with the fixes and opens a pull request. Add `--prepare-only` to skip the PR creation and return a GitHub compare URL instead, so you click "Create pull request" yourself.

### Subcommands

- `warden scan <target>` // scan a local path or `owner/repo` GitHub slug
- `warden score <target>` // 0-100 security score with diminishing-returns per-severity penalties
- `warden fix <target>` // plan / apply auto-fixes (see above)
- `warden upstream <path>`: resolve a project's dependency manifests (`package.json`, `requirements.txt`, `Pipfile.lock`, `go.mod`, `Cargo.toml`) back to their source repos and scan each one's upstream workflows with the full 59-rule detector. Supports `--depth 2` for shallow transitive walks and `--concurrency N` for parallel scanning.
- `warden rules` // print all detection rules grouped by category
- `warden` (no args) // launches an interactive guided menu in a TTY

### Output formats

- `--format console` (default) // colorized terminal output, capped at the 20 most severe findings with a "top rules by count" summary so a single noisy systemic issue doesn't drown out the actually-critical findings; `--all` removes the cap
- `--format json` // structured output for tooling
- `--format sarif` // SARIF 2.1.0 for GitHub Code Scanning upload
- `--format markdown` // collapsible markdown summary suitable for posting as a PR comment
- Live progress events on stderr via `--progress` (NDJSON, one event per workflow file)

### Configuration

- `.warden.toml` walks upward from the scan target for per-project rule disabling and severity overrides
- `--fail-on critical|high|medium|low|none` controls the CI exit code

### Distribution

- Static binaries for `linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64`, `windows-x86_64`
- Multi-arch Docker image at `ghcr.io/projectwarden/warden:1.0.0`
- Cargo: `cargo install wardenscan`
- GitHub Action: `projectwarden/warden@v1` (Docker action with `path`, `fail-on`, and `format` inputs)

### Dogfooding

All GitHub Actions in warden's own CI and release workflows are pinned to 40-char commit SHAs. Warden's self-scan runs on every CI build and must exit clean above the high-severity threshold.
