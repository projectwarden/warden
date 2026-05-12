# Migrating from warden v1 to v2

warden v2.0.0 keeps every CLI flag, every output format, and every rule ID stable. If you only run `warden scan` from CI you can upgrade by bumping the action SHA / Docker tag / `cargo install` and reading the **Severity recalibration** section below to understand why your finding count and severity mix changes.

If you embed `wardenscan` as a library in your own Rust code, the `Rule` trait signature has changed. See **Library API** below.

## TL;DR

- **Pure CI users**: bump to `v2.0.0`, expect fewer high-severity findings and more low/info advisories. WRD-120 in particular now produces dramatically fewer false positives on `${GITHUB_SHA}` / `${GITHUB_REF_NAME}` reads.
- **Library users**: rules now receive `&AuditCtx<'_>` with typed workflow data instead of a raw `&str` body. Update your rule implementations.
- **New features available**: inline `# warden: ignore[WRD-XXX]` directives, cross-step taint propagation, real expression parser, tree-sitter shell analysis. None require config changes to use.

## CI / CLI users

### What stays the same

- `warden scan`, `warden score`, `warden fix`, `warden upstream`, `warden rules`, `warden add-action` all keep their flags, arguments, and exit-code semantics.
- All 53 rule IDs (`WRD-101`, `WRD-310`, ...) are stable. A rule that fired in v1 still fires in v2 unless severity or scope was tuned (see below).
- Output formats (`console`, `json`, `sarif`, `markdown`) keep their schema. SARIF still validates against 2.1.0.
- `.warden.toml` config keeps both `disabled_rules` and `[severity_overrides]` with the same shape.

### What changes (severity recalibration)

v2 calibrates severities so a HIGH finding is genuinely actionable:

| Rule | v1 severity | v2 severity | Why |
|------|-------------|-------------|-----|
| WRD-120 (step output injection) | High (uniformly) | Critical when the upstream write is provably tainted (`github.event.*`, `github.head_ref`); suppressed when provably safe (`$GITHUB_SHA`, `$GITHUB_REF_NAME`, literals); Low advisory when the upstream is unknown (command substitution, untraced bash variables) | Cross-step taint propagation. v1 issued a blanket warning on every step-output read. |
| WRD-440 (ex-WRD-420, Secret Reference Inventory) | Medium | Info | Structural inventory of `${{ secrets.X }}` references; does not imply the secret leaks. Kept as Info for completeness. |
| WRD-826 (undocumented permissions) | Medium | Info | Hygiene rule, not vulnerability. The auto-fixer still adds per-entry comments. |
| WRD-710 (artipacked) | Medium uniformly | High when there's a pre-v6 checkout AND an `upload-artifact` step in the same workflow (the original tj-actions / reviewdog exploit chain), Low otherwise (defense in depth) | Matches `warden fix --apply` 1:1: every place the fixer would touch is now also a finding the scanner emits. |

### What changes (scope tightening)

- `fix_expression_injection` now only rewrites `${{ github.event.* }}` paths that are on WRD-101's canonical `TAINTED_EXPRESSIONS` list. Previously it would also rewrite safe paths like `github.event.repository.name` that the scanner never flagged. PRs from `warden fix --pr` will be smaller and more targeted.
- `fix_missing_concurrency` now only fires for workflows triggered by `push` or `pull_request`, matching WRD-831's actual scanner-side check. Manual-deploy workflows no longer get a surprise concurrency block.
- `fix_checkout_persist_credentials` no longer creates a duplicate `with:` block at the wrong indentation (two related bugs in v1).
- `warden fix` now always emits files with a single trailing newline, no more "no newline at end of file" red indicator in PRs.

### What's new and worth using

**Inline ignore directives.** Suppress a rule at one location without editing `.warden.toml`:

```yaml
- name: Deploy
  run: |
    # warden: ignore[WRD-822]
    echo "value=$SOMETHING" >> "$GITHUB_OUTPUT"
```

The directive can sit on its own line above the offending line, or at the end of the offending line itself. Multiple rule IDs can be combined: `# warden: ignore[WRD-822,WRD-826]`. The parser is quote-aware: `run: echo "# warden: ignore[..]"` inside a string is **not** treated as a directive.

**Cross-step taint propagation.** Nothing to enable. `warden scan` walks every `id:`'d run step, finds writes to `$GITHUB_OUTPUT`, classifies each `key=value` write (`Tainted` / `Safe` / `Secret` / `Literal` / `Unknown`), and rates downstream `${{ steps.X.outputs.Y }}` reads accordingly. This is what eliminates v1's WRD-120 false-positive flood on workflows that build a digest from `$GITHUB_SHA` and read it back later.

### Action upgrade

If you used the v1 SHA pin:

```yaml
- uses: projectwarden/warden@7f13104599d0c765952bc981e370b7c585e9f818  # v1.0.0
```

Replace with v2 (and re-pin to the new SHA after the v2.0.0 tag is published):

```yaml
- uses: projectwarden/warden@e4f665f5171ef446d79cc5c268af6606d78aaf04  # v2.0.0
```

The `with:` inputs (`path`, `fail-on`, `format`) are unchanged.

### Docker upgrade

```sh
docker pull ghcr.io/projectwarden/warden:2
```

The `:1` tag is frozen at v1.0.0. Use `:2` (or `:2.0.0`) for v2.

### Cargo upgrade

```sh
cargo install wardenscan --force
```

Minimum Rust version is now 1.74 (was 1.70 in v1).

## Rule renumbering (v2.0.0)

The convention "severity is encoded in the tens/units digit of the rule number" is now strictly applied. 21 rules were renumbered, 15 renamed for clarity, and several re-rated.

### Backwards compatibility

`.warden.toml` files keep working without changes. The aliases module (`src/rules/aliases.rs`) resolves every legacy ID to its canonical successor at config-load time AND at inline-ignore-directive parse time:

```toml
# Both forms work in v2.0.0; both refer to the same rule (now WRD-840).
disabled_rules = ["WRD-826"]
disabled_rules = ["WRD-840"]
```

```yaml
# Both directives suppress the same rule (now WRD-815).
- run: dangerous-thing  # warden: ignore[WRD-822]
- run: dangerous-thing  # warden: ignore[WRD-815]
```

The same applies to `severity_overrides` and CLI invocations.

### When you should update your config

You should migrate to the new IDs at your convenience because:

1. The aliases system is documented for one major version. v3 may drop legacy IDs entirely.
2. Output (`warden scan --format json`, SARIF, console, markdown) reports the canonical (new) ID, so log filtering and dashboards on the v1 IDs will silently miss findings.
3. New rules will only be issued in the new numbering scheme.

### Quick migration map

(sed-replace your `.warden.toml` and any inline `# warden: ignore[WRD-XXX]` directives.)

```
WRD-120 -> WRD-130    WRD-321 -> WRD-331    WRD-322 -> WRD-332    WRD-323 -> WRD-333
WRD-326 -> WRD-313    WRD-327 -> WRD-314    WRD-420 -> WRD-440    WRD-520 -> WRD-540
WRD-601 -> WRD-621    WRD-710 -> WRD-730    WRD-711 -> WRD-721    WRD-713 -> WRD-722
WRD-720 -> WRD-723    WRD-820 -> WRD-830    WRD-821 -> WRD-816    WRD-822 -> WRD-815
WRD-826 -> WRD-840    WRD-827 -> WRD-841    WRD-828 -> WRD-817    WRD-831 -> WRD-842
WRD-833 -> WRD-843
```

### Severity changes you should know about

These rules' severities changed (independent of the renumber). Update any CI gates, dashboards, or `.warden.toml::severity_overrides` accordingly:

| Rule (new ID) | Old severity | New severity | Why |
|---|---|---|---|
| WRD-331 (was 321) | Medium | Low | Hygiene flag, not vuln |
| WRD-332 (was 322) | Medium | Low | Documentation hygiene |
| WRD-333 (was 323) | Medium | Low | Operator confusion, not exploit |
| WRD-540 (was 520) | Medium | Info | PR-volume hygiene only |
| WRD-621 (was 601) | Critical | Medium | Invisible-unicode is an IOC indicator, not RCE on its own |
| WRD-721 (was 711) | High | Medium | Real-world `secrets: inherit` exploit needs an additional bug |
| WRD-722 (was 713) | High | Medium | Hardcoded creds in YAML is config hygiene, not RCE |
| WRD-815 (was 822) | Medium | High | Active masking-bypass patterns are hostile-code-shaped |
| WRD-816 (was 821) | Medium | High | Confirmed authz bypass, e.g. `contains('admin')` matches `not-admin` |
| WRD-817 (was 828) | Medium | High | Long base64 in workflow YAML aligns with WRD-602 IOC class |
| WRD-841 (was 827) | Medium | Info | Pure efficiency hygiene |
| WRD-842 (was 831) | Low | Info | Resource hygiene, not security |
| WRD-843 (was 833) | Low | Info | Documentation only |

## Library users (`wardenscan` crate)

### Breaking: `Rule` trait now consumes `&AuditCtx<'_>`

In v1, custom rules implemented:

```rust
trait Rule {
    fn id(&self) -> &'static str;
    fn audit(&self, body: &str, file: &Path) -> Vec<Finding>;
}
```

In v2, the trait is:

```rust
use wardenscan::rules::{AuditCtx, Rule, RuleFinding};

impl Rule for MyRule {
    fn id(&self) -> &'static str { "MY-001" }

    fn audit(&self, ctx: &AuditCtx<'_>) -> Vec<RuleFinding> {
        // ctx.loaded     -> &LoadedWorkflow (typed model + spans + raw)
        // ctx.expressions -> &ExprIndex     (parsed ${{ ... }} ASTs)
        // ctx.shell       -> &ShellIndex    (tree-sitter bash, optional)
        // ctx.ignores     -> &IgnoreMap     (inline-ignore directives)
        // ctx.provenance  -> &StepOutputProvenance (cross-step taint)
        Vec::new()
    }
}
```

The `RuleFinding` struct carries byte-exact spans (`(line, column, byte_offset, length)`) so the auto-fixer can rewrite the offending bytes without regenerating the whole document.

### New public types worth knowing

- `wardenscan::models::{Workflow, Job, Step, RunStep, UseStep, Permissions, On}` for typed deserialization
- `wardenscan::expression::{ExprIndex, Expr, TAINTED_SOURCES, TAINTED_EXPRESSIONS}` for expression-AST analysis
- `wardenscan::shell::ShellIndex` for tree-sitter bash queries (behind the default-on `shell-analysis` cargo feature)
- `wardenscan::ignores::IgnoreMap` for `# warden: ignore[...]` parsing
- `wardenscan::taint::{StepOutputProvenance, TaintSource, build_provenance}` for cross-step taint propagation

See `tests/wrd120_taint_test.rs` and `tests/rules_8xx_test.rs` for end-to-end usage examples.

### Cargo features

- `default = ["shell-analysis"]` (unchanged)
- `shell-analysis` enables tree-sitter-bash for run-block parsing. Disable with `--no-default-features` if you need to drop the C-compilation step (the build then falls back to regex-based detection for shell rules).

### Minimum Rust version

1.74 (was 1.70 in v1). `clap_builder` 4.6 needs edition 2024 which lands in 1.85, but the `clap` we depend on is pinned to a release that still works on 1.74. CI tests against stable.

## Known incompatibilities

- v1's `RuleFinding` struct without span info is gone. If you persisted v1 finding payloads, the schema is forward-compatible (extra fields appear in v2 output) but not backward-compatible.
- The `wardenscan::taint` module did not exist in v1. Code that conditionally compiled against `cfg(feature = "taint")` should drop the `cfg` and depend on the module unconditionally.

## Reporting issues

If a v1-passing workflow newly fails on v2 in a way that doesn't match the table above, please file an issue with the offending workflow snippet at <https://github.com/projectwarden/warden/issues>. Severity recalibration is intentional, but new false positives are not.
