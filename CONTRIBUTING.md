# Contributing to warden

Thanks for picking up a task. This file is the practical "how to add or change
a detection rule without breaking the registry" guide. For product direction
and conventions see `CLAUDE.md`; for architecture see the README's
`Architecture` section.

If you have access to the `/rule-new` Claude Code skill, it scaffolds
everything below in one pass. The contents of this file describe the same
workflow done by hand.

## TL;DR for adding a new WRD-* rule

1. Pick the next free `WRD-<NNN>` in the right category (1xx-8xx) and the
   right severity tier within it (see `docs/src/rules/index.md` for both
   tables). Severity is encoded in the last two digits: `X01-X09` critical,
   `X10-X19` high, `X20-X29` medium, `X30-X39` low, `X40-X49` info.
2. Create `src/rules/wrd<NNN>.rs` with a unit struct `WrdNNN` that
   implements `Rule` (see "Rule file template" below).
3. Register the module in `src/rules/mod.rs` and the instance in
   `src/rules/api.rs::all_rules()`. Both lists are kept in numeric order.
4. Add one positive (vulnerable) and one negative (safe) test to the
   matching `tests/rules_<range>_test.rs` bucket.
5. Document the rule in `docs/src/rules/<category>.md`.
6. Add a catalog row in `web/app/rules/rules-data.ts` (and `web/app/page.tsx`
   if it belongs in the landing-page table).
7. Run the verification checklist at the bottom of this file.

## Where things live

| What | Path |
|------|------|
| Rule trait, `AuditCtx`, `RuleFinding`, `Severity` | `src/rules/api.rs` |
| Module declarations | `src/rules/mod.rs` |
| Registry (`all_rules()`) | `src/rules/api.rs` |
| Legacy-ID redirects | `src/rules/aliases.rs` |
| Per-rule source | `src/rules/wrd<NNN>.rs` |
| Per-rule tests | `tests/rules_<range>_test.rs` (1xx_2xx, 3xx, 4xx_7xx, 8xx) |
| Static invariants on the registry | `tests/rule_meta_test.rs` |
| Public docs catalog | `docs/src/rules/<category>.md` (+ `index.md`) |
| Web catalog | `web/app/rules/rules-data.ts`, `web/app/page.tsx` |

## Rule file template

Minimal shape of `src/rules/wrd<NNN>.rs`:

```rust
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct WrdNNN;

impl Rule for WrdNNN {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-NNN",
            name: "Short human title",
            default_severity: Severity::High,
            description: "One-sentence description of what is detected and why \
                          it is dangerous.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        // detection logic, push RuleFinding entries
        findings
    }
}
```

Notes:

- The struct name (`WrdNNN`) and the `meta.id` (`WRD-NNN`) must match the
  filename (`wrd<NNN>.rs`). `tests/rule_meta_test.rs` enforces that the set
  of files on disk matches the set of ids in `all_rules()`, that ids match
  `WRD-<digits>`, and that no two rules share an id.
- If your detection reads `${{ steps.X.outputs.Y }}`, consult
  `ctx.provenance` before flagging. Without that filter, a rule will
  reproduce the v1 false-positive flood that step-output taint propagation
  was designed to fix.
- For raw-text scans (trailing comments serde drops), use
  `crate::rules::line_number_at_offset(content, byte_offset)` to get a
  1-based line for the `Span`. WRD-332 and WRD-333 are existing examples.
- If you renumber an existing rule, add an entry to
  `src/rules/aliases.rs::aliases()` so old `.warden.toml` configs and CLI
  invocations keep working.

## Registering the rule

Two small edits, both kept in numeric order so diffs stay clean:

- `src/rules/mod.rs`: insert `pub mod wrd<NNN>;` at the right position in
  the sorted list.
- `src/rules/api.rs::all_rules()`: insert
  `Box::new(super::wrd<NNN>::WrdNNN),` at the right position.

Forgetting either is caught by `tests/rule_meta_test.rs`, but the failure
message is clearer if both are added together.

## Test fixtures (positive + negative are required)

Every rule ships with one vulnerable fixture and one safe fixture. No
exceptions; this is what stops a rule from quietly regressing or quietly
firing on every workflow on earth.

Test files are bucketed by rule range:

| Range | File |
|-------|------|
| 1xx, 2xx | `tests/rules_1xx_2xx_test.rs` |
| 3xx | `tests/rules_3xx_test.rs` |
| 4xx, 7xx | `tests/rules_4xx_7xx_test.rs` |
| 8xx | `tests/rules_8xx_test.rs` |

Each bucket exposes an `audit_with(rule, yaml)` (or
`audit_with_path(rule, path, yaml)` for `action.yml` / reusable workflows)
helper that builds a real `AuditCtx` from inline YAML. Copy the shape of an
existing pair, for example WRD-101 in `rules_1xx_2xx_test.rs`:

```rust
#[test]
fn test_wrdNNN_<situation>_vulnerable() {
    let yaml = r#"...vulnerable workflow..."#;
    let findings = audit_with(&wrdNNN::WrdNNN, yaml);
    assert!(!findings.is_empty(), "<one-line reason>");
    assert_eq!(findings[0].rule_id, "WRD-NNN");
}

#[test]
fn test_wrdNNN_<situation>_safe() {
    let yaml = r#"...safe workflow..."#;
    let findings = audit_with(&wrdNNN::WrdNNN, yaml);
    assert!(findings.is_empty(), "<one-line reason>");
}
```

Pick the negative fixture with care. The strongest negative is the most
plausible non-vulnerable variant of the positive (same trigger, same
action, value sourced safely), not "a totally unrelated workflow." That is
how false-positive regressions get caught early.

### Running just one rule's tests

```sh
# All tests in one bucket
cargo test --test rules_1xx_2xx_test

# Just the WRD-NNN cases (substring match on test name)
cargo test --test rules_1xx_2xx_test wrdNNN

# Registry invariants
cargo test --test rule_meta_test

# Whole suite
cargo test
```

## Documenting the rule

- `docs/src/rules/<category>.md`: add a section for the new rule. Match
  the structure of neighbours: title, severity, what it catches, what an
  exploit looks like, recommended fix.
- `docs/src/rules/index.md`: add the new id to the category row in the
  numbering table at the top, and bump the rule count in the opening
  sentence.
- `web/app/rules/rules-data.ts`: append a `{ id, name, severity, group,
  description }` row in numeric order. The `web/app/rules/rules-data.test.mjs`
  test covers shape and ordering.
- `web/app/page.tsx`: only if the rule belongs in the landing-page
  highlights table; most rules do not.

## Running the test suite locally

First-time setup: make sure you have a Rust toolchain (`rustup show`
lists a stable channel) and a recent Node (`node --version` is 20 or
newer to match the `next@^16` engines). Then, from the repo root:

```sh
cargo test                           # Rust: whole suite, no env vars
( cd web && npm install && npm test ) # Web: one-time install, then tests
```

If either command fails on a fresh clone, that is a bug worth reporting
before anything else; the suites are intended to pass out of the box.

### Rust tests

```sh
cargo test                                  # whole suite
cargo test --test rules_1xx_2xx_test        # one bucket (see table above)
cargo test --test rule_meta_test            # registry invariants
cargo test --test rules_1xx_2xx_test wrdNNN # one rule (substring match)
```

No environment variables are required. Integration-test YAML fixtures
are inline string literals in the `tests/rules_*_test.rs` files; nothing
is read from disk beyond the `tests/` sources themselves.

### Web tests

The `web/` workspace uses `node --test` (no Jest, no Vitest) with `jiti`
loading TypeScript from `.test.mjs` files. From `web/`:

```sh
npm test               # full suite: app/**/*.test.mjs + lib/**/*.test.mjs
npm run test:contract  # just the /api/scan-preview failure-response
                       # security contract (see "Web API security
                       # contracts" below for what it pins)
npx tsc --noEmit       # type-check without running the tests
```

`npm test` does NOT require any environment variables. The two
file-backed stores are deliberately unset at test import time so runs
are hermetic:

- `WARDEN_SCAN_STATS_FILE` backs the scan-preview "N repos scanned this
  week" counter (`web/lib/scanPreviewStats.ts`).
- `WARDEN_SHARED_SCANS_FILE` backs the anonymous scan-share store
  (`web/lib/sharedScans.ts`).

Tests that exercise the on-disk path set the env var to a
`mkdtempSync(..., "warden-...-")` directory and clean it up in a
`finally` block, so test runs never touch `.local/` or `$HOME`. If you
see a web test fail with an unexpected filesystem error, first check
your shell for stray exports from a prior dev session:

```sh
env | grep WARDEN_
```

`web/.env.local.example` documents every web-side env var and when to
set it for `npm run dev` (not for tests).

## Verification checklist before committing

Run from the repo root:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
( cd web && npx tsc --noEmit && node app/rules/rules-data.test.mjs )
```

Then dogfood: warden's own workflows must stay clean above MEDIUM.

```sh
cargo build --release
./target/release/warden scan . --fail-on high
```

LOW and INFO findings on warden's own workflows are acceptable as long as
each one is individually understood and noted in the commit message. A new
MEDIUM, HIGH, or CRITICAL finding on `.github/workflows/` is a regression;
fix the rule's precision (consult `ctx.provenance`, narrow the trigger, or
exclude the case) rather than suppressing the finding.

## Web API security contracts

The web routes under `web/app/api/` have a few contracts that are not
obvious from reading the code alone. If you refactor a route, read this
first; each rule below exists because a previous change broke it.

### `/api/scan-preview`: failure responses are deliberately opaque

`web/app/api/scan-preview/route.ts` is a public, unauthenticated endpoint
that shells out to the `warden` binary. The response contract for any
non-success path is:

1. A hardcoded, human-readable `error` string. The only strings the route
   is allowed to return in the `error` field are the ones already present
   in `route.ts` (`"Scan preview failed."`,
   `"Failed to parse scan output."`, the rate-limit message, the
   "no workflows" message, `"Repository not found, or it is private."`,
   `"Invalid request body."`, and the repo-validation message). Do not
   introduce new error strings that are derived from `stderr`, from
   `err.message`, or from any other runtime input.
2. Zero bytes of `stderr`, exception messages, stack traces, or spawn
   error text in the response body. The route's final `catch {}` block is
   intentionally argument-less; the variable is not even bound, so it
   cannot be accidentally serialized.
3. No structured `detail`, `reason`, or `debug` field alongside `error`.
   A future contributor will be tempted to add one. Do not.

Why this is strict, and not a "sanitize and return 502" pattern:

- `warden` inherits the server's environment, and in production can be
  invoked with `GITHUB_TOKEN` set. A panic or a library log line can
  print environment values, filesystem paths (`/home/<user>/...`), or the
  remote URL of a cached clone. A sanitization allowlist that tries to
  strip these is fragile; a hardcoded allowlist of response strings is
  provably leak-free.
- Classifying `stderr` by regex into an HTTP category (`rate limit`,
  `not found`, `no workflows`) is fine, because the route then answers
  with one of the hardcoded strings above. It does not echo the matched
  substring. Preserve that shape when adding new classifications.
- A 502 with a structured `{ error, detail }` shape was proposed and
  rejected. The reason is documented in the three tests listed below;
  the test that uses `/home/kali/secrets/ghp_ABCDEF1234567890` as a
  canary is the load-bearing one.

Tests that pin this contract (do not weaken them):

- `route.test.mjs` > `"classifies unrecognized warden failure as generic
  500 without leaking stderr"`: asserts the canary string and the words
  `panic` / `assertion` do not appear anywhere in the serialized body.
- `route.test.mjs` > `"classifies non-zero exit with unparseable stdout
  as 500 'Failed to parse scan output.'"`: pins the exact message for
  the partial-stdout-crash arm.
- `route.test.mjs` > `"rejects non-object JSON stdout (e.g. 'null' or a
  bare number) with 500"`: pins that `null`, primitives, and arrays are
  rejected rather than quietly served as an empty-findings 200 that
  would then be cached for three minutes.

Run just these contract tests with:

```
cd web && npm run test:contract
```

The full `npm test` suite also exercises them, but `test:contract` is the
one-command check to run before and after any refactor that touches
`route.ts`, the classification regexes, or the rate-limit helper.

If a future change needs richer diagnostics for operators, the right
place is a server-side log line (stderr of the Next.js process,
structured so it can be grepped), not the HTTP response body.

## Operational notes

### `/api/scan-preview/stats`: in-memory counter, resets on deploy

`web/lib/scanPreviewStats.ts` is a rolling log of anonymous scan-preview
runs. It powers the landing-page "N public repos scanned this week"
social-proof counter. It is not a database, and a few operational facts
follow from that:

- **The log lives in process memory** (a `globalThis`-pinned array, same
  pattern as `rateLimit.ts` and the preview response cache). Every
  Next.js cold start or redeploy wipes it. On Vercel that means the
  counter can legitimately read `0` right after a push and warm back up
  as traffic arrives. This is expected behavior, not an incident; do
  not page on it.
- **Single-node only.** If the web app is ever horizontally scaled,
  each instance holds its own log and the counter becomes load-balancer
  roulette. Moving to a shared store (Redis, Upstash, a Postgres table)
  is the planned fix; any migration must preserve the invariants
  listed below.
- **Only the miss path of `/api/scan-preview` records.** Cached repeat
  scans of the same slug inside the 3-minute preview cache window do
  not call `recordScan`, so the counter reflects unique-ish scan
  traffic rather than page reloads.
- **Rolling 7-day window, hard cap 5000 entries.** `WINDOW_MS` filters
  at read time in `getStats()`; `MAX_ENTRIES` drops the oldest entries
  at write time in `recordScan()`. If scan volume ever sustains above
  ~5000/week the oldest entries fall out of the window early, and the
  displayed number becomes a rolling max of the last 5000 rather than
  the true last-7-days total. Bump the cap (or switch to a real store)
  before that happens.

Invariants pinned by
`web/app/api/scan-preview/stats/route.test.mjs`, any refactor must
preserve all of these:

1. Cold start (empty log) returns
   `{ scansLast7d: 0, distinctReposLast7d: 0 }` with status 200.
2. Every `recordScan` call increments `scansLast7d`; no
   read-modify-write race may drop an increment, including under
   concurrent invocation of the same slug.
3. `distinctReposLast7d` is `Set`-based: the same slug recorded N times
   contributes 1 to the distinct count.
4. Distinct-slug writes in parallel must not collapse; N parallel
   writes of N unique slugs yield `distinctReposLast7d == N`.
5. The response advertises `Cache-Control: public, max-age=30` so
   landing-page fetches do not turn this into a per-visitor hot path.

If you migrate the store (for example Redis-backed), re-run the
concurrency tests in that file first; the 200-parallel-writes test is
the one that catches a dropped-increment regression before it ships.

## Commit conventions

- Subject prefix: `feat(rules):`, `fix(rules):`, `test(rules):`,
  `docs(rules):` as appropriate.
- One rule per commit when possible. The diff is small (one new file, two
  one-line registry edits, one test pair, one doc paragraph, one catalog
  row), and a focused commit is easier to revert if the rule turns out to
  be noisy in the wild.
- Never push without explicit approval from a maintainer. Local commits are
  cheap; published commits are not. See `CLAUDE.md` for the full rule.
