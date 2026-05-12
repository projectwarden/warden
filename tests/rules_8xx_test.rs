use wardenscan::expression::ExprIndex;
use wardenscan::ignores::IgnoreMap;
use wardenscan::rules::{AuditCtx, Rule, RuleFinding};
use wardenscan::scanner::{load_one, stub_workflow, LoadedFile};
use wardenscan::shell::ShellIndex;
use wardenscan::taint;

fn audit_with(rule: &dyn Rule, yaml: &str) -> Vec<RuleFinding> {
    let loaded_file =
        load_one(std::path::PathBuf::from("test.yml"), yaml.to_string()).expect("load");
    let loaded_wf = match loaded_file {
        LoadedFile::Workflow(w) => *w,
        LoadedFile::Other {
            path, raw, spans, ..
        } => stub_workflow(path, raw, spans),
    };
    let exprs = ExprIndex::build(&loaded_wf.workflow);
    let shell = ShellIndex::build(&loaded_wf.workflow);
    let ignores = IgnoreMap::new();
    let provenance = taint::build_provenance(&loaded_wf.workflow);
    let ctx = AuditCtx {
        loaded: &loaded_wf,
        expressions: &exprs,
        shell: &shell,
        ignores: &ignores,
        provenance: &provenance,
    };
    rule.audit(&ctx)
}

use wardenscan::rules::*;

// ---------------------------------------------------------------------------
// WRD-802: Runtime Self-Hosted Runner Registration (Shai-Hulud persistence)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd802_shai_hulud_ioc_name_vulnerable() {
    let yaml = r#"
name: persist
on: push
jobs:
  runner:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ./config.sh --url https://github.com/victim/org --token T --name SHA1HULUD
          ./run.sh
"#;
    let findings = audit_with(&wrd802::Wrd802, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("SHA1HULUD")),
        "SHA1HULUD runner-name IOC should fire"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd802_config_sh_registration_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  runner:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ./config.sh --url https://github.com/foo/bar --token ABC
"#;
    let findings = audit_with(&wrd802::Wrd802, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("config.sh")),
        "config.sh --token registration should fire"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd802_runasroot_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  runner:
    runs-on: ubuntu-latest
    steps:
      - run: |
          export RUNNER_ALLOW_RUNASROOT=1
          echo hi
"#;
    let findings = audit_with(&wrd802::Wrd802, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.title.contains("RUNNER_ALLOW_RUNASROOT")),
        "RUNNER_ALLOW_RUNASROOT=1 should fire"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd802_benign_run_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "benign"
          ./scripts/run-tests.sh
          cargo test
"#;
    let findings = audit_with(&wrd802::Wrd802, yaml);
    assert!(
        findings.is_empty(),
        "benign run block should not fire; got {} finding(s)",
        findings.len()
    );
}

// ---------------------------------------------------------------------------
// WRD-801: Self-Hosted Runner on PR
// ---------------------------------------------------------------------------

#[test]
fn test_wrd801_vulnerable() {
    let yaml = r#"
name: PR Tests
on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: make test
"#;
    let findings = audit_with(&wrd801::Wrd801, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect self-hosted runner on pull_request"
    );
    assert_eq!(findings[0].rule_id, "WRD-801");
}

#[test]
fn test_wrd801_safe() {
    let yaml = r#"
name: PR Tests
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: make test
"#;
    let findings = audit_with(&wrd801::Wrd801, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag hosted runners on pull_request"
    );
}

// ---------------------------------------------------------------------------
// WRD-810: Confused Deputy
// ---------------------------------------------------------------------------

#[test]
fn test_wrd810_vulnerable() {
    // Use an auto-merge command pattern; rule bails out if any auth-hint
    // keywords (github.actor, permission, team, CODEOWNERS, authorized) appear
    // anywhere in the raw text, so the fixture must avoid those.
    let yaml = r#"
name: AutoMerge
on: pull_request
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto 123
"#;
    let findings = audit_with(&wrd810::Wrd810, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect auto-merge without an authorization check"
    );
    assert_eq!(findings[0].rule_id, "WRD-810");
}

#[test]
fn test_wrd810_safe() {
    let yaml = r#"
name: AutoMerge
on: pull_request
jobs:
  merge:
    if: github.actor == 'specific-user'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto 123
"#;
    let findings = audit_with(&wrd810::Wrd810, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag auto-merge gated on actor check"
    );
}

// ---------------------------------------------------------------------------
// WRD-811: Artifact Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd811_vulnerable() {
    let yaml = r#"
name: Followup
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: ./process.sh
"#;
    let findings = audit_with(&wrd811::Wrd811, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect download-artifact in workflow_run without conclusion check"
    );
    assert_eq!(findings[0].rule_id, "WRD-811");
}

#[test]
fn test_wrd811_safe() {
    let yaml = r#"
name: Followup
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  process:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: ./process.sh
"#;
    let findings = audit_with(&wrd811::Wrd811, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag download-artifact gated on conclusion == 'success'"
    );
}

// ---------------------------------------------------------------------------
// WRD-812: Risky Trigger Default Permissions
// ---------------------------------------------------------------------------

#[test]
fn test_wrd812_vulnerable() {
    let yaml = r#"
name: PRT
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd812::Wrd812, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag pull_request_target without a top-level permissions block"
    );
    assert_eq!(findings[0].rule_id, "WRD-812");
}

#[test]
fn test_wrd812_safe() {
    let yaml = r#"
name: PRT
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd812::Wrd812, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag pull_request_target when top-level permissions block is present"
    );
}

// ---------------------------------------------------------------------------
// WRD-830: Unsound Condition
// ---------------------------------------------------------------------------

#[test]
fn test_wrd830_vulnerable() {
    // The V2 typed model reads `if:` only when it is a string, so quote the
    // literal to keep it a string.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: "true"
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect always-true 'if: \"true\"'"
    );
    assert_eq!(findings[0].rule_id, "WRD-830");
}

#[test]
fn test_wrd830_always_false_literal_fires() {
    // `if:` only round-trips through the typed model when it's a string,
    // so quote the literal to keep it a string (same convention as the
    // existing test_wrd830_vulnerable fixture above).
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: "false"
    steps:
      - run: echo unreachable
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("if: false")),
        "literal if: false should fire"
    );
}

#[test]
fn test_wrd830_expr_wrapped_true_fires() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ true }}
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        !findings.is_empty(),
        "`${{ true }}` should fire the same as bare `true`"
    );
}

#[test]
fn test_wrd830_literal_contains_always_true_fires() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ contains('abc', 'b') }}
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        findings.iter().any(|f| f
            .title
            .contains("contains() over two literals (always true)")),
        "contains('abc','b') should fire as tautological"
    );
}

#[test]
fn test_wrd830_literal_contains_always_false_fires() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ contains('abc', 'z') }}
    steps:
      - run: echo never
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("always false")),
        "contains('abc','z') should fire as always-false"
    );
}

#[test]
fn test_wrd830_literal_startswith_fires() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ startsWith('hello-world', 'hello') }}
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("startsWith")),
        "startsWith with two literals should fire"
    );
}

#[test]
fn test_wrd830_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.actor == 'me'
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(findings.is_empty(), "Should not flag meaningful condition");
}

// ---------------------------------------------------------------------------
// WRD-816: Bypassable Contains Check
// ---------------------------------------------------------------------------

#[test]
fn test_wrd816_vulnerable() {
    // The rule's regex requires one of: event.(issue|pull_request|comment)
    // fields, head_ref, actor, or event.sender.login. Use github.actor.
    let yaml = r#"
name: Gate
on: pull_request
jobs:
  gated:
    if: contains(github.actor, 'admin')
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd816::Wrd816, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect bypassable contains() on user-controlled input"
    );
    assert_eq!(findings[0].rule_id, "WRD-816");
}

#[test]
fn test_wrd816_safe() {
    let yaml = r#"
name: Gate
on: pull_request
jobs:
  gated:
    if: github.actor == 'admin-bot'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd816::Wrd816, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag exact equality check on github.actor"
    );
}

// ---------------------------------------------------------------------------
// WRD-815: Secret Redaction Bypass
// ---------------------------------------------------------------------------

#[test]
fn test_wrd815_vulnerable() {
    let yaml = r#"
name: Bypass
on: push
jobs:
  leak:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.X }}" | base64 -d
"#;
    let findings = audit_with(&wrd815::Wrd815, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect base64 decode piped from a secret reference"
    );
    assert_eq!(findings[0].rule_id, "WRD-815");
}

#[test]
fn test_wrd815_safe() {
    let yaml = r#"
name: Safe
on: push
jobs:
  use:
    runs-on: ubuntu-latest
    steps:
      - run: my-tool ${{ secrets.X }}
"#;
    let findings = audit_with(&wrd815::Wrd815, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag plain secret usage without encoding or splitting"
    );
}

// ---------------------------------------------------------------------------
// WRD-823: Cache Poisoning
// ---------------------------------------------------------------------------

#[test]
fn test_wrd823_vulnerable() {
    let yaml = r#"
name: Release
on:
  release:
    types: [published]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: build-cache
"#;
    let findings = audit_with(&wrd823::Wrd823, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect actions/cache in a release workflow with write-all"
    );
    assert_eq!(findings[0].rule_id, "WRD-823");
}

#[test]
fn test_wrd823_safe() {
    // Note: the rule fires if EITHER a release-style trigger OR elevated
    // permissions are present, so the safe case must drop the release
    // trigger. Using `on: push` with read-only perms exercises the
    // not-applicable path.
    let yaml = r#"
name: Build
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: build-cache
"#;
    let findings = audit_with(&wrd823::Wrd823, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag actions/cache on push with read-only permissions"
    );
}

// ---------------------------------------------------------------------------
// WRD-824: Excessive Permissions
// ---------------------------------------------------------------------------

#[test]
fn test_wrd824_vulnerable_write_all() {
    let yaml = r#"
name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd824::Wrd824, yaml);
    assert!(!findings.is_empty(), "Should detect permissions: write-all");
    assert_eq!(findings[0].rule_id, "WRD-824");
}

#[test]
fn test_wrd824_vulnerable_no_permissions() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd824::Wrd824, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag workflow with no top-level permissions block"
    );
    assert_eq!(findings[0].rule_id, "WRD-824");
}

#[test]
fn test_wrd824_safe() {
    let yaml = r#"
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd824::Wrd824, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag explicit scoped permissions"
    );
}

// ---------------------------------------------------------------------------
// WRD-825: Spoofable Bot Check
// ---------------------------------------------------------------------------

#[test]
fn test_wrd825_vulnerable() {
    // The ExprIndex only picks up `${{ ... }}` occurrences, so wrap the
    // condition expression for the rule to see it.
    let yaml = r#"
name: Bot
on: pull_request
jobs:
  bot:
    if: ${{ github.actor == 'dependabot[bot]' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd825::Wrd825, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect github.actor check against bot name"
    );
    assert_eq!(findings[0].rule_id, "WRD-825");
}

#[test]
fn test_wrd825_safe() {
    let yaml = r#"
name: Bot
on: pull_request
jobs:
  bot:
    if: ${{ github.actor_id == '49699333' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd825::Wrd825, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag numeric actor_id comparison"
    );
}

// ---------------------------------------------------------------------------
// WRD-840: Undocumented Permissions
// ---------------------------------------------------------------------------

#[test]
fn test_wrd840_vulnerable() {
    let yaml = r#"
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd840::Wrd840, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag permissions entry with no comment"
    );
    assert_eq!(findings[0].rule_id, "WRD-840");
}

#[test]
fn test_wrd840_safe() {
    let yaml = r#"
name: CI
on: push
permissions:
  contents: read   # for checkout
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd840::Wrd840, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag permissions entry that has a trailing comment"
    );
}

// ---------------------------------------------------------------------------
// WRD-841: Superfluous Actions
// ---------------------------------------------------------------------------

#[test]
fn test_wrd841_vulnerable() {
    // Unpinned fixture keeps the test compact; rule only checks for the
    // action name and absence of a version input. A SHA-pinned uses: works
    // the same way because the split happens on '@'.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@abcdef1234567890abcdef1234567890abcdef12
      - run: echo hi
"#;
    let findings = audit_with(&wrd841::Wrd841, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag actions/setup-node without a node-version input"
    );
    assert_eq!(findings[0].rule_id, "WRD-841");
}

#[test]
fn test_wrd841_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@abcdef1234567890abcdef1234567890abcdef12
        with:
          node-version: '20'
      - run: echo hi
"#;
    let findings = audit_with(&wrd841::Wrd841, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag setup-node when a node-version is explicitly chosen"
    );
}

// ---------------------------------------------------------------------------
// WRD-817: Obfuscation
// ---------------------------------------------------------------------------

#[test]
fn test_wrd817_vulnerable() {
    // Env value contains a base64 decode operation in a non-run context.
    let yaml = r#"
name: CI
on: push
env:
  CMD: "echo L3Vzci9iaW4vY3VybA== | base64 -d"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd817::Wrd817, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect base64 decode op in an env value"
    );
    assert_eq!(findings[0].rule_id, "WRD-817");
}

#[test]
fn test_wrd817_safe() {
    let yaml = r#"
name: CI
on: push
env:
  CMD: "echo hello"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd817::Wrd817, yaml);
    assert!(findings.is_empty(), "Should not flag plain env var content");
}

// ---------------------------------------------------------------------------
// WRD-842: Missing Concurrency
// ---------------------------------------------------------------------------

#[test]
fn test_wrd842_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd842::Wrd842, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag push workflow with no concurrency block"
    );
    assert_eq!(findings[0].rule_id, "WRD-842");
}

#[test]
fn test_wrd842_safe() {
    let yaml = r#"
name: CI
on: push
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd842::Wrd842, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag workflow with a concurrency block"
    );
}

// ---------------------------------------------------------------------------
// WRD-843: Anonymous Workflow
// ---------------------------------------------------------------------------

#[test]
fn test_wrd843_vulnerable() {
    let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd843::Wrd843, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag workflow without a top-level name"
    );
    assert_eq!(findings[0].rule_id, "WRD-843");
}

#[test]
fn test_wrd843_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd843::Wrd843, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag workflow with a top-level name"
    );
}
