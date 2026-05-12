//! Tests for the WRD-3xx rule family (action pinning, OIDC, denylist, etc.).
//!
//! WRD-314 lives in its own file (`tests/wrd314_test.rs`) since it exercises
//! the standalone `parse_action_yml` helper.

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
// WRD-301: OIDC Trust Boundary Violation
// ---------------------------------------------------------------------------

#[test]
fn test_wrd301_oidc_trust_vulnerable() {
    let yaml = r#"
name: Deploy
on: pull_request_target
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
"#;
    let findings = audit_with(&wrd301::Wrd301, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect id-token: write paired with pull_request_target"
    );
    assert_eq!(findings[0].rule_id, "WRD-301");
}

#[test]
fn test_wrd301_oidc_trust_safe() {
    let yaml = r#"
name: Deploy
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
"#;
    let findings = audit_with(&wrd301::Wrd301, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag id-token: write on push-only triggers"
    );
}

// ---------------------------------------------------------------------------
// WRD-302: Known Vulnerable Action
// ---------------------------------------------------------------------------

#[test]
fn test_wrd302_known_vulnerable_action_vulnerable() {
    // tj-actions/changed-files at any version v1..v44 is the canonical
    // March 2024 supply-chain compromise.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v35
"#;
    let findings = audit_with(&wrd302::Wrd302, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag tj-actions/changed-files@v35 as known vulnerable"
    );
    assert_eq!(findings[0].rule_id, "WRD-302");
}

#[test]
fn test_wrd302_known_vulnerable_action_safe() {
    // v45 is the patched range, which the regex (v1..v44) explicitly excludes.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
"#;
    let findings = audit_with(&wrd302::Wrd302, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag tj-actions/changed-files@v45 (post-fix)"
    );
}

// ---------------------------------------------------------------------------
// WRD-310: Impostor Commit / Suspicious SHA
// ---------------------------------------------------------------------------

#[test]
fn test_wrd310_impostor_commit_vulnerable() {
    // 39-char hex ref (one short of a real SHA) plus an all-zero pin.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@abcdef1234567890abcdef1234567890abcdef1
      - uses: another-org/zero-action@0000000000000000000000000000000000000000
"#;
    let findings = audit_with(&wrd310::Wrd310, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag truncated SHA and/or all-zero placeholder SHA"
    );
    assert!(findings.iter().all(|f| f.rule_id == "WRD-310"));
}

#[test]
fn test_wrd310_impostor_commit_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd310::Wrd310, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag a real 40-char hex SHA"
    );
}

// ---------------------------------------------------------------------------
// WRD-311: Unpinned Actions (renumbered from WRD-320)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd311_unpinned_action_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;
    let findings = audit_with(&wrd311::Wrd311, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag tag-pinned actions/checkout@v4"
    );
    assert_eq!(findings[0].rule_id, "WRD-311");
}

#[test]
fn test_wrd311_unpinned_action_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd311::Wrd311, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag a 40-char SHA-pinned action"
    );
}

// ---------------------------------------------------------------------------
// WRD-331: Archived Action Reference (renumbered from WRD-321)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd331_archived_action_vulnerable() {
    // actions-rs/toolchain is in the archived list.
    let yaml = r#"
name: Rust CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-rs/toolchain@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd331::Wrd331, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag archived actions-rs/toolchain"
    );
    assert_eq!(findings[0].rule_id, "WRD-331");
}

#[test]
fn test_wrd331_archived_action_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd331::Wrd331, yaml);
    assert!(findings.is_empty(), "Should not flag a non-archived action");
}

// ---------------------------------------------------------------------------
// WRD-332: SHA Pin Missing Version Comment (renumbered from WRD-322)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd332_stale_sha_pin_vulnerable() {
    // SHA-pinned with NO trailing `# vX.Y.Z` comment.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd332::Wrd332, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag SHA pin missing the trailing version comment"
    );
    assert_eq!(findings[0].rule_id, "WRD-332");
}

#[test]
fn test_wrd332_stale_sha_pin_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
"#;
    let findings = audit_with(&wrd332::Wrd332, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag SHA pin that carries a version comment"
    );
}

// ---------------------------------------------------------------------------
// WRD-333: Ref Version Mismatch (renumbered from WRD-323)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd333_ref_version_mismatch_vulnerable() {
    // Tag is @v4 but the comment claims v9.9.9 (different major).
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # v9.9.9
"#;
    let findings = audit_with(&wrd333::Wrd333, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag mismatch between @v4 ref and # v9.9.9 comment"
    );
    assert_eq!(findings[0].rule_id, "WRD-333");
}

#[test]
fn test_wrd333_ref_version_mismatch_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # v4.1.0
"#;
    let findings = audit_with(&wrd333::Wrd333, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag matching major version between ref and comment"
    );
}

// ---------------------------------------------------------------------------
// WRD-324: Ref Confusion (branch ref pinning)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd324_branch_ref_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@main
"#;
    let findings = audit_with(&wrd324::Wrd324, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag action pinned to mutable branch ref @main"
    );
    assert_eq!(findings[0].rule_id, "WRD-324");
}

#[test]
fn test_wrd324_branch_ref_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd324::Wrd324, yaml);
    assert!(findings.is_empty(), "Should not flag SHA-pinned action");
}

// ---------------------------------------------------------------------------
// WRD-345: Runtime Binary Fetch (renumbered from WRD-325)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd345_runtime_binary_fetch_vulnerable() {
    // actions/setup-node is in the SETUP_PREFIXES list (Medium severity).
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          node-version: 20
"#;
    let findings = audit_with(&wrd345::Wrd345, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag actions/setup-node as a runtime-binary-fetch action"
    );
    assert_eq!(findings[0].rule_id, "WRD-345");
}

#[test]
fn test_wrd345_runtime_binary_fetch_safe() {
    // actions/checkout is self-contained, not in either prefix list.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd345::Wrd345, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag a self-contained action like actions/checkout"
    );
}

// ---------------------------------------------------------------------------
// WRD-313: Denylisted Action Reference (renumbered from WRD-326)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd313_forbidden_action_vulnerable() {
    // actions/checkout@v1 is on the denylist (EOL).
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
"#;
    let findings = audit_with(&wrd313::Wrd313, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag denylisted actions/checkout@v1"
    );
    assert_eq!(findings[0].rule_id, "WRD-313");
}

#[test]
fn test_wrd313_forbidden_action_safe() {
    // actions/checkout pinned to a SHA is not denylisted.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;
    let findings = audit_with(&wrd313::Wrd313, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag SHA-pinned actions/checkout against the denylist"
    );
}

// ---------------------------------------------------------------------------
// WRD-335: Unverified Action Creator
// ---------------------------------------------------------------------------

#[test]
fn test_wrd335_unverified_creator_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: some-random-org/unknown-action@v1
"#;
    let findings = audit_with(&wardenscan::rules::wrd335::Wrd335, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("some-random-org")),
        "unverified creator should fire WRD-335"
    );
}

#[test]
fn test_wrd335_github_owned_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: github/codeql-action@v3
      - uses: actions/setup-node@v4
"#;
    let findings = audit_with(&wardenscan::rules::wrd335::Wrd335, yaml);
    assert!(
        findings.is_empty(),
        "actions/* and github/* are allowlisted; should not fire"
    );
}

#[test]
fn test_wrd335_well_known_third_party_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
      - uses: aws-actions/configure-aws-credentials@v4
      - uses: astral-sh/setup-uv@v6
      - uses: dtolnay/rust-toolchain@stable
"#;
    let findings = audit_with(&wardenscan::rules::wrd335::Wrd335, yaml);
    assert!(
        findings.is_empty(),
        "well-known third-party creators (docker, aws, astral, dtolnay) should not fire"
    );
}

#[test]
fn test_wrd335_one_finding_per_creator() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: unverified-org/action-a@v1
      - uses: unverified-org/action-b@v1
      - uses: unverified-org/action-c@v1
"#;
    let findings = audit_with(&wardenscan::rules::wrd335::Wrd335, yaml);
    assert_eq!(
        findings.len(),
        1,
        "three uses of same unverified creator should emit one finding, got {}",
        findings.len()
    );
}

#[test]
fn test_wrd335_local_action_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/my-local-action
"#;
    let findings = audit_with(&wardenscan::rules::wrd335::Wrd335, yaml);
    assert!(
        findings.is_empty(),
        "local actions (./...) should not fire WRD-335"
    );
}
