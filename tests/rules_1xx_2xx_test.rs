//! Integration tests for the 100 / 200 series rules.
//!
//! Covers WRD-101, 110, 111, 112, 113, 201, 202, 203. WRD-130 has its own
//! dedicated taint-propagation suite in `tests/wrd130_taint_test.rs`.
//!
//! Each rule gets one positive (vulnerable) and one negative (safe) fixture.

use wardenscan::expression::ExprIndex;
use wardenscan::ignores::IgnoreMap;
use wardenscan::rules::{AuditCtx, Rule, RuleFinding};
use wardenscan::scanner::{load_one, stub_workflow, LoadedFile};
use wardenscan::shell::ShellIndex;
use wardenscan::taint;

fn audit_with(rule: &dyn Rule, yaml: &str) -> Vec<RuleFinding> {
    audit_with_path(rule, "test.yml", yaml)
}

fn audit_with_path(rule: &dyn Rule, path: &str, yaml: &str) -> Vec<RuleFinding> {
    let loaded_file = load_one(std::path::PathBuf::from(path), yaml.to_string()).expect("load");
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
// WRD-101: Expression Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd101_issue_body_in_run_vulnerable() {
    let yaml = r#"
name: t
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
"#;
    let findings = audit_with(&wrd101::Wrd101, yaml);
    assert!(
        !findings.is_empty(),
        "issue.body in run should fire WRD-101"
    );
    assert_eq!(findings[0].rule_id, "WRD-101");
}

#[test]
fn test_wrd101_github_actor_in_run_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello ${{ github.actor }}"
"#;
    let findings = audit_with(&wrd101::Wrd101, yaml);
    assert!(
        findings.is_empty(),
        "github.actor is not in the tainted-source list, should not fire"
    );
}

// ---------------------------------------------------------------------------
// WRD-110: Composite Action Input Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd110_inputs_in_action_run_vulnerable() {
    let yaml = r#"
name: example
description: composite action
inputs:
  user_value:
    description: a value
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.user_value }}"
      shell: bash
"#;
    let findings = audit_with_path(&wrd110::Wrd110, "action.yml", yaml);
    assert!(
        !findings.is_empty(),
        "inputs.X interpolated in composite run should fire WRD-110"
    );
    assert_eq!(findings[0].rule_id, "WRD-110");
}

#[test]
fn test_wrd110_inputs_via_env_safe() {
    let yaml = r#"
name: example
description: composite action
inputs:
  user_value:
    description: a value
runs:
  using: composite
  steps:
    - run: echo "$USER_VALUE"
      shell: bash
      env:
        USER_VALUE: ${{ inputs.user_value }}
"#;
    let findings = audit_with_path(&wrd110::Wrd110, "action.yml", yaml);
    assert!(
        findings.is_empty(),
        "input routed through env var indirection should not fire WRD-110"
    );
}

// ---------------------------------------------------------------------------
// WRD-111: Dispatch Input Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd111_dispatch_input_in_run_vulnerable() {
    let yaml = r#"
name: t
on:
  workflow_dispatch:
    inputs:
      target:
        description: deploy target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.target }}"
"#;
    let findings = audit_with(&wrd111::Wrd111, yaml);
    assert!(
        !findings.is_empty(),
        "workflow_dispatch input in run should fire WRD-111"
    );
    assert_eq!(findings[0].rule_id, "WRD-111");
}

#[test]
fn test_wrd111_workflow_call_input_in_run_vulnerable() {
    // Regression: a workflow_call callee used to be invisible to WRD-111
    // because the rule gated on workflow_dispatch/repository_dispatch
    // only, while fix_expression_injection (the auto-fixer) happily
    // rewrote the expression. That produced the 'N fixes proposed but 0
    // findings' UI mismatch. Now both sides agree.
    let yaml = r#"
name: t
on:
  workflow_call:
    inputs:
      title:
        required: true
        type: string
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.title }}"
"#;
    let findings = audit_with(&wrd111::Wrd111, yaml);
    assert!(
        !findings.is_empty(),
        "workflow_call input in run should fire WRD-111"
    );
    assert_eq!(findings[0].rule_id, "WRD-111");
    assert!(findings[0].title.contains("workflow_call"));
}

#[test]
fn test_wrd111_dispatch_input_via_env_safe() {
    let yaml = r#"
name: t
on:
  workflow_dispatch:
    inputs:
      target:
        description: deploy target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TARGET"
        env:
          TARGET: ${{ inputs.target }}
"#;
    let findings = audit_with(&wrd111::Wrd111, yaml);
    assert!(
        findings.is_empty(),
        "dispatch input passed via env should not fire WRD-111"
    );
}

// ---------------------------------------------------------------------------
// WRD-112: GITHUB_ENV/PATH Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd112_github_env_write_vulnerable() {
    let yaml = r#"
name: t
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "FOO=bar" >> $GITHUB_ENV
"#;
    let findings = audit_with(&wrd112::Wrd112, yaml);
    assert!(
        !findings.is_empty(),
        "appending to $GITHUB_ENV should fire WRD-112"
    );
    assert_eq!(findings[0].rule_id, "WRD-112");
}

#[test]
fn test_wrd112_no_github_env_write_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no special files touched here"
"#;
    let findings = audit_with(&wrd112::Wrd112, yaml);
    assert!(
        findings.is_empty(),
        "run with no GITHUB_ENV write should not fire WRD-112"
    );
}

// ---------------------------------------------------------------------------
// WRD-113: Tainted Reusable Workflow Inputs
// ---------------------------------------------------------------------------

#[test]
fn test_wrd113_reusable_with_head_ref_vulnerable() {
    let yaml = r#"
name: t
on: pull_request_target
jobs:
  call:
    uses: my-org/shared/.github/workflows/build.yml@main
    with:
      branch: ${{ github.head_ref }}
"#;
    let findings = audit_with(&wrd113::Wrd113, yaml);
    assert!(
        !findings.is_empty(),
        "github.head_ref forwarded to reusable workflow should fire WRD-113"
    );
    assert_eq!(findings[0].rule_id, "WRD-113");
}

#[test]
fn test_wrd113_reusable_with_literals_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  call:
    uses: my-org/shared/.github/workflows/build.yml@main
    with:
      branch: main
      env: production
"#;
    let findings = audit_with(&wrd113::Wrd113, yaml);
    assert!(
        findings.is_empty(),
        "literal-only inputs should not fire WRD-113"
    );
}

// ---------------------------------------------------------------------------
// WRD-201: Dangerous Fork Checkout
// ---------------------------------------------------------------------------

#[test]
fn test_wrd201_pr_target_checkout_head_ref_vulnerable() {
    let yaml = r#"
name: t
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"#;
    let findings = audit_with(&wrd201::Wrd201, yaml);
    assert!(
        !findings.is_empty(),
        "pull_request_target + checkout of PR head should fire WRD-201"
    );
    assert_eq!(findings[0].rule_id, "WRD-201");
}

#[test]
fn test_wrd201_pr_target_no_head_checkout_safe() {
    let yaml = r#"
name: t
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "no ref to PR head"
"#;
    let findings = audit_with(&wrd201::Wrd201, yaml);
    assert!(
        findings.is_empty(),
        "pull_request_target without PR-head checkout should not fire WRD-201"
    );
}

// ---------------------------------------------------------------------------
// WRD-202: Build Tool Execution on Untrusted Code
// ---------------------------------------------------------------------------

#[test]
fn test_wrd202_pr_target_checkout_then_npm_install_vulnerable() {
    let yaml = r#"
name: t
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: npm install
"#;
    let findings = audit_with(&wrd202::Wrd202, yaml);
    assert!(
        !findings.is_empty(),
        "pull_request_target + PR-head checkout + npm install should fire WRD-202"
    );
    assert_eq!(findings[0].rule_id, "WRD-202");
}

#[test]
fn test_wrd202_pr_target_no_build_safe() {
    let yaml = r#"
name: t
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: echo "no build commands here"
"#;
    let findings = audit_with(&wrd202::Wrd202, yaml);
    assert!(
        findings.is_empty(),
        "PR-head checkout without any build tool should not fire WRD-202"
    );
}

// ---------------------------------------------------------------------------
// WRD-203: Cross-Workflow Privilege Escalation
// ---------------------------------------------------------------------------

#[test]
fn test_wrd203_workflow_run_write_all_with_download_vulnerable() {
    let yaml = r#"
name: t
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: ./deploy.sh
"#;
    let findings = audit_with(&wrd203::Wrd203, yaml);
    assert!(
        !findings.is_empty(),
        "workflow_run + write-all + download-artifact should fire WRD-203"
    );
    assert_eq!(findings[0].rule_id, "WRD-203");
}

#[test]
fn test_wrd203_workflow_run_contents_read_safe() {
    let yaml = r#"
name: t
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
permissions:
  contents: read
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no artifact download, no write perms"
"#;
    let findings = audit_with(&wrd203::Wrd203, yaml);
    assert!(
        findings.is_empty(),
        "workflow_run with contents:read and no artifact download should not fire WRD-203"
    );
}
