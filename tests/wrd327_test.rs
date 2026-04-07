//! Tests for WRD-327 (Composite Action Internal Unpinned References).
//!
//! These tests exercise the action.yml parser in isolation. They DO NOT hit
//! the real GitHub API. Network behavior is covered by manual runs.

use wardenscan::rules::wrd327::{parse_action_yml, UnpinnedRef};

#[test]
fn test_wrd327_composite_with_unpinned_checkout() {
    let yml = r#"
name: my-action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      shell: bash
"#;
    let findings = parse_action_yml(yml);
    assert_eq!(findings.len(), 1, "expected 1 unpinned ref");
    assert_eq!(
        findings[0],
        UnpinnedRef {
            value: "actions/checkout@v4".to_string(),
            kind: "composite",
        }
    );
}

#[test]
fn test_wrd327_composite_fully_pinned() {
    let yml = r#"
name: my-action
runs:
  using: composite
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
      with:
        node-version: 20
"#;
    let findings = parse_action_yml(yml);
    assert!(
        findings.is_empty(),
        "expected 0 findings, got: {findings:?}"
    );
}

#[test]
fn test_wrd327_composite_mixed() {
    let yml = r#"
name: my-action
runs:
  using: composite
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    - uses: third-party/setup@main
    - uses: actions/setup-node@v4
    - run: echo hello
      shell: bash
"#;
    let findings = parse_action_yml(yml);
    assert_eq!(
        findings.len(),
        2,
        "expected 2 unpinned refs, got {findings:?}"
    );
    let values: Vec<&str> = findings.iter().map(|f| f.value.as_str()).collect();
    assert!(values.contains(&"third-party/setup@main"));
    assert!(values.contains(&"actions/setup-node@v4"));
}

#[test]
fn test_wrd327_docker_unpinned() {
    let yml = r#"
name: docker-action
runs:
  using: docker
  image: docker://alpine:latest
"#;
    let findings = parse_action_yml(yml);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "docker");
    assert_eq!(findings[0].value, "docker://alpine:latest");
}

#[test]
fn test_wrd327_docker_sha_pinned() {
    let yml = r#"
name: docker-action
runs:
  using: docker
  image: docker://alpine@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48
"#;
    let findings = parse_action_yml(yml);
    assert!(
        findings.is_empty(),
        "sha256-pinned docker image should not flag, got: {findings:?}"
    );
}

#[test]
fn test_wrd327_node20_action_no_refs() {
    let yml = r#"
name: my-js-action
runs:
  using: node20
  main: dist/index.js
"#;
    let findings = parse_action_yml(yml);
    assert!(
        findings.is_empty(),
        "node20 action has no internal references, got: {findings:?}"
    );
}

#[test]
fn test_wrd327_malformed_yaml_does_not_panic() {
    let yml = r#"
name: broken
runs:
  using: composite
  steps: [this is: not
    valid - yaml @@@
"#;
    let findings = parse_action_yml(yml);
    assert!(
        findings.is_empty(),
        "malformed yaml should silently return empty, got: {findings:?}"
    );
}
