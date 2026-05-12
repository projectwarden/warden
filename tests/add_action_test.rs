//! Integration tests for `warden add-action`.
//!
//! The most important test in this file is
//! `generated_workflow_passes_warden_own_scan`: it scans the YAML emitted
//! by `add_action::generate_workflow_yaml` with the full warden rule set
//! and asserts ZERO findings at any severity. If you change the workflow
//! template, this test enforces that the new template still applies our
//! own rules to itself. Without this guard rail we'd ship a "best
//! practice" workflow that violates our own best practices.

use std::fs;
use std::path::PathBuf;

use wardenscan::add_action::{
    generate_workflow_yaml, write_workflow_file, CHECKOUT_SHA, CHECKOUT_VERSION, WARDEN_ACTION_SHA,
    WARDEN_ACTION_VERSION, WORKFLOW_PATH,
};
use wardenscan::scanner;

fn unique_tempdir(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "warden-add-action-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&p).expect("create tempdir");
    p
}

#[test]
fn generated_workflow_is_valid_yaml() {
    let yaml = generate_workflow_yaml("high").expect("generate");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("parse YAML");
    // Top-level keys we expect.
    let map = parsed.as_mapping().expect("top-level mapping");
    assert!(map.contains_key("name"));
    assert!(map.contains_key("on"));
    assert!(map.contains_key("permissions"));
    assert!(map.contains_key("concurrency"));
    assert!(map.contains_key("jobs"));
}

#[test]
fn generated_workflow_passes_warden_own_scan() {
    // The keystone test. Generate the YAML, write it to a temp dir,
    // load via the same `scanner::load_local` warden uses, run the
    // full ruleset, and assert ZERO findings of ANY severity. If a new
    // rule starts firing on our own template, we either:
    //   - fix the template, or
    //   - fix the rule (false positive), or
    //   - explicitly suppress the finding via `.warden.toml`
    // The default expectation is "the template is clean".
    let tmp = unique_tempdir("self-scan");
    let yaml = generate_workflow_yaml("high").expect("generate");
    let workflows_dir = tmp.join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).unwrap();
    fs::write(workflows_dir.join("warden.yml"), &yaml).unwrap();

    let workflows = scanner::load_local(&tmp.to_string_lossy()).expect("load_local");
    assert_eq!(
        workflows.len(),
        1,
        "expected exactly one workflow file in the temp repo"
    );

    let findings = scanner::scan(&workflows);

    if !findings.is_empty() {
        // Print every finding so a CI failure tells the maintainer
        // exactly what broke the self-compliance contract.
        for f in &findings {
            eprintln!(
                "  {} [{}] {} ({}:{})",
                f.severity, f.rule_id, f.title, f.file, f.line
            );
        }
        panic!(
            "warden's own add-action template emitted {} finding(s) when scanned by warden itself. Fix the template (src/add_action.rs::generate_workflow_yaml) or the rule(s).",
            findings.len()
        );
    }

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn fail_on_value_is_normalized() {
    let y = generate_workflow_yaml("HIGH").unwrap();
    assert!(y.contains("fail-on: high"));
    let y = generate_workflow_yaml("Critical").unwrap();
    assert!(y.contains("fail-on: critical"));
}

#[test]
fn fail_on_value_round_trips_for_every_level() {
    for level in ["critical", "high", "medium", "low", "none"] {
        let y = generate_workflow_yaml(level).unwrap();
        assert!(
            y.contains(&format!("fail-on: {level}")),
            "expected fail-on: {level} in output"
        );
    }
}

#[test]
fn fail_on_invalid_value_is_rejected() {
    let err = generate_workflow_yaml("warning").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid --fail-on"), "got: {msg}");
}

#[test]
fn both_actions_are_sha_pinned_with_version_comment() {
    let y = generate_workflow_yaml("high").unwrap();
    assert!(y.contains(&format!("actions/checkout@{CHECKOUT_SHA}")));
    assert!(y.contains(&format!("# {CHECKOUT_VERSION}")));
    assert!(y.contains(&format!("projectwarden/warden@{WARDEN_ACTION_SHA}")));
    assert!(y.contains(&format!("# {WARDEN_ACTION_VERSION}")));
}

#[test]
fn write_workflow_file_creates_file_at_expected_path() {
    let tmp = unique_tempdir("write");
    let yaml = generate_workflow_yaml("high").unwrap();
    let written = write_workflow_file(&tmp, &yaml).expect("write");
    assert!(written.ends_with(WORKFLOW_PATH));
    assert!(written.exists());
    let on_disk = fs::read_to_string(&written).unwrap();
    assert_eq!(on_disk, yaml);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn write_workflow_file_refuses_to_overwrite() {
    let tmp = unique_tempdir("no-overwrite");
    let yaml = generate_workflow_yaml("high").unwrap();
    write_workflow_file(&tmp, &yaml).unwrap();
    let err = write_workflow_file(&tmp, &yaml).unwrap_err();
    assert!(err.to_string().contains("already exists"));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn write_workflow_file_errors_on_missing_parent() {
    let bogus = std::env::temp_dir().join("warden-add-action-definitely-does-not-exist-xyzzy");
    let _ = fs::remove_dir_all(&bogus); // ensure absent
    let err = write_workflow_file(&bogus, "name: warden").unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}
