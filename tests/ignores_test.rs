//! End-to-end tests for inline `# warden: ignore[...]` suppression.
//!
//! Validates that the suppression filter applied in `scan_full` actually
//! removes findings produced by V1 rules.

use wardenscan::scanner::{scan_full, Workflow};

fn workflow(yaml: &str) -> Workflow {
    Workflow {
        path: "test.yml".into(),
        content: yaml.into(),
        parsed: serde_yaml::from_str(yaml).unwrap_or_default(),
    }
}

#[test]
fn ignore_trailing_suppresses_wrd101() {
    let with_finding = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"#;
    let suppressed = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"  # warden: ignore[WRD-101]
"#;

    let baseline = scan_full(&[workflow(with_finding)], None, false);
    let with_ignore = scan_full(&[workflow(suppressed)], None, false);

    let baseline_101 = baseline.iter().filter(|f| f.rule_id == "WRD-101").count();
    let suppressed_101 = with_ignore
        .iter()
        .filter(|f| f.rule_id == "WRD-101")
        .count();

    assert!(baseline_101 > 0, "baseline should detect WRD-101");
    assert_eq!(suppressed_101, 0, "trailing ignore should suppress WRD-101");
}

#[test]
fn ignore_standalone_suppresses_next_line() {
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # warden: ignore[WRD-101]
      - run: echo "${{ github.event.issue.title }}"
"#;
    let findings = scan_full(&[workflow(yaml)], None, false);
    let count = findings.iter().filter(|f| f.rule_id == "WRD-101").count();
    assert_eq!(count, 0, "standalone ignore should suppress next code line");
}

#[test]
fn ignore_specific_does_not_suppress_others() {
    // This workflow trips both WRD-101 (expression injection) and a
    // top-level permissions finding (WRD-824). Suppressing WRD-101 alone
    // must leave WRD-824 intact.
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"  # warden: ignore[WRD-101]
"#;
    let findings = scan_full(&[workflow(yaml)], None, false);
    assert!(
        findings.iter().any(|f| f.rule_id != "WRD-101"),
        "non-101 findings should remain"
    );
    assert_eq!(
        findings.iter().filter(|f| f.rule_id == "WRD-101").count(),
        0
    );
}

#[test]
fn v2_wrd101_finding_line_points_at_actual_interpolation_in_block_scalar() {
    // Regression: WRD-101 V2 used to report the run: header line for any
    // interpolation in a `run: |` block. That broke trailing ignore
    // comments on the actual interpolation line. Fixed by tracking
    // `line_offset_in_field` on each ExprOccurrence.
    let yaml = "name: CI\non: issues\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"safe\"\n          echo \"${{ github.event.issue.body }}\"\n";
    let findings = scan_full(&[workflow(yaml)], None, false);
    let wrd101: Vec<_> = findings.iter().filter(|f| f.rule_id == "WRD-101").collect();
    assert_eq!(
        wrd101.len(),
        1,
        "should detect exactly one tainted expression"
    );
    // The injection is on line 9 (`echo "${{ ... }}"`), not line 7 (`run: |`).
    assert_eq!(
        wrd101[0].line, 9,
        "finding should point at the interpolation line, got {}",
        wrd101[0].line
    );
}

#[test]
fn v2_wrd101_catches_taint_wrapped_in_format() {
    // The legacy regex-based WRD-101 only matched on the canonical list of
    // ${{ <tainted> }} occurrences. The V2 implementation walks the
    // expression AST and catches the tainted source even when it's wrapped
    // in `format(...)`, `contains(...)`, or other function calls.
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ format('hi {0}', github.event.issue.body) }}"
"#;
    let findings = scan_full(&[workflow(yaml)], None, false);
    assert!(
        findings.iter().any(|f| f.rule_id == "WRD-101"),
        "V2 should catch the format-wrapped tainted source"
    );
}

#[test]
fn ignore_all_form_suppresses_everything_on_line() {
    let yaml = r#"
name: CI
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"  # warden: ignore
"#;
    let findings = scan_full(&[workflow(yaml)], None, false);
    let line_8_findings = findings.iter().filter(|f| f.line == 8).count();
    assert_eq!(line_8_findings, 0, "ignore-all form clears the line");
}
