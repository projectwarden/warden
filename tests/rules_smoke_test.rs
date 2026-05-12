//! End-to-end smoke test for the `warden` binary.
//!
//! Every other rule test in this crate exercises the detection code in-process
//! by constructing an `AuditCtx` and running a single `Rule`. This file does
//! the opposite: it invokes the real `warden` CLI as a subprocess against a
//! synthetic `.github/workflows/` tree and validates the JSON output shape,
//! so that the scanner -> rules -> output pipeline is exercised as a user
//! would exercise it.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// RAII guard so a panicking assertion still cleans up the tmpdir.
struct TmpDir(PathBuf);

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_fixture() -> TmpDir {
    let root = std::env::temp_dir().join(format!(
        "warden_smoke_{}_{}",
        std::process::id(),
        // nanos-since-epoch gives us uniqueness within a single process when
        // tests run in parallel and the same pid reuses this helper.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let wf_dir = root.join(".github").join("workflows");
    fs::create_dir_all(&wf_dir).expect("create .github/workflows");

    // WRD-101 positive: user-controlled issue title interpolated directly into
    // a `run:` block. This is the canonical expression-injection pattern and
    // is registered as CRITICAL in src/rules/wrd101.rs.
    let vulnerable = r#"name: smoke
on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"#;
    fs::write(wf_dir.join("vulnerable.yml"), vulnerable).expect("write workflow");

    TmpDir(root)
}

#[test]
fn warden_scan_end_to_end_emits_wrd101_finding() {
    let fixture = make_fixture();
    let bin = env!("CARGO_BIN_EXE_warden");

    let out = Command::new(bin)
        .arg("scan")
        .arg(fixture.0.as_os_str())
        .arg("--format")
        .arg("json")
        // Exit 0 regardless of findings so a non-zero status from the
        // `--fail-on high` default does not mask a JSON shape bug.
        .arg("--fail-on")
        .arg("none")
        .output()
        .expect("spawn warden binary");

    assert!(
        out.status.success(),
        "warden scan exited with {:?}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON: {e}\n{stdout}"));

    // Top-level shape sanity: total_findings, summary, findings[] all present.
    assert!(
        parsed.get("total_findings").is_some(),
        "missing total_findings"
    );
    assert!(parsed.get("summary").is_some(), "missing summary");
    let findings = parsed
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings[] missing or not an array");

    let wrd101 = findings
        .iter()
        .find(|f| f.get("rule_id").and_then(|v| v.as_str()) == Some("WRD-101"))
        .unwrap_or_else(|| panic!("no WRD-101 finding in:\n{stdout}"));

    assert_eq!(
        wrd101.get("severity").and_then(|v| v.as_str()),
        Some("critical"),
        "WRD-101 severity regressed"
    );

    let file = wrd101
        .get("file")
        .and_then(|v| v.as_str())
        .expect("finding.file missing");
    assert!(
        file.ends_with("vulnerable.yml"),
        "finding.file did not point at the fixture: {file}"
    );

    // `line` must be a non-zero integer so SARIF / IDE integrations can jump
    // to the right spot; a missing line would regress that contract silently.
    let line = wrd101
        .get("line")
        .and_then(|v| v.as_u64())
        .expect("finding.line missing or not an integer");
    assert!(line > 0, "finding.line should be 1-indexed, got {line}");
}
