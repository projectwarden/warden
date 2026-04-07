use wardenscan::fix::fix_workflow;
use wardenscan::scanner::Workflow;

fn wf(yaml: &str) -> Workflow {
    Workflow {
        path: "test.yml".into(),
        content: yaml.into(),
        parsed: serde_yaml::from_str(yaml).unwrap_or_default(),
    }
}

#[test]
fn test_wrd824_adds_permissions_read_all() {
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(result.fixed.contains("permissions: read-all"));
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("permissions: read-all")));
}

#[test]
fn test_wrd824_skips_when_permissions_present() {
    let yaml = "name: CI\non: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(!result
        .fixes
        .iter()
        .any(|f| f.description.contains("Added top-level permissions")));
}

#[test]
fn test_wrd826_adds_permissions_comment() {
    let yaml = "name: CI\non: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(result
        .fixed
        .contains("# Permissions are scoped to least privilege"));
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("documentation comment")));
}

#[test]
fn test_wrd831_adds_concurrency_block() {
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(result.fixed.contains("concurrency:"));
    assert!(result
        .fixed
        .contains("group: ${{ github.workflow }}-${{ github.ref }}"));
    assert!(result.fixed.contains("cancel-in-progress: true"));
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("concurrency")));
}

#[test]
fn test_wrd831_skips_when_concurrency_present() {
    let yaml = "name: CI\non: push\nconcurrency:\n  group: foo\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(!result
        .fixes
        .iter()
        .any(|f| f.description.contains("concurrency")));
}
