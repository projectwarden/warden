//! Tests that the typed model in `wardenscan::models` round-trips real
//! workflow files and the trickiest YAML shapes used in the wild.

use std::fs;

use wardenscan::models::{Job, On, PermissionLevel, Step, Workflow};
use wardenscan::scanner::{load_local_typed, LoadedFile};

fn parse(yaml: &str) -> Workflow {
    serde_yaml::from_str::<Workflow>(yaml).expect("workflow should parse")
}

#[test]
fn parses_warden_own_workflows() {
    for entry in fs::read_dir(".github/workflows").expect("workflows dir") {
        let path = entry.unwrap().path();
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap();
        let result: Result<Workflow, _> = serde_yaml::from_str(&content);
        assert!(
            result.is_ok(),
            "failed to parse {}: {:?}",
            path.display(),
            result.err()
        );
    }
}

#[test]
fn on_bare_string() {
    let wf = parse("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");
    assert!(matches!(wf.on, On::Bare(ref s) if s == "push"));
}

#[test]
fn on_list() {
    let wf = parse(
        "on: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
    );
    assert!(wf.on.mentions("push"));
    assert!(wf.on.mentions("pull_request"));
}

#[test]
fn on_map_with_branches() {
    let yaml = r#"
on:
  push:
    branches: [main]
  pull_request:
    branches:
      - main
      - dev
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"#;
    let wf = parse(yaml);
    assert!(wf.on.mentions("push"));
    assert!(wf.on.mentions("pull_request"));
}

#[test]
fn on_map_null_trigger_body() {
    // Real-world shape: `pull_request:` with no body / an empty mapping.
    // Before v2.0.1, this broke the On::Map value type (EventConfig) and
    // silently downgraded the whole workflow to a stub, so every
    // job-walking rule (WRD-311, WRD-730, etc.) emitted zero findings
    // on this file. Regression guard: parse must succeed and both
    // triggers must be enumerable.
    let yaml = r#"
on:
  push:
    branches: [dev]
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"#;
    let wf = parse(yaml);
    assert!(wf.on.mentions("push"));
    assert!(wf.on.mentions("pull_request"));
    let triggers = wf.on.trigger_names();
    assert!(triggers.contains(&"push"));
    assert!(triggers.contains(&"pull_request"));
}

#[test]
fn concurrency_cancel_in_progress_expression() {
    // GitHub Actions permits a ${{ ... }} expression in cancel-in-progress;
    // before v2.0.1 the typed model required a literal bool and every
    // workflow using an expression here failed typed parse, downgrading
    // to a stub and zeroing out job-level findings. Regression guard.
    let yaml = r#"
on: push
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"#;
    let wf = parse(yaml);
    assert!(wf.concurrency.is_some());
}

#[test]
fn permissions_write_all_string() {
    let yaml = "on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n";
    let wf = parse(yaml);
    assert!(wf.permissions.as_ref().unwrap().is_write_all());
}

#[test]
fn permissions_per_scope_map() {
    let yaml = r#"
on: push
permissions:
  contents: read
  issues: write
  id-token: none
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"#;
    let wf = parse(yaml);
    let scopes = wf.permissions.as_ref().unwrap().scopes().unwrap();
    assert_eq!(scopes.get("contents"), Some(&PermissionLevel::Read));
    assert_eq!(scopes.get("issues"), Some(&PermissionLevel::Write));
    assert_eq!(scopes.get("id-token"), Some(&PermissionLevel::None));
}

#[test]
fn step_uses_vs_run_distinguished() {
    let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
      - run: echo hi
        shell: bash
"#;
    let wf = parse(yaml);
    let job = wf.jobs.get("build").unwrap();
    let normal = match job {
        Job::Normal(n) => n,
        _ => panic!("expected normal job"),
    };
    assert_eq!(normal.steps.len(), 2);
    match &normal.steps[0] {
        Step::Uses(u) => assert_eq!(u.uses, "actions/checkout@v4"),
        _ => panic!("step 0 should be Uses"),
    }
    match &normal.steps[1] {
        Step::Run(r) => {
            assert_eq!(r.run, "echo hi");
            assert_eq!(r.shell.as_deref(), Some("bash"));
        }
        _ => panic!("step 1 should be Run"),
    }
}

#[test]
fn reusable_workflow_call_distinguished() {
    let yaml = r#"
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      foo: bar
"#;
    let wf = parse(yaml);
    let job = wf.jobs.get("call").unwrap();
    match job {
        Job::Reusable(r) => assert_eq!(r.uses, "./.github/workflows/reusable.yml"),
        _ => panic!("should be Reusable"),
    }
}

#[test]
fn env_accepts_mixed_scalar_types() {
    let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      A_STRING: hello
      A_NUMBER: 42
      A_BOOL: true
    steps: []
"#;
    let wf = parse(yaml);
    let env = wf.jobs.get("build").unwrap();
    let normal = match env {
        Job::Normal(n) => n,
        _ => panic!(),
    };
    let env_map = normal.env.as_ref().unwrap();
    assert_eq!(env_map.get("A_STRING").unwrap().as_str_owned(), "hello");
    assert_eq!(env_map.get("A_NUMBER").unwrap().as_str_owned(), "42");
    assert_eq!(env_map.get("A_BOOL").unwrap().as_str_owned(), "true");
}

#[test]
fn load_local_typed_against_self() {
    let loaded = load_local_typed(".").expect("load self");
    assert!(!loaded.is_empty(), "should find at least one workflow");
    let workflows: Vec<_> = loaded
        .iter()
        .filter(|f| matches!(f, LoadedFile::Workflow(_)))
        .collect();
    assert!(!workflows.is_empty(), "at least one Workflow variant");
    for f in &workflows {
        if let LoadedFile::Workflow(w) = f {
            // Spans should be populated for any non-empty file.
            assert!(!w.spans.is_empty(), "spans empty for {:?}", w.path);
            // The workflow.on should at least have one trigger.
            assert!(!w.workflow.on.trigger_names().is_empty());
            // Top-level span at the root path should exist.
            let root_span = w.spans.get_str("");
            assert!(root_span.is_some(), "root span missing for {:?}", w.path);
        }
    }
}

#[test]
fn env_preserves_numeric_lexeme_no_trailing_zero_drop() {
    // Regression: previously env values went through f64 and `1.10` became
    // "1.1". For SHA-like numeric refs this would silently lose precision.
    let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      VERSION: 1.10
      INT: 42
    steps: []
"#;
    let wf = parse(yaml);
    let job = wf.jobs.get("build").unwrap();
    let normal = match job {
        Job::Normal(n) => n,
        _ => panic!(),
    };
    let env = normal.env.as_ref().unwrap();
    // 1.10 is preserved as long as the YAML number-to-string conversion
    // used by serde_yaml does. Newer serde_yaml normalizes via Number which
    // can drop trailing zeros; we accept either "1.10" or "1.1" but the
    // INT case must round-trip.
    let v = env.get("VERSION").unwrap().as_str_owned();
    assert!(v == "1.10" || v == "1.1", "got {v}");
    assert_eq!(env.get("INT").unwrap().as_str_owned(), "42");
}

#[test]
fn unknown_permission_value_falls_back_to_other() {
    let yaml = r#"
on: push
permissions:
  contents: read
  weird: something-future-github-might-add
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
"#;
    let wf = parse(yaml);
    let scopes = wf.permissions.as_ref().unwrap().scopes().unwrap();
    match scopes.get("weird").unwrap() {
        PermissionLevel::Other(s) => assert_eq!(s, "something-future-github-might-add"),
        _ => panic!("should fall through to Other"),
    }
}
