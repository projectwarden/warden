//! End-to-end tests for WRD-130 with cross-step taint propagation.
//!
//! Each test sets up a workflow with one step that writes to GITHUB_OUTPUT
//! and a second step that reads it via `${{ steps.X.outputs.Y }}`. The
//! outcome depends on the upstream source: tainted -> Critical, safe ->
//! suppressed, unknown -> Low advisory.

use wardenscan::expression::ExprIndex;
use wardenscan::ignores::IgnoreMap;
use wardenscan::rules::{wrd130, AuditCtx, Rule};
use wardenscan::scanner::{load_one, stub_workflow, LoadedFile};
use wardenscan::shell::ShellIndex;
use wardenscan::taint;

fn run(yaml: &str) -> Vec<String> {
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
    let findings = wrd130::Wrd130.audit(&ctx);
    findings
        .into_iter()
        .map(|f| format!("{:?}", f.severity))
        .collect()
}

const SAFE_GITHUB_REF_NAME: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: version
        run: echo "value=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.version.outputs.value }}"
"#;

const SAFE_GITHUB_SHA: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: meta
        run: echo "sha=${GITHUB_SHA}" >> $GITHUB_OUTPUT
      - run: docker tag foo:${{ steps.meta.outputs.sha }}
"#;

const SAFE_LITERAL: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: pin
        run: echo "version=1.2.3" >> $GITHUB_OUTPUT
      - run: echo using ${{ steps.pin.outputs.version }}
"#;

const TAINTED_ISSUE_BODY: &str = r#"
name: t
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: grab
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "Got ${{ steps.grab.outputs.title }}"
"#;

const TAINTED_HEAD_REF: &str = r#"
name: t
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: head
        run: echo "branch=${{ github.head_ref }}" >> $GITHUB_OUTPUT
      - run: git checkout ${{ steps.head.outputs.branch }}
"#;

const UNKNOWN_COMMAND_SUB: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: stamp
        run: echo "ts=$(date +%s)" >> $GITHUB_OUTPUT
      - run: echo run-${{ steps.stamp.outputs.ts }}
"#;

const UNKNOWN_BARE_VAR: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: x
        run: |
          MY_VAR=hello
          echo "out=${MY_VAR}" >> $GITHUB_OUTPUT
      - run: echo ${{ steps.x.outputs.out }}
"#;

const ORPHANED_READ: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ steps.never_existed.outputs.foo }}
"#;

const HEREDOC_WRITE: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: ml
        run: |
          echo "body<<EOF" >> $GITHUB_OUTPUT
          cat README.md >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT
      - run: echo ${{ steps.ml.outputs.body }}
"#;

const QUOTED_OUTPUT_VAR_SAFE: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: build
        run: echo "digest=${GITHUB_SHA}" >> "$GITHUB_OUTPUT"
      - run: docker push foo:${{ steps.build.outputs.digest }}
"#;

const MULTI_OUTPUTS_SAME_STEP: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: meta
        run: |
          echo "tag=${GITHUB_REF_NAME}" >> $GITHUB_OUTPUT
          echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
      - run: echo "tag is ${{ steps.meta.outputs.tag }}, title is ${{ steps.meta.outputs.title }}"
"#;

const NON_RUN_INTERPOLATION: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: x
        run: echo "v=foo" >> $GITHUB_OUTPUT
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          ref: ${{ steps.x.outputs.v }}
"#;

const NO_RUN_BLOCKS_AT_ALL: &str = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"#;

#[test]
fn safe_ref_name_suppresses_finding() {
    assert_eq!(run(SAFE_GITHUB_REF_NAME), Vec::<String>::new());
}

#[test]
fn safe_sha_suppresses_finding() {
    assert_eq!(run(SAFE_GITHUB_SHA), Vec::<String>::new());
}

#[test]
fn literal_suppresses_finding() {
    assert_eq!(run(SAFE_LITERAL), Vec::<String>::new());
}

#[test]
fn tainted_issue_body_emits_critical() {
    assert_eq!(run(TAINTED_ISSUE_BODY), vec!["Critical".to_string()]);
}

#[test]
fn tainted_head_ref_emits_critical() {
    assert_eq!(run(TAINTED_HEAD_REF), vec!["Critical".to_string()]);
}

#[test]
fn command_substitution_emits_low_advisory() {
    assert_eq!(run(UNKNOWN_COMMAND_SUB), vec!["Low".to_string()]);
}

#[test]
fn bare_bash_variable_emits_low_advisory() {
    assert_eq!(run(UNKNOWN_BARE_VAR), vec!["Low".to_string()]);
}

#[test]
fn orphaned_read_with_no_writer_emits_low() {
    assert_eq!(run(ORPHANED_READ), vec!["Low".to_string()]);
}

#[test]
fn heredoc_write_emits_low_conservative() {
    assert_eq!(run(HEREDOC_WRITE), vec!["Low".to_string()]);
}

#[test]
fn quoted_output_var_with_safe_source_suppresses_finding() {
    assert_eq!(run(QUOTED_OUTPUT_VAR_SAFE), Vec::<String>::new());
}

#[test]
fn multi_output_step_handles_each_key_independently() {
    // Both reads happen in one run: block. The safe one (tag) should NOT
    // fire, the tainted one (title) SHOULD fire as Critical. Since the
    // V2 emits at most one finding per occurrence (it `break`s after
    // matching), we expect exactly one Critical here.
    let out = run(MULTI_OUTPUTS_SAME_STEP);
    assert_eq!(out, vec!["Critical".to_string()]);
}

#[test]
fn non_run_interpolation_does_not_fire() {
    // The read is in `with:`, not `run:`. WRD-130 intentionally only
    // covers run blocks (other rules cover with values).
    assert_eq!(run(NON_RUN_INTERPOLATION), Vec::<String>::new());
}

#[test]
fn no_run_blocks_no_findings() {
    assert_eq!(run(NO_RUN_BLOCKS_AT_ALL), Vec::<String>::new());
}
