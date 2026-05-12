//! `ExprIndex`: pre-parsed expression occurrences across a `LoadedWorkflow`.
//!
//! Built once per workflow. Rules query it by step path (when only the
//! step's run/with values are interesting) or iterate every occurrence
//! (when scanning broadly).

use super::ast::Expr;
use super::extract::{extract_expressions, ExtractedExpression};
use super::parser::parse;
use crate::models::{Job, Step, Workflow};

/// One parsed `${{ ... }}` occurrence.
#[derive(Debug, Clone)]
pub struct ExprOccurrence {
    /// Logical location: e.g. `jobs.build.steps[2].run` or
    /// `jobs.build.steps[1].with.script`.
    pub path: String,
    /// The raw expression text (between `${{` and `}}`).
    pub raw: String,
    /// Byte offset (within the *enclosing field's value text*, not the
    /// whole workflow) where the `${{` starts.
    pub byte_start_in_field: usize,
    /// Newline count in the field's value text before the `${{`. Add this
    /// to the field's `start_line` to get the actual line of the
    /// interpolation in source. Necessary for correct line attribution in
    /// multi-line block scalars (`run: |`).
    pub line_offset_in_field: usize,
    /// Parsed AST (or None if the expression failed to parse).
    pub ast: Option<Expr>,
}

/// Indexed view of every `${{ ... }}` occurrence in a workflow, queryable
/// by step path or in bulk.
#[derive(Debug, Default)]
pub struct ExprIndex {
    occurrences: Vec<ExprOccurrence>,
}

impl ExprIndex {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn build(workflow: &Workflow) -> Self {
        Self {
            occurrences: build(workflow),
        }
    }

    pub fn occurrences(&self) -> &[ExprOccurrence] {
        &self.occurrences
    }

    /// Iterate all occurrences whose logical path starts with `prefix`.
    pub fn at_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a ExprOccurrence> {
        self.occurrences
            .iter()
            .filter(move |o| o.path.starts_with(prefix))
    }

    pub fn len(&self) -> usize {
        self.occurrences.len()
    }

    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }
}

/// Walk a typed workflow, scan every string-bearing field for `${{ ... }}`,
/// parse each, and return the collection. Parse failures are recorded as
/// occurrences with `ast: None` so callers can decide how to handle them.
pub fn build(workflow: &Workflow) -> Vec<ExprOccurrence> {
    let mut out = Vec::new();

    if let Some(env) = &workflow.env {
        for (k, v) in env {
            scan_string(&format!("env.{k}"), &v.as_str_owned(), &mut out);
        }
    }
    if let Some(rn) = &workflow.run_name {
        scan_string("run-name", rn, &mut out);
    }
    if let Some(name) = &workflow.name {
        scan_string("name", name, &mut out);
    }

    for (job_name, job) in &workflow.jobs {
        let job_path = format!("jobs.{job_name}");
        match job {
            Job::Normal(j) => {
                if let Some(if_) = &j.if_ {
                    scan_string(&format!("{job_path}.if"), if_, &mut out);
                }
                if let Some(env) = &j.env {
                    for (k, v) in env {
                        scan_string(&format!("{job_path}.env.{k}"), &v.as_str_owned(), &mut out);
                    }
                }
                for (i, step) in j.steps.iter().enumerate() {
                    let step_path = format!("{job_path}.steps[{i}]");
                    visit_step(step, &step_path, &mut out);
                }
            }
            Job::Reusable(r) => {
                if let Some(if_) = &r.if_ {
                    scan_string(&format!("{job_path}.if"), if_, &mut out);
                }
                scan_string(&format!("{job_path}.uses"), &r.uses, &mut out);
                if let Some(with) = &r.with {
                    for (k, v) in with {
                        if let Some(s) = v.as_str() {
                            scan_string(&format!("{job_path}.with.{k}"), s, &mut out);
                        }
                    }
                }
            }
        }
    }

    out
}

fn visit_step(step: &Step, base: &str, out: &mut Vec<ExprOccurrence>) {
    match step {
        Step::Uses(u) => {
            scan_string(&format!("{base}.uses"), &u.uses, out);
            if let Some(if_) = &u.if_ {
                scan_string(&format!("{base}.if"), if_, out);
            }
            if let Some(with) = &u.with {
                for (k, v) in with {
                    scan_string(&format!("{base}.with.{k}"), &v.as_str_owned(), out);
                }
            }
            if let Some(env) = &u.env {
                for (k, v) in env {
                    scan_string(&format!("{base}.env.{k}"), &v.as_str_owned(), out);
                }
            }
        }
        Step::Run(r) => {
            scan_string(&format!("{base}.run"), &r.run, out);
            if let Some(if_) = &r.if_ {
                scan_string(&format!("{base}.if"), if_, out);
            }
            if let Some(env) = &r.env {
                for (k, v) in env {
                    scan_string(&format!("{base}.env.{k}"), &v.as_str_owned(), out);
                }
            }
        }
        Step::Other(_) => {}
    }
}

fn scan_string(path: &str, text: &str, out: &mut Vec<ExprOccurrence>) {
    for ext in extract_expressions(text) {
        let ExtractedExpression {
            inner,
            byte_start,
            byte_end: _,
        } = ext;
        let line_offset_in_field = text[..byte_start].matches('\n').count();
        let ast = parse(&inner).ok();
        out.push(ExprOccurrence {
            path: path.to_string(),
            raw: inner,
            byte_start_in_field: byte_start,
            line_offset_in_field,
            ast,
        });
    }
}

// (Previously a reserved no-op hook for the `on:` field lived here. Removed
// because it was unused and clippy flagged the &mut Vec<_> signature.)

#[cfg(test)]
mod tests {
    use super::super::taint::is_tainted;
    use super::*;

    fn parse_workflow(yaml: &str) -> Workflow {
        serde_yaml::from_str(yaml).expect("parse")
    }

    #[test]
    fn finds_run_block_expression() {
        let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
"#;
        let occs = build(&parse_workflow(yaml));
        assert_eq!(occs.len(), 1);
        assert_eq!(occs[0].path, "jobs.build.steps[0].run");
        let ast = occs[0].ast.as_ref().unwrap();
        let path = &ast.all_paths()[0];
        assert!(is_tainted(path));
    }

    #[test]
    fn finds_with_value_expressions() {
        let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
"#;
        let occs = build(&parse_workflow(yaml));
        assert_eq!(occs.len(), 1);
        assert!(occs[0].path.ends_with("with.ref"));
        assert!(is_tainted(&occs[0].ast.as_ref().unwrap().all_paths()[0]));
    }

    #[test]
    fn skips_strings_without_expressions() {
        let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no expressions here"
"#;
        let occs = build(&parse_workflow(yaml));
        assert!(occs.is_empty());
    }

    #[test]
    fn unparseable_expression_kept_with_none_ast() {
        let yaml = r#"
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ${{ this is not valid }}
"#;
        let occs = build(&parse_workflow(yaml));
        assert_eq!(occs.len(), 1);
        assert!(occs[0].ast.is_none());
    }
}
