use crate::expression::PathSeg;
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::taint::TaintSource;
use crate::yamlpath::Span;

pub struct Wrd130;

impl Rule for Wrd130 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-130",
            name: "Step Output Read (Unknown Provenance)",
            default_severity: Severity::Low,
            description: "steps.*.outputs.* values can be tainted if a previous step set the \
                          output from attacker-controlled data; do not interpolate them in \
                          run: blocks.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for occ in ctx.expressions.occurrences() {
            if !occ.path.ends_with(".run") {
                continue;
            }
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                let Some((step_id, output_key)) = match_steps_output_path(&path) else {
                    continue;
                };

                // Cross-step taint propagation. If we know the upstream
                // write was from a Safe (GitHub-validated) source or a
                // static literal, suppress the finding. If it was from a
                // Tainted source, escalate severity to Critical because
                // we have a confirmed end-to-end injection. Otherwise
                // (Unknown / no provenance), keep the advisory Low.
                let provenance = ctx.provenance.get(&step_id, &output_key);
                let (severity, title_suffix, description) = match provenance {
                    Some(TaintSource::Safe(_)) | Some(TaintSource::Literal) => continue,
                    Some(TaintSource::Secret(_)) => continue,
                    Some(TaintSource::Tainted(src)) => (
                        Severity::Critical,
                        " (taint chain confirmed)".to_string(),
                        format!(
                            "Confirmed cross-step injection. Step `{step_id}` set its `{output_key}` \
                             output from `{src}`, an attacker-controlled source. This run: block \
                             then interpolates that output, executing the attacker's payload as \
                             shell."
                        ),
                    ),
                    Some(TaintSource::Unknown) | None => (
                        Severity::Low,
                        String::new(),
                        format!(
                            "Step `{step_id}` output `{output_key}` is interpolated in a run: \
                             block. The upstream source could not be statically determined; if it \
                             traces to attacker-controlled data, this is a delayed command \
                             injection."
                        ),
                    ),
                };

                let field_span = ctx
                    .loaded
                    .spans
                    .get_str(&occ.path)
                    .unwrap_or_else(Span::placeholder);
                let actual_line = field_span.start_line + occ.line_offset_in_field;
                let span = Span::new(
                    field_span.byte_start,
                    field_span.byte_end,
                    actual_line,
                    field_span.start_col,
                    actual_line,
                    field_span.end_col,
                );
                findings.push(RuleFinding {
                    rule_id: "WRD-130",
                    severity,
                    title: format!("Step output interpolated in run: block{title_suffix}"),
                    description,
                    primary: span,
                    related: Vec::new(),
                    remediation: "Pass the output through an environment variable instead of \
                                  direct interpolation, or validate it before use."
                        .into(),
                });
                break;
            }
        }
        findings
    }
}

/// Match a flattened expression path that looks like
/// `steps.<step_id>.outputs.<key>` and return the step_id + key. Returns
/// None for any other shape.
fn match_steps_output_path(path: &[PathSeg]) -> Option<(String, String)> {
    if path.len() < 4 {
        return None;
    }
    let PathSeg::Root(root) = &path[0] else {
        return None;
    };
    if root != "steps" {
        return None;
    }
    let PathSeg::Field(step_id) = &path[1] else {
        return None;
    };
    let PathSeg::Field(outputs_lit) = &path[2] else {
        return None;
    };
    if outputs_lit != "outputs" {
        return None;
    }
    let PathSeg::Field(output_key) = &path[3] else {
        return None;
    };
    Some((step_id.clone(), output_key.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(s: &str) -> PathSeg {
        PathSeg::Root(s.into())
    }
    fn field(s: &str) -> PathSeg {
        PathSeg::Field(s.into())
    }

    #[test]
    fn matches_canonical_steps_outputs_shape() {
        let path = vec![
            root("steps"),
            field("build"),
            field("outputs"),
            field("sha"),
        ];
        assert_eq!(
            match_steps_output_path(&path),
            Some(("build".into(), "sha".into()))
        );
    }

    #[test]
    fn returns_none_when_path_too_short() {
        let path = vec![root("steps"), field("build"), field("outputs")];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn returns_none_when_root_is_not_steps() {
        let path = vec![
            root("secrets"),
            field("build"),
            field("outputs"),
            field("v"),
        ];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn returns_none_when_first_segment_is_not_root() {
        let path = vec![field("steps"), field("build"), field("outputs"), field("v")];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn returns_none_when_middle_literal_is_not_outputs() {
        let path = vec![root("steps"), field("build"), field("output"), field("v")];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn returns_none_when_step_id_is_index_string() {
        // `steps['my-id'].outputs.value` parses path[1] as IndexString, not
        // Field. The current helper conservatively rejects this shape; this
        // test pins that invariant so any future change (e.g. supporting
        // quoted step ids) is an explicit decision, not an accidental drift.
        let path = vec![
            root("steps"),
            PathSeg::IndexString("my-id".into()),
            field("outputs"),
            field("v"),
        ];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn returns_none_when_output_key_is_numeric_index() {
        let path = vec![
            root("steps"),
            field("build"),
            field("outputs"),
            PathSeg::IndexNum(0),
        ];
        assert_eq!(match_steps_output_path(&path), None);
    }

    #[test]
    fn ignores_trailing_segments_beyond_four() {
        // `steps.build.outputs.json_blob.field` should still match the
        // steps/outputs prefix. The rule cares about the step_id + key
        // pair; nested access into structured output values does not
        // change the provenance lookup key.
        let path = vec![
            root("steps"),
            field("build"),
            field("outputs"),
            field("json_blob"),
            field("field"),
        ];
        assert_eq!(
            match_steps_output_path(&path),
            Some(("build".into(), "json_blob".into()))
        );
    }
}
