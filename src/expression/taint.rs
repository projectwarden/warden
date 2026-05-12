//! Taint sources and pattern matcher.
//!
//! Replaces the regex-based hardcoded list in `src/rules/wrd101.rs`.
//! Patterns use the same dotted form, with `*` as a wildcard for either an
//! array index or a star projection.

use super::ast::PathSeg;

/// The canonical attacker-controlled context paths shipping with warden.
///
/// Source-of-truth contract: this list MUST stay in lockstep with
/// `crate::rules::wrd101::TAINTED_EXPRESSIONS` (consumed by the fixer's
/// `fix_expression_injection`). When the scanner detects a taint that the
/// fixer doesn't rewrite (or vice versa), users get surprise extras in
/// `warden fix --pr` output (regression fixed in 468b667). New rules should
/// consult this list rather than maintain their own.
pub const TAINTED_SOURCES: &[&str] = crate::rules::wrd101::TAINTED_EXPRESSIONS;

/// Match a flattened context path against a dotted pattern.
///
/// `*` in the pattern matches a single segment of any kind: a literal field
/// name, a numeric / string index, a star projection, or a dynamic index.
/// Patterns without a `*` must match exactly.
pub fn matches_pattern(path: &[PathSeg], pattern: &str) -> bool {
    let pattern_segs: Vec<&str> = pattern.split('.').collect();
    if pattern_segs.len() != path.len() {
        return false;
    }
    for (path_seg, pat) in path.iter().zip(pattern_segs.iter()) {
        if *pat == "*" {
            continue;
        }
        let matches = match path_seg {
            PathSeg::Root(s) | PathSeg::Field(s) | PathSeg::IndexString(s) => s == pat,
            PathSeg::IndexNum(n) => &n.to_string() == pat,
            PathSeg::Star | PathSeg::IndexDynamic => false,
        };
        if !matches {
            return false;
        }
    }
    true
}

/// True if any of the [`TAINTED_SOURCES`] patterns match the path.
pub fn is_tainted(path: &[PathSeg]) -> bool {
    TAINTED_SOURCES.iter().any(|p| matches_pattern(path, p))
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse;
    use super::*;

    fn paths_of(input: &str) -> Vec<Vec<PathSeg>> {
        parse(input).unwrap().all_paths()
    }

    #[test]
    fn direct_taint_match() {
        let paths = paths_of("github.event.issue.body");
        assert!(is_tainted(&paths[0]));
    }

    #[test]
    fn safe_path_does_not_match() {
        let paths = paths_of("github.actor");
        assert!(!is_tainted(&paths[0]));
    }

    #[test]
    fn star_pattern_matches_array_index() {
        // pattern: github.event.commits.*.message
        // input:   github.event.commits[0].message  -> path has IndexNum(0)
        let paths = paths_of("github.event.commits[0].message");
        assert!(is_tainted(&paths[0]));
    }

    #[test]
    fn star_pattern_matches_dynamic_index() {
        let paths = paths_of("github.event.commits[matrix.idx].message");
        // The outer path is github.event.commits[?].message; inner expr is matrix.idx.
        let outer = &paths[0];
        assert!(is_tainted(outer));
    }

    #[test]
    fn star_pattern_matches_star_projection() {
        let paths = paths_of("github.event.commits.*.message");
        assert!(is_tainted(&paths[0]));
    }

    #[test]
    fn taint_inside_format_call() {
        let paths = paths_of("format('hi {0}', github.event.issue.body)");
        // The wrapping format() is not tainted; its arg is.
        assert!(paths.iter().any(|p| is_tainted(p)));
    }

    #[test]
    fn head_ref_is_tainted() {
        let paths = paths_of("github.head_ref");
        assert!(is_tainted(&paths[0]));
    }
}
