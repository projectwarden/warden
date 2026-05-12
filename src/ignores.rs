//! Inline ignore-comment parsing and suppression.
//!
//! Authors can suppress findings on a specific line with:
//!
//! ```yaml
//! - run: dangerous-thing  # warden: ignore[WRD-101]
//! - run: also-suppressed  # warden: ignore
//! ```
//!
//! Or on the next non-blank, non-comment line:
//!
//! ```yaml
//! # warden: ignore[WRD-101, WRD-332]
//! - run: dangerous-thing
//! ```
//!
//! Suppressions are parsed once per file during loading and applied centrally
//! in the scanner so individual rules never need to be ignore-aware.

use std::collections::{BTreeSet, HashMap};

use regex::Regex;
use std::sync::OnceLock;

/// Per-line suppression: either everything or a specific rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suppression {
    All,
    Rules(BTreeSet<String>),
}

impl Suppression {
    pub fn covers(&self, rule_id: &str) -> bool {
        match self {
            Suppression::All => true,
            Suppression::Rules(s) => s.contains(rule_id),
        }
    }

    pub fn merge(&mut self, other: Suppression) {
        if matches!(self, Suppression::All) || matches!(other, Suppression::All) {
            *self = Suppression::All;
            return;
        }
        if let (Suppression::Rules(a), Suppression::Rules(b)) = (self, other) {
            a.extend(b);
        }
    }
}

/// Per-file suppression map. Lines are 1-based.
#[derive(Debug, Clone, Default)]
pub struct IgnoreMap {
    by_line: HashMap<usize, Suppression>,
}

impl IgnoreMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, line: usize, supp: Suppression) {
        self.by_line
            .entry(line)
            .and_modify(|existing| existing.merge(supp.clone()))
            .or_insert(supp);
    }

    pub fn is_suppressed(&self, rule_id: &str, line: usize) -> bool {
        self.by_line
            .get(&line)
            .map(|s| s.covers(rule_id))
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.by_line.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_line.is_empty()
    }
}

/// Parse all `# warden: ignore[...]` comments from `content` and produce an
/// `IgnoreMap`. Standalone-comment-on-its-own-line suppressions are forwarded
/// to the next non-blank, non-comment line, matching `# noqa` conventions.
pub fn parse(content: &str) -> IgnoreMap {
    let mut map = IgnoreMap::new();
    let mut pending: Option<Suppression> = None;

    for (idx, line_text) in content.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line_text.trim();
        let is_comment_line = trimmed.starts_with('#');
        let directive = extract_comment(line_text);

        if is_comment_line {
            if let Some(supp) = directive {
                // Apply to THIS comment line too: rules whose primary span
                // can land on the first non-blank line of a block scalar
                // (e.g. WRD-815 fires on `run:`'s first content line, and
                // that first line is sometimes our directive itself).
                map.insert(lineno, supp.clone());
                pending = Some(merge_pending(pending.take(), supp));
            }
            // Unrelated comments do NOT consume pending; pending must
            // attach to the next actual code line.
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        // Real code line: combine any trailing directive on this line with
        // any pending standalone directive that preceded it.
        let combined = match (directive, pending.take()) {
            (Some(d), Some(mut p)) => {
                p.merge(d);
                Some(p)
            }
            (Some(d), None) => Some(d),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        };
        if let Some(s) = combined {
            map.insert(lineno, s);
        }
    }

    map
}

fn merge_pending(pending: Option<Suppression>, new: Suppression) -> Suppression {
    match pending {
        None => new,
        Some(mut p) => {
            p.merge(new);
            p
        }
    }
}

/// True if `byte_offset` in `line` is inside a single- or double-quoted
/// string literal // i.e. preceded by an unmatched opening quote.
///
/// Prevents `name: "do x # warden: ignore[WRD-101]"` from being misread as
/// a real directive (would otherwise let an attacker bury suppression in a
/// scalar value).
fn offset_inside_quoted_string(line: &str, byte_offset: usize) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_backslash = false;
    for (i, ch) in line.char_indices() {
        if i >= byte_offset {
            return in_single || in_double;
        }
        if prev_backslash {
            prev_backslash = false;
            continue;
        }
        match ch {
            '\\' if in_double => prev_backslash = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            _ => {}
        }
    }
    in_single || in_double
}

/// Extract a `warden: ignore[...]` directive from any `#` comment on the line.
fn extract_comment(line: &str) -> Option<Suppression> {
    let comment_start = line.find('#')?;
    // If the `#` is inside a quoted string, it isn't a real comment.
    // Without this, an attacker could bury `# warden: ignore[WRD-101]` in
    // a workflow `name:` and silently disable scanner findings on that line.
    if offset_inside_quoted_string(line, comment_start) {
        return None;
    }
    let comment = &line[comment_start + 1..];
    let m = ignore_re().captures(comment)?;

    if let Some(list) = m.get(1) {
        // Canonicalize legacy IDs (e.g. WRD-822 -> WRD-815) at parse time so
        // a directive written before the v2.0.0 renumber still suppresses
        // the renumbered rule. The aliases module maps every old ID to its
        // current canonical form.
        let rules: BTreeSet<String> = list
            .as_str()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| crate::rules::aliases::canonicalize(s).to_string())
            .collect();
        if rules.is_empty() {
            Some(Suppression::All)
        } else {
            Some(Suppression::Rules(rules))
        }
    } else {
        Some(Suppression::All)
    }
}

fn ignore_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // # warden: ignore           -> Suppression::All
        // # warden: ignore[WRD-101]  -> Suppression::Rules({"WRD-101"})
        // # warden: ignore[WRD-101, WRD-332]
        Regex::new(r"(?i)\bwarden\s*:\s*ignore(?:\s*\[\s*([A-Za-z0-9\-,_\s]*)\s*\])?").unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_specific_rule() {
        let yaml = "- run: stuff  # warden: ignore[WRD-101]\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 1));
        assert!(!map.is_suppressed("WRD-102", 1));
    }

    #[test]
    fn trailing_all() {
        let yaml = "- run: stuff  # warden: ignore\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 1));
        assert!(map.is_suppressed("WRD-anything", 1));
    }

    #[test]
    fn standalone_applies_to_next_code_line() {
        let yaml = "# warden: ignore[WRD-101]\n- run: stuff\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 2));
        // Standalone directives also cover their own line so that rules
        // whose primary span lands on the directive line itself (e.g.
        // shell-aware rules whose `run:` value starts inside a block
        // scalar) still get suppressed.
        assert!(map.is_suppressed("WRD-101", 1));
    }

    #[test]
    fn standalone_skips_blank_and_comment_lines() {
        let yaml = "# warden: ignore[WRD-101]\n\n# unrelated comment\n- run: stuff\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 4));
    }

    #[test]
    fn multiple_rules_in_list() {
        let yaml = "- run: x  # warden: ignore[WRD-101, WRD-332]\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 1));
        assert!(map.is_suppressed("WRD-332", 1));
        assert!(!map.is_suppressed("WRD-other", 1));
    }

    #[test]
    fn no_directive_no_entries() {
        let yaml = "- run: x  # just a comment\n- run: y\n";
        let map = parse(yaml);
        assert!(map.is_empty());
    }

    #[test]
    fn pending_merges_when_two_standalone_in_a_row() {
        let yaml = "# warden: ignore[WRD-101]\n# warden: ignore[WRD-332]\n- run: x\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 3));
        assert!(map.is_suppressed("WRD-332", 3));
    }

    #[test]
    fn case_insensitive_directive() {
        let yaml = "- run: x  # WARDEN: IGNORE[wrd-101]\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("wrd-101", 1));
    }

    #[test]
    fn directive_inside_quoted_string_is_not_a_comment() {
        // Regression: an attacker burying `# warden: ignore[WRD-101]`
        // inside a `name:` value would otherwise silently disable the
        // rule on that line.
        let yaml = "name: \"do x # warden: ignore[WRD-101]\"\n";
        let map = parse(yaml);
        assert!(
            !map.is_suppressed("WRD-101", 1),
            "directive inside quoted string must not suppress"
        );
    }

    #[test]
    fn real_trailing_comment_after_quoted_string_still_works() {
        // The real `#` is OUTSIDE the quoted string here.
        let yaml = "name: \"do x\"  # warden: ignore[WRD-101]\n";
        let map = parse(yaml);
        assert!(map.is_suppressed("WRD-101", 1));
    }
}
