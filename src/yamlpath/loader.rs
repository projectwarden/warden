use std::fmt;

use saphyr::{LoadableYamlNode, MarkedYaml, Scalar, YamlData};

use super::path::YamlPath;
use super::span::Span;
use super::table::SpanTable;

/// Errors emitted by [`load`].
#[derive(Debug)]
pub enum LoadError {
    /// The YAML failed to parse.
    Parse(String),
    /// The document contained zero top-level YAML documents.
    Empty,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Parse(msg) => write!(f, "yaml parse error: {msg}"),
            LoadError::Empty => write!(f, "yaml document is empty"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Parse `content` with `saphyr` and produce a [`SpanTable`] mapping every
/// node's logical [`YamlPath`] to its byte-exact source [`Span`].
///
/// Uses the first YAML document in the input. Any subsequent documents are
/// ignored (workflow files always contain exactly one).
///
/// Note on indices: `saphyr`'s `Marker::index()` is inconsistent (sometimes
/// chars, sometimes bytes // see saphyr-parser-0.0.6/src/scanner.rs). We
/// derive byte offsets from `line()`/`col()` against the source string,
/// which are reliable per YAML 1.2.
pub fn load(content: &str) -> Result<SpanTable, LoadError> {
    let docs =
        MarkedYaml::load_from_str(content).map_err(|e| LoadError::Parse(format!("{e:?}")))?;
    let root = docs.into_iter().next().ok_or(LoadError::Empty)?;
    let line_starts = compute_line_starts(content);
    let mut table = SpanTable::new();
    walk(&root, &YamlPath::new(), content, &line_starts, &mut table);
    Ok(table)
}

fn walk(
    node: &MarkedYaml<'_>,
    path: &YamlPath,
    content: &str,
    line_starts: &[usize],
    table: &mut SpanTable,
) {
    table.insert(
        path.clone(),
        span_from_saphyr(&node.span, content, line_starts),
    );

    match &node.data {
        YamlData::Mapping(map) => {
            for (k, v) in map {
                if let Some(key_str) = scalar_string(k) {
                    let child_path = path.push_key(key_str);
                    walk(v, &child_path, content, line_starts, table);
                }
            }
        }
        YamlData::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                let child_path = path.push_index(i);
                walk(item, &child_path, content, line_starts, table);
            }
        }
        _ => {}
    }
}

fn scalar_string(node: &MarkedYaml<'_>) -> Option<String> {
    match &node.data {
        YamlData::Value(Scalar::String(s)) => Some(s.to_string()),
        YamlData::Value(Scalar::Boolean(b)) => Some(b.to_string()),
        YamlData::Value(Scalar::Integer(i)) => Some(i.to_string()),
        _ => None,
    }
}

fn span_from_saphyr(span: &saphyr_parser::Span, content: &str, line_starts: &[usize]) -> Span {
    let byte_start = byte_offset_for(content, line_starts, span.start.line(), span.start.col());
    let byte_end = byte_offset_for(content, line_starts, span.end.line(), span.end.col());
    Span::new(
        byte_start,
        byte_end,
        span.start.line(),
        span.start.col(),
        span.end.line(),
        span.end.col(),
    )
}

/// Compute the byte offset where each 1-based line begins.
fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Convert (1-based line, 1-based char column) to a byte offset.
/// `col` is treated as a char count per the YAML 1.2 grammar; the loop
/// walks UTF-8 chars from the line start.
fn byte_offset_for(content: &str, line_starts: &[usize], line: usize, col: usize) -> usize {
    let line_idx = line.saturating_sub(1);
    let line_start = line_starts.get(line_idx).copied().unwrap_or(content.len());
    if col <= 1 {
        return line_start;
    }
    let after = &content[line_start..];
    let mut chars_left = col - 1;
    for (off, ch) in after.char_indices() {
        if chars_left == 0 {
            return line_start + off;
        }
        if ch == '\n' {
            // Don't walk past the line end if the parser over-reports col.
            return line_start + off;
        }
        chars_left -= 1;
    }
    content.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_simple_mapping() {
        let yaml = "name: hi\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
        let table = load(yaml).unwrap();
        assert!(table.get_str("name").is_some());
        assert!(table.get_str("jobs").is_some());
        assert!(table.get_str("jobs.build").is_some());
        assert!(table.get_str("jobs.build.runs-on").is_some());
    }

    #[test]
    fn loads_sequence_indices() {
        let yaml = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo hi\n";
        let table = load(yaml).unwrap();
        assert!(table.get_str("jobs.build.steps[0]").is_some());
        assert!(table.get_str("jobs.build.steps[0].uses").is_some());
        assert!(table.get_str("jobs.build.steps[1].run").is_some());
    }

    #[test]
    fn span_lines_are_one_based() {
        let yaml = "name: hi\njobs: {}\n";
        let table = load(yaml).unwrap();
        let name_span = table.get_str("name").unwrap();
        assert_eq!(name_span.start_line, 1);
        let jobs_span = table.get_str("jobs").unwrap();
        assert_eq!(jobs_span.start_line, 2);
    }

    #[test]
    fn parse_error_returns_err() {
        // Unmatched bracket
        let bad = "jobs: [unclosed\n";
        assert!(load(bad).is_err());
    }

    #[test]
    fn byte_offsets_correct_with_non_ascii_above() {
        // Multi-byte chars in a comment before the field should not throw
        // off byte offsets. The SpanTable maps `permissions` -> span of
        // the *value* (an inner mapping), whose start is at saphyr's
        // reported indent column.
        let yaml = "# café ☕ in the comment\nname: hi\npermissions:\n  contents: read\n";
        let table = load(yaml).unwrap();
        let perm_span = table.get_str("permissions").unwrap();
        assert!(perm_span.byte_start <= yaml.len());
        assert!(perm_span.byte_end <= yaml.len());
        // Span is within line 4 (the inner mapping). Trim leading whitespace
        // and check we land on the inner key.
        assert_eq!(perm_span.start_line, 4);
        let slice = &yaml[perm_span.byte_start..];
        assert!(
            slice.trim_start().starts_with("contents"),
            "value-of-permissions span should land near 'contents', got {:?}",
            &slice[..slice.len().min(30)]
        );
    }

    #[test]
    fn byte_offsets_survive_crlf_line_endings() {
        // Real-world workflows sometimes carry CRLF (Windows editors, GitHub
        // web edits). `compute_line_starts` only splits on `\n`, but the
        // trailing `\r` of a preceding line is inside the PREVIOUS line per
        // our starts table // byte_start of the next field should still
        // land past the `\r` and on the field's first content byte.
        let yaml = "name: hi\r\non: push\r\njobs:\r\n  build:\r\n    runs-on: ubuntu-latest\r\n";
        let table = load(yaml).unwrap();
        let jobs_span = table.get_str("jobs").unwrap();
        assert!(jobs_span.byte_start <= yaml.len());
        // Whatever we point at, it should not span into a different logical
        // row or hit the `\r` sentinel garbage.
        let slice = &yaml[jobs_span.byte_start..];
        assert!(slice.trim_start().starts_with("build"), "got {slice:?}");
    }

    #[test]
    fn tab_indented_yaml_fails_gracefully() {
        // Tabs are explicitly disallowed as indentation in YAML 1.2, so
        // saphyr rejects them. We just want to confirm the loader returns
        // a clean `LoadError::Parse(_)` instead of panicking on such input.
        let yaml = "on: push\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n";
        match load(yaml) {
            Err(LoadError::Parse(_)) => {}
            other => panic!("expected Parse error on tab indent, got {other:?}"),
        }
    }

    #[test]
    fn byte_offsets_correct_for_top_level_after_unicode() {
        let yaml = "name: \"héllo\"\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n";
        let table = load(yaml).unwrap();
        // jobs is on line 3 in source.
        let jobs_span = table.get_str("jobs").unwrap();
        assert!(jobs_span.byte_start <= yaml.len());
        let slice = &yaml[jobs_span.byte_start..];
        assert!(slice.trim_start().starts_with("build"));
    }
}
