//! Find `${{ ... }}` substrings inside arbitrary text.
//!
//! Used by the [`super::index::ExprIndex`] builder to scan every string
//! field of a workflow (run, with values, env, if, name, ...) for
//! expression occurrences.

/// One extracted `${{ ... }}` occurrence.
#[derive(Debug, Clone)]
pub struct ExtractedExpression {
    /// The bytes inside the `${{` and `}}` markers, with surrounding
    /// whitespace trimmed.
    pub inner: String,
    /// Byte offset (within the source text) of the `$` of `${{`.
    pub byte_start: usize,
    /// Byte offset (exclusive) of the second `}` of `}}`.
    pub byte_end: usize,
}

/// Scan `text` and return every `${{ ... }}` substring.
///
/// Brace counting is balanced: an inner `}` does not terminate the
/// expression unless it's a literal `}}` at the same nesting depth as the
/// opening `${{`. Quoted strings inside the expression are respected so
/// that something like `${{ format('a}}b', x) }}` parses as a single
/// expression.
pub fn extract_expressions(text: &str) -> Vec<ExtractedExpression> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    // Need at least 3 bytes to start a `${{` match. Inclusive upper bound
    // so a buffer ending exactly with `${{` is still scanned (it'll just
    // never find a closing `}}` and be discarded).
    while i + 3 <= bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' && bytes[i + 2] == b'{' {
            let start = i;
            i += 3;
            let inner_start = i;
            let mut depth: i32 = 1;
            let mut in_string = false;

            while i < bytes.len() {
                let b = bytes[i];

                if in_string {
                    if b == b'\'' {
                        // '' is escape inside string.
                        if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                            i += 2;
                            continue;
                        }
                        in_string = false;
                        i += 1;
                        continue;
                    }
                    i += 1;
                    continue;
                }

                if b == b'\'' {
                    in_string = true;
                    i += 1;
                    continue;
                }
                if b == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    depth += 1;
                    i += 2;
                    continue;
                }
                if b == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        let inner_end = i;
                        let inner = std::str::from_utf8(&bytes[inner_start..inner_end])
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        out.push(ExtractedExpression {
                            inner,
                            byte_start: start,
                            byte_end: i + 2,
                        });
                        i += 2;
                        break;
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_expression() {
        let text = "echo ${{ github.event.issue.body }} hi";
        let exprs = extract_expressions(text);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].inner, "github.event.issue.body");
    }

    #[test]
    fn finds_multiple_expressions_on_one_line() {
        let text = "${{ a.b }} and ${{ c.d }}";
        let exprs = extract_expressions(text);
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn handles_brace_inside_string_literal() {
        let text = "${{ format('a}}b', x) }}";
        let exprs = extract_expressions(text);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].inner, "format('a}}b', x)");
    }

    #[test]
    fn no_expressions() {
        let text = "just plain text";
        assert!(extract_expressions(text).is_empty());
    }

    #[test]
    fn unterminated_does_not_panic() {
        let text = "${{ never closes";
        let exprs = extract_expressions(text);
        // Doesn't crash; depending on policy, may emit zero or partial.
        // Acceptable either way as long as no panic.
        let _ = exprs;
    }

    #[test]
    fn byte_offsets_are_correct() {
        let text = "abc ${{ x }} def";
        let exprs = extract_expressions(text);
        assert_eq!(exprs[0].byte_start, 4);
        assert_eq!(&text[exprs[0].byte_start..exprs[0].byte_end], "${{ x }}");
    }

    #[test]
    fn apostrophes_in_plain_text_do_not_swallow_following_expression() {
        // Reviewer flagged a concern: a plain-text apostrophe might set
        // `in_string=true` and cause the following ${{ }} to be skipped.
        // It shouldn't, because `in_string` is local to each expression
        // scan. This test asserts the actual behavior.
        let text = "echo don't worry ${{ github.event.x }} ok";
        let exprs = extract_expressions(text);
        assert_eq!(
            exprs.len(),
            1,
            "expression after apostrophe must still be found"
        );
        assert_eq!(exprs[0].inner, "github.event.x");
    }

    #[test]
    fn apostrophe_inside_expression_string_is_handled() {
        // 'don''t' is a valid GHA string with the doubled-apostrophe escape.
        let text = "${{ contains('don''t', x) }}";
        let exprs = extract_expressions(text);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].inner, "contains('don''t', x)");
    }
}
