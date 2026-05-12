use serde::Serialize;

/// A byte-exact range in a source file.
///
/// Lines and columns are 1-based to match editor and SARIF conventions.
/// Byte offsets are 0-based and refer to the raw UTF-8 source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

impl Span {
    pub fn new(
        byte_start: usize,
        byte_end: usize,
        start_line: usize,
        start_col: usize,
        end_line: usize,
        end_col: usize,
    ) -> Self {
        Self {
            byte_start,
            byte_end,
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }

    /// A zero-width span at line/col 1. Used as a fallback when a rule
    /// couldn't resolve a real span for a finding. Keeps the sentinel
    /// consistent across all 53 V2 rules instead of open-coding
    /// `Span::new(0, 0, 1, 1, 1, 1)` in every one.
    pub const fn placeholder() -> Self {
        Self {
            byte_start: 0,
            byte_end: 0,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 1,
        }
    }

    pub fn contains_byte(&self, offset: usize) -> bool {
        offset >= self.byte_start && offset < self.byte_end
    }

    pub fn contains_line(&self, line: usize) -> bool {
        line >= self.start_line && line <= self.end_line
    }
}
