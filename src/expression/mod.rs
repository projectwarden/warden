//! GitHub Actions `${{ ... }}` expression parser.
//!
//! Parses the small expression language documented at
//! <https://docs.github.com/en/actions/learn-github-actions/expressions>
//! into an AST, plus helpers to extract `${{ ... }}` substrings from
//! arbitrary text and to test paths against taint-source patterns.
//!
//! The motivating use case: replace the hardcoded `TAINTED_EXPRESSIONS`
//! string list in `src/rules/wrd101.rs` with semantic matching that catches
//! tainted contexts even when wrapped in `format()`, `contains()`, etc.

mod ast;
mod extract;
mod index;
mod lexer;
mod parser;
mod taint;

pub use ast::{path_to_string, BinaryOp, Expr, Literal, PathSeg, UnaryOp};
pub use extract::{extract_expressions, ExtractedExpression};
pub use index::{build as build_index, ExprIndex, ExprOccurrence};
pub use lexer::LexError;
pub use parser::{parse, ParseError};
pub use taint::{is_tainted, matches_pattern, TAINTED_SOURCES};
