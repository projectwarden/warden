//! Span-aware YAML loading.
//!
//! `serde_yaml` discards source positions, which makes it impossible to
//! produce byte-exact diagnostics or feed precise ranges into SARIF output.
//! This module wraps `saphyr` (which preserves spans on every node) and
//! exposes a `SpanTable` keyed by a `YamlPath` so rules can look up the
//! span of any logical position in the document without holding onto the
//! `saphyr` tree itself.

mod loader;
mod path;
mod span;
mod table;

pub use loader::{load, LoadError};
pub use path::{YamlPath, YamlPathSegment};
pub use span::Span;
pub use table::SpanTable;
