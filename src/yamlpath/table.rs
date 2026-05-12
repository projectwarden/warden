use std::collections::HashMap;

use super::path::YamlPath;
use super::span::Span;

/// Maps a `YamlPath` to the source span of the value at that path.
///
/// Built once per workflow during load. Rules query it on demand to
/// recover byte-exact spans for findings without holding the parsed tree.
#[derive(Debug, Clone, Default)]
pub struct SpanTable {
    map: HashMap<YamlPath, Span>,
}

impl SpanTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: YamlPath, span: Span) {
        self.map.insert(path, span);
    }

    pub fn get(&self, path: &YamlPath) -> Option<Span> {
        self.map.get(path).copied()
    }

    /// Convenience: parse a dotted path string then look it up.
    pub fn get_str(&self, path: &str) -> Option<Span> {
        super::path::parse(path).and_then(|p| self.get(&p))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&YamlPath, &Span)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut t = SpanTable::new();
        let p = YamlPath::new().push_key("jobs").push_key("build");
        t.insert(p.clone(), Span::new(10, 20, 1, 1, 1, 11));
        assert_eq!(t.get(&p).unwrap().byte_start, 10);
    }

    #[test]
    fn get_by_str() {
        let mut t = SpanTable::new();
        let p = YamlPath::new()
            .push_key("jobs")
            .push_key("build")
            .push_key("steps")
            .push_index(0);
        t.insert(p, Span::new(0, 5, 1, 1, 1, 6));
        assert!(t.get_str("jobs.build.steps[0]").is_some());
        assert!(t.get_str("jobs.missing").is_none());
    }
}
