use std::fmt;

/// A single step in a YAML path: either a mapping key or a sequence index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum YamlPathSegment {
    Key(String),
    Index(usize),
}

impl fmt::Display for YamlPathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YamlPathSegment::Key(k) => write!(f, "{k}"),
            YamlPathSegment::Index(i) => write!(f, "[{i}]"),
        }
    }
}

/// A logical path into a YAML document, e.g. `jobs.build.steps[2].run`.
///
/// Used as the key into a `SpanTable` to recover the source span of any
/// node without holding a reference to the parsed tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct YamlPath {
    pub segments: Vec<YamlPathSegment>,
}

impl YamlPath {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn push_key(&self, key: impl Into<String>) -> Self {
        let mut next = self.clone();
        next.segments.push(YamlPathSegment::Key(key.into()));
        next
    }

    pub fn push_index(&self, idx: usize) -> Self {
        let mut next = self.clone();
        next.segments.push(YamlPathSegment::Index(idx));
        next
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

impl fmt::Display for YamlPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for seg in &self.segments {
            match seg {
                YamlPathSegment::Key(k) => {
                    if !first {
                        write!(f, ".")?;
                    }
                    write!(f, "{k}")?;
                }
                YamlPathSegment::Index(i) => write!(f, "[{i}]")?,
            }
            first = false;
        }
        Ok(())
    }
}

/// Parse a dotted path string like `jobs.build.steps[2].run` into a YamlPath.
/// Returns None on malformed input.
pub fn parse(s: &str) -> Option<YamlPath> {
    let mut segments = Vec::new();
    let mut chars = s.chars().peekable();
    let mut current = String::new();
    let mut in_index = false;

    while let Some(&c) = chars.peek() {
        match c {
            '.' if !in_index => {
                chars.next();
                if !current.is_empty() {
                    segments.push(YamlPathSegment::Key(std::mem::take(&mut current)));
                }
            }
            '[' if !in_index => {
                chars.next();
                if !current.is_empty() {
                    segments.push(YamlPathSegment::Key(std::mem::take(&mut current)));
                }
                in_index = true;
            }
            ']' if in_index => {
                chars.next();
                let idx: usize = current.parse().ok()?;
                segments.push(YamlPathSegment::Index(idx));
                current.clear();
                in_index = false;
            }
            _ => {
                current.push(c);
                chars.next();
            }
        }
    }
    if in_index {
        return None;
    }
    if !current.is_empty() {
        segments.push(YamlPathSegment::Key(current));
    }
    Some(YamlPath { segments })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = parse("jobs.build.steps[2].run").unwrap();
        assert_eq!(p.segments.len(), 5);
        assert_eq!(p.to_string(), "jobs.build.steps[2].run");
    }

    #[test]
    fn push_helpers() {
        let p = YamlPath::new()
            .push_key("jobs")
            .push_key("build")
            .push_key("steps")
            .push_index(0)
            .push_key("uses");
        assert_eq!(p.to_string(), "jobs.build.steps[0].uses");
    }

    #[test]
    fn empty_path() {
        let p = YamlPath::new();
        assert!(p.is_empty());
        assert_eq!(p.to_string(), "");
    }
}
