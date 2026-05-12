use std::collections::HashMap;

/// Classification of where a step output value came from.
///
/// Built by walking each `run:` block's bash and looking at the right-hand
/// side of every `>> $GITHUB_OUTPUT` write. Rules consult this to decide
/// whether a downstream `${{ steps.X.outputs.Y }}` read is real injection
/// risk, advisory, or safely suppressible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSource {
    /// Attacker-controlled. Originates from `github.event.*` (issue/PR
    /// title/body, comments, head_ref, etc.). Reading this in a downstream
    /// run block is real command injection.
    Tainted(String),

    /// GitHub-validated runner env var (`GITHUB_REF_NAME`, `GITHUB_SHA`,
    /// `GITHUB_REPOSITORY`, ...). GitHub guarantees these match a strict
    /// allowlist of characters; safe to consume.
    Safe(String),

    /// Secret value from `secrets.X`. Not an injection risk per se, but a
    /// downstream rule (WRD-440 family) may care about exposure surface.
    Secret(String),

    /// Could not statically determine: command substitution `$(...)`, file
    /// content via `cat`, plain bash variable with no traceable origin.
    /// Conservative default: treat as potentially tainted.
    Unknown,

    /// Static literal in the workflow YAML, with no expansion. Safe.
    Literal,
}

impl TaintSource {
    /// True if a downstream consumer should treat this value as
    /// potentially attacker-controlled.
    pub fn is_dangerous(&self) -> bool {
        matches!(self, TaintSource::Tainted(_) | TaintSource::Unknown)
    }

    /// True if we're confident the value is fine to interpolate.
    pub fn is_safe(&self) -> bool {
        matches!(self, TaintSource::Safe(_) | TaintSource::Literal)
    }
}

/// Provenance map: `(step_id, output_key) -> TaintSource`.
///
/// Built once per workflow during scan. Lookup is by exact (step_id,
/// output_key) match. Steps without an `id:` field cannot have their
/// outputs traced and don't contribute entries (a `${{ steps.X.outputs.Y }}`
/// read with no matching write is treated as `None`, which rules
/// generally interpret as Unknown / conservative).
#[derive(Debug, Default, Clone)]
pub struct StepOutputProvenance {
    map: HashMap<(String, String), TaintSource>,
}

impl StepOutputProvenance {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        step_id: impl Into<String>,
        output_key: impl Into<String>,
        source: TaintSource,
    ) {
        self.map.insert((step_id.into(), output_key.into()), source);
    }

    pub fn get(&self, step_id: &str, output_key: &str) -> Option<&TaintSource> {
        self.map.get(&(step_id.to_string(), output_key.to_string()))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(String, String), &TaintSource)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_predicates() {
        assert!(TaintSource::Tainted("github.event.x".into()).is_dangerous());
        assert!(TaintSource::Unknown.is_dangerous());
        assert!(!TaintSource::Safe("GITHUB_REF_NAME".into()).is_dangerous());
        assert!(!TaintSource::Literal.is_dangerous());
        assert!(TaintSource::Safe("GITHUB_SHA".into()).is_safe());
        assert!(TaintSource::Literal.is_safe());
        assert!(!TaintSource::Tainted("x".into()).is_safe());
    }

    #[test]
    fn record_and_get() {
        let mut p = StepOutputProvenance::new();
        p.record(
            "version",
            "value",
            TaintSource::Safe("GITHUB_REF_NAME".into()),
        );
        p.record(
            "grab",
            "title",
            TaintSource::Tainted("github.event.issue.title".into()),
        );
        assert_eq!(p.len(), 2);
        assert!(matches!(
            p.get("version", "value"),
            Some(TaintSource::Safe(_))
        ));
        assert!(matches!(
            p.get("grab", "title"),
            Some(TaintSource::Tainted(_))
        ));
        assert!(p.get("missing", "key").is_none());
    }
}
