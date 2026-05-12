//! Rule ID aliases for backwards compatibility.
//!
//! Several rules were renumbered in v2.0.0 to align with the documented
//! convention that severity is encoded in the tens/units digit of the rule
//! number (e.g. WRD-X40+ = info). To avoid breaking `.warden.toml`
//! configs and CLI invocations that reference the old IDs, we resolve
//! every legacy ID to its canonical successor at config-load time and
//! at CLI-input time.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Resolve a possibly-legacy rule ID to its canonical current form.
/// Returns the input unchanged if no alias exists.
pub fn canonicalize(rule_id: &str) -> &str {
    aliases().get(rule_id).copied().unwrap_or(rule_id)
}

/// Returns true if the given ID is a legacy alias for a renumbered rule.
pub fn is_alias(rule_id: &str) -> bool {
    aliases().contains_key(rule_id)
}

fn aliases() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        // (old, new) pairs from the v2.0.0 renumbering. Keep this list
        // sorted by old ID so future additions are easy to spot.
        m.insert("WRD-120", "WRD-130");
        m.insert("WRD-320", "WRD-311");
        m.insert("WRD-321", "WRD-331");
        m.insert("WRD-322", "WRD-332");
        m.insert("WRD-323", "WRD-333");
        m.insert("WRD-325", "WRD-345");
        m.insert("WRD-326", "WRD-313");
        m.insert("WRD-327", "WRD-314");
        m.insert("WRD-420", "WRD-440");
        m.insert("WRD-512", "WRD-522");
        m.insert("WRD-520", "WRD-540");
        m.insert("WRD-601", "WRD-621");
        m.insert("WRD-710", "WRD-730");
        m.insert("WRD-711", "WRD-721");
        m.insert("WRD-713", "WRD-722");
        m.insert("WRD-720", "WRD-723");
        m.insert("WRD-731", "WRD-715");
        m.insert("WRD-820", "WRD-830");
        m.insert("WRD-821", "WRD-816");
        m.insert("WRD-822", "WRD-815");
        m.insert("WRD-826", "WRD-840");
        m.insert("WRD-827", "WRD-841");
        m.insert("WRD-828", "WRD-817");
        m.insert("WRD-831", "WRD-842");
        m.insert("WRD-833", "WRD-843");
        m
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_legacy_ids() {
        assert_eq!(canonicalize("WRD-826"), "WRD-840");
        assert_eq!(canonicalize("WRD-822"), "WRD-815");
    }

    #[test]
    fn passes_through_canonical_ids() {
        assert_eq!(canonicalize("WRD-101"), "WRD-101");
        assert_eq!(canonicalize("WRD-840"), "WRD-840");
    }

    #[test]
    fn detects_alias() {
        assert!(is_alias("WRD-826"));
        assert!(!is_alias("WRD-840"));
    }
}
