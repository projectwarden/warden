//! Static invariants on the rule registry.
//!
//! These catch the copy-paste class of bugs where a new rule is cloned from
//! a neighbour and something gets forgotten: the `meta.id` still says the
//! donor's number, or two rules ship the same id and SARIF/JSON dedup logic
//! silently collapses their findings, or a `src/rules/wrdNNN.rs` file never
//! gets wired into `all_rules()` so it ships as dead code.
//!
//! Enforced here:
//!   1. Every `meta.id` matches the pattern `WRD-<digits>`.
//!   2. No two rules in `all_rules()` share an `id`.
//!   3. The set of `src/rules/wrdNNN.rs` files on disk is the same as the set
//!      of ids registered in `all_rules()` (after mapping `wrdNNN` to
//!      `WRD-NNN`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use wardenscan::rules::all_rules;

fn id_matches_wrd_digits(id: &str) -> bool {
    match id.strip_prefix("WRD-") {
        Some(rest) => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

#[test]
fn every_meta_id_matches_wrd_digits_pattern() {
    for rule in all_rules() {
        let id = rule.meta().id;
        assert!(
            id_matches_wrd_digits(id),
            "rule id {id:?} does not match pattern WRD-<digits>",
        );
    }
}

#[test]
fn no_two_rules_share_an_id() {
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for rule in all_rules() {
        *counts.entry(rule.meta().id).or_insert(0) += 1;
    }
    let dupes: Vec<_> = counts.iter().filter(|(_, &n)| n > 1).collect();
    assert!(
        dupes.is_empty(),
        "duplicate rule ids in all_rules(): {dupes:?}",
    );
}

#[test]
fn rule_files_and_registered_ids_match_one_to_one() {
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("rules");

    let mut ids_from_files: HashSet<String> = HashSet::new();
    for entry in std::fs::read_dir(&rules_dir).expect("read src/rules") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().into_string().unwrap_or_default();
        // Skip non-rule files like mod.rs, api.rs, aliases.rs.
        let Some(stem) = name.strip_suffix(".rs") else {
            continue;
        };
        let Some(digits) = stem.strip_prefix("wrd") else {
            continue;
        };
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        ids_from_files.insert(format!("WRD-{digits}"));
    }

    let ids_from_registry: HashSet<String> = all_rules()
        .iter()
        .map(|r| r.meta().id.to_string())
        .collect();

    let only_on_disk: Vec<_> = ids_from_files.difference(&ids_from_registry).collect();
    let only_registered: Vec<_> = ids_from_registry.difference(&ids_from_files).collect();

    assert!(
        only_on_disk.is_empty(),
        "rule files exist on disk but not registered in all_rules(): {only_on_disk:?}",
    );
    assert!(
        only_registered.is_empty(),
        "rule ids registered in all_rules() without a matching src/rules/wrdNNN.rs file: {only_registered:?}",
    );
}
