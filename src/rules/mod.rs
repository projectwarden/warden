pub mod wrd101;
pub mod wrd110;
pub mod wrd111;
pub mod wrd112;
pub mod wrd113;
pub mod wrd130;
pub mod wrd201;
pub mod wrd202;
pub mod wrd203;
pub mod wrd301;
pub mod wrd302;
pub mod wrd310;
pub mod wrd311;
pub mod wrd313;
pub mod wrd314;
pub mod wrd324;
pub mod wrd331;
pub mod wrd332;
pub mod wrd333;
pub mod wrd335;
pub mod wrd345;
pub mod wrd421;
pub mod wrd422;
pub mod wrd424;
pub mod wrd440;
pub mod wrd510;
pub mod wrd511;
pub mod wrd521;
pub mod wrd522;
pub mod wrd525;
pub mod wrd526;
pub mod wrd527;
pub mod wrd540;
pub mod wrd602;
pub mod wrd621;
pub mod wrd701;
pub mod wrd712;
pub mod wrd714;
pub mod wrd715;
pub mod wrd721;
pub mod wrd722;
pub mod wrd723;
pub mod wrd730;
pub mod wrd801;
pub mod wrd802;
pub mod wrd810;
pub mod wrd811;
pub mod wrd812;
pub mod wrd815;
pub mod wrd816;
pub mod wrd817;
pub mod wrd823;
pub mod wrd824;
pub mod wrd825;
pub mod wrd830;
pub mod wrd840;
pub mod wrd841;
pub mod wrd842;
pub mod wrd843;

pub mod aliases;
pub mod api;
pub use crate::expression::ExprIndex;
pub use crate::shell::ShellIndex;
pub use api::{all_rules, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};

/// Output finding emitted by the scanner. Consumed by every output formatter
/// (console, JSON, SARIF, markdown). V2 rules emit a richer `RuleFinding` and
/// lower into this shape via `RuleFinding::into_legacy` for output.
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub remediation: String,
}

/// Find the 1-based line number of a byte offset in text. Still used by a
/// handful of V2 rules whose underlying detection happens against raw text
/// (WRD-332 / WRD-333 / WRD-840: trailing-comment scans that serde drops).
pub fn line_number_at_offset(content: &str, offset: usize) -> usize {
    content[..offset.min(content.len())].matches('\n').count() + 1
}
