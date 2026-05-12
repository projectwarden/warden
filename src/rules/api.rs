//! Rule API: typed model + spans + ignore-aware.
//!
//! `Rule` is the trait every detection implements. Each rule receives an
//! `AuditCtx` (typed `LoadedWorkflow` + pre-parsed expressions + parsed shell
//! ASTs + inline-ignore map) and returns `Vec<RuleFinding>`. Findings carry
//! byte-exact `Span`s and lower to the legacy `Finding` (consumed by the
//! console / JSON / SARIF / markdown output formatters) via
//! `RuleFinding::into_legacy`.

use crate::expression::ExprIndex;
use crate::ignores::IgnoreMap;
use crate::scanner::LoadedWorkflow;
use crate::shell::ShellIndex;
use crate::taint::StepOutputProvenance;
use crate::yamlpath::Span;

/// Severity tier of a finding. Maps onto the legacy stringly-typed
/// `Finding::severity` for output, but rules use the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// Static rule metadata, returned by `Rule::meta`.
pub struct RuleMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub default_severity: Severity,
    pub description: &'static str,
}

/// A rule finding with byte-exact span info and optional related spans.
pub struct RuleFinding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub primary: Span,
    pub related: Vec<(Span, String)>,
    pub remediation: String,
}

/// Per-workflow context handed to every rule.
pub struct AuditCtx<'a> {
    pub loaded: &'a LoadedWorkflow,
    pub expressions: &'a ExprIndex,
    pub shell: &'a ShellIndex,
    pub ignores: &'a IgnoreMap,
    /// Cross-step taint provenance: for each `(step_id, output_key)` we
    /// know whether the value was set from a tainted source, a safe
    /// GitHub-validated runner env var, a secret, an unanalysable command
    /// substitution, or a static literal. Rules consult this to decide
    /// whether a `${{ steps.X.outputs.Y }}` read is real injection risk.
    pub provenance: &'a StepOutputProvenance,
}

/// New rule trait. V2 rules consume typed models + spans.
pub trait Rule: Send + Sync {
    fn meta(&self) -> RuleMeta;
    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding>;
}

impl RuleFinding {
    /// Lower to a legacy `Finding` for output formatters that haven't
    /// migrated yet. The byte-exact span collapses to a 1-based line.
    pub fn into_legacy(self, file: &str) -> super::Finding {
        super::Finding {
            rule_id: self.rule_id.to_string(),
            severity: self.severity.as_str().to_string(),
            title: self.title,
            description: self.description,
            file: file.to_string(),
            line: self.primary.start_line,
            remediation: self.remediation,
        }
    }
}

/// V2 rule registry. Populated as rules migrate from the legacy `Rule` trait.
/// Each entry must have a matching `pub struct WrdNNNV2; impl Rule for ...`
/// in the corresponding `src/rules/wrdNNN.rs`.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(super::wrd101::Wrd101),
        Box::new(super::wrd110::Wrd110),
        Box::new(super::wrd111::Wrd111),
        Box::new(super::wrd112::Wrd112),
        Box::new(super::wrd113::Wrd113),
        Box::new(super::wrd130::Wrd130),
        Box::new(super::wrd201::Wrd201),
        Box::new(super::wrd202::Wrd202),
        Box::new(super::wrd203::Wrd203),
        Box::new(super::wrd301::Wrd301),
        Box::new(super::wrd302::Wrd302),
        Box::new(super::wrd310::Wrd310),
        Box::new(super::wrd311::Wrd311),
        Box::new(super::wrd313::Wrd313),
        Box::new(super::wrd314::Wrd314),
        Box::new(super::wrd324::Wrd324),
        Box::new(super::wrd331::Wrd331),
        Box::new(super::wrd332::Wrd332),
        Box::new(super::wrd333::Wrd333),
        Box::new(super::wrd335::Wrd335),
        Box::new(super::wrd345::Wrd345),
        Box::new(super::wrd421::Wrd421),
        Box::new(super::wrd422::Wrd422),
        Box::new(super::wrd424::Wrd424),
        Box::new(super::wrd440::Wrd440),
        Box::new(super::wrd510::Wrd510),
        Box::new(super::wrd511::Wrd511),
        Box::new(super::wrd521::Wrd521),
        Box::new(super::wrd522::Wrd522),
        Box::new(super::wrd525::Wrd525),
        Box::new(super::wrd526::Wrd526),
        Box::new(super::wrd527::Wrd527),
        Box::new(super::wrd540::Wrd540),
        Box::new(super::wrd602::Wrd602),
        Box::new(super::wrd621::Wrd621),
        Box::new(super::wrd701::Wrd701),
        Box::new(super::wrd712::Wrd712),
        Box::new(super::wrd714::Wrd714),
        Box::new(super::wrd715::Wrd715),
        Box::new(super::wrd721::Wrd721),
        Box::new(super::wrd722::Wrd722),
        Box::new(super::wrd723::Wrd723),
        Box::new(super::wrd730::Wrd730),
        Box::new(super::wrd801::Wrd801),
        Box::new(super::wrd802::Wrd802),
        Box::new(super::wrd810::Wrd810),
        Box::new(super::wrd811::Wrd811),
        Box::new(super::wrd812::Wrd812),
        Box::new(super::wrd815::Wrd815),
        Box::new(super::wrd816::Wrd816),
        Box::new(super::wrd817::Wrd817),
        Box::new(super::wrd823::Wrd823),
        Box::new(super::wrd824::Wrd824),
        Box::new(super::wrd825::Wrd825),
        Box::new(super::wrd830::Wrd830),
        Box::new(super::wrd840::Wrd840),
        Box::new(super::wrd841::Wrd841),
        Box::new(super::wrd842::Wrd842),
        Box::new(super::wrd843::Wrd843),
    ]
}
