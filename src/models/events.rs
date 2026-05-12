use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::common::OneOrMany;

/// `on:` accepts a bare string, a list of triggers, or a map of trigger -> config.
///
/// The map value is `Option<EventConfig>` because YAML allows `pull_request:`
/// with no body (i.e. `pull_request: null` / empty mapping); `EventConfig`
/// alone cannot deserialize from a bare `null` even with all fields
/// defaulted, and before this wrapper every workflow using that shape failed
/// typed parsing and silently downgraded to a stub (no job-level findings).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum On {
    Bare(String),
    List(Vec<String>),
    Map(BTreeMap<String, Option<EventConfig>>),
}

impl On {
    /// True if any form mentions the given trigger name.
    pub fn mentions(&self, trigger: &str) -> bool {
        match self {
            On::Bare(s) => s == trigger,
            On::List(l) => l.iter().any(|s| s == trigger),
            On::Map(m) => m.contains_key(trigger),
        }
    }

    /// Iterate every trigger name regardless of representation.
    pub fn trigger_names(&self) -> Vec<&str> {
        match self {
            On::Bare(s) => vec![s.as_str()],
            On::List(l) => l.iter().map(String::as_str).collect(),
            On::Map(m) => m.keys().map(String::as_str).collect(),
        }
    }
}

/// Per-trigger configuration. Most fields are best-effort.
///
/// `null` is also valid (e.g. `pull_request:` with no body) and is handled
/// at the `On::Map` level by wrapping the value in `Option`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EventConfig {
    #[serde(default)]
    pub branches: Option<OneOrMany<String>>,
    #[serde(default, rename = "branches-ignore")]
    pub branches_ignore: Option<OneOrMany<String>>,
    #[serde(default)]
    pub tags: Option<OneOrMany<String>>,
    #[serde(default, rename = "tags-ignore")]
    pub tags_ignore: Option<OneOrMany<String>>,
    #[serde(default)]
    pub paths: Option<OneOrMany<String>>,
    #[serde(default, rename = "paths-ignore")]
    pub paths_ignore: Option<OneOrMany<String>>,
    #[serde(default)]
    pub types: Option<OneOrMany<String>>,
    #[serde(default)]
    pub workflows: Option<OneOrMany<String>>,
    #[serde(default)]
    pub schedule: Option<Vec<ScheduleEntry>>,
    #[serde(default)]
    pub inputs: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub secrets: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub outputs: Option<BTreeMap<String, serde_yaml::Value>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScheduleEntry {
    pub cron: String,
}
