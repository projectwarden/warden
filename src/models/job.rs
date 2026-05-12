use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::common::{Container, Defaults, EnvValue, OneOrMany};
use super::permissions::Permissions;
use super::step::Step;

/// A job is either a normal job (with `runs-on:` and steps) or a reusable
/// workflow call (with `uses:` at the job level).
///
/// `NormalJob` is big (steps + strategy + container + services); boxing
/// keeps the enum small (required by clippy's `large_enum_variant`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Job {
    Reusable(Box<ReusableCallJob>),
    Normal(Box<NormalJob>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NormalJob {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "runs-on")]
    pub runs_on: Option<serde_yaml::Value>,
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub needs: Option<OneOrMany<String>>,
    #[serde(default, rename = "if")]
    pub if_: Option<String>,
    #[serde(default)]
    pub environment: Option<serde_yaml::Value>,
    #[serde(default)]
    pub concurrency: Option<Concurrency>,
    #[serde(default)]
    pub outputs: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, EnvValue>>,
    #[serde(default)]
    pub defaults: Option<Defaults>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default, rename = "timeout-minutes")]
    pub timeout_minutes: Option<f64>,
    #[serde(default)]
    pub strategy: Option<Strategy>,
    #[serde(default, rename = "continue-on-error")]
    pub continue_on_error: Option<bool>,
    #[serde(default)]
    pub container: Option<Container>,
    #[serde(default)]
    pub services: Option<BTreeMap<String, Container>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReusableCallJob {
    pub uses: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub needs: Option<OneOrMany<String>>,
    #[serde(default, rename = "if")]
    pub if_: Option<String>,
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub with: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub secrets: Option<serde_yaml::Value>,
    #[serde(default)]
    pub strategy: Option<Strategy>,
    #[serde(default)]
    pub concurrency: Option<Concurrency>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Strategy {
    #[serde(default)]
    pub matrix: Option<serde_yaml::Value>,
    #[serde(default, rename = "fail-fast")]
    pub fail_fast: Option<bool>,
    #[serde(default, rename = "max-parallel")]
    pub max_parallel: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Concurrency {
    Bare(String),
    Detailed {
        group: String,
        // GitHub Actions permits a ${{ ... }} expression here, not just a
        // literal bool (e.g. `cancel-in-progress: ${{ github.event_name ==
        // 'pull_request' }}`). Storing as Value keeps typed parsing working;
        // no rule currently needs to evaluate this field semantically.
        #[serde(default, rename = "cancel-in-progress")]
        cancel_in_progress: Option<serde_yaml::Value>,
    },
}
