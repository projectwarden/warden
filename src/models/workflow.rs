use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::common::{Defaults, EnvValue};
use super::events::On;
use super::job::{Concurrency, Job};
use super::permissions::Permissions;

/// A typed GitHub Actions workflow file.
///
/// Fields use `#[serde(default)]` aggressively because real-world workflows
/// omit nearly every optional key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Workflow {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "run-name")]
    pub run_name: Option<String>,
    pub on: On,
    #[serde(default)]
    pub permissions: Option<Permissions>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, EnvValue>>,
    #[serde(default)]
    pub defaults: Option<Defaults>,
    #[serde(default)]
    pub concurrency: Option<Concurrency>,
    pub jobs: BTreeMap<String, Job>,
}
