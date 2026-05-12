use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::common::EnvValue;

/// A single step in a job. GitHub Actions distinguishes two shapes by which
/// of `uses:` or `run:` is present; we model that as an enum.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Step {
    Uses(UsesStep),
    Run(RunStep),
    /// Anything else (e.g. an empty step). We keep it parsed but generic so
    /// loading never hard-fails on unusual workflows.
    Other(serde_yaml::Value),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UsesStep {
    pub uses: String,

    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "if")]
    pub if_: Option<String>,
    #[serde(default)]
    pub with: Option<BTreeMap<String, ScalarOrExpr>>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, EnvValue>>,
    #[serde(default, rename = "continue-on-error")]
    pub continue_on_error: Option<bool>,
    #[serde(default, rename = "timeout-minutes")]
    pub timeout_minutes: Option<f64>,
    #[serde(default, rename = "working-directory")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunStep {
    pub run: String,

    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "if")]
    pub if_: Option<String>,
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default, rename = "working-directory")]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, EnvValue>>,
    #[serde(default, rename = "continue-on-error")]
    pub continue_on_error: Option<bool>,
    #[serde(default, rename = "timeout-minutes")]
    pub timeout_minutes: Option<f64>,
}

/// A `with:` value: any scalar GitHub will stringify (string, number, bool)
/// possibly containing `${{ ... }}` expressions.
///
/// We deserialize through `serde_yaml::Value` first and then format back to
/// a string so that numeric refs like `1.10` (which would lose the trailing
/// zero through `f64`) are preserved as their original lexeme. This matters
/// for action SHA refs and version pins.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ScalarOrExpr {
    String(String),
    Null,
}

impl<'de> Deserialize<'de> for ScalarOrExpr {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_yaml::Value::deserialize(d)?;
        Ok(match v {
            serde_yaml::Value::Null => ScalarOrExpr::Null,
            serde_yaml::Value::String(s) => ScalarOrExpr::String(s),
            serde_yaml::Value::Bool(b) => ScalarOrExpr::String(b.to_string()),
            serde_yaml::Value::Number(n) => ScalarOrExpr::String(n.to_string()),
            other => ScalarOrExpr::String(
                serde_yaml::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            ),
        })
    }
}

impl ScalarOrExpr {
    pub fn as_str_owned(&self) -> String {
        match self {
            ScalarOrExpr::String(s) => s.clone(),
            ScalarOrExpr::Null => String::new(),
        }
    }
}

impl Step {
    /// Quick accessor: the step's `id:` if any.
    pub fn id(&self) -> Option<&str> {
        match self {
            Step::Uses(s) => s.id.as_deref(),
            Step::Run(s) => s.id.as_deref(),
            Step::Other(_) => None,
        }
    }
}
