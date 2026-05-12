use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

/// Accept a single value or a list of values; serialize as whatever was given.
///
/// GitHub Actions repeatedly uses this shape (`branches: main` vs
/// `branches: [main, dev]`).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            One(T),
            Many(Vec<T>),
        }
        Ok(match Inner::<T>::deserialize(d)? {
            Inner::One(v) => OneOrMany::One(v),
            Inner::Many(vs) => OneOrMany::Many(vs),
        })
    }
}

impl<T> OneOrMany<T> {
    pub fn iter(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        match self {
            OneOrMany::One(v) => Box::new(std::iter::once(v)),
            OneOrMany::Many(vs) => Box::new(vs.iter()),
        }
    }
}

/// Accept a bare boolean or a richer struct, e.g.
/// `defaults: false` vs `defaults: { run: { shell: bash } }`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BoolOr<T> {
    Bool(bool),
    Value(T),
}

/// A scalar value in env / with / etc. that GitHub will stringify.
///
/// We round-trip through `serde_yaml::Value` then format back to a string
/// so numeric refs (e.g. `1.10`) preserve their original lexeme rather than
/// getting normalized through `f64`.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum EnvValue {
    String(String),
    Null,
}

impl<'de> Deserialize<'de> for EnvValue {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = serde_yaml::Value::deserialize(d)?;
        Ok(match v {
            serde_yaml::Value::Null => EnvValue::Null,
            serde_yaml::Value::String(s) => EnvValue::String(s),
            serde_yaml::Value::Bool(b) => EnvValue::String(b.to_string()),
            serde_yaml::Value::Number(n) => EnvValue::String(n.to_string()),
            other => EnvValue::String(
                serde_yaml::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            ),
        })
    }
}

impl EnvValue {
    /// Stringified form, suitable for substring/regex inspection.
    pub fn as_str_owned(&self) -> String {
        match self {
            EnvValue::String(s) => s.clone(),
            EnvValue::Null => String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Defaults {
    #[serde(default)]
    pub run: Option<RunDefaults>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunDefaults {
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default, rename = "working-directory")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Container {
    Bare(String),
    Detailed(ContainerDetailed),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContainerDetailed {
    pub image: String,
    #[serde(default)]
    pub credentials: Option<Credentials>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, EnvValue>>,
    #[serde(default)]
    pub ports: Option<Vec<EnvValue>>,
    #[serde(default)]
    pub volumes: Option<Vec<String>>,
    #[serde(default)]
    pub options: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Credentials {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}
