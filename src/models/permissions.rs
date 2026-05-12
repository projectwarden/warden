use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `permissions:` accepts either a bulk-grant string (`read-all`, `write-all`)
/// or a per-scope mapping.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Permissions {
    All(String),
    Map(BTreeMap<String, PermissionLevel>),
}

impl Permissions {
    /// True if this is a bulk-write grant (`write-all`).
    pub fn is_write_all(&self) -> bool {
        matches!(self, Permissions::All(s) if s.eq_ignore_ascii_case("write-all"))
    }

    /// True if this is a bulk-read grant (`read-all`).
    pub fn is_read_all(&self) -> bool {
        matches!(self, Permissions::All(s) if s.eq_ignore_ascii_case("read-all"))
    }

    /// Iterate the per-scope grants, if any.
    pub fn scopes(&self) -> Option<&BTreeMap<String, PermissionLevel>> {
        match self {
            Permissions::Map(m) => Some(m),
            _ => None,
        }
    }
}

/// `read | write | none` plus an `Other` fallback so unknown values from
/// the workflow don't cause a hard parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PermissionLevel {
    Read,
    Write,
    None,
    Other(String),
}

impl<'de> Deserialize<'de> for PermissionLevel {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Ok(match s.to_ascii_lowercase().as_str() {
            "read" => PermissionLevel::Read,
            "write" => PermissionLevel::Write,
            "none" => PermissionLevel::None,
            _ => PermissionLevel::Other(s),
        })
    }
}

impl PermissionLevel {
    pub fn as_str(&self) -> &str {
        match self {
            PermissionLevel::Read => "read",
            PermissionLevel::Write => "write",
            PermissionLevel::None => "none",
            PermissionLevel::Other(s) => s.as_str(),
        }
    }
}
