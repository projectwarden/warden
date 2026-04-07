//! crates.io resolver.

use anyhow::Result;
use serde_json::Value;

use super::manifest::normalize_github_url;
use super::resolver::{registry_client, RepoRef, Resolver};

pub struct CargoResolver;

impl Resolver for CargoResolver {
    fn ecosystem(&self) -> &str {
        "cargo"
    }

    fn resolve(&self, name: &str) -> Result<Option<RepoRef>> {
        let client = registry_client()?;
        let url = format!("https://crates.io/api/v1/crates/{name}");
        let resp = client.get(&url).send()?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: Value = resp.json()?;
        let repo_url = extract_crates_repository(&v);
        Ok(repo_url
            .and_then(|s| normalize_github_url(&s))
            .map(|(owner, repo)| RepoRef {
                owner,
                repo,
                ecosystem: "cargo".into(),
                dep_name: name.into(),
                dep_version: None,
            }))
    }
}

pub fn extract_crates_repository(v: &Value) -> Option<String> {
    v.get("crate")
        .and_then(|c| c.get("repository"))
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
}
