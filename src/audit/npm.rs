//! npm registry resolver.

use anyhow::Result;
use serde_json::Value;

use super::manifest::normalize_github_url;
use super::resolver::{registry_client, RepoRef, Resolver};

pub struct NpmResolver;

impl Resolver for NpmResolver {
    fn ecosystem(&self) -> &str {
        "npm"
    }

    fn resolve(&self, name: &str) -> Result<Option<RepoRef>> {
        let client = registry_client()?;
        let url = format!("https://registry.npmjs.org/{name}");
        let resp = client.get(&url).send()?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: Value = resp.json()?;
        let repo_url = extract_repository_url(&v);
        Ok(repo_url
            .and_then(|s| normalize_github_url(&s))
            .map(|(owner, repo)| RepoRef {
                owner,
                repo,
                ecosystem: "npm".into(),
                dep_name: name.into(),
                dep_version: None,
            }))
    }
}

/// Pure helper for unit testing: read `repository.url` from an npm registry
/// JSON response.
pub fn extract_repository_url(v: &Value) -> Option<String> {
    let repo = v.get("repository")?;
    if let Some(s) = repo.as_str() {
        return Some(s.to_string());
    }
    repo.get("url")
        .and_then(|u| u.as_str())
        .map(|s| s.to_string())
}
