//! PyPI resolver.

use anyhow::Result;
use serde_json::Value;

use super::manifest::normalize_github_url;
use super::resolver::{registry_client, RepoRef, Resolver};

pub struct PypiResolver;

impl Resolver for PypiResolver {
    fn ecosystem(&self) -> &str {
        "pypi"
    }

    fn resolve(&self, name: &str) -> Result<Option<RepoRef>> {
        let client = registry_client()?;
        let url = format!("https://pypi.org/pypi/{name}/json");
        let resp = client.get(&url).send()?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: Value = resp.json()?;
        let candidate = extract_source_candidate(&v);
        Ok(candidate
            .and_then(|s| normalize_github_url(&s))
            .map(|(owner, repo)| RepoRef {
                owner,
                repo,
                ecosystem: "pypi".into(),
                dep_name: name.into(),
                dep_version: None,
            }))
    }
}

/// Pure helper: fish out the most likely GitHub URL from a pypi JSON blob.
/// Checks project_urls.Source, project_urls.Homepage, then info.home_page.
///
/// Key matching is genuinely case-insensitive: we walk every key in
/// `project_urls` and compare via `eq_ignore_ascii_case` against the priority
/// list, instead of guessing the upstream's exact capitalization.
pub fn extract_source_candidate(v: &Value) -> Option<String> {
    let info = v.get("info")?;
    if let Some(urls) = info.get("project_urls").and_then(|u| u.as_object()) {
        // Priority order. Earlier entries beat later ones.
        let priority: &[&str] = &["Source", "Source Code", "Repository", "Homepage"];
        for wanted in priority {
            for (k, val) in urls.iter() {
                if k.eq_ignore_ascii_case(wanted) {
                    if let Some(url) = val.as_str() {
                        if url.contains("github.com") {
                            return Some(url.to_string());
                        }
                    }
                }
            }
        }
    }
    if let Some(hp) = info.get("home_page").and_then(|u| u.as_str()) {
        if hp.contains("github.com") {
            return Some(hp.to_string());
        }
    }
    None
}
