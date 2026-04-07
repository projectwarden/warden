//! Go module resolver.

use anyhow::Result;

use super::manifest::go_module_to_github;
use super::resolver::{RepoRef, Resolver};

pub struct GoResolver;

impl Resolver for GoResolver {
    fn ecosystem(&self) -> &str {
        "go"
    }

    fn resolve(&self, name: &str) -> Result<Option<RepoRef>> {
        // Go modules are special: the module path itself is the source
        // location for github-hosted modules, so no network call needed.
        Ok(go_module_to_github(name).map(|(owner, repo)| RepoRef {
            owner,
            repo,
            ecosystem: "go".into(),
            dep_name: name.into(),
            dep_version: None,
        }))
    }
}
