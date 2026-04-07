//! Trait and dispatch for ecosystem-specific source-repo resolvers.

use std::time::Duration;

use anyhow::Result;
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;

#[derive(Debug, Clone)]
pub struct RepoRef {
    pub owner: String,
    pub repo: String,
    #[allow(dead_code)]
    pub ecosystem: String,
    #[allow(dead_code)]
    pub dep_name: String,
    #[allow(dead_code)]
    pub dep_version: Option<String>,
}

pub trait Resolver: Send + Sync {
    fn ecosystem(&self) -> &str;
    fn resolve(&self, name: &str) -> Result<Option<RepoRef>>;
}

/// Shared HTTP client for registry lookups.
pub fn registry_client() -> Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        USER_AGENT,
        concat!("warden-scanner/", env!("CARGO_PKG_VERSION"), " (upstream)")
            .parse()
            .unwrap(),
    );
    Ok(Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?)
}

pub fn for_ecosystem(eco: &str) -> Box<dyn Resolver> {
    match eco {
        "npm" => Box::new(super::npm::NpmResolver),
        "pypi" => Box::new(super::pypi::PypiResolver),
        "go" => Box::new(super::go::GoResolver),
        "cargo" => Box::new(super::cargo::CargoResolver),
        _ => Box::new(NoopResolver),
    }
}

pub struct NoopResolver;
impl Resolver for NoopResolver {
    fn ecosystem(&self) -> &str {
        "unknown"
    }
    fn resolve(&self, _name: &str) -> Result<Option<RepoRef>> {
        Ok(None)
    }
}
