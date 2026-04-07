use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

use super::Workflow;

const GITHUB_API: &str = "https://api.github.com";

#[derive(Deserialize)]
struct ContentEntry {
    name: String,
    path: String,
    download_url: Option<String>,
}

#[derive(Deserialize)]
struct RateLimitError {
    message: Option<String>,
}

/// Build a configured HTTP client with optional auth token.
pub(crate) fn build_client(token: Option<&str>) -> Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        USER_AGENT,
        concat!("warden-scanner/", env!("CARGO_PKG_VERSION"))
            .parse()
            .unwrap(),
    );
    headers.insert(ACCEPT, "application/vnd.github.v3+json".parse().unwrap());

    // Treat an empty token as no token. CI often passes GITHUB_TOKEN="" when
    // a secret is unset, which would produce `Authorization: Bearer ` and a
    // 401 from GitHub instead of falling back to anonymous (60 req/hr) access.
    if let Some(t) = token.filter(|s| !s.is_empty()) {
        let val = format!("Bearer {t}");
        headers.insert(
            AUTHORIZATION,
            val.parse().context("Invalid GitHub token format")?,
        );
    }

    Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")
}

/// List workflow YAML files in .github/workflows/ via the GitHub Contents API.
fn list_workflow_files(client: &Client, owner: &str, repo: &str) -> Result<Vec<ContentEntry>> {
    let url = format!("{GITHUB_API}/repos/{owner}/{repo}/contents/.github/workflows");

    let resp = client
        .get(&url)
        .send()
        .context("Failed to reach GitHub API")?;

    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        let body: RateLimitError = resp.json().unwrap_or(RateLimitError { message: None });
        bail!(
            "GitHub API rate limit hit: {}",
            body.message.unwrap_or_else(|| "rate limited".to_string())
        );
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        bail!("No .github/workflows directory found in {owner}/{repo}");
    }

    if !status.is_success() {
        bail!("GitHub API returned status {status}");
    }

    let entries: Vec<ContentEntry> = resp.json().context("Failed to parse GitHub API response")?;

    let yaml_files: Vec<ContentEntry> = entries
        .into_iter()
        .filter(|e| e.name.ends_with(".yml") || e.name.ends_with(".yaml"))
        .collect();

    Ok(yaml_files)
}

/// Fetch the raw content of a single file from GitHub.
fn fetch_file_content(client: &Client, download_url: &str) -> Result<String> {
    let resp = client
        .get(download_url)
        .send()
        .context("Failed to fetch workflow file")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("Failed to fetch file content, status {status}");
    }

    resp.text().context("Failed to read response body")
}

/// Load all workflow files from a GitHub repository.
pub fn load_github(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Workflow>> {
    let client = build_client(token)?;
    let files = list_workflow_files(&client, owner, repo)?;

    let mut workflows = Vec::new();

    for entry in &files {
        let url = match &entry.download_url {
            Some(u) => u.clone(),
            None => continue,
        };

        let content = match fetch_file_content(&client, &url) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: could not fetch {}: {}", entry.path, e);
                continue;
            }
        };

        let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML in {}", entry.path))?;

        workflows.push(Workflow {
            path: entry.path.clone(),
            content: content.clone(),
            parsed,
        });
    }

    Ok(workflows)
}
