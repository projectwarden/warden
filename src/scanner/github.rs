use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

use super::Workflow;

const GITHUB_API: &str = "https://api.github.com";
const GITHUB_GRAPHQL: &str = "https://api.github.com/graphql";

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

/// Fetch all workflow files via a single GitHub GraphQL query.
///
/// The query asks for the `.github/workflows` tree with inline blob text,
/// so both the file listing and every file's content arrive in one round trip.
/// This requires a valid token (GraphQL has no anonymous access).
fn load_github_graphql(client: &Client, owner: &str, repo: &str) -> Result<Vec<Workflow>> {
    let graphql_query = r#"query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { object(expression: "HEAD:.github/workflows") { ... on Tree { entries { name object { ... on Blob { text } } } } } } }"#;
    let body = serde_json::json!({
        "query": graphql_query,
        "variables": { "owner": owner, "name": repo }
    });

    let resp = client
        .post(GITHUB_GRAPHQL)
        .json(&body)
        .send()
        .context("Failed to reach GitHub GraphQL API")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("GitHub GraphQL API returned status {status}");
    }

    let body: serde_json::Value = resp.json().context("Failed to parse GraphQL response")?;

    if let Some(errors) = body.get("errors") {
        bail!("GraphQL errors: {errors}");
    }

    let tree = body
        .pointer("/data/repository/object/entries")
        .and_then(|v| v.as_array())
        .context("No .github/workflows directory found (GraphQL returned no tree entries)")?;

    let mut workflows = Vec::new();
    for entry in tree {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }

        let content = match entry.pointer("/object/text").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => continue,
        };

        let path = format!(".github/workflows/{name}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML in {}", path))?;

        workflows.push(Workflow {
            path,
            content,
            parsed,
        });
    }

    Ok(workflows)
}

/// Load all workflow files from a GitHub repository.
///
/// When a token is available, uses a single GraphQL query that fetches
/// both the file listing and all file contents in one round trip. Falls
/// back to the N+1 REST approach if no token is provided (GraphQL
/// requires authentication) or if the GraphQL call fails.
pub fn load_github(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Workflow>> {
    let has_token = token.is_some_and(|t| !t.is_empty());
    let client = build_client(token)?;

    if has_token {
        match load_github_graphql(&client, owner, repo) {
            Ok(workflows) => return Ok(workflows),
            Err(e) => {
                eprintln!("Warning: GraphQL fetch failed, falling back to REST: {e}");
            }
        }
    }

    load_github_rest(&client, owner, repo)
}

/// REST fallback: 1 call to list files, then N parallel calls to fetch content.
fn load_github_rest(client: &Client, owner: &str, repo: &str) -> Result<Vec<Workflow>> {
    let files = list_workflow_files(client, owner, repo)?;

    let fetched: Vec<Option<(String, String)>> = std::thread::scope(|s| {
        let client_ref = client;
        let handles: Vec<_> = files
            .iter()
            .map(|entry| {
                let path = entry.path.clone();
                let url = entry.download_url.clone();
                s.spawn(move || {
                    let url = url?;
                    match fetch_file_content(client_ref, &url) {
                        Ok(content) => Some((path, content)),
                        Err(e) => {
                            eprintln!("Warning: could not fetch {}: {}", path, e);
                            None
                        }
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(None))
            .collect()
    });

    let mut workflows = Vec::with_capacity(fetched.len());
    for (path, content) in fetched.into_iter().flatten() {
        let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML in {}", path))?;
        workflows.push(Workflow {
            path,
            content,
            parsed,
        });
    }

    Ok(workflows)
}
