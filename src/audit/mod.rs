//! Supply chain auditing: resolve a project's direct (and optionally depth-2)
//! dependencies back to their source repos on GitHub, then run the full
//! warden detector against each of those repos' workflow files.
//!
//! Deliberately uses `std::thread::scope` + `std::sync::mpsc` for concurrency
//! instead of tokio, since the rest of warden is built on `reqwest::blocking`.

pub mod cargo;
pub mod go;
pub mod manifest;
pub mod npm;
pub mod pypi;
pub mod resolver;

use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::rules::Finding;
use crate::scanner;

use resolver::RepoRef;

/// A dependency discovered in a manifest.
#[derive(Debug, Clone)]
pub struct Dep {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

/// Result of scanning a single dependency's source repo.
#[derive(Debug, Clone, Serialize)]
pub struct DepResult {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
    pub source_repo: Option<String>,
    pub findings: Vec<FindingOut>,
    pub score: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingOut {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub remediation: String,
}

impl From<&Finding> for FindingOut {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.clone(),
            severity: f.severity.clone(),
            title: f.title.clone(),
            description: f.description.clone(),
            file: f.file.clone(),
            line: f.line,
            remediation: f.remediation.clone(),
        }
    }
}

/// Top-level audit summary.
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub total_deps: usize,
    pub resolved_deps: usize,
    pub deps_with_findings: usize,
    pub total_findings: usize,
    pub results: Vec<DepResult>,
}

/// Absolute cap on deps we'll resolve, even at depth 2.
const MAX_DEPS: usize = 500;

/// Orchestrate an upstream run against a local project directory.
pub fn run(path: &str, concurrency: usize, depth: u8, token: Option<&str>) -> Result<AuditReport> {
    let mut discovered = manifest::discover(path)?;
    if discovered.is_empty() {
        bail!(
            "No supported dependency manifests found at {path}. Looked for: package.json, requirements.txt, Pipfile.lock, go.mod, Cargo.toml"
        );
    }

    // Deduplicate within depth 1 first.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    discovered.retain(|d| seen.insert((d.ecosystem.clone(), d.name.clone())));

    if discovered.len() > MAX_DEPS {
        eprintln!(
            "warning: capping deps at {} (found {})",
            MAX_DEPS,
            discovered.len()
        );
        discovered.truncate(MAX_DEPS);
    }

    if token.is_none() && discovered.len() > 30 {
        eprintln!(
            "warning: no GITHUB_TOKEN set and {} deps to scan; unauthenticated GitHub API quota is 60 req/hr, you WILL get rate-limited. Set GITHUB_TOKEN.",
            discovered.len()
        );
    }

    eprintln!("upstream: {} direct deps discovered", discovered.len());

    let mut results = scan_deps(&discovered, concurrency, token);

    // Depth 2: for each successfully-scanned dep, try to fetch its manifest from
    // its source repo and resolve THOSE deps. Dedup against what we've seen.
    if depth >= 2 {
        let mut next_batch: Vec<Dep> = Vec::new();
        for r in &results {
            let Some(slug) = r.source_repo.as_deref() else {
                continue;
            };
            let Some((owner, repo)) = slug.split_once('/') else {
                continue;
            };
            match fetch_remote_manifest_deps(owner, repo, token) {
                Ok(deps) => {
                    for d in deps {
                        let key = (d.ecosystem.clone(), d.name.clone());
                        if seen.insert(key) {
                            next_batch.push(d);
                            if seen.len() >= MAX_DEPS {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("warning: could not fetch transitive manifest from {slug}: {e}");
                }
            }
            if seen.len() >= MAX_DEPS {
                break;
            }
        }
        if !next_batch.is_empty() {
            eprintln!("upstream: {} depth-2 deps discovered", next_batch.len());
            let mut more = scan_deps(&next_batch, concurrency, token);
            results.append(&mut more);
        }
    }

    let total_deps = results.len();
    let resolved_deps = results
        .iter()
        .filter(|r| r.source_repo.is_some() && r.error.is_none())
        .count();
    let deps_with_findings = results.iter().filter(|r| !r.findings.is_empty()).count();
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();

    Ok(AuditReport {
        total_deps,
        resolved_deps,
        deps_with_findings,
        total_findings,
        results,
    })
}

/// Fan deps out to a pool of worker threads, resolve each to a GitHub repo,
/// scan the repo, and collect results. Uses `thread::scope` + `mpsc` channels.
fn scan_deps(deps: &[Dep], concurrency: usize, token: Option<&str>) -> Vec<DepResult> {
    let concurrency = concurrency.clamp(1, 32);

    // Work queue (shared Arc<Mutex<Vec>>). Workers pop from the back.
    let queue: Arc<Mutex<Vec<Dep>>> = Arc::new(Mutex::new(deps.to_vec()));
    let (tx, rx) = mpsc::channel::<DepResult>();

    thread::scope(|s| {
        for worker_id in 0..concurrency {
            let q = Arc::clone(&queue);
            let tx = tx.clone();
            let token = token.map(|t| t.to_string());
            s.spawn(move || {
                loop {
                    let dep_opt = {
                        let mut guard = q.lock().unwrap();
                        guard.pop()
                    };
                    let Some(dep) = dep_opt else { return };

                    // Polite jitter: stagger bursts per worker.
                    thread::sleep(Duration::from_millis(100 + (worker_id as u64 * 13)));

                    let res = scan_one(&dep, token.as_deref());
                    let _ = tx.send(res);
                }
            });
        }
        drop(tx);
    });

    rx.into_iter().collect()
}

fn scan_one(dep: &Dep, token: Option<&str>) -> DepResult {
    let resolver = resolver::for_ecosystem(&dep.ecosystem);
    let repo_ref: Option<RepoRef> = match resolver.resolve(&dep.name) {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!(
                "warning: could not resolve source repo for {} ({}): {}",
                dep.name, dep.ecosystem, e
            );
            None
        }
    };

    let Some(rref) = repo_ref else {
        return DepResult {
            name: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: dep.ecosystem.clone(),
            source_repo: None,
            findings: vec![],
            score: 100,
            error: Some("source repo not resolvable".to_string()),
        };
    };

    let slug = format!("{}/{}", rref.owner, rref.repo);

    match scanner::load_github(&rref.owner, &rref.repo, token) {
        Ok(workflows) => {
            // Guard against panics inside a rule so one bad regex doesn't
            // abort the whole audit. The existing `scan` command runs rules
            // one workflow at a time via the main thread, so a panic there
            // just kills the process. Here we're in a worker, so catch it.
            let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scanner::scan(&workflows)
            }));
            let findings = match scan_result {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("warning: scanner panicked on {slug}, skipping");
                    return DepResult {
                        name: dep.name.clone(),
                        version: dep.version.clone(),
                        ecosystem: dep.ecosystem.clone(),
                        source_repo: Some(slug),
                        findings: vec![],
                        score: 100,
                        error: Some("scanner panicked".to_string()),
                    };
                }
            };
            let score = scanner::score(&findings);
            let outs: Vec<FindingOut> = findings.iter().map(FindingOut::from).collect();
            DepResult {
                name: dep.name.clone(),
                version: dep.version.clone(),
                ecosystem: dep.ecosystem.clone(),
                source_repo: Some(slug),
                findings: outs,
                score,
                error: None,
            }
        }
        Err(e) => {
            let msg = format!("{e}");
            // Repos without workflows are not actually errors for our purposes.
            let is_missing = msg.contains("No .github/workflows directory found");
            if !is_missing {
                eprintln!("warning: scan of {slug} failed: {e}");
            }
            DepResult {
                name: dep.name.clone(),
                version: dep.version.clone(),
                ecosystem: dep.ecosystem.clone(),
                source_repo: Some(slug),
                findings: vec![],
                score: 100,
                error: if is_missing { None } else { Some(msg) },
            }
        }
    }
}

/// Fetch a remote project's manifests from the root of a GitHub repo and
/// parse them for dependencies. Best-effort; returns an empty vec if none
/// of the candidate files exist.
fn fetch_remote_manifest_deps(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Dep>> {
    use reqwest::blocking::Client;
    use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        USER_AGENT,
        concat!("warden-scanner/", env!("CARGO_PKG_VERSION"), " (upstream)")
            .parse()
            .unwrap(),
    );
    headers.insert(ACCEPT, "application/vnd.github.v3.raw".parse().unwrap());
    // Treat empty token as no token (CI passes "" when secret is unset).
    if let Some(t) = token.filter(|s| !s.is_empty()) {
        let val = format!("Bearer {t}");
        if let Ok(h) = val.parse() {
            headers.insert(AUTHORIZATION, h);
        }
    }
    let client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?;

    let candidates = [
        ("Cargo.toml", "cargo"),
        ("package.json", "npm"),
        ("go.mod", "go"),
        ("requirements.txt", "pypi"),
    ];

    let mut out = Vec::new();
    for (file, eco) in candidates {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{file}");
        let resp = match client.get(&url).send() {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        let body = match resp.text() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let parsed = match eco {
            "cargo" => manifest::parse_cargo_toml(&body).unwrap_or_default(),
            "npm" => manifest::parse_package_json(&body).unwrap_or_default(),
            "go" => manifest::parse_go_mod(&body, false).unwrap_or_default(),
            "pypi" => manifest::parse_requirements_txt(&body).unwrap_or_default(),
            _ => vec![],
        };
        out.extend(parsed);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

pub fn print_console(report: &AuditReport) {
    use colored::Colorize;

    println!(
        "\n{} {} scanned, {} with findings, {} total findings\n",
        report.total_deps.to_string().bold(),
        if report.total_deps == 1 {
            "dependency"
        } else {
            "dependencies"
        },
        report.deps_with_findings,
        report.total_findings,
    );

    let mut any = false;
    for dep in &report.results {
        if dep.findings.is_empty() {
            continue;
        }
        any = true;
        let slug = dep
            .source_repo
            .clone()
            .unwrap_or_else(|| "<unresolved>".to_string());
        println!(
            "{} {}{} ({}) -> {} // {} finding{}",
            "Dep:".bold(),
            dep.name,
            dep.version
                .as_ref()
                .map(|v| format!("@{v}"))
                .unwrap_or_default(),
            dep.ecosystem,
            slug.cyan(),
            dep.findings.len(),
            if dep.findings.len() == 1 { "" } else { "s" },
        );
        for f in &dep.findings {
            let sev = match f.severity.as_str() {
                "critical" => "CRITICAL".red().bold().to_string(),
                "high" => "HIGH".red().to_string(),
                "medium" => "MEDIUM".yellow().to_string(),
                "low" => "LOW".blue().to_string(),
                o => o.to_uppercase(),
            };
            println!(
                "  {:<20} [{}] {} // {}:{}",
                sev, f.rule_id, f.title, f.file, f.line
            );
        }
        println!();
    }

    if !any {
        println!(
            "{}",
            "No findings across any resolved dependency.".green().bold()
        );
    }
}

pub fn print_json(report: &AuditReport) {
    match serde_json::to_string_pretty(report) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize audit report: {e}"),
    }
}

pub fn print_markdown(report: &AuditReport) {
    let mut out = String::new();
    out.push_str("## warden upstream\n\n");
    out.push_str(&format!(
        "**Summary:** {} dependencies scanned, {} with findings, {} total findings\n\n",
        report.total_deps, report.deps_with_findings, report.total_findings
    ));
    for dep in &report.results {
        if dep.findings.is_empty() {
            continue;
        }
        let slug = dep
            .source_repo
            .clone()
            .unwrap_or_else(|| "<unresolved>".to_string());
        out.push_str(&format!(
            "### `{}` ({}) -> `{}`\n\n",
            dep.name, dep.ecosystem, slug
        ));
        for f in &dep.findings {
            out.push_str(&format!(
                "- **{}** `{}` {} // `{}:{}`\n",
                f.severity.to_uppercase(),
                f.rule_id,
                f.title,
                f.file,
                f.line
            ));
        }
        out.push('\n');
    }
    print!("{out}");
}

pub fn print_sarif(report: &AuditReport) {
    // Flatten all findings back into the existing finding shape but rewrite
    // file paths to include the source repo slug so code-scanning surfaces
    // the alerts on the right project.
    let mut flat: Vec<Finding> = Vec::new();
    for dep in &report.results {
        let slug = dep
            .source_repo
            .clone()
            .unwrap_or_else(|| "unresolved".to_string());
        for f in &dep.findings {
            flat.push(Finding {
                rule_id: f.rule_id.clone(),
                severity: f.severity.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                file: format!("{}/{}", slug, f.file),
                line: f.line,
                remediation: f.remediation.clone(),
            });
        }
    }
    crate::output::sarif(&flat);
}

/// Compute whether any finding across the whole report meets a severity
/// threshold. Mirrors `should_fail` in main.rs but operates on `FindingOut`.
pub fn max_severity_rank(report: &AuditReport) -> u8 {
    let mut best: u8 = 99;
    for dep in &report.results {
        for f in &dep.findings {
            let r = match f.severity.to_lowercase().as_str() {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            if r < best {
                best = r;
            }
        }
    }
    best
}
