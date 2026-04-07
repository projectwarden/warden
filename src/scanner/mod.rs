pub mod github;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_yaml::Value;

use crate::config::WardenConfig;
use crate::rules;
use crate::rules::Finding;

/// A parsed GitHub Actions workflow file.
#[derive(Debug, Clone)]
pub struct Workflow {
    pub path: String,
    pub content: String,
    pub parsed: Value,
}

/// Load workflow files from a local directory or file path.
/// Looks for .github/workflows/*.yml and *.yaml files.
pub fn load_local(path: &str) -> Result<Vec<Workflow>> {
    let p = Path::new(path);

    if !p.exists() {
        bail!("Path does not exist: {path}");
    }

    if p.is_file() {
        let content =
            fs::read_to_string(p).with_context(|| format!("Failed to read file: {path}"))?;
        let parsed: Value = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML: {path}"))?;
        return Ok(vec![Workflow {
            path: path.to_string(),
            content,
            parsed,
        }]);
    }

    // Directory: look for .github/workflows/
    let workflow_dir: PathBuf;
    let candidate = p.join(".github").join("workflows");
    if candidate.is_dir() {
        workflow_dir = candidate;
    } else if p.is_dir() {
        // Maybe the user pointed directly at a workflows directory
        workflow_dir = p.to_path_buf();
    } else {
        bail!(
            "Could not find workflow files at {path}. Expected a .github/workflows/ directory or a YAML file."
        );
    }

    let mut workflows = Vec::new();

    let entries = fs::read_dir(&workflow_dir)
        .with_context(|| format!("Failed to read directory: {}", workflow_dir.display()))?;

    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let file_path = entry.path();

        let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }

        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;

        let parsed: Value = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML in {}", file_path.display()))?;

        let relative_path = file_path
            .strip_prefix(p)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .to_string();

        workflows.push(Workflow {
            path: relative_path,
            content,
            parsed,
        });
    }

    // Also pick up `.github/dependabot.yml` if present, so rules like WRD-520
    // (Dependabot Cooldown) and WRD-521 (Dependabot Insecure Execution) have
    // a target to scan. The dependabot config isn't a workflow but is part of
    // the same security surface.
    let dependabot_path = p.join(".github").join("dependabot.yml");
    if dependabot_path.is_file() {
        if let Ok(content) = fs::read_to_string(&dependabot_path) {
            if let Ok(parsed) = serde_yaml::from_str::<Value>(&content) {
                let relative_path = dependabot_path
                    .strip_prefix(p)
                    .unwrap_or(&dependabot_path)
                    .to_string_lossy()
                    .to_string();
                workflows.push(Workflow {
                    path: relative_path,
                    content,
                    parsed,
                });
            }
        }
    }

    if workflows.is_empty() {
        bail!("No workflow YAML files found in {}", workflow_dir.display());
    }

    Ok(workflows)
}

/// Load workflows from a GitHub repository via the API.
pub fn load_github(owner: &str, repo: &str, token: Option<&str>) -> Result<Vec<Workflow>> {
    github::load_github(owner, repo, token)
}

/// Run all rules against the provided workflows and return deduplicated findings.
pub fn scan(workflows: &[Workflow]) -> Vec<Finding> {
    scan_with_config(workflows, None)
}

/// Run all rules against the provided workflows, optionally applying a
/// `.warden.toml` config (disabled rules, severity overrides).
pub fn scan_with_config(workflows: &[Workflow], config: Option<&WardenConfig>) -> Vec<Finding> {
    scan_full(workflows, config, false)
}

/// Full scan entrypoint with config + optional progress emission.
pub fn scan_full(
    workflows: &[Workflow],
    config: Option<&WardenConfig>,
    emit_progress: bool,
) -> Vec<Finding> {
    let all = rules::all_rules();
    let mut findings = Vec::new();

    if emit_progress {
        let ev = serde_json::json!({
            "event": "scan_start",
            "total": workflows.len(),
        });
        eprintln!("{ev}");
    }

    for (idx, workflow) in workflows.iter().enumerate() {
        if emit_progress {
            let ev = serde_json::json!({
                "event": "scan_file",
                "path": workflow.path,
                "index": idx + 1,
                "total": workflows.len(),
                "findings_so_far": findings.len(),
            });
            eprintln!("{ev}");
        }
        for rule in &all {
            if let Some(cfg) = config {
                if cfg.is_disabled(rule.id()) {
                    continue;
                }
            }
            let mut results = rule.check(workflow);
            findings.append(&mut results);
        }
    }

    // Deduplicate by (rule_id, file, line, title)
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for f in findings {
        let key = (f.rule_id.clone(), f.file.clone(), f.line, f.title.clone());
        if seen.insert(key) {
            deduped.push(f);
        }
    }

    // Sort by severity (critical first), then file, then line
    // Apply severity overrides before sorting so the order reflects them.
    if let Some(cfg) = config {
        cfg.apply(&mut deduped);
    }

    deduped.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    if emit_progress {
        let ev = serde_json::json!({
            "event": "scan_done",
            "total_findings": deduped.len(),
        });
        eprintln!("{ev}");
    }

    deduped
}

/// Map severity string to a sort rank (lower = more severe).
fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Calculate a security score from 100 using diminishing returns.
///
/// Scoring model:
///   Critical: first -20, subsequent -10 each, max penalty -40
///   High:     first -10, subsequent -3 each,  max penalty -30
///   Medium:   first -5,  subsequent -1 each,  max penalty -20
///   Low:      first -2,  subsequent -1 each,  max penalty -10
pub fn score(findings: &[Finding]) -> u32 {
    let mut critical: u32 = 0;
    let mut high: u32 = 0;
    let mut medium: u32 = 0;
    let mut low: u32 = 0;

    for f in findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    let penalty = |count: u32, first: u32, subsequent: u32, max: u32| -> u32 {
        if count == 0 {
            return 0;
        }
        let total = first + count.saturating_sub(1) * subsequent;
        total.min(max)
    };

    let total_penalty = penalty(critical, 20, 10, 40)
        + penalty(high, 10, 3, 30)
        + penalty(medium, 5, 1, 20)
        + penalty(low, 2, 1, 10);

    100u32.saturating_sub(total_penalty)
}
