pub mod github;
mod loaded;

pub use loaded::{load_one, stub_workflow, LoadedFile, LoadedWorkflow};

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

    // Also pick up `.github/dependabot.yml` if present, so rules like WRD-540
    // (Dependabot Daily Without Grouping) and WRD-521 (Dependabot PR Untrusted Execution) have
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

/// Span-aware, typed counterpart to [`load_local`]. Returns a [`LoadedFile`]
/// per discovered YAML so V2 rules can consume typed nodes plus byte-exact
/// spans without re-parsing.
pub fn load_local_typed(path: &str) -> Result<Vec<LoadedFile>> {
    let p = Path::new(path);

    if !p.exists() {
        bail!("Path does not exist: {path}");
    }

    let mut out = Vec::new();

    if p.is_file() {
        let raw = fs::read_to_string(p).with_context(|| format!("Failed to read file: {path}"))?;
        out.push(load_one(p.to_path_buf(), raw)?);
        return Ok(out);
    }

    let workflow_dir: PathBuf;
    let candidate = p.join(".github").join("workflows");
    if candidate.is_dir() {
        workflow_dir = candidate;
    } else if p.is_dir() {
        workflow_dir = p.to_path_buf();
    } else {
        bail!(
            "Could not find workflow files at {path}. Expected a .github/workflows/ directory or a YAML file."
        );
    }

    let entries = fs::read_dir(&workflow_dir)
        .with_context(|| format!("Failed to read directory: {}", workflow_dir.display()))?;

    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let file_path = entry.path();
        let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let raw = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        let relative = file_path
            .strip_prefix(p)
            .unwrap_or(&file_path)
            .to_path_buf();
        out.push(load_one(relative, raw)?);
    }

    let dependabot_path = p.join(".github").join("dependabot.yml");
    if dependabot_path.is_file() {
        if let Ok(raw) = fs::read_to_string(&dependabot_path) {
            let relative = dependabot_path
                .strip_prefix(p)
                .unwrap_or(&dependabot_path)
                .to_path_buf();
            if let Ok(loaded) = load_one(relative, raw) {
                out.push(loaded);
            }
        }
    }

    Ok(out)
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
    let v2 = rules::all_rules();
    let mut findings = Vec::new();
    let mut ignore_maps: Vec<(String, crate::ignores::IgnoreMap)> = Vec::new();

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

        // Parse inline `# warden: ignore[...]` directives once per file.
        ignore_maps.push((
            workflow.path.clone(),
            crate::ignores::parse(&workflow.content),
        ));

        // Rules run against a typed `LoadedWorkflow`, rebuilt from the
        // legacy `Workflow`'s raw content. Non-workflow YAMLs (dependabot.yml)
        // go through a stub so rules that only consume raw text can fire.
        if !v2.is_empty() {
            let loaded_opt = match loaded::load_one(
                std::path::PathBuf::from(&workflow.path),
                workflow.content.clone(),
            ) {
                Ok(LoadedFile::Workflow(w)) => Some(*w),
                Ok(LoadedFile::Other {
                    path, raw, spans, ..
                }) => Some(loaded::stub_workflow(path, raw, spans)),
                Err(_) => None,
            };
            if let Some(loaded_wf) = loaded_opt {
                let expr_index = crate::expression::ExprIndex::build(&loaded_wf.workflow);
                let shell_index = crate::shell::ShellIndex::build(&loaded_wf.workflow);
                let provenance = crate::taint::build_provenance(&loaded_wf.workflow);
                let ignores_for_ctx = &ignore_maps.last().unwrap().1;
                let ctx = rules::AuditCtx {
                    loaded: &loaded_wf,
                    expressions: &expr_index,
                    shell: &shell_index,
                    ignores: ignores_for_ctx,
                    provenance: &provenance,
                };
                for rule in &v2 {
                    let meta = rule.meta();
                    if let Some(cfg) = config {
                        if cfg.is_disabled(meta.id) {
                            continue;
                        }
                    }
                    for fv2 in rule.audit(&ctx) {
                        findings.push(fv2.into_legacy(&workflow.path));
                    }
                }
            }
        }
    }

    // Apply inline-ignore suppressions before dedupe / sort.
    findings.retain(|f| {
        let map = ignore_maps
            .iter()
            .find(|(p, _)| p == &f.file)
            .map(|(_, m)| m);
        match map {
            Some(m) => !m.is_suppressed(&f.rule_id, f.line),
            None => true,
        }
    });

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
