//! Span-aware, typed view of a loaded workflow file.
//!
//! Lives alongside the legacy `Workflow` (in `super`) during the migration.
//! Once every rule has migrated to consume `LoadedWorkflow`, the legacy
//! `Workflow` can be retired.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::models;
use crate::yamlpath::{self, SpanTable};

/// One workflow file loaded with a typed model AND a span table.
pub struct LoadedWorkflow {
    pub path: PathBuf,
    pub raw: String,
    pub workflow: models::Workflow,
    pub spans: SpanTable,
    /// True if `workflow` was synthesized from a non-workflow YAML (e.g.
    /// dependabot.yml). Structural rules should skip such files; raw-text /
    /// path-aware rules can still inspect `raw`.
    pub is_stub: bool,
}

/// Result of loading a single file from `.github/`.
///
/// Workflow YAMLs round-trip into `models::Workflow`; non-workflow YAMLs
/// (currently just `dependabot.yml`) are kept as raw text + span table so
/// the rules that target them can still operate without forcing a
/// schema-aware deserialization.
pub enum LoadedFile {
    Workflow(Box<LoadedWorkflow>),
    Other {
        path: PathBuf,
        raw: String,
        spans: SpanTable,
        /// The serde error that prevented typed deserialization. Surfaced
        /// for callers that want to log / diagnose schema mismatches
        /// instead of silently treating the file as raw-only.
        deserialize_error: Option<String>,
    },
}

impl LoadedFile {
    pub fn path(&self) -> &PathBuf {
        match self {
            LoadedFile::Workflow(w) => &w.path,
            LoadedFile::Other { path, .. } => path,
        }
    }

    pub fn raw(&self) -> &str {
        match self {
            LoadedFile::Workflow(w) => &w.raw,
            LoadedFile::Other { raw, .. } => raw,
        }
    }

    pub fn spans(&self) -> &SpanTable {
        match self {
            LoadedFile::Workflow(w) => &w.spans,
            LoadedFile::Other { spans, .. } => spans,
        }
    }
}

/// Load a single YAML file as a typed `LoadedWorkflow`. If the file's shape
/// doesn't deserialize into `models::Workflow` (e.g. dependabot config),
/// returns `LoadedFile::Other` instead so callers can still reason about it.
pub fn load_one(path: PathBuf, raw: String) -> Result<LoadedFile> {
    let spans =
        yamlpath::load(&raw).with_context(|| format!("yaml parse failed: {}", path.display()))?;

    match serde_yaml::from_str::<models::Workflow>(&raw) {
        Ok(workflow) => Ok(LoadedFile::Workflow(Box::new(LoadedWorkflow {
            path,
            raw,
            workflow,
            spans,
            is_stub: false,
        }))),
        Err(e) => Ok(LoadedFile::Other {
            path,
            raw,
            spans,
            deserialize_error: Some(e.to_string()),
        }),
    }
}

/// Build a synthetic `LoadedWorkflow` whose typed model is empty // useful
/// for routing non-workflow YAMLs (e.g. dependabot.yml) through V2 rules
/// that only inspect `ctx.loaded.raw` / `ctx.loaded.path` / `ctx.loaded.spans`.
///
/// Rules that walk `workflow.jobs` will see an empty map and produce no
/// findings, which is the right behavior for files that aren't workflows.
pub fn stub_workflow(
    path: PathBuf,
    raw: String,
    spans: crate::yamlpath::SpanTable,
) -> LoadedWorkflow {
    let workflow = models::Workflow {
        name: None,
        run_name: None,
        on: models::On::Bare("none".to_string()),
        permissions: None,
        env: None,
        defaults: None,
        concurrency: None,
        jobs: std::collections::BTreeMap::new(),
    };
    LoadedWorkflow {
        path,
        raw,
        workflow,
        spans,
        is_stub: true,
    }
}
