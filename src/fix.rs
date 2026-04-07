use std::collections::HashMap;
use std::fs;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};

use crate::scanner::Workflow;

/// A single fix applied to a workflow file.
#[derive(Debug, Clone)]
pub struct FixRecord {
    pub file: String,
    pub line: usize,
    pub description: String,
}

/// Result of running the fixer on a workflow.
pub struct FixResult {
    pub path: String,
    pub original: String,
    pub fixed: String,
    pub fixes: Vec<FixRecord>,
}

/// Build a GitHub API client with optional token.
fn build_client(token: Option<&str>) -> Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        USER_AGENT,
        concat!("warden-scanner/", env!("CARGO_PKG_VERSION"))
            .parse()
            .unwrap(),
    );
    headers.insert(ACCEPT, "application/vnd.github.v3+json".parse().unwrap());

    // Treat empty token as no token (avoid `Authorization: Bearer ` -> 401).
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

#[derive(Deserialize)]
struct GitRef {
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    obj_type: String,
    url: Option<String>,
}

#[derive(Deserialize)]
struct TagObject {
    object: GitObject,
}

/// Resolve a tag reference to a full commit SHA via the GitHub API.
/// Returns None if resolution fails (network error, not found, etc.).
fn resolve_tag_to_sha(client: &Client, owner: &str, repo: &str, tag: &str) -> Option<String> {
    // Try refs/tags/<tag> first
    let url = format!("https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}");

    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let git_ref: GitRef = resp.json().ok()?;

    // If it's a direct commit, return the SHA
    if git_ref.object.obj_type == "commit" {
        return Some(git_ref.object.sha);
    }

    // If it's an annotated tag, dereference it to get the commit
    if git_ref.object.obj_type == "tag" {
        if let Some(ref url) = git_ref.object.url {
            let resp2 = client.get(url).send().ok()?;
            if resp2.status().is_success() {
                let tag_obj: TagObject = resp2.json().ok()?;
                return Some(tag_obj.object.sha);
            }
        }
    }

    // Fallback: return whatever SHA we got
    Some(git_ref.object.sha)
}

/// Apply all fixes to a single workflow, returning the fixed content and a list of changes.
pub fn fix_workflow(workflow: &Workflow, github_token: Option<&str>) -> FixResult {
    let mut content = workflow.content.clone();
    let mut fixes = Vec::new();

    // Pass 1: Pin unpinned actions to SHA
    content = fix_unpin_actions(&content, github_token, &workflow.path, &mut fixes);

    // Pass 2: Extract expressions from run blocks to env vars
    content = fix_expression_injection(&content, &workflow.path, &mut fixes);

    // Pass 3: Add persist-credentials: false to checkout steps
    content = fix_checkout_persist_credentials(&content, &workflow.path, &mut fixes);

    // Pass 4: Add top-level permissions: read-all if missing (WRD-824)
    if let Some((new_content, rec)) = fix_missing_permissions(&content, &workflow.path) {
        content = new_content;
        fixes.push(rec);
    }

    // Pass 5: Add documentation comment above permissions: block (WRD-826)
    if let Some((new_content, rec)) = fix_permissions_comment(&content, &workflow.path) {
        content = new_content;
        fixes.push(rec);
    }

    // Pass 6: Add concurrency: block if missing (WRD-831)
    if let Some((new_content, rec)) = fix_missing_concurrency(&content, &workflow.path) {
        content = new_content;
        fixes.push(rec);
    }

    FixResult {
        path: workflow.path.clone(),
        original: workflow.content.clone(),
        fixed: content,
        fixes,
    }
}

/// Pin action references like `uses: owner/repo@v1` to their commit SHA.
fn fix_unpin_actions(
    content: &str,
    token: Option<&str>,
    file: &str,
    fixes: &mut Vec<FixRecord>,
) -> String {
    let re =
        Regex::new(r"(?m)^(\s*uses:\s*)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v[a-zA-Z0-9._-]+)\s*$")
            .unwrap();

    let client = build_client(token).ok();
    // Cache resolved SHAs so we don't hit the API repeatedly for the same action
    let mut sha_cache: HashMap<String, Option<String>> = HashMap::new();

    let lines: Vec<&str> = content.lines().collect();
    let mut result_lines: Vec<String> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if let Some(caps) = re.captures(line) {
            let prefix = caps.get(1).unwrap().as_str();
            let action = caps.get(2).unwrap().as_str();
            let tag = caps.get(3).unwrap().as_str();

            let cache_key = format!("{action}@{tag}");
            let sha = sha_cache
                .entry(cache_key.clone())
                .or_insert_with(|| {
                    if let Some(ref c) = client {
                        let parts: Vec<&str> = action.split('/').collect();
                        if parts.len() == 2 {
                            resolve_tag_to_sha(c, parts[0], parts[1], tag)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .clone();

            if let Some(sha) = sha {
                let new_line = format!("{prefix}{action}@{sha} # {tag}");
                result_lines.push(new_line);
                fixes.push(FixRecord {
                    file: file.to_string(),
                    line: i + 1,
                    description: format!(
                        "Pinned {}@{} to SHA {}",
                        action,
                        tag,
                        &sha[..sha.len().min(12)]
                    ),
                });
                continue;
            }
        }
        result_lines.push(line.to_string());
    }

    result_lines.join("\n")
}

/// Extract dangerous expressions from `run:` blocks into `env:` mappings.
fn fix_expression_injection(content: &str, file: &str, fixes: &mut Vec<FixRecord>) -> String {
    // Match expressions that could be injection vectors
    let expr_re =
        Regex::new(r"\$\{\{\s*(github\.event\.[a-zA-Z0-9_.]+|inputs\.[a-zA-Z0-9_.]+)\s*\}\}")
            .unwrap();
    // Match a `- run:` line (single-line run value on the same line)
    let run_line_re = Regex::new(r"^(\s*-?\s*run:\s*)(.+)$").unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut result_lines: Vec<String> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check if this is a `run:` line with inline content (not a block scalar)
        if let Some(run_caps) = run_line_re.captures(line) {
            let prefix = run_caps.get(1).unwrap().as_str();
            let run_body = run_caps.get(2).unwrap().as_str();

            // Skip block scalars (| or >)
            let trimmed_body = run_body.trim();
            if trimmed_body == "|"
                || trimmed_body == "|-"
                || trimmed_body == ">"
                || trimmed_body == ">-"
            {
                result_lines.push(line.to_string());
                i += 1;
                // Also scan the block scalar lines for expressions
                let base_indent = prefix.len();
                let mut block_lines: Vec<String> = Vec::new();
                let mut env_vars: Vec<(String, String)> = Vec::new();
                let block_start = i;

                while i < lines.len() {
                    let bline = lines[i];
                    let bline_indent = bline.len() - bline.trim_start().len();
                    if !bline.trim().is_empty() && bline_indent <= base_indent {
                        break;
                    }
                    block_lines.push(bline.to_string());
                    i += 1;
                }

                // Check block lines for expressions
                let mut new_block_lines = block_lines.clone();
                for bl in &mut new_block_lines {
                    for expr_cap in expr_re.find_iter(&bl.clone()) {
                        let full_expr = expr_cap.as_str();
                        let inner = expr_re
                            .captures(full_expr)
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default();

                        let var_name = expression_to_var_name(&inner);
                        if !env_vars.iter().any(|(_, e)| e == full_expr) {
                            env_vars.push((var_name.clone(), full_expr.to_string()));
                        }
                        let existing_var = env_vars
                            .iter()
                            .find(|(_, e)| e == full_expr)
                            .map(|(v, _)| v.clone())
                            .unwrap();
                        *bl = bl.replace(full_expr, &format!("${existing_var}"));
                    }
                }

                if !env_vars.is_empty() {
                    // Determine the indentation of the step (find the `- run:` or `run:` indent)
                    let step_indent = determine_step_indent(prefix);

                    // Insert env: block before the run: line (which is already pushed)
                    let env_line = format!("{step_indent}env:");
                    let mut env_block = vec![env_line];
                    for (var, expr) in &env_vars {
                        env_block.push(format!("{step_indent}  {var}: {expr}"));
                    }
                    // Insert env block before the run: line
                    let run_line_saved = result_lines.pop().unwrap();
                    for eb in env_block {
                        result_lines.push(eb);
                    }
                    result_lines.push(run_line_saved);

                    for bl in &new_block_lines {
                        result_lines.push(bl.to_string());
                    }

                    fixes.push(FixRecord {
                        file: file.to_string(),
                        line: block_start,
                        description: format!(
                            "Extracted {} expression(s) from run block to env vars",
                            env_vars.len()
                        ),
                    });
                } else {
                    for bl in &block_lines {
                        result_lines.push(bl.to_string());
                    }
                }
                continue;
            }

            // Single-line run: value
            let exprs: Vec<(String, String)> = expr_re
                .captures_iter(run_body)
                .map(|c| {
                    let full = c.get(0).unwrap().as_str().to_string();
                    let inner = c.get(1).unwrap().as_str().to_string();
                    (full, inner)
                })
                .collect();

            if !exprs.is_empty() {
                let step_indent = determine_step_indent(prefix);
                let mut new_run = run_body.to_string();
                let mut env_entries: Vec<(String, String)> = Vec::new();
                let mut seen: HashMap<String, String> = HashMap::new();

                for (full_expr, inner) in &exprs {
                    let var_name = if let Some(existing) = seen.get(full_expr) {
                        existing.clone()
                    } else {
                        let vn = expression_to_var_name(inner);
                        seen.insert(full_expr.clone(), vn.clone());
                        env_entries.push((vn.clone(), full_expr.clone()));
                        vn
                    };
                    new_run = new_run.replace(full_expr.as_str(), &format!("${var_name}"));
                }

                // Emit env: block, then the modified run: line
                result_lines.push(format!("{step_indent}env:"));
                for (var, expr) in &env_entries {
                    result_lines.push(format!("{step_indent}  {var}: {expr}"));
                }
                result_lines.push(format!("{prefix}{new_run}"));

                fixes.push(FixRecord {
                    file: file.to_string(),
                    line: i + 1,
                    description: format!(
                        "Extracted {} expression(s) from run to env vars",
                        env_entries.len()
                    ),
                });

                i += 1;
                continue;
            }
        }

        result_lines.push(line.to_string());
        i += 1;
    }

    result_lines.join("\n")
}

/// Add `persist-credentials: false` to checkout steps that lack it.
fn fix_checkout_persist_credentials(
    content: &str,
    file: &str,
    fixes: &mut Vec<FixRecord>,
) -> String {
    let checkout_re = Regex::new(r"(?m)^(\s*-?\s*uses:\s*actions/checkout@\S+)").unwrap();
    let persist_re = Regex::new(r"(?i)persist-credentials").unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut result_lines: Vec<String> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        result_lines.push(line.to_string());

        if checkout_re.is_match(line) {
            // Determine indentation for the `with:` block
            let leading = line.len() - line.trim_start().len();
            // Check if there's already a `with:` block following
            let with_indent = leading + 2; // typical step property indent
            let inner_indent = with_indent + 2;

            // Look ahead: does persist-credentials already exist in this step?
            let mut has_persist = false;
            let mut has_with = false;
            let mut j = i + 1;

            // Scan the rest of this step
            while j < lines.len() {
                let next = lines[j].trim();
                // If we hit another step or a job-level key, stop
                if !next.is_empty() {
                    let next_indent = lines[j].len() - lines[j].trim_start().len();
                    if next_indent <= leading && (next.starts_with('-') || !next.starts_with('#')) {
                        break;
                    }
                }
                if persist_re.is_match(lines[j]) {
                    has_persist = true;
                    break;
                }
                if lines[j].trim().starts_with("with:") {
                    has_with = true;
                }
                j += 1;
            }

            if !has_persist {
                if has_with {
                    // Insert `persist-credentials: false` right after the `with:` line
                    // We'll handle this by consuming lines up to and including `with:`
                    while i + 1 < lines.len() {
                        i += 1;
                        result_lines.push(lines[i].to_string());
                        if lines[i].trim().starts_with("with:") {
                            let w_indent = lines[i].len() - lines[i].trim_start().len();
                            result_lines.push(format!(
                                "{}persist-credentials: false",
                                " ".repeat(w_indent + 2)
                            ));
                            fixes.push(FixRecord {
                                file: file.to_string(),
                                line: i + 1,
                                description: "Added persist-credentials: false to checkout step"
                                    .to_string(),
                            });
                            break;
                        }
                    }
                } else {
                    // No `with:` block; add one
                    result_lines.push(format!("{}with:", " ".repeat(with_indent)));
                    result_lines.push(format!(
                        "{}persist-credentials: false",
                        " ".repeat(inner_indent)
                    ));
                    fixes.push(FixRecord {
                        file: file.to_string(),
                        line: i + 1,
                        description: "Added persist-credentials: false to checkout step"
                            .to_string(),
                    });
                }
            }
        }

        i += 1;
    }

    result_lines.join("\n")
}

/// Convert a GitHub Actions expression path to a screaming snake case env var name.
/// e.g. "github.event.issue.title" -> "ISSUE_TITLE"
/// e.g. "inputs.name" -> "INPUT_NAME"
fn expression_to_var_name(expr: &str) -> String {
    let parts: Vec<&str> = expr.split('.').collect();
    let meaningful: Vec<&str> = if parts.first() == Some(&"github") {
        // Skip "github" and "event"
        parts.iter().skip(2).copied().collect()
    } else if parts.first() == Some(&"inputs") {
        let mut v = vec!["INPUT"];
        v.extend(parts.iter().skip(1).copied());
        v
    } else {
        parts.clone()
    };

    meaningful.join("_").to_uppercase().replace('-', "_")
}

/// Determine step-level indentation from the run: line prefix.
/// For "      - run: ", returns "        " (indent of step properties).
/// For "        run: ", returns "        " (same indent).
fn determine_step_indent(prefix: &str) -> String {
    // Find where the keyword starts (after any leading whitespace and optional "- ")
    let trimmed = prefix.trim_start();
    let leading_spaces = prefix.len() - trimmed.len();

    if trimmed.starts_with("- ") {
        // Step list item: properties are indented 2 more than the dash
        " ".repeat(leading_spaces + 2)
    } else {
        // Already a step property
        " ".repeat(leading_spaces)
    }
}

/// Find the line index (0-based) where the top-level `on:` block ends.
/// Returns the index of the first line AFTER the on: block at column 0.
/// Returns None if the file structure is unrecognizable.
fn find_end_of_on_block(lines: &[&str]) -> Option<usize> {
    // Find `on:` at column 0
    let on_start = lines.iter().position(|l| {
        let trimmed = l.trim_start();
        (trimmed.starts_with("on:") || trimmed == "on:" || trimmed.starts_with("on "))
            && l.len() == trimmed.len()
    })?;

    // Check if on: is inline (e.g. "on: push" or "on: [push]")
    let on_line = lines[on_start];
    let after_on = on_line.trim_start_matches("on:").trim();
    if !after_on.is_empty() {
        return Some(on_start + 1);
    }

    // Otherwise, scan forward while lines are indented (part of the on: block) or blank
    let mut i = on_start + 1;
    while i < lines.len() {
        let l = lines[i];
        if l.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = l.len() - l.trim_start().len();
        if indent == 0 {
            return Some(i);
        }
        i += 1;
    }
    Some(i)
}

/// Detect whether a top-level `permissions:` key exists at column 0.
fn has_top_level_key(content: &str, key: &str) -> bool {
    let needle_colon = format!("{key}:");
    content.lines().any(|l| {
        let trimmed = l.trim_start();
        l.len() == trimmed.len()
            && (trimmed == needle_colon || trimmed.starts_with(&format!("{needle_colon} ")))
    })
}

/// Detect whether ANY `concurrency:` key exists at any indentation.
fn has_any_key(content: &str, key: &str) -> bool {
    let needle = format!("{key}:");
    content.lines().any(|l| {
        let t = l.trim_start();
        t == needle || t.starts_with(&format!("{needle} "))
    })
}

/// WRD-824: Insert `permissions: read-all` after the top-level `on:` block if missing.
fn fix_missing_permissions(content: &str, file: &str) -> Option<(String, FixRecord)> {
    if has_top_level_key(content, "permissions") {
        return None;
    }

    let lines: Vec<&str> = content.lines().collect();
    let insert_at = find_end_of_on_block(&lines)?;

    let trailing_newline = content.ends_with('\n');
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    new_lines.insert(insert_at, "permissions: read-all".to_string());

    let mut out = new_lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }

    Some((
        out,
        FixRecord {
            file: file.to_string(),
            line: insert_at + 1,
            description: "Added top-level permissions: read-all".to_string(),
        },
    ))
}

/// WRD-826: Insert a documentation comment above a top-level `permissions:` line if none.
fn fix_permissions_comment(content: &str, file: &str) -> Option<(String, FixRecord)> {
    let lines: Vec<&str> = content.lines().collect();
    let perm_idx = lines.iter().position(|l| {
        let t = l.trim_start();
        l.len() == t.len() && (t == "permissions:" || t.starts_with("permissions:"))
    })?;

    // Skip if previous non-blank line is a comment
    if perm_idx > 0 {
        let prev = lines[perm_idx - 1].trim_start();
        if prev.starts_with('#') {
            return None;
        }
    }

    let comment = "# Permissions are scoped to least privilege. See https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs";

    let trailing_newline = content.ends_with('\n');
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    new_lines.insert(perm_idx, comment.to_string());

    let mut out = new_lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }

    Some((
        out,
        FixRecord {
            file: file.to_string(),
            line: perm_idx + 1,
            description: "Added documentation comment above permissions: block".to_string(),
        },
    ))
}

/// WRD-831: Insert a top-level `concurrency:` block if none exists anywhere.
fn fix_missing_concurrency(content: &str, file: &str) -> Option<(String, FixRecord)> {
    if has_any_key(content, "concurrency") {
        return None;
    }

    let lines: Vec<&str> = content.lines().collect();

    // Prefer inserting after permissions: block; else after on:
    let insert_at = if let Some(perm_idx) = lines.iter().position(|l| {
        let t = l.trim_start();
        l.len() == t.len() && (t == "permissions:" || t.starts_with("permissions:"))
    }) {
        // If permissions is inline (permissions: read-all), insert after that line.
        let perm_line = lines[perm_idx];
        let after = perm_line.trim_start_matches("permissions:").trim();
        if !after.is_empty() {
            perm_idx + 1
        } else {
            // Multiline permissions block: find first line at column 0 after perm_idx
            let mut i = perm_idx + 1;
            while i < lines.len() {
                let l = lines[i];
                if !l.trim().is_empty() {
                    let indent = l.len() - l.trim_start().len();
                    if indent == 0 {
                        break;
                    }
                }
                i += 1;
            }
            i
        }
    } else {
        find_end_of_on_block(&lines)?
    };

    let block = vec![
        "concurrency:".to_string(),
        "  group: ${{ github.workflow }}-${{ github.ref }}".to_string(),
        "  cancel-in-progress: true".to_string(),
    ];

    let trailing_newline = content.ends_with('\n');
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    for (offset, bl) in block.into_iter().enumerate() {
        new_lines.insert(insert_at + offset, bl);
    }

    let mut out = new_lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }

    Some((
        out,
        FixRecord {
            file: file.to_string(),
            line: insert_at + 1,
            description: "Added top-level concurrency: block".to_string(),
        },
    ))
}

/// Run the fixer on all provided workflows and print/write results.
///
/// `plan_only = true` means show what would change without writing files
/// (terraform-style plan). `plan_only = false` actually rewrites the files.
pub fn run_fix(
    workflows: &[Workflow],
    github_token: Option<&str>,
    plan_only: bool,
) -> Result<usize> {
    let mut total_fixes = 0;

    for workflow in workflows {
        let result = fix_workflow(workflow, github_token);

        if result.fixes.is_empty() {
            continue;
        }

        total_fixes += result.fixes.len();

        println!(
            "\n{}  ({} fix{})",
            result.path.bold(),
            result.fixes.len(),
            if result.fixes.len() == 1 { "" } else { "es" }
        );

        for fix in &result.fixes {
            println!("  {} L{}: {}", "+".green(), fix.line, fix.description);
        }

        if !plan_only {
            // Resolve the actual file path for writing back
            let write_path = &workflow.path;
            fs::write(write_path, &result.fixed)
                .with_context(|| format!("Failed to write fixed file: {write_path}"))?;
            println!("  {} Written to {}", "->".blue(), write_path);
        }
    }

    if total_fixes == 0 {
        println!("No fixable issues found.");
    } else if plan_only {
        println!(
            "\n{} fix{} would be applied. Re-run with `--apply` to write changes.",
            total_fixes,
            if total_fixes == 1 { "" } else { "es" }
        );
    } else {
        println!(
            "\n{} fix{} applied.",
            total_fixes,
            if total_fixes == 1 { "" } else { "es" }
        );
    }

    Ok(total_fixes)
}

#[derive(Serialize)]
pub struct JsonFixRecord {
    pub line: usize,
    pub description: String,
}

#[derive(Serialize)]
pub struct JsonFileResult {
    pub path: String,
    pub original: String,
    pub fixed: String,
    pub fixes: Vec<JsonFixRecord>,
}

#[derive(Serialize)]
pub struct JsonOutput {
    pub files: Vec<JsonFileResult>,
    pub total_fixes: usize,
    /// True when the fixer was run in plan mode (no writes). The JSON output
    /// itself is always pure data and never touches disk; this flag is just
    /// metadata so consumers know whether the source files are unchanged.
    pub plan_only: bool,
}

/// Run the fixer and return structured data. Does NOT write to disk.
/// Only includes files that had at least one fix applied.
pub fn run_fix_json(
    workflows: &[Workflow],
    github_token: Option<&str>,
    plan_only: bool,
) -> JsonOutput {
    let mut files = Vec::new();
    let mut total_fixes = 0;

    for workflow in workflows {
        let result = fix_workflow(workflow, github_token);
        if result.fixes.is_empty() {
            continue;
        }
        total_fixes += result.fixes.len();
        files.push(JsonFileResult {
            path: result.path,
            original: result.original,
            fixed: result.fixed,
            fixes: result
                .fixes
                .into_iter()
                .map(|f| JsonFixRecord {
                    line: f.line,
                    description: f.description,
                })
                .collect(),
        });
    }

    JsonOutput {
        files,
        total_fixes,
        plan_only,
    }
}

// -----------------------------------------------------------------------
// Pull-request creation
// -----------------------------------------------------------------------

/// Base64-encode bytes using the standard alphabet with padding.
/// Small local implementation so we don't pull in a new crate just for this.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHA[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

#[derive(Deserialize)]
struct RepoInfo {
    default_branch: String,
    #[serde(default)]
    permissions: Option<RepoPermissions>,
}

#[derive(Deserialize, Default)]
struct RepoPermissions {
    #[serde(default)]
    push: bool,
}

#[derive(Deserialize)]
struct ContentsGet {
    sha: String,
}

#[derive(Deserialize)]
struct PullRequestResp {
    html_url: String,
}

#[derive(Deserialize)]
struct AuthUser {
    login: String,
}

/// Fork `upstream_owner/upstream_repo` under the authenticated user and wait
/// until the fork is queryable. Returns `(fork_owner, fork_repo)`.
fn fork_and_wait(
    client: &Client,
    api: &str,
    upstream_owner: &str,
    upstream_repo: &str,
) -> Result<(String, String)> {
    // 1. Trigger the fork. Returns 202 quickly even if the fork is async.
    let fork_url = format!("{api}/repos/{upstream_owner}/{upstream_repo}/forks");
    let resp = client
        .post(&fork_url)
        .send()
        .with_context(|| format!("POST {fork_url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().unwrap_or_default();
        bail!("Failed to fork repo: HTTP {status} {txt}");
    }

    // 2. Resolve authenticated user login.
    let me_url = format!("{api}/user");
    let me: AuthUser = client
        .get(&me_url)
        .send()
        .with_context(|| format!("GET {me_url}"))?
        .error_for_status()
        .context("Failed to read /user (token needs at minimum `user:email` scope; for fork creation also needs `public_repo` and `workflow`)")?
        .json()
        .context("Failed to parse /user JSON")?;

    // 3. Poll the fork until it exists. GitHub usually finishes within ~5s
    // for small repos and up to ~30s for large monorepos.
    let probe_url = format!("{}/repos/{}/{}", api, me.login, upstream_repo);
    for attempt in 0..20u32 {
        let resp = client
            .get(&probe_url)
            .send()
            .with_context(|| format!("GET {probe_url}"))?;
        if resp.status().is_success() {
            return Ok((me.login, upstream_repo.to_string()));
        }
        std::thread::sleep(std::time::Duration::from_millis(
            1500 + (attempt as u64) * 250,
        ));
    }
    bail!(
        "Fork of {upstream_owner}/{upstream_repo} did not become available within ~30s. Try again in a moment."
    );
}

/// Open a pull request against `owner/repo` containing all the files from
/// `payload`. Returns the new PR's HTML URL.
///
/// When `plan_only` is true, no HTTP requests are made; a synthetic URL is
/// returned and a plan is printed to stderr. This lets callers exercise the
/// code path in CI without a real token.
pub fn open_fix_pr(
    owner: &str,
    repo: &str,
    branch: Option<&str>,
    payload: &JsonOutput,
    token: Option<&str>,
    plan_only: bool,
    prepare_only: bool,
) -> Result<String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let branch_name = branch
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("warden/auto-fix-{ts}"));

    let total_fixes = payload.total_fixes;
    let title = format!(
        "warden: auto-fix {} security finding{}",
        total_fixes,
        if total_fixes == 1 { "" } else { "s" }
    );

    let mut body =
        String::from("This PR was generated automatically by `warden fix --pr --apply`.\n\n");
    body.push_str("## Fixes applied\n\n");
    for file in &payload.files {
        body.push_str(&format!(
            "### `{}` ({} fix{})\n",
            file.path,
            file.fixes.len(),
            if file.fixes.len() == 1 { "" } else { "es" }
        ));
        for fix in &file.fixes {
            body.push_str(&format!("- L{}: {}\n", fix.line, fix.description));
        }
        body.push('\n');
    }
    body.push_str("---\n_generated by [warden](https://github.com/projectwarden/warden)_\n");

    if plan_only {
        eprintln!(
            "[plan] Would {} against {}/{}",
            if prepare_only {
                "prepare branch (no PR)"
            } else {
                "create PR"
            },
            owner,
            repo
        );
        eprintln!("[plan] Branch: {branch_name}");
        eprintln!("[plan] Title: {title}");
        eprintln!("[plan] Files: {}", payload.files.len());
        for file in &payload.files {
            eprintln!("[plan]   - {} ({} fixes)", file.path, file.fixes.len());
        }
        if prepare_only {
            return Ok(format!(
                "https://github.com/{owner}/{repo}/compare/PLAN...{branch_name}?expand=1"
            ));
        }
        return Ok(format!(
            "https://github.com/{owner}/{repo}/pull/PLAN (branch: {branch_name})"
        ));
    }

    let token = token.ok_or_else(|| {
        anyhow::anyhow!("--pr requires a GitHub token. Set GITHUB_TOKEN or pass --github-token.")
    })?;
    let client = build_client(Some(token))?;
    let api = "https://api.github.com";

    // 1. Resolve default branch + check write access on upstream.
    let upstream_owner = owner.to_string();
    let upstream_repo = repo.to_string();
    let repo_url = format!("{api}/repos/{upstream_owner}/{upstream_repo}");
    let repo_info: RepoInfo = client
        .get(&repo_url)
        .send()
        .with_context(|| format!("GET {repo_url}"))?
        .error_for_status()
        .with_context(|| "Failed to fetch repo info (check token scopes and repo slug)")?
        .json()
        .context("Failed to parse repo info JSON")?;
    let default_branch = repo_info.default_branch.clone();

    // Decide whether to work on the upstream directly or on a fork.
    let has_push = repo_info
        .permissions
        .as_ref()
        .map(|p| p.push)
        .unwrap_or(false);
    let (work_owner, work_repo) = if has_push {
        (upstream_owner.clone(), upstream_repo.clone())
    } else {
        eprintln!(
            "No write access to {upstream_owner}/{upstream_repo}. Forking under your account..."
        );
        let (fo, fr) = fork_and_wait(&client, api, &upstream_owner, &upstream_repo)?;
        eprintln!("Fork ready: {fo}/{fr}");
        (fo, fr)
    };

    // 2. Get the SHA of the default branch tip on the working repo.
    let ref_url = format!("{api}/repos/{work_owner}/{work_repo}/git/ref/heads/{default_branch}");
    let base_ref: GitRef = client
        .get(&ref_url)
        .send()
        .with_context(|| format!("GET {ref_url}"))?
        .error_for_status()
        .with_context(|| format!("Failed to read ref heads/{default_branch}"))?
        .json()
        .context("Failed to parse ref JSON")?;
    let base_sha = base_ref.object.sha;

    // 3. Create the new branch. If it already exists, retry with a suffix.
    let create_ref_url = format!("{api}/repos/{work_owner}/{work_repo}/git/refs");
    let mut final_branch = branch_name.clone();
    for attempt in 0..3u32 {
        let candidate = if attempt == 0 {
            final_branch.clone()
        } else {
            format!("{}-{}", branch_name, ts.wrapping_add(attempt as u64))
        };
        let body = serde_json::json!({
            "ref": format!("refs/heads/{}", candidate),
            "sha": base_sha,
        });
        let resp = client
            .post(&create_ref_url)
            .json(&body)
            .send()
            .with_context(|| format!("POST {create_ref_url}"))?;
        let status = resp.status();
        if status.is_success() {
            final_branch = candidate;
            break;
        }
        if status.as_u16() == 422 {
            // Reference already exists; try another name.
            if attempt == 2 {
                bail!("Could not create a unique branch after 3 attempts");
            }
            continue;
        }
        let txt = resp.text().unwrap_or_default();
        bail!("Failed to create branch ref: HTTP {status} {txt}");
    }

    // 4. Commit each fixed file via the Contents API on the working repo.
    for file in &payload.files {
        let contents_url = format!(
            "{}/repos/{}/{}/contents/{}",
            api, work_owner, work_repo, file.path
        );
        // Fetch existing file to get its blob SHA on the base branch.
        let existing: Option<ContentsGet> = client
            .get(&contents_url)
            .query(&[("ref", default_branch.as_str())])
            .send()
            .with_context(|| format!("GET {contents_url}"))?
            .json()
            .ok();
        let put_body = match existing {
            Some(e) => serde_json::json!({
                "message": format!("warden: fix {}", file.path),
                "content": base64_encode(file.fixed.as_bytes()),
                "branch": final_branch,
                "sha": e.sha,
            }),
            None => serde_json::json!({
                "message": format!("warden: add fixed {}", file.path),
                "content": base64_encode(file.fixed.as_bytes()),
                "branch": final_branch,
            }),
        };
        let resp = client
            .put(&contents_url)
            .json(&put_body)
            .send()
            .with_context(|| format!("PUT {contents_url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().unwrap_or_default();
            bail!("Failed to commit {}: HTTP {} {}", file.path, status, txt);
        }
    }

    // 5. Either open the PR, or return a compare URL the user can click.
    if prepare_only {
        // Compare URL. If we forked, point at the upstream repo's compare
        // page in the cross-repo form: base...fork_owner:branch.
        if work_owner != upstream_owner {
            return Ok(format!(
                "https://github.com/{upstream_owner}/{upstream_repo}/compare/{default_branch}...{work_owner}:{final_branch}?expand=1"
            ));
        }
        return Ok(format!(
            "https://github.com/{upstream_owner}/{upstream_repo}/compare/{default_branch}...{final_branch}?expand=1"
        ));
    }

    // Open the PR against upstream. `head` uses owner:branch when forked.
    let pr_url = format!("{api}/repos/{upstream_owner}/{upstream_repo}/pulls");
    let head = if work_owner != upstream_owner {
        format!("{work_owner}:{final_branch}")
    } else {
        final_branch.clone()
    };
    let pr_body = serde_json::json!({
        "title": title,
        "head": head,
        "base": default_branch,
        "body": body,
    });
    let pr: PullRequestResp = client
        .post(&pr_url)
        .json(&pr_body)
        .send()
        .with_context(|| format!("POST {pr_url}"))?
        .error_for_status()
        .context("Failed to open pull request")?
        .json()
        .context("Failed to parse PR response")?;

    Ok(pr.html_url)
}

#[cfg(test)]
mod pr_tests {
    use super::*;

    #[test]
    fn base64_encodes_known_values() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn open_fix_pr_plan_only_returns_synthetic_url() {
        let payload = JsonOutput {
            files: vec![JsonFileResult {
                path: ".github/workflows/ci.yml".to_string(),
                original: "a".to_string(),
                fixed: "b".to_string(),
                fixes: vec![JsonFixRecord {
                    line: 3,
                    description: "Pinned actions/checkout to SHA".to_string(),
                }],
            }],
            total_fixes: 1,
            plan_only: true,
        };
        let url = open_fix_pr(
            "me",
            "repo",
            Some("test-branch"),
            &payload,
            None,
            true,
            false,
        )
        .expect("plan-only run should succeed without a token");
        assert!(url.contains("me/repo"));
        assert!(url.contains("PLAN"));
        assert!(url.contains("test-branch"));
    }

    #[test]
    fn open_fix_pr_requires_token_when_applying() {
        let payload = JsonOutput {
            files: vec![],
            total_fixes: 0,
            plan_only: false,
        };
        let err = open_fix_pr("me", "repo", None, &payload, None, false, false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("token"), "unexpected error: {msg}");
    }
}
