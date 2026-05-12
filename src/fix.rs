use std::collections::{HashMap, HashSet};
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

/// Build a GitHub API client with optional token. Shared with `add_action`
/// (and any future module that needs to talk to the GitHub REST API).
pub(crate) fn build_client(token: Option<&str>) -> Result<Client> {
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
pub(crate) struct GitRef {
    pub object: GitObject,
}

#[derive(Deserialize)]
pub(crate) struct GitObject {
    pub sha: String,
    #[serde(rename = "type")]
    pub obj_type: String,
    pub url: Option<String>,
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

/// Ensure the string ends with exactly one newline. POSIX text files
/// must end with `\n` ("a sequence of zero or more lines, each terminated
/// by a newline"). Many tools rely on this: `wc -l` undercounts files
/// without it, `cat` concatenation loses file boundaries, git renders
/// "\ No newline at end of file" in diffs, GitHub shows the red dot
/// indicator on the affected line in PRs, and some POSIX shells skip
/// the last line of a script entirely if it's missing the terminator.
/// We always normalize this whenever a fixer rewrites file contents,
/// so even files that arrived without a trailing newline get fixed
/// for free as a side effect of any other auto-fix.
fn ensure_trailing_newline(mut s: String) -> String {
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Apply all fixes to a single workflow, returning the fixed content and a list of changes.
///
/// Callers that process many workflows in a single invocation should prefer
/// [`fix_workflow_cached`] with a shared SHA cache; otherwise every workflow
/// pays the full cost of resolving `actions/checkout@v6`-style tags against
/// the GitHub API, even though hundreds of workflows across a repo typically
/// reference the same tagged dependencies.
pub fn fix_workflow(workflow: &Workflow, github_token: Option<&str>) -> FixResult {
    let mut cache: HashMap<String, Option<String>> = HashMap::new();
    fix_workflow_cached(workflow, github_token, &mut cache)
}

/// Apply all fixes to a single workflow, reusing `sha_cache` across calls.
///
/// The cache key is `"<owner>/<repo>@<tag>"`; one resolved SHA lookup is
/// worth reusing across every workflow in the same repo (and sometimes
/// across a whole `warden fix` invocation that spans multiple repos, when
/// several repos pin the same popular action tag). Each cache hit saves
/// one GitHub API round trip.
pub fn fix_workflow_cached(
    workflow: &Workflow,
    github_token: Option<&str>,
    sha_cache: &mut HashMap<String, Option<String>>,
) -> FixResult {
    let mut content = workflow.content.clone();
    let mut fixes = Vec::new();

    // Parity guard with scanner. Every rule that walks `workflow.jobs`
    // bails when the typed parse downgrades a file to a stub; the
    // fixer's text-based passes used to keep firing regardless, so a
    // single YAML-shape we hadn't taught the typed model would emit
    // "11 proposed fixes / 2 findings" UI inconsistencies. Detect the
    // stub case here once and short-circuit every pass.
    if crate::scanner::load_one(
        std::path::PathBuf::from(&workflow.path),
        workflow.content.clone(),
    )
    .ok()
    .map(|lf| matches!(lf, crate::scanner::LoadedFile::Other { .. }))
    .unwrap_or(false)
    {
        return FixResult {
            path: workflow.path.clone(),
            original: workflow.content.clone(),
            fixed: workflow.content.clone(),
            fixes,
        };
    }

    // Pass 1: Pin unpinned actions to SHA
    content = fix_unpin_actions(
        &content,
        github_token,
        &workflow.path,
        &mut fixes,
        sha_cache,
    );

    // Pass 2: Extract expressions from run blocks to env vars
    content = fix_expression_injection(&content, &workflow.path, &mut fixes);

    // Pass 3: Add persist-credentials: false to checkout steps
    content = fix_checkout_persist_credentials(&content, &workflow.path, &mut fixes);

    // Pass 4: Add top-level permissions: read-all if missing (WRD-824)
    if let Some((new_content, rec)) = fix_missing_permissions(&content, &workflow.path) {
        content = new_content;
        fixes.push(rec);
    }

    // Pass 5: Add inline documentation comment to each permission entry (WRD-840)
    if let Some((new_content, recs)) = fix_permission_entry_comments(&content, &workflow.path) {
        content = new_content;
        fixes.extend(recs);
    }

    // Pass 6: Add concurrency: block if missing (WRD-842)
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
///
/// `sha_cache` is shared across every workflow in a single `warden fix`
/// run so repeated references to the same tag (e.g. `actions/checkout@v6`
/// appearing in 12 workflows) only pay one GitHub API round trip.
fn fix_unpin_actions(
    content: &str,
    token: Option<&str>,
    file: &str,
    fixes: &mut Vec<FixRecord>,
    sha_cache: &mut HashMap<String, Option<String>>,
) -> String {
    let re =
        Regex::new(r"(?m)^(\s*uses:\s*)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v[a-zA-Z0-9._-]+)\s*$")
            .unwrap();

    let client = build_client(token).ok();

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

    ensure_trailing_newline(result_lines.join("\n"))
}

/// Resolve every unique (action, tag) pair across `workflows` in parallel
/// and fill `sha_cache` with the results before the serial fix passes run.
///
/// The old flow resolved SHAs lazily, one per match site, in line-order.
/// A repo with ten unique unpinned actions paid ten serial ~300 ms
/// GitHub API round trips (~3 s of wall time) before the first fix pass
/// even started emitting. Prewarming in parallel collapses that to a
/// single round trip's worth of time; subsequent lookups from
/// `fix_unpin_actions` are pure cache hits.
///
/// Silently no-ops when the HTTP client cannot be built (e.g. offline,
/// no token and the rate limiter stubs us out). Subsequent fixes then
/// fall through to the existing per-line path, which already tolerates
/// `None` from resolution.
fn prewarm_sha_cache(
    workflows: &[Workflow],
    token: Option<&str>,
    sha_cache: &mut HashMap<String, Option<String>>,
) {
    let re =
        Regex::new(r"(?m)^\s*uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v[a-zA-Z0-9._-]+)\s*$")
            .unwrap();

    let mut unique: HashSet<(String, String)> = HashSet::new();
    for w in workflows {
        for caps in re.captures_iter(&w.content) {
            let action = caps.get(1).unwrap().as_str().to_string();
            let tag = caps.get(2).unwrap().as_str().to_string();
            let key = format!("{action}@{tag}");
            if !sha_cache.contains_key(&key) {
                unique.insert((action, tag));
            }
        }
    }

    if unique.is_empty() {
        return;
    }

    let client = match build_client(token) {
        Ok(c) => c,
        Err(_) => return,
    };

    let to_resolve: Vec<(String, String)> = unique.into_iter().collect();
    let resolved: Vec<(String, Option<String>)> = std::thread::scope(|s| {
        let client_ref = &client;
        let handles: Vec<_> = to_resolve
            .iter()
            .map(|(action, tag)| {
                let action = action.clone();
                let tag = tag.clone();
                s.spawn(move || {
                    let sha = match action.split_once('/') {
                        Some((owner, repo)) => resolve_tag_to_sha(client_ref, owner, repo, &tag),
                        None => None,
                    };
                    (format!("{action}@{tag}"), sha)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| (String::new(), None)))
            .collect()
    });

    for (key, sha) in resolved {
        if !key.is_empty() {
            sha_cache.insert(key, sha);
        }
    }
}

/// True if the captured expression path is one the WRD-101 family treats as
/// attacker-controlled. The fixer must agree with the scanner here: if we
/// rewrite an expression that no rule flagged, the resulting fix-PR has
/// surprise extras the user can't trace back to a finding.
///
/// `github.event.*` paths are tightly checked against the canonical
/// TAINTED_EXPRESSIONS list (the same one wrd101 uses), so safe paths like
/// `github.event.repository.name` are NOT rewritten.
///
/// `inputs.*` is treated as always-tainted because the rules that flag it
/// (WRD-110 composite, WRD-111 dispatch, WRD-113 reusable workflow_call) all
/// fire whenever inputs.* appears in a run block in their respective context.
/// A regular push workflow with `${{ inputs.X }}` in a run is invalid YAML
/// at runtime anyway (inputs is empty), so the rewrite is harmless.
fn is_taintable_expression(inner: &str) -> bool {
    if let Some(rest) = inner.strip_prefix("github.event.") {
        for tainted in crate::rules::wrd101::TAINTED_EXPRESSIONS {
            // Strip the `github.event.` prefix from the tainted pattern (every
            // entry on the canonical list starts with that, except `github.head_ref`).
            let Some(t_rest) = tainted.strip_prefix("github.event.") else {
                continue;
            };
            // Match at dot boundaries: `issue.title` matches `issue.title`
            // and `issue.title.foo` (deeper paths under a tainted root), but
            // NOT `issue.title_other`.
            if rest == t_rest || rest.starts_with(&format!("{t_rest}.")) {
                return true;
            }
        }
        return false;
    }
    if inner == "github.head_ref" {
        return true;
    }
    if inner.starts_with("inputs.") {
        return true;
    }
    false
}

/// Extract dangerous expressions from `run:` blocks into `env:` mappings.
/// Only rewrites expressions that `is_taintable_expression` accepts, so the
/// fixer matches the WRD-101 / WRD-110 / WRD-111 / WRD-113 / WRD-130 family
/// 1:1 and never produces surprise extras in `warden fix --pr` output.
fn fix_expression_injection(content: &str, file: &str, fixes: &mut Vec<FixRecord>) -> String {
    // Match candidate expressions. The membership check below filters out
    // any path the WRD-101 family wouldn't actually flag.
    let expr_re = Regex::new(
        r"\$\{\{\s*(github\.event\.[a-zA-Z0-9_.]+|github\.head_ref|inputs\.[a-zA-Z0-9_.]+)\s*\}\}",
    )
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

                        // Skip safe `github.event.*` paths that the scanner
                        // would not have flagged (e.g. `repository.name`).
                        if !is_taintable_expression(&inner) {
                            continue;
                        }

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

            // Single-line run: value. Same membership filter as the block
            // scalar branch above so safe `github.event.*` paths are skipped.
            let exprs: Vec<(String, String)> = expr_re
                .captures_iter(run_body)
                .filter_map(|c| {
                    let full = c.get(0).unwrap().as_str().to_string();
                    let inner = c.get(1).unwrap().as_str().to_string();
                    if is_taintable_expression(&inner) {
                        Some((full, inner))
                    } else {
                        None
                    }
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

    ensure_trailing_newline(result_lines.join("\n"))
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
            // Find where `uses:` itself starts on the line. For
            //     "        uses: actions/checkout@..."
            // this is the line indent (e.g. col 8). For the compact list
            // form
            //     "      - uses: actions/checkout@..."
            // it's 2 more than the line indent (col 8) because the `- `
            // prefix consumes 2 columns. Sibling step properties
            // (`with:`, `env:`, `if:`, ...) all align with `uses:` itself,
            // not with the leading `-`. Computing `leading` from the line
            // indent alone produced wrong values for the compact form.
            let leading = line
                .find("uses:")
                .unwrap_or_else(|| line.len() - line.trim_start().len());
            let with_indent = leading;
            let inner_indent = leading + 2;

            // Look ahead: does persist-credentials already exist in this step?
            let mut has_persist = false;
            let mut has_with = false;
            let mut j = i + 1;

            // Scan the rest of this step. We exit when we leave the step's
            // scope -- which means a non-blank line at indent strictly less
            // than `leading` (next step's `- name:`, next job, or top-level
            // key). Lines at the same indent as `leading` are SIBLING step
            // properties and we want to keep scanning into them. The
            // previous `<= leading` break terminated as soon as it saw the
            // existing `with:` line at the same indent as `uses:`, which
            // left has_with=false and made the fallback branch insert a
            // duplicate `with:` block at the wrong indent.
            while j < lines.len() {
                let next = lines[j].trim();
                if !next.is_empty() {
                    let next_indent = lines[j].len() - lines[j].trim_start().len();
                    if next_indent < leading {
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

    ensure_trailing_newline(result_lines.join("\n"))
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

    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    new_lines.insert(insert_at, "permissions: read-all".to_string());

    Some((
        ensure_trailing_newline(new_lines.join("\n")),
        FixRecord {
            file: file.to_string(),
            line: insert_at + 1,
            description: "Added top-level permissions: read-all".to_string(),
        },
    ))
}

/// Default explanation for a (permission, level) pair, used by the WRD-840
/// per-entry comment fixer below. The wording mirrors what GitHub's own
/// permissions docs use, so reviewers reading the diff aren't surprised.
fn default_permission_explanation(perm: &str, level: &str) -> &'static str {
    match (perm, level) {
        ("contents", "read") => "required to read repository contents",
        ("contents", "write") => "required to push commits, branches, or releases",
        ("contents", "none") => "explicitly denying contents access",
        ("packages", "read") => "required to pull container images / packages from GHCR",
        ("packages", "write") => "required to push container images / packages to GHCR",
        ("actions", "read") => "required to read workflow runs / artifacts",
        ("actions", "write") => "required to dispatch workflows or modify workflow runs",
        ("deployments", "read") => "required to read deployment status",
        ("deployments", "write") => "required to create deployments",
        ("id-token", "read") => "required to read OIDC tokens",
        ("id-token", "write") => {
            "required for OIDC token exchange (cloud auth, sigstore, attestations)"
        }
        ("issues", "read") => "required to read issues",
        ("issues", "write") => "required to create or comment on issues",
        ("pull-requests", "read") => "required to read pull requests",
        ("pull-requests", "write") => "required to create, comment on, or modify pull requests",
        ("statuses", "read") => "required to read commit statuses",
        ("statuses", "write") => "required to set commit statuses",
        ("security-events", "read") => "required to read code scanning alerts",
        ("security-events", "write") => "required to upload SARIF reports / code scanning results",
        ("checks", "read") => "required to read check runs",
        ("checks", "write") => "required to create or update check runs",
        ("pages", "read") => "required to read GitHub Pages config",
        ("pages", "write") => "required to deploy to GitHub Pages",
        ("discussions", "read") => "required to read discussions",
        ("discussions", "write") => "required to create or comment on discussions",
        ("repository-projects", "read") => "required to read repository projects",
        ("repository-projects", "write") => "required to modify repository projects",
        ("attestations", "read") => "required to read attestations",
        ("attestations", "write") => "required to write attestations",
        _ => "required for this workflow",
    }
}

/// WRD-840: Add an inline `# explanation` comment to every permission entry
/// that lacks one. Walks every `<perm>: <level>` line under any `permissions:`
/// block (top-level or per-job) and appends a default explanation if neither
/// the line itself nor the line above already has a `#` comment. Returns one
/// FixRecord per modified entry so the count matches the number of WRD-840
/// findings the rule produced. The previous version of this fixer added a
/// single block-level comment, which counted as 1 fix but did not actually
/// satisfy WRD-840's per-entry check, leaving stale findings on the next scan.
fn fix_permission_entry_comments(content: &str, file: &str) -> Option<(String, Vec<FixRecord>)> {
    let entry_re = Regex::new(
        r"^(\s+)(contents|packages|actions|deployments|id-token|issues|pull-requests|statuses|security-events|checks|pages|discussions|repository-projects|attestations)(\s*:\s*)(read|write|none)\s*$",
    )
    .unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let mut records: Vec<FixRecord> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let Some(caps) = entry_re.captures(line) else {
            continue;
        };
        // Skip if the line already has any inline `#` (the regex enforces no
        // trailing comment so this should never trigger, but defense in depth)
        if line.contains('#') {
            continue;
        }
        // Skip if the previous line is already a `# ...` comment
        if idx > 0 && lines[idx - 1].trim_start().starts_with('#') {
            continue;
        }

        let leading = caps.get(1).unwrap().as_str();
        let perm = caps.get(2).unwrap().as_str();
        let level = caps.get(4).unwrap().as_str();
        let explanation = default_permission_explanation(perm, level);

        new_lines[idx] = format!("{leading}{perm}: {level}  # {explanation}");

        records.push(FixRecord {
            file: file.to_string(),
            line: idx + 1,
            description: format!("Documented `{perm}: {level}` permission entry"),
        });
    }

    if records.is_empty() {
        return None;
    }

    Some((ensure_trailing_newline(new_lines.join("\n")), records))
}

/// WRD-842: Insert a top-level `concurrency:` block if none exists anywhere.
///
/// Only fires when the workflow is triggered by `push` or `pull_request`,
/// matching what WRD-842's scanner-side check requires. A
/// `workflow_dispatch`-only or `schedule`-only workflow does not get a
/// concurrency block from this fixer because the rule wouldn't have flagged
/// it, and adding one would be a surprise extra in the fix-PR.
fn fix_missing_concurrency(content: &str, file: &str) -> Option<(String, FixRecord)> {
    if has_any_key(content, "concurrency") {
        return None;
    }

    // Match WRD-842's `^\s*(push|pull_request)\s*:` regex exactly so the
    // scanner and fixer fire on the same set of workflows.
    let trigger_re = Regex::new(r"(?m)^\s*(push|pull_request)\s*:").unwrap();
    if !trigger_re.is_match(content) {
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

    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    for (offset, bl) in block.into_iter().enumerate() {
        new_lines.insert(insert_at + offset, bl);
    }

    Some((
        ensure_trailing_newline(new_lines.join("\n")),
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
    // Shared SHA cache across every workflow in this run. Popular tags
    // like `actions/checkout@v6` appearing in 12 workflows would
    // otherwise cost 12 GitHub API round trips. The prewarm pass below
    // pushes that further: it resolves every unique (action, tag) in
    // parallel before any workflow fix runs, so the serial fix passes
    // only see cache hits and emit output immediately.
    let mut sha_cache: HashMap<String, Option<String>> = HashMap::new();
    prewarm_sha_cache(workflows, github_token, &mut sha_cache);

    for workflow in workflows {
        let result = fix_workflow_cached(workflow, github_token, &mut sha_cache);

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
    // Shared SHA cache across every workflow in this run. See run_fix for
    // the same optimization on the CLI path. prewarm_sha_cache fills
    // the cache in parallel before the serial fix loop starts.
    let mut sha_cache: HashMap<String, Option<String>> = HashMap::new();
    prewarm_sha_cache(workflows, github_token, &mut sha_cache);

    for workflow in workflows {
        let result = fix_workflow_cached(workflow, github_token, &mut sha_cache);
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
pub(crate) fn base64_encode(input: &[u8]) -> String {
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
pub(crate) struct RepoInfo {
    pub default_branch: String,
    #[serde(default)]
    pub permissions: Option<RepoPermissions>,
}

#[derive(Deserialize, Default)]
pub(crate) struct RepoPermissions {
    #[serde(default)]
    pub push: bool,
}

#[derive(Deserialize)]
pub(crate) struct ContentsGet {
    pub sha: String,
}

#[derive(Deserialize)]
pub(crate) struct PullRequestResp {
    pub html_url: String,
}

#[derive(Deserialize)]
pub(crate) struct AuthUser {
    pub login: String,
}

/// Fork `upstream_owner/upstream_repo` under the authenticated user and wait
/// until the fork is queryable. Returns `(fork_owner, fork_repo)`.
pub(crate) fn fork_and_wait(
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
