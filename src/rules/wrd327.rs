use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-327: Composite Action Internal Unpinned References.
///
/// Detects the case where a workflow SHA-pins a composite (or Docker) action
/// at the top level, but that action's own `action.yml` internally references
/// other actions that are NOT SHA-pinned. Pinning the outer action does not
/// protect against tag mutation in its transitive dependencies, so a
/// compromise of the inner reference propagates into the user's workflow
/// even though they did everything right at the top level.
///
/// This closes a coverage gap vs. poutine's `unpinnable_action.rego`.
pub struct Wrd327;

/// Max number of distinct outer actions we will fetch per workflow, to avoid
/// hammering the GitHub API on workflows that reference many actions.
const MAX_ACTIONS_PER_WORKFLOW: usize = 10;

/// An unpinned reference discovered inside an upstream action.yml.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinnedRef {
    /// The raw `uses:` or `image:` value that was not SHA-pinned.
    pub value: String,
    /// Kind of the enclosing action: "composite" or "docker".
    pub kind: &'static str,
}

fn re_uses() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"uses\s*:\s*([a-zA-Z0-9_.\-/]+)@([A-Za-z0-9_.\-]+)").unwrap())
}

fn re_sha40() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{40}$").unwrap())
}

/// Cache of fetched action.yml contents keyed by "owner/repo@sha".
fn cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn debug_enabled() -> bool {
    std::env::var("WARDEN_DEBUG")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn debug(msg: &str) {
    if debug_enabled() {
        eprintln!("[WRD-327] {msg}");
    }
}

/// Parse an action.yml payload and return all unpinned internal references.
/// Returns an empty vector for node20/node16 actions, malformed YAML, or when
/// all internal references are SHA-pinned.
pub fn parse_action_yml(content: &str) -> Vec<UnpinnedRef> {
    let mut out = Vec::new();

    let parsed: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let Some(runs) = parsed.get("runs").and_then(|v| v.as_mapping()) else {
        return out;
    };

    let using = runs
        .get(serde_yaml::Value::String("using".into()))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match using {
        "composite" => {
            let Some(steps) = runs
                .get(serde_yaml::Value::String("steps".into()))
                .and_then(|v| v.as_sequence())
            else {
                return out;
            };

            for step in steps {
                let Some(step_map) = step.as_mapping() else {
                    continue;
                };
                let Some(uses_val) = step_map
                    .get(serde_yaml::Value::String("uses".into()))
                    .and_then(|v| v.as_str())
                else {
                    continue;
                };

                // Skip local refs and docker refs, poutine also excludes these.
                if uses_val.starts_with("./")
                    || uses_val.starts_with("../")
                    || uses_val.starts_with("docker://")
                {
                    continue;
                }

                // Split on '@' to extract ref.
                let Some(at_pos) = uses_val.rfind('@') else {
                    // No @ref at all, definitely unpinned.
                    out.push(UnpinnedRef {
                        value: uses_val.to_string(),
                        kind: "composite",
                    });
                    continue;
                };

                let ref_val = &uses_val[at_pos + 1..];
                if !re_sha40().is_match(ref_val) {
                    out.push(UnpinnedRef {
                        value: uses_val.to_string(),
                        kind: "composite",
                    });
                }
            }
        }
        "docker" => {
            // Docker actions declare the image in runs.image
            let Some(image) = runs
                .get(serde_yaml::Value::String("image".into()))
                .and_then(|v| v.as_str())
            else {
                return out;
            };

            // Only docker:// references count, Dockerfile references are
            // built locally from the action's own repo.
            let Some(docker_ref) = image.strip_prefix("docker://") else {
                return out;
            };

            // SHA-pinned docker images use `@sha256:...`
            if !docker_ref.contains("@sha256:") {
                out.push(UnpinnedRef {
                    value: image.to_string(),
                    kind: "docker",
                });
            }
        }
        _ => {
            // node16, node20, etc., have no internal action references.
        }
    }

    out
}

/// Fetch an action.yml (or action.yaml) from GitHub via the Contents API, raw media type.
/// Returns Some(content) on success, None on any failure (logs when WARDEN_DEBUG=1).
fn fetch_action_manifest(
    client: &reqwest::blocking::Client,
    owner: &str,
    repo: &str,
    sha: &str,
) -> Option<String> {
    let key = format!("{owner}/{repo}@{sha}");
    if let Ok(guard) = cache().lock() {
        if let Some(cached) = guard.get(&key) {
            return cached.clone();
        }
    }

    let result = fetch_manifest_uncached(client, owner, repo, sha);
    if let Ok(mut guard) = cache().lock() {
        guard.insert(key, result.clone());
    }
    result
}

fn fetch_manifest_uncached(
    client: &reqwest::blocking::Client,
    owner: &str,
    repo: &str,
    sha: &str,
) -> Option<String> {
    for filename in ["action.yml", "action.yaml"] {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/contents/{filename}?ref={sha}");
        let resp = match client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/vnd.github.v3.raw")
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                debug(&format!("network error fetching {url}: {e}"));
                continue;
            }
        };

        if !resp.status().is_success() {
            debug(&format!("non-success status {} for {url}", resp.status()));
            continue;
        }

        match resp.text() {
            Ok(body) => return Some(body),
            Err(e) => {
                debug(&format!("body read error for {url}: {e}"));
                continue;
            }
        }
    }
    None
}

impl Rule for Wrd327 {
    fn id(&self) -> &str {
        "WRD-327"
    }

    fn name(&self) -> &str {
        "Composite Action Internal Unpinned"
    }

    fn severity(&self) -> &str {
        "high"
    }

    fn description(&self) -> &str {
        "A composite or Docker action used by this workflow has unpinned action \
         references inside its own action.yml. Pinning the top-level action does \
         not protect against tag mutation in its internal dependencies."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;
        let uses_re = re_uses();
        let sha_re = re_sha40();

        // Build a lazy client. If we can't build one (shouldn't happen), silently skip.
        let token = std::env::var("GITHUB_TOKEN").ok();
        let client = match crate::scanner::github::build_client(token.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                debug(&format!("could not build HTTP client: {e}"));
                return findings;
            }
        };

        let mut checked = 0usize;
        let mut seen_outer: std::collections::HashSet<String> = std::collections::HashSet::new();

        for m in uses_re.captures_iter(content) {
            if checked >= MAX_ACTIONS_PER_WORKFLOW {
                debug(&format!(
                    "hit per-workflow cap ({MAX_ACTIONS_PER_WORKFLOW}), skipping remaining uses in {}",
                    workflow.path
                ));
                break;
            }

            let action = m.get(1).unwrap().as_str();
            let ref_val = m.get(2).unwrap().as_str();
            let full_match = m.get(0).unwrap();

            // Skip local actions.
            if action.starts_with("./") || action.starts_with("../") {
                continue;
            }

            // Skip docker:// refs (those are not owner/repo form anyway, but defensive).
            if action.starts_with("docker") {
                continue;
            }

            // Must look like owner/repo (two segments). Sub-actions like owner/repo/sub
            // resolve to the same repo manifest, so only take the first two.
            let parts: Vec<&str> = action.split('/').collect();
            if parts.len() < 2 {
                continue;
            }
            let owner = parts[0];
            let repo = parts[1];

            // Only descend into already-SHA-pinned refs. WRD-320 covers the
            // unpinned outer case, and without a SHA we don't have an
            // immutable commit to fetch the manifest at.
            if !sha_re.is_match(ref_val) {
                continue;
            }

            let dedupe_key = format!("{owner}/{repo}@{ref_val}");
            if !seen_outer.insert(dedupe_key) {
                continue;
            }
            checked += 1;

            let manifest = match fetch_action_manifest(&client, owner, repo, ref_val) {
                Some(m) => m,
                None => continue,
            };

            let unpinned = parse_action_yml(&manifest);
            if unpinned.is_empty() {
                continue;
            }

            let line = line_number_at_offset(content, full_match.start());
            let short_sha = &ref_val[..ref_val.len().min(7)];

            for inner in unpinned {
                let inner_value = inner.value;
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: "high".to_string(),
                    title: format!(
                        "{owner}/{repo}@{short_sha} has unpinned internal action: {inner_value}"
                    ),
                    description: format!(
                        "Workflow uses {owner}/{repo} pinned to a SHA, but that action's \
                         action.yml references {inner_value} which is not SHA-pinned. A \
                         compromise of {inner_value} would propagate into your workflow even \
                         though you did everything right at the top level."
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: format!(
                        "Either fork {owner}/{repo} and pin its internal actions, or use an \
                         alternative action whose action.yml only references SHA-pinned \
                         dependencies."
                    ),
                });
            }
        }

        findings
    }
}
