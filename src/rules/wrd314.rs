use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;

/// WRD-314: Transitive Action Pin Bypass.
///
/// Detects the case where a workflow SHA-pins a composite (or Docker) action
/// at the top level, but that action's own `action.yml` internally references
/// other actions that are NOT SHA-pinned. Pinning the outer action does not
/// protect against tag mutation in its transitive dependencies, so a
/// compromise of the inner reference propagates into the user's workflow
/// even though they did everything right at the top level.
///
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
        eprintln!("[WRD-314] {msg}");
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
    let url = format!("https://api.github.com/repos/{owner}/{repo}/contents/action.yml?ref={sha}");
    let resp = match client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/vnd.github.v3.raw")
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            debug(&format!("network error fetching {url}: {e}"));
            return None;
        }
    };

    if resp.status().is_success() {
        return resp.text().ok();
    }

    // Rare fallback: some actions use action.yaml instead of action.yml.
    let url2 =
        format!("https://api.github.com/repos/{owner}/{repo}/contents/action.yaml?ref={sha}");
    let resp2 = match client
        .get(&url2)
        .header(reqwest::header::ACCEPT, "application/vnd.github.v3.raw")
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            debug(&format!("network error fetching {url2}: {e}"));
            return None;
        }
    };

    if resp2.status().is_success() {
        return resp2.text().ok();
    }

    debug(&format!(
        "no action.yml or action.yaml found for {owner}/{repo}@{sha}"
    ));
    None
}

// ---------------------------------------------------------------------------
// V2: typed-model walk over step `uses:` values. Reuses the module-level
// `fetch_action_manifest` / `parse_action_yml` helpers and the shared
// `cache()` mutex so V1 and V2 share a single HTTP client + cache.
// ---------------------------------------------------------------------------

pub struct Wrd314;

impl Rule for Wrd314 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-314",
            name: "Transitive Action Pin Bypass",
            default_severity: Severity::High,
            description: "A composite or Docker action used by this workflow has unpinned action \
                          references inside its own action.yml. Pinning the top-level action does \
                          not protect against tag mutation in its internal dependencies.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;

        let token = std::env::var("GITHUB_TOKEN").ok();
        let client = match crate::scanner::github::build_client(token.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                debug(&format!("could not build HTTP client: {e}"));
                return Vec::new();
            }
        };

        let sha_re = re_sha40();
        let mut seen_outer: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Phase 1: collect all unique SHA-pinned refs that need fetching.
        struct FetchTarget {
            owner: String,
            repo: String,
            ref_val: String,
            job_name: String,
            step_index: usize,
        }
        let mut targets: Vec<FetchTarget> = Vec::new();

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                if targets.len() >= MAX_ACTIONS_PER_WORKFLOW {
                    break;
                }
                let Step::Uses(u) = step else { continue };
                let Some((action, ref_val)) = u.uses.split_once('@') else {
                    continue;
                };
                if action.starts_with("./")
                    || action.starts_with("../")
                    || action.starts_with("docker")
                {
                    continue;
                }
                let parts: Vec<&str> = action.split('/').collect();
                if parts.len() < 2 {
                    continue;
                }
                if !sha_re.is_match(ref_val) {
                    continue;
                }
                let dedupe_key = format!("{}/{}@{}", parts[0], parts[1], ref_val);
                if !seen_outer.insert(dedupe_key) {
                    continue;
                }
                targets.push(FetchTarget {
                    owner: parts[0].to_string(),
                    repo: parts[1].to_string(),
                    ref_val: ref_val.to_string(),
                    job_name: job_name.clone(),
                    step_index: i,
                });
            }
        }

        if targets.is_empty() {
            return Vec::new();
        }

        // Phase 2: fetch all manifests in parallel.
        let manifests: Vec<Option<String>> = std::thread::scope(|s| {
            let client_ref = &client;
            let handles: Vec<_> = targets
                .iter()
                .map(|t| {
                    let owner = &t.owner;
                    let repo = &t.repo;
                    let sha = &t.ref_val;
                    s.spawn(move || fetch_action_manifest(client_ref, owner, repo, sha))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or(None))
                .collect()
        });

        // Phase 3: check results and emit findings.
        let mut findings = Vec::new();
        for (target, manifest) in targets.iter().zip(manifests) {
            let Some(manifest) = manifest else { continue };
            let unpinned = parse_action_yml(&manifest);
            if unpinned.is_empty() {
                continue;
            }
            let span = ctx
                .loaded
                .spans
                .get_str(&format!(
                    "jobs.{}.steps[{}]",
                    target.job_name, target.step_index
                ))
                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
            let short_sha = &target.ref_val[..target.ref_val.len().min(7)];
            for inner in unpinned {
                let inner_value = inner.value;
                findings.push(RuleFinding {
                    rule_id: "WRD-314",
                    severity: Severity::High,
                    title: format!(
                        "{}/{}@{short_sha} has unpinned internal action: {inner_value}",
                        target.owner, target.repo,
                    ),
                    description: format!(
                        "Workflow uses {}/{} pinned to a SHA, but that action's \
                         action.yml references {inner_value} which is not SHA-pinned. A \
                         compromise of {inner_value} would propagate into your workflow \
                         even though you did everything right at the top level.",
                        target.owner, target.repo,
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: format!(
                        "Either fork {}/{} and pin its internal actions, or use \
                         an alternative action whose action.yml only references \
                         SHA-pinned dependencies.",
                        target.owner, target.repo,
                    ),
                });
            }
        }

        findings
    }
}
