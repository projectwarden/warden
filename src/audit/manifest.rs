//! Manifest discovery and parsing. All parsers are pure functions over string
//! input so they can be unit-tested without touching disk or the network.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::Dep;

/// Walk the given project directory for supported manifests (non-recursive:
/// we only look at the project root) and return the union of discovered deps.
pub fn discover(path: &str) -> Result<Vec<Dep>> {
    let p = Path::new(path);
    if !p.exists() {
        anyhow::bail!("path does not exist: {path}");
    }

    let mut out: Vec<Dep> = Vec::new();

    let pkg_json = p.join("package.json");
    if pkg_json.is_file() {
        let body = fs::read_to_string(&pkg_json)
            .with_context(|| format!("reading {}", pkg_json.display()))?;
        if let Ok(mut deps) = parse_package_json(&body) {
            out.append(&mut deps);
        }
    }

    let pip_lock = p.join("Pipfile.lock");
    if pip_lock.is_file() {
        let body = fs::read_to_string(&pip_lock)?;
        if let Ok(mut deps) = parse_pipfile_lock(&body) {
            out.append(&mut deps);
        }
    } else {
        let req = p.join("requirements.txt");
        if req.is_file() {
            let body = fs::read_to_string(&req)?;
            if let Ok(mut deps) = parse_requirements_txt(&body) {
                out.append(&mut deps);
            }
        }
    }

    let gomod = p.join("go.mod");
    if gomod.is_file() {
        let body = fs::read_to_string(&gomod)?;
        if let Ok(mut deps) = parse_go_mod(&body, false) {
            out.append(&mut deps);
        }
    }

    let cargo = p.join("Cargo.toml");
    if cargo.is_file() {
        let body = fs::read_to_string(&cargo)?;
        if let Ok(mut deps) = parse_cargo_toml(&body) {
            out.append(&mut deps);
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// package.json (npm)
// ---------------------------------------------------------------------------

pub fn parse_package_json(body: &str) -> Result<Vec<Dep>> {
    let v: serde_json::Value = serde_json::from_str(body).context("package.json not valid JSON")?;
    let mut out = Vec::new();
    for key in &["dependencies", "devDependencies"] {
        if let Some(obj) = v.get(*key).and_then(|o| o.as_object()) {
            for (name, val) in obj {
                out.push(Dep {
                    ecosystem: "npm".into(),
                    name: name.clone(),
                    version: val.as_str().map(|s| s.to_string()),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// requirements.txt (PyPI)
// ---------------------------------------------------------------------------

pub fn parse_requirements_txt(body: &str) -> Result<Vec<Dep>> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("-e")
            || line.starts_with("-r")
        {
            continue;
        }
        // Strip inline comment
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        // Extract name: stop at any of [<>=!~; ]
        let stop_chars: &[char] = &['<', '>', '=', '!', '~', ';', ' ', '['];
        let name_end = line
            .find(|c: char| stop_chars.contains(&c))
            .unwrap_or(line.len());
        let name = line[..name_end].trim().to_string();
        if name.is_empty() {
            continue;
        }
        out.push(Dep {
            ecosystem: "pypi".into(),
            name,
            version: None,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Pipfile.lock (PyPI)
// ---------------------------------------------------------------------------

pub fn parse_pipfile_lock(body: &str) -> Result<Vec<Dep>> {
    let v: serde_json::Value = serde_json::from_str(body).context("Pipfile.lock not valid JSON")?;
    let mut out = Vec::new();
    for key in &["default", "develop"] {
        if let Some(obj) = v.get(*key).and_then(|o| o.as_object()) {
            for (name, val) in obj {
                let version = val
                    .get("version")
                    .and_then(|s| s.as_str())
                    .map(|s| s.trim_start_matches("==").to_string());
                out.push(Dep {
                    ecosystem: "pypi".into(),
                    name: name.clone(),
                    version,
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// go.mod (Go)
// ---------------------------------------------------------------------------

pub fn parse_go_mod(body: &str, include_indirect: bool) -> Result<Vec<Dep>> {
    let mut out = Vec::new();
    let mut in_block = false;

    for raw in body.lines() {
        let line = raw.trim();

        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            extract_go_require(line, include_indirect, &mut out);
            continue;
        }

        if let Some(rest) = line.strip_prefix("require ") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
                continue;
            }
            // Single-line require
            extract_go_require(rest, include_indirect, &mut out);
        } else if line == "require (" {
            in_block = true;
        }
    }
    Ok(out)
}

fn extract_go_require(line: &str, include_indirect: bool, out: &mut Vec<Dep>) {
    if line.is_empty() || line.starts_with("//") {
        return;
    }
    // Split off trailing comment
    let (code, comment) = match line.find("//") {
        Some(i) => (line[..i].trim(), &line[i..]),
        None => (line, ""),
    };
    if !include_indirect && comment.contains("indirect") {
        return;
    }
    let mut parts = code.split_whitespace();
    let Some(path) = parts.next() else { return };
    let version = parts.next().map(|s| s.to_string());
    if path.is_empty() {
        return;
    }
    out.push(Dep {
        ecosystem: "go".into(),
        name: path.to_string(),
        version,
    });
}

// ---------------------------------------------------------------------------
// Cargo.toml (crates.io)
// ---------------------------------------------------------------------------

pub fn parse_cargo_toml(body: &str) -> Result<Vec<Dep>> {
    let v: toml::Value = toml::from_str(body).context("Cargo.toml not valid TOML")?;
    let mut out = Vec::new();
    for key in &["dependencies", "dev-dependencies"] {
        if let Some(tab) = v.get(*key).and_then(|t| t.as_table()) {
            for (name, val) in tab {
                let version = match val {
                    toml::Value::String(s) => Some(s.clone()),
                    toml::Value::Table(t) => t
                        .get("version")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    _ => None,
                };
                // Skip path/git-only deps (no version implies local or git)
                if let toml::Value::Table(t) = val {
                    if t.contains_key("path") || t.contains_key("git") {
                        // Still include if it has a registry name we can hit? Skip for safety.
                        if !t.contains_key("version") {
                            continue;
                        }
                    }
                }
                out.push(Dep {
                    ecosystem: "cargo".into(),
                    name: name.clone(),
                    version,
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// URL normalization (shared by all resolvers)
// ---------------------------------------------------------------------------

/// Normalize a git/https URL pointing at github.com into `(owner, repo)`.
/// Returns None for non-github URLs or unparseable input.
pub fn normalize_github_url(raw: &str) -> Option<(String, String)> {
    let mut s = raw.trim().to_string();
    // Strip schemes and prefixes. Order-sensitive: `git+` may wrap any of the
    // others (e.g. `git+ssh://git@github.com:foo/bar`).
    for prefix in &["git+", "git://", "ssh://git@", "https://", "http://"] {
        if s.starts_with(prefix) {
            s = s[prefix.len()..].to_string();
        }
    }
    if let Some(rest) = s.strip_prefix("git@github.com:") {
        s = format!("github.com/{rest}");
    }
    // After stripping `ssh://git@` from `ssh://git@github.com:foo/bar`, we end
    // up with `github.com:foo/bar`, which uses scp-style colon as the host /
    // path separator. Normalize that colon to a slash so the prefix check
    // below succeeds.
    if let Some(rest) = s.strip_prefix("github.com:") {
        s = format!("github.com/{rest}");
    }
    if !s.starts_with("github.com/") {
        return None;
    }
    let rest = &s["github.com/".len()..];
    let rest = rest.trim_end_matches('/');
    // Strip a single trailing `.git` suffix. The previous implementation used
    // `trim_end_matches`, which strips repeatedly and would mangle weird
    // legitimate names like `repo.git.git` (or, more importantly, leave
    // `.git.git` callers in an inconsistent state).
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

/// Extract `(owner, repo)` from a Go module path like `github.com/foo/bar/v2`.
pub fn go_module_to_github(module: &str) -> Option<(String, String)> {
    let m = module.trim();
    let rest = m.strip_prefix("github.com/")?;
    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_git_plus_ssh_with_colon_separator() {
        // The historic bug: `git+` strips, then `ssh://git@` strips, leaving
        // `github.com:foo/bar` (scp-style colon). Must still resolve.
        let got = normalize_github_url("git+ssh://git@github.com:foo/bar");
        assert_eq!(got, Some(("foo".to_string(), "bar".to_string())));
    }

    #[test]
    fn normalize_strip_dot_git_is_single_strip() {
        // `trim_end_matches(".git")` would strip both occurrences and yield
        // `repo`. We want a single strip so the actual repo name is preserved.
        let got = normalize_github_url("https://github.com/foo/repo.git.git");
        assert_eq!(got, Some(("foo".to_string(), "repo.git".to_string())));
    }
}
