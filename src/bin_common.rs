//! Helpers shared between the clap-driven flow in `main.rs` and the
//! interactive menu in `interactive.rs`.
//!
//! Lives bin-side rather than in `lib.rs` because it is purely about
//! routing CLI inputs (target strings, fail levels) into the existing
//! library entrypoints, and does not belong in the public library API.

use anyhow::Result;
use std::path::Path;

use wardenscan::config;
use wardenscan::rules;
use wardenscan::scanner;

/// Severity threshold used by `--fail-on` style flags. Mirrors clap's
/// enum so the value can flow through the interactive layer too.
#[derive(Clone, Copy, Debug)]
pub enum FailLevel {
    Critical,
    High,
    Medium,
    Low,
    None,
}

/// Determine whether a target string looks like a GitHub `owner/repo` reference.
///
/// Used to decide whether to dispatch a scan to the GitHub API loader or to
/// the local-filesystem loader.
pub fn is_github_repo(target: &str) -> bool {
    let parts: Vec<&str> = target.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let owner = parts[0];
    let repo = parts[1];

    !owner.is_empty()
        && !repo.is_empty()
        && !owner.starts_with('.')
        && !owner.starts_with('/')
        && !std::path::Path::new(target).exists()
}

/// Load `.warden.toml` for a local scan target. Returns `None` for remote
/// GitHub targets (no on-disk config to walk).
pub fn load_config_for(target: &str) -> Option<config::WardenConfig> {
    if is_github_repo(target) {
        return None;
    }
    let path = Path::new(target);
    let start = if path.exists() { path } else { Path::new(".") };
    config::load_from(start)
}

/// Load workflows from the target (local path or GitHub repo).
pub fn load_workflows(target: &str, token: Option<&str>) -> Result<Vec<scanner::Workflow>> {
    if is_github_repo(target) {
        let parts: Vec<&str> = target.split('/').collect();
        let owner = parts[0];
        let repo = parts[1];
        eprintln!("Fetching workflows from GitHub: {owner}/{repo}");
        scanner::load_github(owner, repo, token)
    } else {
        scanner::load_local(target)
    }
}

/// Check if any finding meets or exceeds the fail-on threshold.
pub fn should_fail(findings: &[rules::Finding], level: FailLevel) -> bool {
    let threshold = match level {
        FailLevel::None => return false,
        FailLevel::Critical => 0,
        FailLevel::High => 1,
        FailLevel::Medium => 2,
        FailLevel::Low => 3,
    };

    findings.iter().any(|f| {
        let rank = match f.severity.to_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        rank <= threshold
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_github_repo_recognizes_owner_repo() {
        assert!(is_github_repo("vercel/next.js"));
        assert!(is_github_repo("aquasecurity/trivy"));
    }

    #[test]
    fn is_github_repo_rejects_paths_and_garbage() {
        assert!(!is_github_repo("."));
        assert!(!is_github_repo("./foo"));
        assert!(!is_github_repo("foo"));
        assert!(!is_github_repo("a/b/c"));
        assert!(!is_github_repo(""));
    }

    #[test]
    fn should_fail_respects_threshold() {
        let mk = |sev: &str| rules::Finding {
            rule_id: "WRD-000".into(),
            severity: sev.into(),
            title: "t".into(),
            description: "d".into(),
            file: "f".into(),
            line: 1,
            remediation: "r".into(),
        };

        let only_low = vec![mk("low")];
        assert!(!should_fail(&only_low, FailLevel::High));
        assert!(should_fail(&only_low, FailLevel::Low));

        let one_critical = vec![mk("critical")];
        assert!(should_fail(&one_critical, FailLevel::Critical));
        assert!(should_fail(&one_critical, FailLevel::High));
        assert!(!should_fail(&one_critical, FailLevel::None));
    }
}
