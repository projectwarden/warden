//! `.warden.toml` project-level configuration.
//!
//! Users drop a `.warden.toml` file in their repo root (or any parent of the
//! scan target) to disable specific rules or override severities.
//!
//! Example:
//!
//! ```toml
//! disabled_rules = ["WRD-710", "WRD-201"]
//!
//! [severity_overrides]
//! "WRD-322" = "low"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::rules::Finding;

/// Parsed `.warden.toml` configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WardenConfig {
    /// Rule IDs to suppress entirely (e.g. `["WRD-710"]`).
    pub disabled_rules: Vec<String>,

    /// Override the severity of a rule's findings. Values should be one of
    /// `critical`, `high`, `medium`, `low`.
    pub severity_overrides: HashMap<String, String>,
}

impl WardenConfig {
    /// Return true if this rule should be completely suppressed.
    pub fn is_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.iter().any(|r| r == rule_id)
    }

    /// Apply both severity overrides and disabled-rules filtering to a set of
    /// findings, in place.
    pub fn apply(&self, findings: &mut Vec<Finding>) {
        findings.retain(|f| !self.is_disabled(&f.rule_id));
        if !self.severity_overrides.is_empty() {
            for f in findings.iter_mut() {
                if let Some(new_sev) = self.severity_overrides.get(&f.rule_id) {
                    f.severity = new_sev.to_lowercase();
                }
            }
        }
    }
}

/// Walk from `dir` up toward the filesystem root looking for `.warden.toml`.
/// Returns `None` if no config is found or if parsing fails (errors are
/// logged to stderr but don't abort the scan).
pub fn load_from(dir: &Path) -> Option<WardenConfig> {
    let start = if dir.is_file() {
        dir.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        dir.to_path_buf()
    };

    let mut current: Option<&Path> = Some(&start);
    while let Some(c) = current {
        let candidate = c.join(".warden.toml");
        if candidate.is_file() {
            match std::fs::read_to_string(&candidate) {
                Ok(text) => match toml::from_str::<WardenConfig>(&text) {
                    Ok(cfg) => return Some(cfg),
                    Err(e) => {
                        eprintln!("warning: failed to parse {}: {}", candidate.display(), e);
                        return None;
                    }
                },
                Err(e) => {
                    eprintln!("warning: failed to read {}: {}", candidate.display(), e);
                    return None;
                }
            }
        }
        current = c.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn finding(rule: &str, sev: &str) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            severity: sev.to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            file: "f".to_string(),
            line: 1,
            remediation: "r".to_string(),
        }
    }

    #[test]
    fn disabled_rules_are_filtered() {
        let cfg = WardenConfig {
            disabled_rules: vec!["WRD-710".to_string()],
            ..Default::default()
        };
        let mut findings = vec![finding("WRD-710", "high"), finding("WRD-101", "critical")];
        cfg.apply(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WRD-101");
    }

    #[test]
    fn severity_overrides_apply() {
        let mut overrides = HashMap::new();
        overrides.insert("WRD-010".to_string(), "low".to_string());
        let cfg = WardenConfig {
            severity_overrides: overrides,
            ..Default::default()
        };
        let mut findings = vec![finding("WRD-010", "high")];
        cfg.apply(&mut findings);
        assert_eq!(findings[0].severity, "low");
    }

    #[test]
    fn load_from_reads_toml_and_walks_parents() {
        let tmp = std::env::temp_dir().join(format!("warden-cfg-test-{}", std::process::id()));
        let nested = tmp.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            tmp.join(".warden.toml"),
            r#"
disabled_rules = ["WRD-710"]

[severity_overrides]
"WRD-322" = "low"
"#,
        )
        .unwrap();

        let cfg = load_from(&nested).expect("config should be found");
        assert!(cfg.is_disabled("WRD-710"));
        assert_eq!(cfg.severity_overrides.get("WRD-322").unwrap(), "low");

        fs::remove_dir_all(&tmp).ok();
    }
}
