use regex::Regex;
use std::sync::OnceLock;

use super::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

pub struct Wrd828;

fn re_base64_string() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match base64-encoded strings of at least 40 characters (likely encoded payloads)
        Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap()
    })
}

fn re_encoded_payload() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(base64\s*-d|base64\s+--decode|\batob\b|Buffer\.from\([^)]+,\s*['"]base64['"])"#,
        )
        .unwrap()
    })
}

fn re_env_or_with() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s+(env|with)\s*:").unwrap())
}

/// Check if a byte offset falls inside a run: block (heuristic).
fn is_in_run_block(content: &str, offset: usize) -> bool {
    // Walk backwards from offset to find the most recent key
    let before = &content[..offset];
    let last_run = before.rfind("run:");
    let last_env = before.rfind("env:");
    let last_with = before.rfind("with:");

    match last_run {
        Some(run_pos) => {
            // If run: is the most recent block key, we are in a run block
            let env_pos = last_env.unwrap_or(0);
            let with_pos = last_with.unwrap_or(0);
            run_pos > env_pos && run_pos > with_pos
        }
        None => false,
    }
}

impl Rule for Wrd828 {
    fn id(&self) -> &str {
        "WRD-828"
    }
    fn name(&self) -> &str {
        "Obfuscation in Workflow"
    }
    fn severity(&self) -> &str {
        "medium"
    }
    fn description(&self) -> &str {
        "Detects base64-encoded strings, hex-encoded strings, or decode operations \
         in non-run contexts (env blocks, with: inputs)"
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        // Only check if there are env or with blocks
        if !re_env_or_with().is_match(content) {
            return findings;
        }

        // Check for encoded payloads in non-run contexts
        for m in re_encoded_payload().find_iter(content) {
            if is_in_run_block(content, m.start()) {
                continue; // Skip run: blocks (covered by WRD-602)
            }
            let line = line_number_at_offset(content, m.start());
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                title: "Decode operation in non-run context".to_string(),
                description: "A base64 decode or similar operation appears in an env: \
                    or with: block. This is unusual and may indicate an attempt to \
                    obfuscate malicious content."
                    .to_string(),
                file: workflow.path.clone(),
                line,
                remediation: "Review the encoded content and verify it is legitimate. \
                    If the value must be encoded, add a comment explaining why."
                    .to_string(),
            });
        }

        // Check for suspiciously long base64 strings in non-run contexts
        for m in re_base64_string().find_iter(content) {
            if is_in_run_block(content, m.start()) {
                continue;
            }
            // Skip if this looks like a SHA pin (exactly 40 hex chars)
            if m.as_str().len() == 40 {
                continue;
            }
            let line = line_number_at_offset(content, m.start());
            let line_content = content.lines().nth(line.saturating_sub(1)).unwrap_or("");
            // Only flag if in env/with context (heuristic: indented value)
            if line_content.contains("env:")
                || line_content.contains("with:")
                || (line_content.trim_start().starts_with('-') || line_content.contains(": "))
            {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    title: "Possible encoded payload in workflow metadata".to_string(),
                    description: format!(
                        "A long base64-like string ({} chars) was found outside a run: \
                         block. This may indicate obfuscated content.",
                        m.as_str().len()
                    ),
                    file: workflow.path.clone(),
                    line,
                    remediation: "Review the encoded content. If it is legitimate, add a \
                        comment explaining what it contains and why it is encoded."
                        .to_string(),
                });
            }
        }

        findings
    }
}
