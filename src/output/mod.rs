use colored::Colorize;
use serde_json::json;

use crate::rules::Finding;
use crate::scanner;

/// Print findings to the console with colored severity indicators.
///
/// Default cap for the table view is 20 (the most severe). Pass `None` to
/// remove the cap entirely (`--all` mode).
pub fn console(findings: &[Finding]) {
    console_capped(findings, Some(20));
}

/// Print findings, capping the table at `cap` of the most severe entries.
/// Detailed remediation blocks are also subject to the cap.
pub fn console_capped(findings: &[Finding], cap: Option<usize>) {
    if findings.is_empty() {
        println!("{}", "No security issues found.".green().bold());
        return;
    }

    println!(
        "\n{} {} found:\n",
        findings.len().to_string().bold(),
        if findings.len() == 1 {
            "issue"
        } else {
            "issues"
        }
    );

    // Summary counts
    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();

    if critical > 0 {
        println!("  {} Critical: {}", "!!".red().bold(), critical);
    }
    if high > 0 {
        println!("  {}  High: {}", "!".red(), high);
    }
    if medium > 0 {
        println!("  {}  Medium: {}", "~".yellow(), medium);
    }
    if low > 0 {
        println!("  {}  Low: {}", "-".blue(), low);
    }
    println!();

    // Top rules by count. Helps users see when one systemic issue
    // (e.g. 50x WRD-320 unpinned) is dominating the noise vs when
    // they have a wide spread of distinct findings.
    if findings.len() >= 5 {
        let mut by_rule: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for f in findings {
            *by_rule.entry(f.rule_id.clone()).or_insert(0) += 1;
        }
        if by_rule.len() > 1 {
            let mut counts: Vec<(String, usize)> = by_rule.into_iter().collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            // Only show the summary if the top rule accounts for >= 20% of findings.
            let top_count = counts[0].1;
            if top_count * 5 >= findings.len() {
                println!("  {}", "Top rules by count:".bold());
                for (rule_id, count) in counts.iter().take(5) {
                    let title = findings
                        .iter()
                        .find(|f| &f.rule_id == rule_id)
                        .map(|f| f.title.as_str())
                        .unwrap_or("");
                    println!(
                        "    {:<10} {:>4}  {}",
                        rule_id,
                        count,
                        truncate(title, 60).dimmed()
                    );
                }
                println!();
            }
        }
    }

    // Sort findings by severity (critical first, then high, medium, low)
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| match f.severity.as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    });

    // Apply cap to the table view.
    let total = sorted.len();
    let limit = cap.unwrap_or(total).min(total);
    let table_slice = &sorted[..limit];
    let hidden = total - limit;

    // Table header
    println!(
        "  {:<12} {:<14} {:<44} LOCATION",
        "SEVERITY", "RULE", "TITLE"
    );
    println!("  {}", "-".repeat(90));

    for f in table_slice {
        let severity_str = format_severity(&f.severity);
        let location = if f.line > 0 {
            format!("{}:{}", f.file, f.line)
        } else {
            f.file.clone()
        };

        println!(
            "  {:<22} {:<14} {:<44} {}",
            severity_str,
            f.rule_id,
            truncate(&f.title, 43),
            location,
        );
    }

    if hidden > 0 {
        println!(
            "  {}",
            format!("... and {hidden} more (use --all, or save the report to see everything)")
                .dimmed()
        );
    }

    println!();

    // Show detailed remediation for critical and high findings, also capped.
    let serious_all: Vec<&Finding> = sorted
        .iter()
        .copied()
        .filter(|f| f.severity == "critical" || f.severity == "high")
        .collect();

    let serious_limit = cap.unwrap_or(serious_all.len()).min(serious_all.len());
    let serious = &serious_all[..serious_limit];
    let serious_hidden = serious_all.len() - serious_limit;

    if !serious.is_empty() {
        println!(
            "{}",
            "Remediation details for critical/high findings:".bold()
        );
        println!();

        for f in serious {
            let severity_str = format_severity(&f.severity);
            println!("  {} [{}] {}", severity_str, f.rule_id, f.title.bold());
            println!("    File: {}", f.file);
            if f.line > 0 {
                println!("    Line: {}", f.line);
            }
            println!("    {}", truncate_description(&f.description));
            println!("    Fix: {}", f.remediation);
            println!();
        }

        if serious_hidden > 0 {
            println!(
                "  {}",
                format!(
                    "... and {serious_hidden} more critical/high finding{} (use --all to see all details)",
                    if serious_hidden == 1 { "" } else { "s" }
                )
                .dimmed()
            );
            println!();
        }
    }
}

/// Truncate a finding description to ~120 chars and add a hint that the
/// full text is available in the JSON output. Keeps the console view tidy
/// and avoids walls of text.
fn truncate_description(s: &str) -> String {
    // Collapse newlines so descriptions don't break the table layout.
    let collapsed = s.replace(['\n', '\r'], " ");
    if collapsed.chars().count() <= 120 {
        collapsed
    } else {
        let cut: String = collapsed.chars().take(117).collect();
        format!("{cut}... (more in --format json)")
    }
}

/// Output findings as JSON.
pub fn json_output(findings: &[Finding]) {
    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();

    let output = json!({
        "total_findings": findings.len(),
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "findings": findings.iter().map(|f| {
            json!({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "remediation": f.remediation,
            })
        }).collect::<Vec<_>>(),
    });

    match serde_json::to_string_pretty(&output) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("Failed to serialize findings to JSON: {e}"),
    }
}

/// Output findings in SARIF 2.1.0 format.
pub fn sarif(findings: &[Finding]) {
    let rule_ids: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        findings
            .iter()
            .filter_map(|f| {
                if seen.insert(f.rule_id.clone()) {
                    Some(f.rule_id.clone())
                } else {
                    None
                }
            })
            .collect()
    };

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|rule_id| {
            let sample = findings.iter().find(|f| &f.rule_id == rule_id);
            json!({
                "id": rule_id,
                "shortDescription": {
                    "text": sample.map(|f| f.title.as_str()).unwrap_or("")
                },
                "helpUri": format!(
                    "https://github.com/projectwarden/warden/blob/main/docs/rules/{}.md",
                    rule_id.to_lowercase()
                ),
                "properties": {
                    "security-severity": match sample.map(|f| f.severity.as_str()) {
                        Some("critical") => "9.5",
                        Some("high") => "8.0",
                        Some("medium") => "5.5",
                        Some("low") => "3.0",
                        _ => "0.0",
                    }
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": match f.severity.as_str() {
                    "critical" | "high" => "error",
                    "medium" => "warning",
                    _ => "note",
                },
                "message": {
                    "text": format!("{}: {}", f.title, f.description)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": if f.line > 0 { f.line } else { 1 }
                        }
                    }
                }],
                "fixes": [{
                    "description": {
                        "text": f.remediation
                    }
                }]
            })
        })
        .collect();

    let sarif_doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "warden",
                    "informationUri": "https://github.com/projectwarden/warden",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    match serde_json::to_string_pretty(&sarif_doc) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("Failed to serialize SARIF output: {e}"),
    }
}

/// Emit findings as a Markdown summary suitable for PR comments.
///
/// Groups findings by severity, wraps each group in a `<details>` block,
/// and includes a short summary line with the overall score.
pub fn markdown(findings: &[Finding]) -> String {
    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();
    let score = scanner::score(findings);

    let mut out = String::new();
    out.push_str("## 🛡️ warden security scan\n\n");

    if findings.is_empty() {
        out.push_str(&format!(
            "**Summary:** No security issues found // score: **{score}/100**\n"
        ));
        return out;
    }

    out.push_str(&format!(
        "**Summary:** {} finding{} ({} critical, {} high, {} medium, {} low) // score: **{}/100**\n\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        critical,
        high,
        medium,
        low,
        score
    ));

    for (label, sev) in [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
    ] {
        let group: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        // Critical and high default open; medium/low collapsed.
        let open = matches!(sev, "critical" | "high");
        out.push_str(&format!(
            "<details{}>\n<summary><strong>{} findings ({})</strong></summary>\n\n",
            if open { " open" } else { "" },
            label,
            group.len()
        ));
        for f in group {
            let loc = if f.line > 0 {
                format!("`{}:{}`", f.file, f.line)
            } else {
                format!("`{}`", f.file)
            };
            out.push_str(&format!(
                "- **`{}`** {} // {}\n",
                f.rule_id,
                escape_md(&f.title),
                loc
            ));
            if !f.description.is_empty() {
                out.push_str(&format!("  - {}\n", escape_md(&f.description)));
            }
            if !f.remediation.is_empty() {
                out.push_str(&format!("  - _Fix:_ {}\n", escape_md(&f.remediation)));
            }
        }
        out.push_str("\n</details>\n\n");
    }

    out.push_str("---\n_generated by [warden](https://github.com/projectwarden/warden)_\n");
    out
}

/// Escape characters that would break Markdown list rendering.
fn escape_md(s: &str) -> String {
    s.replace('\n', " ").replace('\r', "")
}

/// Format severity with color for terminal output.
fn format_severity(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".red().bold().to_string(),
        "high" => "HIGH".red().to_string(),
        "medium" => "MEDIUM".yellow().to_string(),
        "low" => "LOW".blue().to_string(),
        other => other.to_uppercase(),
    }
}

/// Truncate a string to a maximum char length, appending "..." if truncated.
/// Uses char-aware truncation so multi-byte UTF-8 (emoji, accented letters, etc.)
/// in finding titles cannot panic on a non-char-boundary slice.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let take = max_len.saturating_sub(3);
        let prefix: String = s.chars().take(take).collect();
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &str, sev: &str, title: &str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            severity: sev.to_string(),
            title: title.to_string(),
            description: "desc".to_string(),
            file: file.to_string(),
            line,
            remediation: "remed".to_string(),
        }
    }

    #[test]
    fn markdown_empty() {
        let out = markdown(&[]);
        assert!(out.contains("warden security scan"));
        assert!(out.contains("No security issues"));
        assert!(out.contains("100/100"));
    }

    #[test]
    fn truncate_description_short_string_unchanged() {
        let s = "a short description";
        assert_eq!(truncate_description(s), s);
    }

    #[test]
    fn truncate_description_long_string_capped_with_hint() {
        let s = "x".repeat(400);
        let out = truncate_description(&s);
        assert!(
            out.contains("(more in --format json)"),
            "expected truncation hint in: {out}"
        );
        assert!(
            out.chars().count() < 200,
            "expected truncated output, got {} chars",
            out.chars().count()
        );
    }

    #[test]
    fn truncate_description_collapses_newlines() {
        let s = "first line\nsecond line\rthird";
        let out = truncate_description(s);
        assert!(!out.contains('\n'));
        assert!(!out.contains('\r'));
    }

    #[test]
    fn markdown_groups_by_severity() {
        let findings = vec![
            f("WRD-101", "critical", "Expression injection", "a.yml", 8),
            f("WRD-201", "high", "Pull request target", "b.yml", 3),
            f("WRD-301", "medium", "Unpinned action", "c.yml", 12),
        ];
        let out = markdown(&findings);
        assert!(out.contains("## 🛡️ warden security scan"));
        assert!(out.contains("3 findings"));
        assert!(out.contains("Critical findings (1)"));
        assert!(out.contains("High findings (1)"));
        assert!(out.contains("Medium findings (1)"));
        assert!(out.contains("`WRD-101`"));
        assert!(out.contains("`a.yml:8`"));
        assert!(out.contains("<details"));
        assert!(out.contains("_Fix:_"));
    }
}
