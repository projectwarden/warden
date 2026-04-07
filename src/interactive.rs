//! Interactive guided experience for `warden`.
//!
//! Launched when the user runs `warden` with zero arguments in a TTY. Drives
//! a small dialoguer-based menu loop that wraps the existing scan / fix /
//! score / upstream / rules entrypoints. Non-interactive use of warden
//! (any subcommand or `--help`) does NOT touch this module.
//!
//! All the actual scanning logic still lives in `wardenscan::scanner`,
//! `wardenscan::fix`, and `wardenscan::audit`. This file is purely UX glue.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Select};

use wardenscan::audit;
use wardenscan::fix;
use wardenscan::output;
use wardenscan::rules;
use wardenscan::scanner;

use crate::bin_common::{is_github_repo, load_config_for, load_workflows};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Detect whether stdin/stdout are connected to a real terminal. Used by
/// `main.rs` to decide if `warden` (no args) should launch the interactive
/// menu or just print `--help`. CI pipes / `echo | warden` must NEVER hang
/// waiting for input.
pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// Top-level menu options. Order matches the visual menu.
#[derive(Clone, Copy)]
enum MenuChoice {
    ScanRemote,
    ScanLocal,
    Fix,
    Upstream,
    Rules,
    Exit,
}

impl MenuChoice {
    fn label(self) -> &'static str {
        match self {
            MenuChoice::ScanRemote => "Scan a GitHub repository          (e.g. vercel/next.js)",
            MenuChoice::ScanLocal => "Scan a local project / directory  (.github/workflows/)",
            MenuChoice::Fix => "Auto-fix workflow file(s)         (plan + apply)",
            MenuChoice::Upstream => {
                "Scan upstream of your dependencies     (scan your dependencies' upstream CI/CD)"
            }
            MenuChoice::Rules => "List all detection rules",
            MenuChoice::Exit => "Exit",
        }
    }

    fn all() -> &'static [MenuChoice] {
        &[
            MenuChoice::ScanRemote,
            MenuChoice::ScanLocal,
            MenuChoice::Fix,
            MenuChoice::Upstream,
            MenuChoice::Rules,
            MenuChoice::Exit,
        ]
    }
}

/// Print the title banner. Kept short and free of emoji per spec.
fn print_banner() {
    let rule_count = rules::all_rules().len();
    let line_top = "+----------------------------------------+";
    let line_bot = "+----------------------------------------+";
    let title = "warden";
    let subtitle = "CI/CD security scanner";
    let meta = format!("v{VERSION} // {rule_count} detection rules");

    println!();
    println!("{}", line_top.dimmed());
    println!("{}  {:<38}{}", "|".dimmed(), title.bold(), "|".dimmed());
    println!("{}  {:<38}{}", "|".dimmed(), subtitle, "|".dimmed());
    println!("{}  {:<38}{}", "|".dimmed(), meta.dimmed(), "|".dimmed());
    println!("{}", line_bot.dimmed());
    println!();
}

/// Entrypoint called from `main.rs` when no args are passed in a TTY.
/// Returns Ok(()) on clean exit, never propagates a Ctrl-C as an error.
pub fn run() -> Result<()> {
    print_banner();

    let theme = ColorfulTheme::default();

    loop {
        let labels: Vec<&'static str> = MenuChoice::all().iter().map(|c| c.label()).collect();

        let pick = Select::with_theme(&theme)
            .with_prompt("What would you like to do?")
            .items(&labels)
            .default(0)
            .interact_opt()
            .context("menu selection failed")?;

        let Some(idx) = pick else {
            // User hit Esc / Ctrl-C at the menu. Treat as exit.
            println!("\nGoodbye.");
            return Ok(());
        };

        let choice = MenuChoice::all()[idx];

        let flow_result = match choice {
            MenuChoice::ScanRemote => flow_scan(&theme, ScanKind::Remote),
            MenuChoice::ScanLocal => flow_scan(&theme, ScanKind::Local),
            MenuChoice::Fix => flow_fix(&theme),
            MenuChoice::Upstream => flow_upstream(&theme),
            MenuChoice::Rules => flow_rules(),
            MenuChoice::Exit => {
                println!("\nGoodbye.");
                return Ok(());
            }
        };

        if let Err(e) = flow_result {
            eprintln!("\n{}: {:#}", "Error".red().bold(), e);
        }

        // Pause + return to menu unless the user already exited inside the flow.
        if !prompt_continue()? {
            println!("Goodbye.");
            return Ok(());
        }
    }
}

/// Prompt for [Enter] to continue or [q] to quit.
fn prompt_continue() -> Result<bool> {
    print!("\n[Enter] to return to main menu, [q] to quit: ");
    io::stdout().flush().ok();

    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_err() {
        return Ok(false);
    }
    let trimmed = buf.trim().to_lowercase();
    Ok(!matches!(trimmed.as_str(), "q" | "quit" | "exit"))
}

#[derive(Clone, Copy)]
enum ScanKind {
    Remote,
    Local,
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

fn flow_scan(theme: &ColorfulTheme, kind: ScanKind) -> Result<()> {
    let target: String = match kind {
        ScanKind::Remote => Input::with_theme(theme)
            .with_prompt("Repository (owner/repo)")
            .with_initial_text("")
            .default("cli/cli".to_string())
            .show_default(true)
            .interact_text()
            .context("input cancelled")?,
        ScanKind::Local => Input::with_theme(theme)
            .with_prompt("Path")
            .default(".".to_string())
            .show_default(true)
            .interact_text()
            .context("input cancelled")?,
    };

    let target = target.trim().to_string();
    if target.is_empty() {
        return Err(anyhow!("no target provided"));
    }

    if matches!(kind, ScanKind::Remote) && !is_github_repo(&target) {
        eprintln!(
            "{} '{}' does not look like an owner/repo; trying anyway",
            "warning:".yellow().bold(),
            target
        );
    }

    let token = std::env::var("GITHUB_TOKEN").ok();

    println!("\n{} {}...", "Scanning".bold(), target.cyan());

    let workflows = load_workflows(&target, token.as_deref())?;
    println!(
        "Found {} workflow file{}.",
        workflows.len(),
        if workflows.len() == 1 { "" } else { "s" }
    );

    let cfg = load_config_for(&target);
    if cfg.is_some() {
        println!("Loaded .warden.toml config");
    }

    // Use scan_full with progress so the user gets per-file updates on stderr.
    let findings = scanner::scan_full(&workflows, cfg.as_ref(), true);
    let score = scanner::score(&findings);

    println!();
    println!(
        "{} {} finding{} in {} workflow{}. Score: {}",
        "Done.".green().bold(),
        findings.len().to_string().bold(),
        if findings.len() == 1 { "" } else { "s" },
        workflows.len(),
        if workflows.len() == 1 { "" } else { "s" },
        format_score(score),
    );
    println!();

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();
    println!(
        "  {} {}    {} {}    {} {}    {} {}",
        "Critical:".red().bold(),
        critical,
        "High:".red(),
        high,
        "Medium:".yellow(),
        medium,
        "Low:".blue(),
        low,
    );

    // Capped console view (top 20).
    output::console_capped(&findings, Some(20));

    // Offer to save full results to a file.
    maybe_save_findings(theme, &target, &findings)?;

    Ok(())
}

fn flow_fix(theme: &ColorfulTheme) -> Result<()> {
    let path: String = Input::with_theme(theme)
        .with_prompt("Path")
        .default(".".to_string())
        .show_default(true)
        .interact_text()
        .context("input cancelled")?;

    let token = std::env::var("GITHUB_TOKEN").ok();
    let workflows = load_workflows(&path, token.as_deref())?;

    println!(
        "\n{} {} workflow file{} for fixable issues...\n",
        "Planning fixes for".bold(),
        workflows.len(),
        if workflows.len() == 1 { "" } else { "s" }
    );

    // Dry-run pass to gather a plan without modifying anything.
    let plan = fix::run_fix_json(&workflows, token.as_deref(), true);

    if plan.files.is_empty() {
        println!("{}", "No fixable issues found.".green().bold());
        return Ok(());
    }

    for file in &plan.files {
        println!(
            "{}  ({} fix{})",
            file.path.bold(),
            file.fixes.len(),
            if file.fixes.len() == 1 { "" } else { "es" }
        );
        for f in &file.fixes {
            println!("  {} L{}: {}", "+".green(), f.line, f.description);
        }
        println!();
    }

    println!(
        "{} fix{} would be applied across {} file{}.",
        plan.total_fixes.to_string().bold(),
        if plan.total_fixes == 1 { "" } else { "es" },
        plan.files.len(),
        if plan.files.len() == 1 { "" } else { "s" }
    );

    let apply = Confirm::with_theme(theme)
        .with_prompt("Apply these fixes?")
        .default(false)
        .interact_opt()
        .context("confirmation cancelled")?
        .unwrap_or(false);

    if !apply {
        println!("{}", "No changes written.".dimmed());
        return Ok(());
    }

    // Apply: write each precomputed fixed payload to disk. We reuse the
    // already-computed JSON payload so we don't double-call GitHub for
    // SHA resolution.
    let mut written = 0usize;
    for file in &plan.files {
        fs::write(&file.path, &file.fixed)
            .with_context(|| format!("failed to write {}", file.path))?;
        written += 1;
        println!("{} {}", "->".blue(), file.path);
    }

    println!(
        "\n{} {} fix{} applied across {} file{}.",
        "Done.".green().bold(),
        plan.total_fixes,
        if plan.total_fixes == 1 { "" } else { "es" },
        written,
        if written == 1 { "" } else { "s" }
    );

    Ok(())
}

fn flow_upstream(theme: &ColorfulTheme) -> Result<()> {
    let path: String = Input::with_theme(theme)
        .with_prompt("Path")
        .default(".".to_string())
        .show_default(true)
        .interact_text()
        .context("input cancelled")?;

    let depth_str: String = Input::with_theme(theme)
        .with_prompt("Depth (1 = direct deps only, 2 = also deps-of-deps)")
        .default("1".to_string())
        .show_default(true)
        .validate_with(|s: &String| -> Result<(), &str> {
            match s.trim() {
                "1" | "2" => Ok(()),
                _ => Err("enter 1 or 2"),
            }
        })
        .interact_text()
        .context("input cancelled")?;
    let depth: u8 = depth_str.trim().parse().unwrap_or(1);

    let conc_str: String = Input::with_theme(theme)
        .with_prompt("Concurrency")
        .default("8".to_string())
        .show_default(true)
        .validate_with(|s: &String| -> Result<(), &str> {
            match s.trim().parse::<usize>() {
                Ok(n) if (1..=32).contains(&n) => Ok(()),
                _ => Err("enter an integer 1..32"),
            }
        })
        .interact_text()
        .context("input cancelled")?;
    let concurrency: usize = conc_str.trim().parse().unwrap_or(8);

    let token = std::env::var("GITHUB_TOKEN").ok();

    println!(
        "\n{} dependencies under {} (depth={depth}, concurrency={concurrency})...\n",
        "Auditing".bold(),
        path.cyan()
    );

    let report = audit::run(&path, concurrency, depth, token.as_deref())?;
    audit::print_console(&report);

    maybe_save_audit_report(theme, &path, &report)?;
    Ok(())
}

fn flow_rules() -> Result<()> {
    let mut all = rules::all_rules();
    all.sort_by(|a, b| a.id().cmp(b.id()));

    println!("\n{} detection rules available:\n", all.len());
    println!("  {:<10} {:<22} NAME", "ID", "SEVERITY");
    println!("  {}", "-".repeat(72));

    let cap = 30usize;
    let total = all.len();

    for (idx, rule) in all.iter().enumerate() {
        if idx == cap && total > cap {
            // Pause for paging.
            println!(
                "  {}",
                format!("-- {idx} of {total} -- press Enter for more, q to stop --").dimmed()
            );
            io::stdout().flush().ok();
            let mut buf = String::new();
            if io::stdin().read_line(&mut buf).is_err() {
                break;
            }
            if buf.trim().eq_ignore_ascii_case("q") {
                println!("  {}", format!("(stopped at {idx}/{total})").dimmed());
                return Ok(());
            }
        }

        let severity_str = format_severity_label(rule.severity());
        println!("  {:<10} {:<32} {}", rule.id(), severity_str, rule.name());
    }
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Save-to-file helpers
// ---------------------------------------------------------------------------

fn maybe_save_findings(
    theme: &ColorfulTheme,
    target: &str,
    findings: &[rules::Finding],
) -> Result<()> {
    let save = Confirm::with_theme(theme)
        .with_prompt("Save full results to a file?")
        .default(false)
        .interact_opt()
        .context("confirmation cancelled")?
        .unwrap_or(false);

    if !save {
        return Ok(());
    }

    let formats = ["JSON", "SARIF", "Markdown"];
    let format_idx = Select::with_theme(theme)
        .with_prompt("Format")
        .items(formats.as_slice())
        .default(0)
        .interact_opt()
        .context("format selection cancelled")?;

    let Some(format_idx) = format_idx else {
        return Ok(());
    };

    let (ext, content) = match format_idx {
        0 => ("json", build_findings_json(findings)),
        1 => ("sarif", build_findings_sarif(findings)),
        _ => ("md", output::markdown(findings)),
    };

    let path = build_output_path(target, ext);
    fs::write(&path, content).with_context(|| format!("failed to write {path}"))?;
    println!("{} {}", "Saved:".green().bold(), path);
    Ok(())
}

fn maybe_save_audit_report(
    theme: &ColorfulTheme,
    target: &str,
    report: &audit::AuditReport,
) -> Result<()> {
    let save = Confirm::with_theme(theme)
        .with_prompt("Save full audit report to a file?")
        .default(false)
        .interact_opt()
        .context("confirmation cancelled")?
        .unwrap_or(false);

    if !save {
        return Ok(());
    }

    let formats = ["JSON", "Markdown"];
    let format_idx = Select::with_theme(theme)
        .with_prompt("Format")
        .items(formats.as_slice())
        .default(0)
        .interact_opt()
        .context("format selection cancelled")?;

    let Some(format_idx) = format_idx else {
        return Ok(());
    };

    let (ext, content) = match format_idx {
        0 => (
            "json",
            serde_json::to_string_pretty(report)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        ),
        _ => ("md", build_audit_markdown(report)),
    };

    let path = build_output_path(target, ext);
    fs::write(&path, content).with_context(|| format!("failed to write {path}"))?;
    println!("{} {}", "Saved:".green().bold(), path);
    Ok(())
}

/// Build a `./warden-<sanitized-target>-<timestamp>.<ext>` path.
pub fn build_output_path(target: &str, ext: &str) -> String {
    let safe = sanitize_target(target);
    let stamp = timestamp_compact();
    format!("./warden-{safe}-{stamp}.{ext}")
}

fn sanitize_target(target: &str) -> String {
    let mut out = String::with_capacity(target.len());
    for c in target.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if matches!(c, '-' | '_') {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed
    }
}

fn timestamp_compact() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Lightweight YYYYMMDD-HHMM via /proc/uptime free conversion. We don't
    // want to pull in chrono just for a filename, so we use a simple
    // gmtime-equivalent. Days since epoch -> civil date.
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    let hh = (secs % 86_400) / 3600;
    let mm = (secs % 3600) / 60;
    format!("{y:04}{mo:02}{d:02}-{hh:02}{mm:02}")
}

/// Howard Hinnant's civil_from_days algorithm. Pure integer math, no deps.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn build_findings_json(findings: &[rules::Finding]) -> String {
    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();

    let value = serde_json::json!({
        "total_findings": findings.len(),
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "findings": findings.iter().map(|f| serde_json::json!({
            "rule_id": f.rule_id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "file": f.file,
            "line": f.line,
            "remediation": f.remediation,
        })).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

fn build_findings_sarif(findings: &[rules::Finding]) -> String {
    // Reuse the SARIF generator by capturing stdout. Cheaper alternative:
    // duplicate the small SARIF builder here. We choose duplication so the
    // interactive flow doesn't fork stdout.
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

    let rules_json: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|rule_id| {
            let sample = findings.iter().find(|f| &f.rule_id == rule_id);
            serde_json::json!({
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
            serde_json::json!({
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

    let doc = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "warden",
                    "informationUri": "https://github.com/projectwarden/warden",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_json
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

fn build_audit_markdown(report: &audit::AuditReport) -> String {
    let mut out = String::new();
    out.push_str("## warden upstream\n\n");
    out.push_str(&format!(
        "**Summary:** {} dependencies scanned, {} with findings, {} total findings\n\n",
        report.total_deps, report.deps_with_findings, report.total_findings
    ));
    for dep in &report.results {
        if dep.findings.is_empty() {
            continue;
        }
        let slug = dep
            .source_repo
            .clone()
            .unwrap_or_else(|| "<unresolved>".to_string());
        out.push_str(&format!(
            "### `{}` ({}) -> `{}`\n\n",
            dep.name, dep.ecosystem, slug
        ));
        for f in &dep.findings {
            out.push_str(&format!(
                "- **{}** `{}` {} // `{}:{}`\n",
                f.severity.to_uppercase(),
                f.rule_id,
                f.title,
                f.file,
                f.line
            ));
        }
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

fn format_score(score: u32) -> String {
    let s = format!("{score}/100");
    if score >= 80 {
        s.green().bold().to_string()
    } else if score >= 50 {
        s.yellow().bold().to_string()
    } else {
        s.red().bold().to_string()
    }
}

fn format_severity_label(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".red().bold().to_string(),
        "high" => "HIGH".red().to_string(),
        "medium" => "MEDIUM".yellow().to_string(),
        "low" => "LOW".blue().to_string(),
        other => other.to_uppercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_target_repo_slug() {
        assert_eq!(sanitize_target("cli/cli"), "cli-cli");
        assert_eq!(sanitize_target("aquasecurity/trivy"), "aquasecurity-trivy");
        assert_eq!(sanitize_target("."), "target");
        assert_eq!(sanitize_target("./my project"), "my-project");
    }

    #[test]
    fn build_output_path_format() {
        let p = build_output_path("cli/cli", "json");
        assert!(p.starts_with("./warden-cli-cli-"));
        assert!(p.ends_with(".json"));
    }

    #[test]
    fn civil_date_known_value() {
        // 2026-04-06 -> days since 1970-01-01 = 20549
        let (y, m, d) = civil_from_days(20_549);
        assert_eq!((y, m, d), (2026, 4, 6));
    }

    #[test]
    fn build_findings_json_includes_summary() {
        let findings = vec![rules::Finding {
            rule_id: "WRD-101".into(),
            severity: "critical".into(),
            title: "Expression injection".into(),
            description: "user input flows into shell".into(),
            file: ".github/workflows/ci.yml".into(),
            line: 42,
            remediation: "wrap in env var".into(),
        }];
        let s = build_findings_json(&findings);
        assert!(s.contains("\"total_findings\": 1"));
        assert!(s.contains("\"critical\": 1"));
        assert!(s.contains("\"WRD-101\""));
    }

    #[test]
    fn build_findings_sarif_basic_shape() {
        let findings = vec![rules::Finding {
            rule_id: "WRD-202".into(),
            severity: "high".into(),
            title: "Pull request target".into(),
            description: "...".into(),
            file: ".github/workflows/pr.yml".into(),
            line: 3,
            remediation: "use pull_request".into(),
        }];
        let s = build_findings_sarif(&findings);
        assert!(s.contains("\"version\": \"2.1.0\""));
        assert!(s.contains("\"WRD-202\""));
        assert!(s.contains("\"level\": \"error\""));
    }

    #[test]
    fn format_score_colors_change_with_tier() {
        // Just confirm the function returns SOMETHING for each tier and
        // doesn't panic. Actual color escapes depend on terminal env.
        for score in [10u32, 60, 95] {
            let s = format_score(score);
            assert!(s.contains(&format!("{score}/100")));
        }
    }
}
