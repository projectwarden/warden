use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;

use wardenscan::audit;
use wardenscan::fix;
use wardenscan::output;
use wardenscan::rules;
use wardenscan::scanner;

mod bin_common;
mod interactive;

use bin_common::{load_config_for, load_workflows, should_fail, FailLevel as CommonFailLevel};

const TOP_AFTER_HELP: &str = "\
EXAMPLES:
    warden                           Launch the interactive guided menu (TTY only)
    warden scan .                    Scan the current project
    warden scan cli/cli              Scan a public GitHub repo
    warden score aquasecurity/trivy  Compute a security score for a remote repo
    warden fix .                     Plan auto-fixes (no writes by default)
    warden fix . --apply             Apply auto-fixes to disk
    warden upstream .                Scan your dependencies' upstream CI/CD workflows
    warden rules                     List every detection rule

For per-subcommand examples and flags, run `warden <COMMAND> --help`.";

#[derive(Parser)]
#[command(
    name = "warden",
    about = "CI/CD security scanner for GitHub Actions workflows",
    long_about = "warden scans GitHub Actions workflows for misconfigurations, expression \
injection, supply-chain weaknesses, and other CI/CD-specific vulnerabilities. \
Run with no arguments inside a TTY to launch the interactive guided menu.",
    after_help = TOP_AFTER_HELP,
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

const SCAN_AFTER_HELP: &str = "\
EXAMPLES:
    # Scan the current project
    warden scan .

    # Scan a public repo
    warden scan cli/cli

    # Scan another well-known repo
    warden scan aquasecurity/trivy

    # Write SARIF for GitHub Code Scanning
    warden scan . --format sarif > results.sarif

    # Fail CI only on critical findings
    warden scan . --fail-on critical

    # Print every finding (no top-20 cap)
    warden scan pytorch/pytorch --all";

const SCORE_AFTER_HELP: &str = "\
EXAMPLES:
    # Score the current project
    warden score .

    # Score a public repo
    warden score cli/cli

    # JSON output for dashboards
    warden score aquasecurity/trivy --format json";

const FIX_AFTER_HELP: &str = "\
EXAMPLES:
    # Plan: print fixable issues, do NOT touch any file (default)
    warden fix .

    # Apply: actually rewrite files in place
    warden fix . --apply

    # Apply to a single file
    warden fix .github/workflows/ci.yml --apply

    # Compute fixes for a remote repo and emit JSON (no disk writes either way)
    warden fix cli/cli --format json

    # Push a branch with the fixes and print a compare URL (you click `Create PR` yourself)
    GITHUB_TOKEN=ghp_... warden fix . --pr myorg/myrepo --prepare-only

    # Push a branch AND open the PR for you
    GITHUB_TOKEN=ghp_... warden fix . --pr myorg/myrepo --apply";

const AUDIT_AFTER_HELP: &str = "\
EXAMPLES:
    # Audit the current project's direct dependencies
    warden upstream .

    # Scan upstream + deps-of-deps
    warden upstream . --depth 2

    # Crank concurrency for a fast scan with a token
    GITHUB_TOKEN=ghp_... warden upstream . --concurrency 16

    # JSON output for the dashboard
    warden upstream . --format json";

const RULES_AFTER_HELP: &str = "\
EXAMPLES:
    # Print every detection rule grouped by severity
    warden rules";

#[derive(Subcommand)]
enum Commands {
    /// Scan workflows for security vulnerabilities
    #[command(
        long_about = "Scan GitHub Actions workflows for security vulnerabilities. \
TARGET can be a local path (`.`, `./my-project`, a single .yml file) or a \
GitHub `owner/repo` slug (e.g. `cli/cli`, `aquasecurity/trivy`).",
        after_help = SCAN_AFTER_HELP
    )]
    Scan {
        /// Local path, or GitHub owner/repo
        ///
        /// Examples: . | ./my-project | cli/cli | aquasecurity/trivy
        target: String,

        /// Output format: console | json | sarif | markdown
        #[arg(long, default_value = "console", value_enum)]
        format: OutputFormat,

        /// Minimum severity that causes a non-zero exit code: critical | high | medium | low | none
        #[arg(long, default_value = "high")]
        fail_on: FailLevel,

        /// GitHub personal access token (or set GITHUB_TOKEN env var)
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,

        /// Emit NDJSON progress events on stderr (one per workflow)
        #[arg(long, default_value_t = false)]
        progress: bool,

        /// Print every finding instead of capping the console view at 20
        #[arg(long, default_value_t = false)]
        all: bool,
    },

    /// Calculate a security score for workflows
    #[command(
        long_about = "Compute a 0-100 security score for the workflows in TARGET. \
TARGET can be a local path or a GitHub owner/repo slug.",
        after_help = SCORE_AFTER_HELP
    )]
    Score {
        /// Local path, or GitHub owner/repo
        ///
        /// Examples: . | cli/cli | aquasecurity/trivy
        target: String,

        /// Output format: console | json | sarif | markdown
        #[arg(long, default_value = "console", value_enum)]
        format: OutputFormat,

        /// Minimum severity that causes a non-zero exit code
        #[arg(long, default_value = "high")]
        fail_on: FailLevel,

        /// GitHub personal access token (or set GITHUB_TOKEN env var)
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,
    },

    /// Auto-fix security issues in workflow files
    #[command(
        long_about = "Compute and apply automatic fixes for common workflow security \
issues (unpinned actions, expression injection, missing permissions, ...). \
PATH can be a workflow file, a directory, or a GitHub owner/repo slug.",
        after_help = FIX_AFTER_HELP
    )]
    Fix {
        /// Local path to a workflow file or directory, or GitHub owner/repo
        ///
        /// Examples: . | .github/workflows/ci.yml | cli/cli
        path: String,

        /// Apply the fixes by writing changes to disk. Without this flag,
        /// `warden fix` runs in plan mode (terraform-style): it prints the
        /// proposed fixes but does not modify any file. This makes the safe
        /// thing the default and forces explicit opt-in for destructive writes.
        #[arg(long)]
        apply: bool,

        /// Output format. `console` prints colored human output (and writes
        /// files when `--apply` is set). `json` emits structured output and
        /// never writes to disk regardless of `--apply`; the caller is
        /// responsible for persisting the `fixed` content from the JSON payload.
        #[arg(long, default_value = "console", value_enum)]
        format: FixFormat,

        /// GitHub personal access token (or set GITHUB_TOKEN env var)
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,

        /// Open a pull request with the computed fixes against `owner/repo`.
        /// Requires GITHUB_TOKEN with `contents:write` and `pull-requests:write`.
        #[arg(long, value_name = "OWNER/REPO")]
        pr: Option<String>,

        /// Branch name to create for the PR (default: `warden/auto-fix-<unix-ts>`).
        #[arg(long)]
        branch: Option<String>,

        /// Prepare the branch and push the fixes, but do NOT call the GitHub
        /// API to create the pull request. Instead, return a compare URL the
        /// user can click to review and submit the PR themselves.
        #[arg(long)]
        prepare_only: bool,
    },

    /// Audit a project's dependencies by scanning their source repos for CI/CD vulnerabilities
    #[command(
        long_about = "Resolve a project's direct (and optionally depth-2) dependencies \
back to their source repositories on GitHub, then run warden's full rule set against \
each one's workflows. Helps you spot supply-chain risk in the libraries you depend on.",
        after_help = AUDIT_AFTER_HELP
    )]
    Upstream {
        /// Directory to inspect for dependency manifests
        ///
        /// Examples: . | ./my-project
        #[arg(default_value = ".")]
        path: String,

        /// Number of dep repos to scan in parallel
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Output format: console | json | sarif | markdown
        #[arg(long, default_value = "console", value_enum)]
        format: OutputFormat,

        /// Minimum severity that causes a non-zero exit code
        #[arg(long, default_value = "high")]
        fail_on: FailLevel,

        /// Dependency walk depth (1 = direct deps only, 2 = also deps-of-deps)
        #[arg(long, default_value_t = 1)]
        depth: u8,

        /// GitHub personal access token (or set GITHUB_TOKEN env var)
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,
    },

    /// List all available detection rules
    #[command(after_help = RULES_AFTER_HELP)]
    Rules,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Console,
    Json,
    Sarif,
    /// Markdown output suitable for PR comments.
    #[value(alias = "pr-comment")]
    Markdown,
}

#[derive(Clone, ValueEnum)]
enum FixFormat {
    Console,
    Json,
}

#[derive(Clone, ValueEnum)]
enum FailLevel {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl From<&FailLevel> for CommonFailLevel {
    fn from(f: &FailLevel) -> Self {
        match f {
            FailLevel::Critical => CommonFailLevel::Critical,
            FailLevel::High => CommonFailLevel::High,
            FailLevel::Medium => CommonFailLevel::Medium,
            FailLevel::Low => CommonFailLevel::Low,
            FailLevel::None => CommonFailLevel::None,
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            format,
            fail_on,
            github_token,
            progress,
            all,
        } => {
            let workflows = load_workflows(&target, github_token.as_deref())?;
            if !progress {
                eprintln!(
                    "Scanning {} workflow file{}...",
                    workflows.len(),
                    if workflows.len() == 1 { "" } else { "s" }
                );
            }

            let cfg = load_config_for(&target);
            if cfg.is_some() && !progress {
                eprintln!("Loaded .warden.toml config");
            }
            let findings = scanner::scan_full(&workflows, cfg.as_ref(), progress);

            match format {
                OutputFormat::Console => {
                    if all {
                        output::console_capped(&findings, None);
                    } else {
                        output::console(&findings);
                    }
                }
                OutputFormat::Json => output::json_output(&findings),
                OutputFormat::Sarif => output::sarif(&findings),
                OutputFormat::Markdown => print!("{}", output::markdown(&findings)),
            }

            Ok(should_fail(&findings, (&fail_on).into()))
        }

        Commands::Score {
            target,
            format,
            fail_on,
            github_token,
        } => {
            let workflows = load_workflows(&target, github_token.as_deref())?;
            eprintln!(
                "Scoring {} workflow file{}...",
                workflows.len(),
                if workflows.len() == 1 { "" } else { "s" }
            );

            let cfg = load_config_for(&target);
            if cfg.is_some() {
                eprintln!("Loaded .warden.toml config");
            }
            let findings = scanner::scan_with_config(&workflows, cfg.as_ref());
            let score_val = scanner::score(&findings);

            match format {
                OutputFormat::Console => {
                    let score_display = format!("{score_val}/100");
                    let colored_score = if score_val >= 80 {
                        score_display.green().bold()
                    } else if score_val >= 50 {
                        score_display.yellow().bold()
                    } else {
                        score_display.red().bold()
                    };
                    println!("\nSecurity Score: {colored_score}");

                    let critical = findings.iter().filter(|f| f.severity == "critical").count();
                    let high = findings.iter().filter(|f| f.severity == "high").count();
                    let medium = findings.iter().filter(|f| f.severity == "medium").count();
                    let low = findings.iter().filter(|f| f.severity == "low").count();

                    println!(
                        "  Findings: {critical} critical, {high} high, {medium} medium, {low} low"
                    );
                    println!();

                    if score_val < 80 {
                        output::console(&findings);
                    }
                }
                OutputFormat::Json => {
                    let output = serde_json::json!({
                        "score": score_val,
                        "total_findings": findings.len(),
                        "summary": {
                            "critical": findings.iter().filter(|f| f.severity == "critical").count(),
                            "high": findings.iter().filter(|f| f.severity == "high").count(),
                            "medium": findings.iter().filter(|f| f.severity == "medium").count(),
                            "low": findings.iter().filter(|f| f.severity == "low").count(),
                        },
                    });
                    match serde_json::to_string_pretty(&output) {
                        Ok(s) => println!("{s}"),
                        Err(e) => bail!("Failed to serialize score output: {e}"),
                    }
                }
                OutputFormat::Sarif => {
                    output::sarif(&findings);
                }
                OutputFormat::Markdown => {
                    print!("{}", output::markdown(&findings));
                }
            }

            Ok(should_fail(&findings, (&fail_on).into()))
        }

        Commands::Fix {
            path,
            apply,
            format,
            github_token,
            pr,
            branch,
            prepare_only,
        } => {
            let workflows = load_workflows(&path, github_token.as_deref())?;

            // Plan mode is the default. `--apply` opts in to writing changes
            // (whether that's to disk locally, or to a real GitHub PR remotely).
            let plan_only = !apply;

            if let Some(repo_slug) = pr {
                // PR mode: compute fixes in memory, push a branch, open a PR.
                let payload = fix::run_fix_json(&workflows, github_token.as_deref(), plan_only);
                if payload.files.is_empty() {
                    println!("No fixable issues found; skipping PR creation.");
                    return Ok(false);
                }
                let (owner, repo) = match repo_slug.split_once('/') {
                    Some((o, r)) if !o.is_empty() && !r.is_empty() => (o, r),
                    _ => bail!("--pr expects OWNER/REPO, got: {repo_slug}"),
                };
                let url = fix::open_fix_pr(
                    owner,
                    repo,
                    branch.as_deref(),
                    &payload,
                    github_token.as_deref(),
                    plan_only,
                    prepare_only,
                )?;
                println!("{url}");
                return Ok(false);
            }

            match format {
                FixFormat::Console => {
                    eprintln!(
                        "{} {} workflow file{}...",
                        if plan_only {
                            "Planning fixes for"
                        } else {
                            "Applying fixes to"
                        },
                        workflows.len(),
                        if workflows.len() == 1 { "" } else { "s" }
                    );
                    fix::run_fix(&workflows, github_token.as_deref(), plan_only)?;
                }
                FixFormat::Json => {
                    // JSON mode never writes to disk; caller handles persistence.
                    let payload = fix::run_fix_json(&workflows, github_token.as_deref(), plan_only);
                    let s = serde_json::to_string(&payload)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize fix output: {e}"))?;
                    println!("{s}");
                }
            }
            Ok(false)
        }

        Commands::Upstream {
            path,
            concurrency,
            format,
            fail_on,
            depth,
            github_token,
        } => {
            let report = audit::run(&path, concurrency, depth, github_token.as_deref())?;
            match format {
                OutputFormat::Console => audit::print_console(&report),
                OutputFormat::Json => audit::print_json(&report),
                OutputFormat::Markdown => audit::print_markdown(&report),
                OutputFormat::Sarif => audit::print_sarif(&report),
            }
            let best = audit::max_severity_rank(&report);
            let threshold = match fail_on {
                FailLevel::None => return Ok(false),
                FailLevel::Critical => 0,
                FailLevel::High => 1,
                FailLevel::Medium => 2,
                FailLevel::Low => 3,
            };
            Ok(best <= threshold)
        }

        Commands::Rules => {
            let mut all = rules::all_rules();

            if all.is_empty() {
                println!("No rules registered.");
                return Ok(false);
            }

            // Sort by rule ID so categories are grouped
            all.sort_by(|a, b| a.id().cmp(b.id()));

            println!("\n{} detection rules available:\n", all.len());
            println!("  {:<10} {:<12} NAME", "ID", "SEVERITY");
            println!("  {}", "-".repeat(60));

            for rule in &all {
                let severity_str = match rule.severity().to_lowercase().as_str() {
                    "critical" => "CRITICAL".red().bold().to_string(),
                    "high" => "HIGH".red().to_string(),
                    "medium" => "MEDIUM".yellow().to_string(),
                    "low" => "LOW".blue().to_string(),
                    other => other.to_uppercase(),
                };
                println!("  {:<10} {:<22} {}", rule.id(), severity_str, rule.name());
            }
            println!();

            Ok(false)
        }
    }
}

fn main() {
    // Zero-arg invocation in a TTY launches the interactive menu. In CI or
    // when piped (`echo | warden`), fall through to clap so we print help
    // instead of hanging on a `read_line`.
    if std::env::args_os().len() == 1 && interactive::stdin_is_tty() {
        match interactive::run() {
            Ok(()) => return,
            Err(e) => {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                std::process::exit(2);
            }
        }
    }

    match run() {
        Ok(should_exit_nonzero) => {
            if should_exit_nonzero {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}: {:#}", "Error".red().bold(), e);
            std::process::exit(2);
        }
    }
}
