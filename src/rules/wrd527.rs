use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::expression::PathSeg;
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: complements WRD-525 (which covers PyPI + npm) by detecting the same
// class of long-lived-publish-token use against Cargo (crates.io) and
// RubyGems registries. Both are common secondary registries the 2025
// supply-chain-attack wave spread through (Ultralytics pivoted into PyPI,
// but the class generalises): long-lived stored API tokens in place of
// the OIDC trusted-publisher mechanism each registry now supports.
//
// Crates.io and RubyGems both rolled out OIDC-based trusted publishing in
// late 2025; using a stored CARGO_REGISTRY_TOKEN / GEM_HOST_API_KEY is now
// the "legacy path," and warden should flag it so teams migrate.
// ---------------------------------------------------------------------------

pub struct Wrd527;

fn re_cargo_publish() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)(?:^|[\s;&|])cargo\s+publish\b").unwrap())
}

fn re_gem_push() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)(?:^|[\s;&|])gem\s+push\b").unwrap())
}

fn secret_name(path: &[PathSeg]) -> Option<String> {
    if path.len() < 2 {
        return None;
    }
    match &path[0] {
        PathSeg::Root(r) if r == "secrets" => {}
        _ => return None,
    }
    match &path[1] {
        PathSeg::Field(f) => Some(f.clone()),
        PathSeg::IndexString(s) => Some(s.clone()),
        _ => None,
    }
}

fn is_cargo_secret(name: &str) -> bool {
    matches!(
        name,
        "CARGO_REGISTRY_TOKEN" | "CRATES_IO_TOKEN" | "CARGO_TOKEN"
    )
}

fn is_gem_secret(name: &str) -> bool {
    matches!(name, "GEM_HOST_API_KEY" | "RUBYGEMS_API_KEY")
}

impl Rule for Wrd527 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-527",
            name: "Registry Publish Without Trusted Publishing",
            default_severity: Severity::Medium,
            description: "Detects Cargo / RubyGems publish steps using a stored \
                          long-lived token (CARGO_REGISTRY_TOKEN, CRATES_IO_TOKEN, \
                          GEM_HOST_API_KEY, RUBYGEMS_API_KEY) instead of the OIDC \
                          trusted-publisher path each registry now supports. Pairs \
                          with WRD-525 (PyPI + npm). Stored tokens widen the blast \
                          radius of any repo / artifact leak (see Ultralytics 2024, \
                          which chained head_ref injection into a long-lived PyPI \
                          token).",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let mut findings = Vec::new();

        // Shell-content check: run: blocks that call cargo publish / gem push.
        #[cfg(feature = "shell-analysis")]
        {
            for occ in ctx.shell.occurrences() {
                let script = &occ.script;
                let hit = if let Some(m) = re_cargo_publish().find(script) {
                    Some((
                        "cargo publish without trusted-publisher OIDC",
                        "This `run:` block calls `cargo publish`. crates.io shipped \
                         OIDC-based trusted publishing in late 2025; using a stored \
                         CARGO_REGISTRY_TOKEN widens the blast radius of any repo \
                         or artifact leak.",
                        m,
                    ))
                } else {
                    re_gem_push().find(script).map(|m| {
                        (
                            "gem push without trusted-publisher OIDC",
                            "This `run:` block calls `gem push`. RubyGems supports \
                             OIDC-based trusted publishing; using a stored \
                             GEM_HOST_API_KEY widens the blast radius of any repo or \
                             artifact leak.",
                            m,
                        )
                    })
                };

                if let Some((title, desc, m)) = hit {
                    let span = ctx
                        .loaded
                        .spans
                        .get_str(&occ.path)
                        .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                    let offset_line = script[..m.start()].matches('\n').count();
                    let actual_line = span.start_line + offset_line;
                    let line_span = Span::new(
                        span.byte_start,
                        span.byte_end,
                        actual_line,
                        span.start_col,
                        actual_line,
                        span.end_col,
                    );
                    findings.push(RuleFinding {
                        rule_id: "WRD-527",
                        severity: Severity::Medium,
                        title: title.to_string(),
                        description: desc.to_string(),
                        primary: line_span,
                        related: Vec::new(),
                        remediation: "Migrate to the registry's trusted-publisher \
                                      OIDC flow (id-token: write + configure the \
                                      registry to accept this repository). Remove \
                                      the stored token secret once OIDC is working."
                            .to_string(),
                    });
                }
            }
        }

        // Secret-reference check: any Cargo/RubyGems token referenced in expressions.
        for occ in ctx.expressions.occurrences() {
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                let Some(name) = secret_name(&path) else {
                    continue;
                };
                let title_desc: Option<(&str, &str)> = if is_cargo_secret(&name) {
                    Some((
                        "Cargo registry token stored as secret",
                        "A Cargo / crates.io token is referenced as a repository \
                         secret. OIDC trusted publishing eliminates the need for \
                         a stored long-lived token.",
                    ))
                } else if is_gem_secret(&name) {
                    Some((
                        "RubyGems API key stored as secret",
                        "A RubyGems API key is referenced as a repository secret. \
                         OIDC trusted publishing eliminates the need for a stored \
                         long-lived token.",
                    ))
                } else {
                    None
                };
                if let Some((title, desc)) = title_desc {
                    let field_span = ctx
                        .loaded
                        .spans
                        .get_str(&occ.path)
                        .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                    let actual_line = field_span.start_line + occ.line_offset_in_field;
                    let span = Span::new(
                        field_span.byte_start,
                        field_span.byte_end,
                        actual_line,
                        field_span.start_col,
                        actual_line,
                        field_span.end_col,
                    );
                    findings.push(RuleFinding {
                        rule_id: "WRD-527",
                        severity: Severity::Medium,
                        title: title.to_string(),
                        description: desc.to_string(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Migrate to OIDC trusted publishing and \
                                      remove the stored secret."
                            .to_string(),
                    });
                    break;
                }
            }
        }

        findings
    }
}
