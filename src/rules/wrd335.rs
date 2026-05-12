use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Job, Step};
use crate::yamlpath::Span;
use std::collections::HashSet;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// V2: flags `uses: <owner>/<repo>@ref` where <owner> is not in a curated
// allowlist of well-known-safe GitHub Actions creators. Mirrors poutine's
// `github_action_from_unverified_creator_used` rule, which is itself a
// lighter-weight version of "is this publisher vetted."
//
// Low severity: many legitimate small-creator actions are perfectly safe,
// and the allowlist is necessarily opinionated. Users can suppress per
// rule via `.warden.toml` [severity_overrides] or per occurrence via
// `# warden: ignore[WRD-335]`. We emit at most one finding per unique
// creator per workflow to avoid flooding.
//
// Source of the allowlist: GitHub-owned orgs, major cloud providers,
// well-known language toolchains, and OSS security/ops tooling regularly
// audited by the community. Out-of-list does NOT mean malicious; it means
// "you should at least confirm this author and SHA-pin it."
// ---------------------------------------------------------------------------

pub struct Wrd335;

fn trusted_creators() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            // GitHub itself and first-party.
            "actions",
            "github",
            "github-early-access",
            // Major cloud platforms.
            "aws-actions",
            "azure",
            "google-github-actions",
            "cloudflare",
            "hashicorp",
            "terraform-ci",
            "digitalocean",
            // Containers / registries.
            "docker",
            "helm",
            // Language toolchains.
            "dart-lang",
            "golang",
            "golangci",
            "dtolnay",
            "rust-lang",
            "astral-sh",
            "pnpm",
            "nodejs",
            "denoland",
            "oven-sh",
            "pypa",
            "ruby",
            "actions-rs",
            "swatinem",
            "taiki-e",
            // Build + test tooling widely used.
            "cypress-io",
            "playwright-community",
            "pact-foundation",
            "rhysd",
            "biomejs",
            "withastro",
            "peaceiris",
            "crazy-max",
            "softprops",
            "reviewdog",
            // Code quality + security vendors (OSS-facing).
            "codecov",
            "sonarsource",
            "snyk",
            "gitguardian",
            "trufflesecurity",
            "zaproxy",
            "davidanson",
            // Platform vendors.
            "vercel",
            "netlify",
            "fly-actions",
            // AI / ML.
            "huggingface",
            "anthropics",
            // warden itself, so projects dogfooding it don't self-flag.
            "projectwarden",
        ]
        .into_iter()
        .collect()
    })
}

fn owner_from_uses(uses: &str) -> Option<&str> {
    if uses.starts_with("./") || uses.starts_with("../") {
        return None;
    }
    let before_at = uses.split('@').next()?;
    let owner = before_at.split('/').next()?;
    if owner.is_empty() {
        return None;
    }
    Some(owner)
}

impl Rule for Wrd335 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-335",
            name: "Unverified Action Creator",
            default_severity: Severity::Low,
            description: "Flags GitHub Actions whose creator is not on warden's \
                          allowlist of well-known-safe publishers. Not malicious by \
                          itself, but a useful signal to cross-check the creator, \
                          SHA-pin the action, and add it to your own allowlist. \
                          Mirrors poutine's unverified-creator rule.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let trusted = trusted_creators();
        let mut seen: HashSet<String> = HashSet::new();
        let mut findings = Vec::new();

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Uses(u) = step else { continue };
                let Some(owner) = owner_from_uses(&u.uses) else {
                    continue;
                };
                if trusted.contains(&owner.to_ascii_lowercase().as_str()) {
                    continue;
                }
                // Also accept mixed-case canonical match.
                if trusted.contains(&owner) {
                    continue;
                }
                if !seen.insert(owner.to_string()) {
                    continue;
                }

                let span_path = format!("jobs.{job_name}.steps[{i}]");
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&span_path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-335",
                    severity: Severity::Low,
                    title: format!("Action from unverified creator: {owner}/..."),
                    description: format!(
                        "`{owner}/...` is not on warden's allowlist of well-known \
                         creators (GitHub-first-party, major cloud vendors, common \
                         language toolchains, vetted OSS security tools). This is \
                         not evidence of malice, but unverified creators have been \
                         the entry point for multiple supply-chain incidents; at \
                         minimum, cross-check the author, SHA-pin the action, and \
                         consider adding the creator to your organisation's own \
                         allowlist."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: format!(
                        "If you trust this creator, add them to your `.warden.toml` \
                         allowlist or suppress with \
                         `# warden: ignore[WRD-335]`. Always SHA-pin the \
                         action (`{owner}/...@<40-char-sha>`)."
                    ),
                });
            }
        }

        findings
    }
}
