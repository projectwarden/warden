use regex::Regex;
use std::sync::OnceLock;

use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walks each run: block via ctx.shell.occurrences() and flags the specific
// runtime-self-hosted-runner-registration shapes used by the Shai-Hulud 2.0
// npm worm (2025-11) and the PyTorch self-hosted takeover class. Different
// from WRD-801 (which flags workflows that USE self-hosted runners on a PR
// trigger); this rule flags workflows that REGISTER a fresh runner at
// runtime from inside the job itself, which is a persistence primitive.
//
// Sources:
//   - https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
//     (Shai-Hulud 2.0 worm, SHA1HULUD runner name IOC, 25k+ repos hit)
//   - https://www.sysdig.com/blog/how-threat-actors-are-using-self-hosted-github-actions-runners-as-backdoors
// ---------------------------------------------------------------------------

pub struct Wrd802;

fn re_config_sh() -> &'static Regex {
    // `config.sh ... --token ...` or `./config.sh ... --token ...`.
    // Token can be anywhere on the line after config.sh.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)(?:^|[/\s])config\.sh[^\n]*?--token").unwrap())
}

fn re_run_sh_ephemeral() -> &'static Regex {
    // `./run.sh` or `run.sh` on its own (starts the configured runner).
    // We require a preceding `./` or start-of-line + no slash to avoid
    // false-matching random paths like `foo/bar/run.sh`.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)(?:^|[\s;&])(?:\./)?run\.sh(?:\s|$)").unwrap())
}

fn re_runasroot() -> &'static Regex {
    // RUNNER_ALLOW_RUNASROOT=1 exported or inline-set.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"RUNNER_ALLOW_RUNASROOT\s*=\s*1").unwrap())
}

fn re_shai_hulud_ioc() -> &'static Regex {
    // Literal runner-name IOC from Shai-Hulud 2.0. Matching the exact name
    // costs us nothing and gives us a loud CRITICAL when it appears.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)--name\s+SHA1HULUD|SHA1HULUD").unwrap())
}

impl Rule for Wrd802 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-802",
            name: "Runtime Self-Hosted Runner Registration",
            default_severity: Severity::Critical,
            description: "Detects workflows that register a fresh self-hosted runner from \
                          inside a run: block (via config.sh --token, ./run.sh, or \
                          RUNNER_ALLOW_RUNASROOT=1). This is a persistence primitive used \
                          by the Shai-Hulud 2.0 npm worm (2025-11) and similar attacks to \
                          turn a victim repo into a C2 endpoint.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }

        #[cfg(feature = "shell-analysis")]
        {
            let mut findings = Vec::new();
            for occ in ctx.shell.occurrences() {
                let script = &occ.script;
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&occ.path)
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));

                // Highest-confidence IOC first; if present, emit once and move on.
                if re_shai_hulud_ioc().is_match(script) {
                    findings.push(RuleFinding {
                        rule_id: "WRD-802",
                        severity: Severity::Critical,
                        title: "Shai-Hulud IOC: runner name 'SHA1HULUD' in run block".into(),
                        description: "This run: block references the literal string 'SHA1HULUD', \
                             the runner-name IOC published by Unit 42 for the Shai-Hulud \
                             2.0 npm worm (2025-11). If this is an intentional string \
                             match in incident-response tooling, suppress with \
                             `# warden: ignore[WRD-802]`."
                            .into(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Treat this workflow as compromised; rotate any secrets it \
                             had access to, revoke registered runners named SHA1HULUD \
                             at the org level, and audit recent commits for the \
                             bun_environment.js / setup_bun.js payloads."
                            .into(),
                    });
                    continue;
                }

                let mut hit = None;
                if re_config_sh().is_match(script) {
                    hit = Some((
                        "Runner registration via config.sh --token in run: block",
                        "This run: block invokes actions-runner's config.sh with a \
                         --token flag, which registers the host as a self-hosted \
                         runner. When executed inside a workflow, this turns the job \
                         into a C2 persistence primitive: after the job ends, the \
                         runner remains registered and continues listening for jobs \
                         from the registering principal.",
                    ));
                } else if re_run_sh_ephemeral().is_match(script) {
                    hit = Some((
                        "Runner start via run.sh in run: block",
                        "This run: block invokes actions-runner's run.sh (or \
                         ./run.sh), which starts a configured self-hosted runner. \
                         Combined with a prior config.sh --token registration, this \
                         is the two-step Shai-Hulud-class persistence pattern.",
                    ));
                } else if re_runasroot().is_match(script) {
                    hit = Some((
                        "RUNNER_ALLOW_RUNASROOT=1 set in run: block",
                        "This run: block sets RUNNER_ALLOW_RUNASROOT=1, which \
                         lets the actions-runner binary start as root. Legitimate \
                         CI almost never needs this; it is commonly seen in \
                         attacker-dropped runner-registration workflows.",
                    ));
                }

                if let Some((title, desc)) = hit {
                    findings.push(RuleFinding {
                        rule_id: "WRD-802",
                        severity: Severity::Critical,
                        title: title.to_string(),
                        description: desc.to_string(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Do not register self-hosted runners from inside a \
                             workflow. Provision runners out-of-band via Terraform, \
                             an org-level control plane, or GitHub's managed runner \
                             autoscaler. If you see an unexpected runner appearing \
                             after a commit, investigate; this pattern was used by \
                             Shai-Hulud 2.0 to compromise 25k+ repositories."
                            .into(),
                    });
                }
            }
            findings
        }
        #[cfg(not(feature = "shell-analysis"))]
        {
            let _ = ctx;
            Vec::new()
        }
    }
}
