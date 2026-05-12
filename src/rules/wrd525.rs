use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::expression::PathSeg;
use crate::models::{Job, PermissionLevel, Permissions, Step};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk workflow + job permissions for `id-token: write`; walk steps for
// pypa/gh-action-pypi-publish. Use ctx.expressions to detect
// secrets.PYPI_* / secrets.NPM_TOKEN / secrets.NODE_AUTH_TOKEN references.
// ---------------------------------------------------------------------------

pub struct Wrd525;

fn permissions_have_id_token_write(p: &Permissions) -> bool {
    match p {
        Permissions::All(_) => false,
        Permissions::Map(m) => match m.get("id-token") {
            Some(PermissionLevel::Write) => true,
            Some(PermissionLevel::Other(s)) => s.eq_ignore_ascii_case("write"),
            _ => false,
        },
    }
}

fn workflow_has_id_token_write(wf: &crate::models::Workflow) -> bool {
    if let Some(p) = &wf.permissions {
        if permissions_have_id_token_write(p) {
            return true;
        }
    }
    for job in wf.jobs.values() {
        let job_perms = match job {
            Job::Normal(j) => j.permissions.as_ref(),
            Job::Reusable(r) => r.permissions.as_ref(),
        };
        if let Some(p) = job_perms {
            if permissions_have_id_token_write(p) {
                return true;
            }
        }
    }
    false
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

fn is_pypi_secret(name: &str) -> bool {
    matches!(name, "PYPI_TOKEN" | "PYPI_API_TOKEN" | "PYPI_PASSWORD")
}

fn is_npm_secret(name: &str) -> bool {
    matches!(name, "NPM_TOKEN" | "NODE_AUTH_TOKEN")
}

impl Rule for Wrd525 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-525",
            name: "Long-Lived Publish Token In Use",
            default_severity: Severity::Medium,
            description: "Detects PyPI/npm publish workflows using stored API tokens instead of \
                          OIDC trusted publishing",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();

        let has_id_token = workflow_has_id_token_write(wf);

        // PyPI publish step without id-token: write.
        if !has_id_token {
            for (job_name, job) in &wf.jobs {
                let Job::Normal(j) = job else {
                    continue;
                };
                for (i, step) in j.steps.iter().enumerate() {
                    if let Step::Uses(u) = step {
                        if u.uses.starts_with("pypa/gh-action-pypi-publish") {
                            let step_path = format!("jobs.{job_name}.steps[{i}].uses");
                            let span = ctx
                                .loaded
                                .spans
                                .get_str(&step_path)
                                .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                            findings.push(RuleFinding {
                                rule_id: "WRD-525",
                                severity: Severity::Medium,
                                title: "PyPI publish without trusted publishing (OIDC)".into(),
                                description: "pypa/gh-action-pypi-publish is used without \
                                              'id-token: write' permission. Trusted publishing \
                                              via OIDC is more secure than long-lived API \
                                              tokens because it eliminates stored secrets \
                                              entirely."
                                    .into(),
                                primary: span,
                                related: Vec::new(),
                                remediation: "Configure trusted publishing on PyPI and add \
                                              'id-token: write' to permissions. Remove any \
                                              PYPI_TOKEN secrets. See \
                                              https://docs.pypi.org/trusted-publishers/"
                                    .into(),
                            });
                        }
                    }
                }
            }
        }

        // Any reference to PyPI token or npm token secrets.
        for occ in ctx.expressions.occurrences() {
            let Some(ast) = occ.ast.as_ref() else {
                continue;
            };
            for path in ast.all_paths() {
                let Some(name) = secret_name(&path) else {
                    continue;
                };
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
                if is_pypi_secret(&name) {
                    findings.push(RuleFinding {
                        rule_id: "WRD-525",
                        severity: Severity::Medium,
                        title: "PyPI API token stored as secret".into(),
                        description: "A PyPI API token is referenced as a repository secret. \
                                      Trusted publishing via OIDC eliminates the need for \
                                      stored tokens."
                            .into(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Migrate to trusted publishing (OIDC) and remove the \
                                      stored PyPI token. See \
                                      https://docs.pypi.org/trusted-publishers/"
                            .into(),
                    });
                } else if is_npm_secret(&name) {
                    findings.push(RuleFinding {
                        rule_id: "WRD-525",
                        severity: Severity::Medium,
                        title: "npm publish using stored token".into(),
                        description: "npm publish uses a stored NPM_TOKEN or NODE_AUTH_TOKEN \
                                      secret. Consider using npm provenance with OIDC for a \
                                      more secure publishing flow."
                            .into(),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Use 'npm publish --provenance' with OIDC (id-token: \
                                      write) instead of stored tokens. See \
                                      https://docs.npmjs.com/generating-provenance-statements"
                            .into(),
                    });
                }
            }
        }

        findings
    }
}
