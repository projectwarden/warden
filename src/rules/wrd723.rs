use super::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::models::{Container, Job};
use crate::yamlpath::Span;

// ---------------------------------------------------------------------------
// V2: walk typed Job::Normal container/services. Handles both the bare
// `container: "image"` form and the detailed `container: { image: "..." }`
// form, and scopes the check to actual container declarations (the legacy
// regex fires on any `image:` key in the file).
// ---------------------------------------------------------------------------

pub struct Wrd723;

fn is_pinned(image: &str) -> bool {
    image.contains("@sha256:")
}

impl Rule for Wrd723 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-723",
            name: "Unpinned Docker Image",
            default_severity: Severity::Medium,
            description: "Detects container or services image references that are not pinned \
                          to a specific @sha256: digest.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        let mut findings = Vec::new();
        let default_span = || Span::new(0, 0, 1, 1, 1, 1);

        let emit = |path: &str, image_ref: &str, findings: &mut Vec<RuleFinding>| {
            let span = ctx.loaded.spans.get_str(path).unwrap_or_else(default_span);
            findings.push(RuleFinding {
                rule_id: "WRD-723",
                severity: Severity::Medium,
                title: format!("Unpinned Docker image: {image_ref}"),
                description: "Docker images referenced by tag (e.g. :latest, :v1) can be \
                              replaced with a compromised version. Pinning by digest ensures \
                              immutability."
                    .to_string(),
                primary: span,
                related: Vec::new(),
                remediation: "Pin the image to a sha256 digest, e.g. \
                              image: node:18@sha256:abcdef..."
                    .to_string(),
            });
        };

        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };

            // Job-level container.
            if let Some(container) = &j.container {
                match container {
                    Container::Bare(image) => {
                        if !is_pinned(image) {
                            let path = format!("jobs.{job_name}.container");
                            emit(&path, image, &mut findings);
                        }
                    }
                    Container::Detailed(d) => {
                        if !is_pinned(&d.image) {
                            let path = format!("jobs.{job_name}.container.image");
                            emit(&path, &d.image, &mut findings);
                        }
                    }
                }
            }

            // Services map.
            if let Some(services) = &j.services {
                for (svc_name, svc) in services {
                    match svc {
                        Container::Bare(image) => {
                            if !is_pinned(image) {
                                let path = format!("jobs.{job_name}.services.{svc_name}");
                                emit(&path, image, &mut findings);
                            }
                        }
                        Container::Detailed(d) => {
                            if !is_pinned(&d.image) {
                                let path = format!("jobs.{job_name}.services.{svc_name}.image");
                                emit(&path, &d.image, &mut findings);
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}
