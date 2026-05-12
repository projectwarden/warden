use regex::Regex;

use crate::models::{Job, Step};
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

const BUILD_COMMANDS: &[&str] = &[
    "npm", "npx", "yarn", "pnpm", "pip", "pip3", "cargo", "make", "cmake", "gradle", "gradlew",
    "mvn", "mvnw", "go build", "go run", "go test", "poetry", "bundle", "rake", "ant", "bazel",
    "pants", "sbt",
];

// ---------------------------------------------------------------------------
// V2: require pull_request_target + a checkout step whose with.ref is the PR
// head, then walk subsequent Step::Run entries in the same job for known build
// tool invocations. We match command names with word boundaries against the
// raw run text.
// ---------------------------------------------------------------------------

pub struct Wrd202;

fn job_checks_out_pr_head(steps: &[Step]) -> bool {
    for step in steps {
        let Step::Uses(u) = step else { continue };
        if !u.uses.starts_with("actions/checkout@") {
            continue;
        }
        let Some(with) = &u.with else { continue };
        let Some(ref_val) = with.get("ref") else {
            continue;
        };
        let ref_str = ref_val.as_str_owned();
        if ref_str.contains("github.event.pull_request.head.sha")
            || ref_str.contains("github.event.pull_request.head.ref")
            || ref_str.contains("github.head_ref")
        {
            return true;
        }
    }
    false
}

fn find_build_cmd_in_run(run_text: &str) -> Option<&'static str> {
    for cmd in BUILD_COMMANDS {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(cmd));
        let re = Regex::new(&pattern).unwrap();
        if re.is_match(run_text) {
            return Some(cmd);
        }
    }
    None
}

impl Rule for Wrd202 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-202",
            name: "Build Tool Execution on Untrusted Code",
            default_severity: Severity::Critical,
            description: "pull_request_target workflow checks out fork code and executes build \
                          tools, allowing arbitrary code execution with write permissions.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        if ctx.loaded.is_stub {
            return Vec::new();
        }
        let wf = &ctx.loaded.workflow;
        if !wf.on.mentions("pull_request_target") {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (job_name, job) in &wf.jobs {
            let Job::Normal(j) = job else { continue };
            if !job_checks_out_pr_head(&j.steps) {
                continue;
            }
            for (i, step) in j.steps.iter().enumerate() {
                let Step::Run(r) = step else { continue };
                let Some(cmd) = find_build_cmd_in_run(&r.run) else {
                    continue;
                };
                let span = ctx
                    .loaded
                    .spans
                    .get_str(&format!("jobs.{job_name}.steps[{i}]"))
                    .unwrap_or_else(|| Span::new(0, 0, 1, 1, 1, 1));
                findings.push(RuleFinding {
                    rule_id: "WRD-202",
                    severity: Severity::Critical,
                    title: format!("Build tool '{cmd}' executed on untrusted fork code"),
                    description: format!(
                        "The workflow uses pull_request_target, checks out the PR head, and \
                         runs '{cmd}'. An attacker can modify build scripts or config in their \
                         fork to execute arbitrary code with elevated privileges."
                    ),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Do not run build commands on untrusted code in \
                                  pull_request_target workflows. Use pull_request trigger \
                                  instead, or run builds in a separate unprivileged workflow."
                        .into(),
                });
            }
        }
        findings
    }
}
