use std::sync::OnceLock;

use regex::Regex;

use super::provenance::{StepOutputProvenance, TaintSource};
use crate::models::{Job, Step, Workflow};

/// GitHub-set runner env vars whose values are validated by the platform.
/// Reading these into a step output is safe.
///
/// Notably absent: `GITHUB_HEAD_REF` (PR branch name, user-controlled) and
/// `GITHUB_REF` when on a `pull_request_target` event (also reflects PR
/// state). Per GitHub Security Lab guidance.
const SAFE_GITHUB_ENV_VARS: &[&str] = &[
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_SHA",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_JOB",
    "GITHUB_ACTION",
    "GITHUB_ACTION_REF",
    "GITHUB_ACTION_REPOSITORY",
    "GITHUB_API_URL",
    "GITHUB_SERVER_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_EVENT_NAME",
    "GITHUB_BASE_REF",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "RUNNER_NAME",
    "RUNNER_ENVIRONMENT",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
    "RUNNER_WORKSPACE",
];

/// Walk every `Job::Normal` step in a workflow, and for each `Step::Run`
/// with an `id:`, find writes to `$GITHUB_OUTPUT` and classify the source.
pub fn build_provenance(workflow: &Workflow) -> StepOutputProvenance {
    let mut prov = StepOutputProvenance::new();
    for job in workflow.jobs.values() {
        if let Job::Normal(j) = job {
            for step in &j.steps {
                if let Step::Run(r) = step {
                    let Some(step_id) = r.id.as_ref() else {
                        continue;
                    };
                    analyze_run_block(&r.run, step_id, &mut prov);
                }
            }
        }
    }
    prov
}

/// Scan a single `run:` block for writes to `$GITHUB_OUTPUT` and record
/// the inferred source for each `key=value` pair.
///
/// Recognises `echo "key=value" >> $GITHUB_OUTPUT`, the unquoted
/// `>> "$GITHUB_OUTPUT"` and `>> ${GITHUB_OUTPUT}` variants, and `printf`
/// alternatives. Heredoc multi-line writes are conservatively recorded as
/// Unknown because their value spans multiple lines.
fn analyze_run_block(script: &str, step_id: &str, prov: &mut StepOutputProvenance) {
    for cap in echo_assign_re().captures_iter(script) {
        let key = cap.get(1).map(|m| m.as_str().trim().to_string());
        let value = cap.get(2).map(|m| m.as_str().to_string());
        if let (Some(key), Some(value)) = (key, value) {
            prov.record(step_id, key, classify_value_source(&value));
        }
    }

    // Heredoc form: `echo "key<<EOF" >> $GITHUB_OUTPUT` ... `EOF`. We
    // can't easily parse the body with regex, so anything heredoc-shaped
    // gets a conservative Unknown classification.
    for cap in heredoc_assign_re().captures_iter(script) {
        let key = cap.get(1).map(|m| m.as_str().trim().to_string());
        if let Some(key) = key {
            prov.record(step_id, key, TaintSource::Unknown);
        }
    }
}

/// Classify what's on the right-hand side of `key=` in a step output write.
fn classify_value_source(value: &str) -> TaintSource {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');

    // 1. Tainted: any `${{ github.event.* }}` or `${{ github.head_ref }}`
    //    or any expression that flattens to a known TAINTED_SOURCES path.
    if let Some(matched) = match_tainted_expression(trimmed) {
        return TaintSource::Tainted(matched);
    }

    // 2. Secret: any `${{ secrets.X }}`.
    if secrets_re().is_match(trimmed) {
        return TaintSource::Secret(trimmed.to_string());
    }

    // 3. Safe GitHub env vars: `$GITHUB_REF_NAME`, `${GITHUB_SHA}`, etc.
    //    All occurrences of bash-style refs must be in the safe set; if
    //    even one is unrecognised, we downgrade to Unknown.
    let env_refs = collect_env_refs(trimmed);
    if !env_refs.is_empty() {
        let all_safe = env_refs
            .iter()
            .all(|name| SAFE_GITHUB_ENV_VARS.contains(&name.as_str()));
        if all_safe {
            return TaintSource::Safe(trimmed.to_string());
        }
        return TaintSource::Unknown;
    }

    // 4. Command substitution `$(...)` or backtick `\`...\``: cannot
    //    statically analyse the subshell's output. Conservative.
    if trimmed.contains("$(") || trimmed.contains('`') {
        return TaintSource::Unknown;
    }

    // 5. Bare `${{ ... }}` expression that wasn't tainted or secret.
    //    Treat as Unknown unless it's a known safe context.
    if trimmed.contains("${{") {
        return TaintSource::Unknown;
    }

    // 6. No expansions at all: pure literal.
    TaintSource::Literal
}

fn match_tainted_expression(value: &str) -> Option<String> {
    // Use the same canonical taint list as the rest of the codebase so the
    // scanner stays internally consistent (see crate::expression::taint).
    for pattern in crate::expression::TAINTED_SOURCES {
        let escaped = regex::escape(pattern);
        let re = Regex::new(&format!(r"\$\{{\{{?\s*{escaped}")).unwrap();
        if re.is_match(value) {
            return Some(pattern.to_string());
        }
    }
    None
}

fn collect_env_refs(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Braced form, including bash parameter expansion modifiers like
    // `${VAR#prefix}`, `${VAR:-default}`, `${VAR##*/}` etc. We capture
    // just the variable name (group 1) and ignore the modifier tail.
    let braced = Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)[^}]*\}").unwrap();
    let bare = Regex::new(r"\$([A-Z_][A-Z0-9_]*)").unwrap();
    for cap in braced.captures_iter(value) {
        out.push(cap[1].to_string());
    }
    for cap in bare.captures_iter(value) {
        let name = cap[1].to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn echo_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Matches:
        //   echo "key=value" >> $GITHUB_OUTPUT
        //   echo "key=value" >> "$GITHUB_OUTPUT"
        //   echo "key=value" >> ${GITHUB_OUTPUT}
        //   printf '%s\n' "key=value" >> $GITHUB_OUTPUT  (best effort)
        //
        // Captures: 1 = key (left of `=`), 2 = value (right of `=`).
        Regex::new(
            r#"(?m)\b(?:echo|printf[^"]*)\s+"?([A-Za-z_][A-Za-z0-9_-]*)=([^">]*?)"?\s*>>\s*"?\$\{?GITHUB_OUTPUT\}?"?"#,
        )
        .unwrap()
    })
}

fn heredoc_assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `echo "key<<EOF" >> $GITHUB_OUTPUT` style. Capture 1 = key.
        Regex::new(
            r#"(?m)\becho\s+"?([A-Za-z_][A-Za-z0-9_-]*)<<\s*\w+"?\s*>>\s*"?\$\{?GITHUB_OUTPUT\}?"?"#,
        )
        .unwrap()
    })
}

fn secrets_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{\{\s*secrets\.").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(value: &str) -> TaintSource {
        classify_value_source(value)
    }

    #[test]
    fn safe_github_ref_name() {
        assert!(matches!(
            classify("${GITHUB_REF_NAME#v}"),
            TaintSource::Safe(_)
        ));
        assert!(matches!(classify("$GITHUB_SHA"), TaintSource::Safe(_)));
        assert!(matches!(
            classify("${GITHUB_REPOSITORY}-${GITHUB_RUN_ID}"),
            TaintSource::Safe(_)
        ));
    }

    #[test]
    fn tainted_github_event() {
        assert!(matches!(
            classify("${{ github.event.issue.body }}"),
            TaintSource::Tainted(_)
        ));
        assert!(matches!(
            classify("hi-${{ github.head_ref }}"),
            TaintSource::Tainted(_)
        ));
    }

    #[test]
    fn secret_value() {
        assert!(matches!(
            classify("${{ secrets.MY_TOKEN }}"),
            TaintSource::Secret(_)
        ));
    }

    #[test]
    fn unknown_command_substitution() {
        assert!(matches!(classify("$(date +%s)"), TaintSource::Unknown));
        assert!(matches!(classify("`hostname`"), TaintSource::Unknown));
    }

    #[test]
    fn unknown_unrecognised_env() {
        // MY_VAR isn't in the safe list and we can't trace its origin.
        assert!(matches!(classify("$MY_VAR"), TaintSource::Unknown));
        // Mixed: one safe + one unknown -> Unknown.
        assert!(matches!(
            classify("${GITHUB_SHA}-${SOMETHING_ELSE}"),
            TaintSource::Unknown
        ));
    }

    #[test]
    fn literal_no_expansion() {
        assert!(matches!(classify("plain-string"), TaintSource::Literal));
        assert!(matches!(classify("v1.2.3"), TaintSource::Literal));
    }

    #[test]
    fn analyses_simple_echo_write() {
        let script = r#"echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT""#;
        let mut prov = StepOutputProvenance::new();
        analyze_run_block(script, "version", &mut prov);
        assert!(matches!(
            prov.get("version", "version"),
            Some(TaintSource::Safe(_))
        ));
    }

    #[test]
    fn analyses_tainted_write() {
        let script = r#"echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT"#;
        let mut prov = StepOutputProvenance::new();
        analyze_run_block(script, "grab", &mut prov);
        assert!(matches!(
            prov.get("grab", "title"),
            Some(TaintSource::Tainted(_))
        ));
    }

    #[test]
    fn analyses_multiple_writes_per_step() {
        let script = r#"
            echo "tag=${GITHUB_REF_NAME}" >> $GITHUB_OUTPUT
            echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
            echo "now=$(date)" >> $GITHUB_OUTPUT
        "#;
        let mut prov = StepOutputProvenance::new();
        analyze_run_block(script, "meta", &mut prov);
        assert!(matches!(
            prov.get("meta", "tag"),
            Some(TaintSource::Safe(_))
        ));
        assert!(matches!(
            prov.get("meta", "title"),
            Some(TaintSource::Tainted(_))
        ));
        assert!(matches!(
            prov.get("meta", "now"),
            Some(TaintSource::Unknown)
        ));
    }

    #[test]
    fn heredoc_form_marked_unknown() {
        let script = r#"
            echo "body<<EOF" >> $GITHUB_OUTPUT
            echo "$some_var" >> $GITHUB_OUTPUT
            echo "EOF" >> $GITHUB_OUTPUT
        "#;
        let mut prov = StepOutputProvenance::new();
        analyze_run_block(script, "ml", &mut prov);
        assert!(matches!(prov.get("ml", "body"), Some(TaintSource::Unknown)));
    }
}
