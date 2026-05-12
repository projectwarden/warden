use wardenscan::fix::fix_workflow;
use wardenscan::scanner::Workflow;

fn wf(yaml: &str) -> Workflow {
    Workflow {
        path: "test.yml".into(),
        content: yaml.into(),
        parsed: serde_yaml::from_str(yaml).unwrap_or_default(),
    }
}

#[test]
fn test_wrd824_adds_permissions_read_all() {
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(result.fixed.contains("permissions: read-all"));
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("permissions: read-all")));
}

#[test]
fn test_wrd824_skips_when_permissions_present() {
    let yaml = "name: CI\non: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(!result
        .fixes
        .iter()
        .any(|f| f.description.contains("Added top-level permissions")));
}

#[test]
fn test_wrd840_adds_inline_comment_per_permission_entry() {
    // The fixer should walk every entry under a real permissions: block (not the
    // shorthand `permissions: read-all` form) and append an inline `# explanation`
    // to each entry that lacks one. Each modified entry produces its own FixRecord
    // so the count matches WRD-840's per-entry findings.
    let yaml = "name: CI\non: push\npermissions:\n  contents: read\n  pages: write\n  id-token: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);

    assert!(
        result
            .fixed
            .contains("contents: read  # required to read repository contents"),
        "expected inline comment on contents: read, got:\n{}",
        result.fixed
    );
    assert!(
        result
            .fixed
            .contains("pages: write  # required to deploy to GitHub Pages"),
        "expected inline comment on pages: write, got:\n{}",
        result.fixed
    );
    assert!(
        result
            .fixed
            .contains("id-token: write  # required for OIDC token exchange"),
        "expected inline comment on id-token: write, got:\n{}",
        result.fixed
    );

    let perm_fixes: Vec<_> = result
        .fixes
        .iter()
        .filter(|f| f.description.contains("permission entry"))
        .collect();
    assert_eq!(
        perm_fixes.len(),
        3,
        "expected 3 per-entry permission fixes, got: {:?}",
        result.fixes
    );
}

#[test]
fn test_wrd840_skips_already_documented_entries() {
    // Lines that already have an inline `#` comment, OR whose preceding line is
    // a `#` comment, should be left alone. Only undocumented entries get fixed.
    let yaml = "name: CI\non: push\npermissions:\n  contents: read  # already explained\n  # next entry has an above-line comment\n  pages: write\n  id-token: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);

    // contents: read keeps its existing inline comment unchanged
    assert!(result.fixed.contains("contents: read  # already explained"));
    // pages: write has a # comment line above it, so it stays unchanged
    assert!(result
        .fixed
        .contains("# next entry has an above-line comment"));
    assert!(result.fixed.lines().any(|l| l.trim() == "pages: write"));
    // id-token: write is the only undocumented one; the fixer should add an inline comment
    assert!(result
        .fixed
        .contains("id-token: write  # required for OIDC token exchange"));

    let perm_fixes: Vec<_> = result
        .fixes
        .iter()
        .filter(|f| f.description.contains("permission entry"))
        .collect();
    assert_eq!(
        perm_fixes.len(),
        1,
        "expected 1 per-entry permission fix (only id-token: write), got: {:?}",
        result.fixes
    );
}

#[test]
fn test_wrd730_persist_credentials_inserts_inside_existing_with_block() {
    // Regression test for the bug where the look-ahead loop's break condition
    // was `next_indent <= leading`, which terminated as soon as it saw an
    // existing sibling `with:` block at the same indent as `uses:`. The fixer
    // would then fall into the "create a new with: block" branch and emit a
    // duplicate `with:` at the wrong indent. With the fix, the loop scans
    // through the existing `with:` block and inserts `persist-credentials: false`
    // INSIDE it instead of creating a duplicate.
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout\n        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n        with:\n          fetch-depth: 0\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);

    assert!(result.fixed.contains("persist-credentials: false"));

    // There must be EXACTLY ONE `with:` line in the resulting file (the existing
    // one). A duplicate would be a regression.
    let with_count = result.fixed.lines().filter(|l| l.trim() == "with:").count();
    assert_eq!(
        with_count, 1,
        "expected exactly 1 `with:` block, got {} in:\n{}",
        with_count, result.fixed
    );

    // persist-credentials and fetch-depth should sit at the same indent
    // (they're siblings inside the same `with:` block).
    let persist_line = result
        .fixed
        .lines()
        .find(|l| l.contains("persist-credentials"))
        .expect("persist-credentials line missing");
    let fetch_line = result
        .fixed
        .lines()
        .find(|l| l.contains("fetch-depth"))
        .expect("fetch-depth line missing");
    let persist_indent = persist_line.len() - persist_line.trim_start().len();
    let fetch_indent = fetch_line.len() - fetch_line.trim_start().len();
    assert_eq!(
        persist_indent, fetch_indent,
        "persist-credentials and fetch-depth should be siblings at the same indent"
    );
}

#[test]
fn test_wrd730_persist_credentials_creates_with_block_if_missing() {
    // When the checkout step has no `with:` block at all, the fixer should
    // create one at the correct indentation: `with:` is a SIBLING of `uses:`
    // (same indent), and `persist-credentials: false` sits two columns deeper.
    let yaml = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout\n        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);

    assert!(result.fixed.contains("persist-credentials: false"));

    let uses_line = result
        .fixed
        .lines()
        .find(|l| l.contains("uses: actions/checkout"))
        .expect("uses line missing");
    let with_line = result
        .fixed
        .lines()
        .find(|l| l.trim() == "with:")
        .expect("with line missing");
    let uses_indent = uses_line.len() - uses_line.trim_start().len();
    let with_indent = with_line.len() - with_line.trim_start().len();
    assert_eq!(
        uses_indent, with_indent,
        "with: should be a sibling of uses: (same indent)"
    );
}

#[test]
fn test_fixers_always_emit_trailing_newline() {
    // Regression test for the bug where fix_unpin_actions / fix_expression_injection
    // / fix_checkout_persist_credentials called result_lines.join("\n") without
    // re-appending the trailing newline, producing files with the GitHub red
    // "no newline at end of file" indicator.
    //
    // Case A: source ends with \n -> output also ends with \n (preservation)
    let with_nl = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result_a = fix_workflow(&wf(with_nl), None);
    assert!(result_a.fixed.ends_with('\n'));

    // Case B: source does NOT end with \n -> output STILL ends with \n
    // (the fixer normalizes for free)
    let no_nl = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi";
    let result_b = fix_workflow(&wf(no_nl), None);
    assert!(
        result_b.fixed.ends_with('\n'),
        "fixer should normalize trailing newline even on input that lacks one; got tail: {:?}",
        &result_b.fixed[result_b.fixed.len().saturating_sub(20)..]
    );
}

#[test]
fn test_wrd842_adds_concurrency_block() {
    // Block-form `on:` with push trigger. WRD-842 (and the fixer, post the
    // fixer/scanner consistency commit) only fires when the workflow is
    // triggered by `push` or `pull_request` in the line-start form. The
    // earlier inline-form fixture (`on: push`) was masking the fact that
    // both rule and fixer have a known blind spot for the inline form.
    let yaml = "name: CI\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(result.fixed.contains("concurrency:"));
    assert!(result
        .fixed
        .contains("group: ${{ github.workflow }}-${{ github.ref }}"));
    assert!(result.fixed.contains("cancel-in-progress: true"));
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("concurrency")));
}

#[test]
fn test_wrd842_skips_when_concurrency_present() {
    let yaml = "name: CI\non:\n  push:\n    branches: [main]\nconcurrency:\n  group: foo\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(!result
        .fixes
        .iter()
        .any(|f| f.description.contains("concurrency")));
}

#[test]
fn test_wrd842_skips_when_only_workflow_dispatch() {
    // Manual-trigger-only workflow: WRD-842 doesn't fire (no push or
    // pull_request trigger), so the fixer must NOT add concurrency either.
    // Regression test for the fixer/scanner consistency commit that
    // tightened fix_missing_concurrency to require WRD-842's trigger
    // conditions.
    let yaml = "name: Deploy\non:\n  workflow_dispatch:\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploying\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(
        !result.fixed.contains("concurrency:"),
        "fixer should not add concurrency to a workflow_dispatch-only workflow because WRD-842 wouldn't have flagged it"
    );
    assert!(!result
        .fixes
        .iter()
        .any(|f| f.description.contains("concurrency")));
}

#[test]
fn test_wrd101_fixer_extracts_tainted_github_event_path() {
    // `github.event.pull_request.title` IS in WRD-101's TAINTED_EXPRESSIONS
    // list, so the fixer should rewrite it to an env var.
    let yaml = "name: CI\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(
        result.fixed.contains("env:"),
        "expected env: block, got:\n{}",
        result.fixed
    );
    assert!(result
        .fixes
        .iter()
        .any(|f| f.description.contains("Extracted")));
}

#[test]
fn test_wrd101_fixer_skips_safe_github_event_path() {
    // `github.event.repository.name` is NOT in TAINTED_EXPRESSIONS (it's a
    // safe value, GitHub validates repo names). The fixer must NOT rewrite
    // it. Regression test for the fixer/scanner consistency commit that
    // tightened fix_expression_injection to only rewrite expressions
    // WRD-101 would actually flag.
    let yaml = "name: CI\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.repository.name }}\"\n";
    let result = fix_workflow(&wf(yaml), None);
    assert!(
        !result.fixed.contains("REPOSITORY_NAME"),
        "fixer should not extract a safe github.event.* path that no rule flags"
    );
    assert!(
        !result
            .fixes
            .iter()
            .any(|f| f.description.contains("Extracted") && f.description.contains("expression")),
        "fixer should not emit an Extracted-expression fix for a safe path"
    );
}
