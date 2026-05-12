#!/usr/bin/env bash
# Scaffold a new warden detection rule end-to-end (Rust side only).
#
# Creates src/rules/wrd<NNN>.rs from a template, inserts the module
# declaration in src/rules/mod.rs and the registry entry in
# src/rules/api.rs at the correct numeric position, and appends a
# positive + negative test pair to the matching tests/rules_*_test.rs
# bucket. Then runs `cargo build` to verify the skeleton compiles.
#
# Does NOT touch docs/src/rules/*.md or web/app/rules/rules-data.ts; the
# script prints a reminder for those so the contributor can finish the
# catalog by hand (see CONTRIBUTING.md).
#
# Does NOT run `cargo test`, stage files, or commit.
#
# Usage:
#   scripts/new-rule.sh <WRD-NNN> "<short human title>"
#
# Examples:
#   scripts/new-rule.sh WRD-215 "Workflow dispatch without input validation"
#   scripts/new-rule.sh 733 "Base64 payload in run step"

set -euo pipefail

if [ "$#" -lt 2 ]; then
    cat >&2 <<'USAGE'
Usage: scripts/new-rule.sh <WRD-NNN> "<short human title>"

Severity is inferred from the last two digits of the id:
    X01-X09 critical, X10-X19 high, X20-X29 medium,
    X30-X39 low,      X40-X49 info.
USAGE
    exit 2
fi

# -------- parse + validate the id --------------------------------------------
RAW_ID="$1"
TITLE="$2"

# Accept "WRD-215", "wrd215", or bare "215".
NUM="${RAW_ID#[Ww][Rr][Dd]-}"
NUM="${NUM#[Ww][Rr][Dd]}"

if ! [[ "$NUM" =~ ^[0-9]+$ ]]; then
    echo "error: could not parse a numeric id from '$RAW_ID'" >&2
    exit 2
fi
if [ "${#NUM}" -ne 3 ]; then
    echo "error: expected a 3-digit id (got $NUM from '$RAW_ID')" >&2
    exit 2
fi

ID_NUM=$((10#$NUM))
if [ "$ID_NUM" -lt 100 ] || [ "$ID_NUM" -gt 899 ]; then
    echo "error: WRD id $NUM is outside the 100-899 range" >&2
    exit 2
fi

CATEGORY_DIGIT="${NUM:0:1}"
SEV_DIGITS=$((10#${NUM:1:2}))

# -------- severity from last two digits --------------------------------------
if   [ "$SEV_DIGITS" -le 9 ];  then SEV_ENUM="Critical"; SEV_LOWER="critical"
elif [ "$SEV_DIGITS" -le 19 ]; then SEV_ENUM="High";     SEV_LOWER="high"
elif [ "$SEV_DIGITS" -le 29 ]; then SEV_ENUM="Medium";   SEV_LOWER="medium"
elif [ "$SEV_DIGITS" -le 39 ]; then SEV_ENUM="Low";      SEV_LOWER="low"
elif [ "$SEV_DIGITS" -le 49 ]; then SEV_ENUM="Info";     SEV_LOWER="info"
else
    echo "error: severity-tier digits ${NUM:1:2} outside 00-49; see CONTRIBUTING.md" >&2
    exit 2
fi

# -------- test bucket --------------------------------------------------------
case "$CATEGORY_DIGIT" in
    1|2) BUCKET="rules_1xx_2xx_test.rs" ;;
    3)   BUCKET="rules_3xx_test.rs" ;;
    4|5|6|7) BUCKET="rules_4xx_7xx_test.rs" ;;
    8)   BUCKET="rules_8xx_test.rs" ;;
    *)   echo "error: no test bucket defined for ${CATEGORY_DIGIT}xx" >&2; exit 2 ;;
esac

# -------- repo-relative paths ------------------------------------------------
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

RULE_FILE="src/rules/wrd${NUM}.rs"
MOD_FILE="src/rules/mod.rs"
API_FILE="src/rules/api.rs"
TEST_FILE="tests/${BUCKET}"
STRUCT="Wrd${NUM}"
RULE_ID="WRD-${NUM}"

# -------- guard against duplicates ------------------------------------------
if [ -e "$RULE_FILE" ]; then
    echo "error: $RULE_FILE already exists; refusing to overwrite" >&2
    exit 1
fi
if grep -q "^pub mod wrd${NUM};" "$MOD_FILE"; then
    echo "error: $MOD_FILE already declares wrd${NUM}" >&2
    exit 1
fi
if grep -q "super::wrd${NUM}::" "$API_FILE"; then
    echo "error: $API_FILE already registers wrd${NUM}" >&2
    exit 1
fi

# -------- render the rule file ----------------------------------------------
cat > "$RULE_FILE" <<RULE_EOF
use crate::rules::{AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

pub struct ${STRUCT};

impl Rule for ${STRUCT} {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "${RULE_ID}",
            name: "${TITLE}",
            default_severity: Severity::${SEV_ENUM},
            description: "TODO: one-sentence description of what is detected and why it is dangerous.",
        }
    }

    fn audit(&self, _ctx: &AuditCtx) -> Vec<RuleFinding> {
        // TODO: detection logic. Remember to consult \`_ctx.provenance\`
        // before flagging anything read via \`\${{ steps.X.outputs.Y }}\`.
        let _ = Span {
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
            byte_start: 0,
            byte_end: 0,
        };
        Vec::new()
    }
}
RULE_EOF

# -------- insert into src/rules/mod.rs at the sorted position ---------------
# The mod.rs layout is: one `pub mod wrdNNN;` per line in numeric order,
# a blank line, then `pub mod aliases;` etc. We insert before the first
# existing module whose number is greater than ours, and as a fallback
# before the `pub mod aliases;` line if we are numerically largest.
python3 - "$MOD_FILE" "$NUM" <<'PY'
import re, sys
path, num = sys.argv[1], int(sys.argv[2])
lines = open(path).read().splitlines(keepends=True)
insert_at = None
for i, line in enumerate(lines):
    m = re.match(r'pub mod wrd(\d+);', line)
    if m and int(m.group(1)) > num:
        insert_at = i
        break
if insert_at is None:
    for i, line in enumerate(lines):
        if line.startswith('pub mod aliases;'):
            insert_at = i
            break
if insert_at is None:
    sys.exit("could not find insertion point in mod.rs")
lines.insert(insert_at, f'pub mod wrd{num:03d};\n')
open(path, 'w').writelines(lines)
PY

# -------- insert into src/rules/api.rs::all_rules() -------------------------
python3 - "$API_FILE" "$NUM" <<'PY'
import re, sys
path, num = sys.argv[1], int(sys.argv[2])
text = open(path).read()
lines = text.splitlines(keepends=True)

# Find the `vec![` line and the closing `]` of all_rules().
start = end = None
for i, line in enumerate(lines):
    if start is None and 'vec![' in line:
        start = i + 1
    elif start is not None and line.strip() == ']':
        end = i
        break
if start is None or end is None:
    sys.exit("could not locate vec![...] body in api.rs")

insert_at = None
for i in range(start, end):
    m = re.search(r'super::wrd(\d+)::', lines[i])
    if m and int(m.group(1)) > num:
        insert_at = i
        break
if insert_at is None:
    insert_at = end

# Match the indentation of the surrounding vec! entries.
indent = re.match(r'\s*', lines[start]).group(0) if start < end else '        '
lines.insert(insert_at, f'{indent}Box::new(super::wrd{num:03d}::Wrd{num:03d}),\n')
open(path, 'w').writelines(lines)
PY

# -------- append positive + negative test stubs to the right bucket ---------
# Use a fairly neutral vulnerable / safe pair so the suite compiles; the
# contributor is expected to replace the YAML with something their
# detection actually catches (the TODO comment points them at it).
cat >> "$TEST_FILE" <<TEST_EOF

// ---------------------------------------------------------------------------
// ${RULE_ID}: ${TITLE}
// ---------------------------------------------------------------------------

#[test]
fn test_wrd${NUM}_todo_vulnerable() {
    // TODO: replace with a fixture your detection actually fires on.
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo todo
"#;
    let findings = audit_with(&wrd${NUM}::${STRUCT}, yaml);
    // The detection logic is still a stub, so no findings are expected
    // yet. Flip this to \`!findings.is_empty()\` once the rule is real.
    assert!(
        findings.is_empty(),
        "${RULE_ID} stub should not fire until detection logic is implemented"
    );
}

#[test]
fn test_wrd${NUM}_todo_safe() {
    let yaml = r#"
name: t
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
"#;
    let findings = audit_with(&wrd${NUM}::${STRUCT}, yaml);
    assert!(
        findings.is_empty(),
        "${RULE_ID} safe fixture must never fire"
    );
}
TEST_EOF

# -------- quick compile check -----------------------------------------------
echo ">>> cargo build (skeleton compile check)"
if ! cargo build --quiet; then
    echo "error: cargo build failed; revert the changes under src/rules and tests/${BUCKET} before retrying" >&2
    exit 1
fi

cat <<DONE

Scaffolded ${RULE_ID} (${SEV_LOWER}):
  new     ${RULE_FILE}
  mod     ${MOD_FILE}        (inserted pub mod wrd${NUM};)
  api     ${API_FILE}        (inserted Box::new(super::wrd${NUM}::${STRUCT}))
  tests   tests/${BUCKET}    (appended positive + negative stubs)

Still TODO by hand (see CONTRIBUTING.md):
  - Fill in the detection logic in ${RULE_FILE}
  - Replace the stub YAML + asserts in tests/${BUCKET}
  - Add a section in docs/src/rules/<category>.md and update docs/src/rules/index.md
  - Append a row to web/app/rules/rules-data.ts (and web/app/page.tsx if
    the rule belongs in the landing-page highlights table)

Then run: cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
DONE
