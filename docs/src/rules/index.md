# Rules Overview

Warden includes 53 detection rules organized into eight categories. Rules are identified by a code prefixed with `WRD-`.

## Rule Numbering

The hundreds digit indicates the category:

| Prefix | Category | Rules |
|--------|----------|-------|
| 1xx | [Injection](./injection.md) | WRD-101, WRD-110 to WRD-113, WRD-120 |
| 2xx | [Triggers](./triggers.md) | WRD-201 to WRD-203 |
| 3xx | [Supply Chain](./supply-chain.md) | WRD-301, WRD-302, WRD-310, WRD-320 to WRD-327 |
| 4xx | [Permissions](./permissions.md) | WRD-420 to WRD-422, WRD-424 |
| 5xx | [AI Security](./ai-security.md) | WRD-510, WRD-511, WRD-520, WRD-521, WRD-525 |
| 6xx | [Steganography](./steganography.md) | WRD-601, WRD-602 |
| 7xx | [Integrity](./integrity.md) | WRD-701, WRD-710 to WRD-714, WRD-720 |
| 8xx | [Logic](./logic.md) | WRD-801, WRD-810 to WRD-812, WRD-820 to WRD-828, WRD-831, WRD-833 |

## Severity Encoding

Severity is encoded in the last two digits of the rule number:

| Last two digits | Severity |
|-----------------|----------|
| X01 - X09 | Critical |
| X10 - X19 | High |
| X20 - X29 | Medium |
| X30 - X39 | Low |

Examples:
- `WRD-101`: Injection, Critical (01)
- `WRD-110`: Injection, High (10)
- `WRD-320`: Supply Chain, Medium (20) // scanner promotes this to High when calculating fail-on threshold
- `WRD-831`: Logic, Low (31)

## Severity Definitions

**Critical** - Direct code execution, secret exfiltration, or full repository compromise possible. Fix immediately. Block merges.

**High** - Significant attack surface with likely exploitability under common conditions. Fix before merge.

**Medium** - Increased risk that requires specific conditions to exploit, or defense-in-depth concern. Fix in near term.

**Low** - Minor hardening gap, informational, or best-practice deviation. Address when convenient.

## Suppressing Rules

Suppress rules globally via `.warden.toml` in the repository root (or any
parent directory of the scan target). The config file has just two fields:

```toml
# Suppress specific rules
disabled_rules = ["WRD-710", "WRD-826"]

# Override severities
[severity_overrides]
"WRD-322" = "low"
```

`disabled_rules` removes those rule IDs from every scan. There is no
per-file suppression and no category-level toggle in v1.0.

## Custom Severity Overrides

Use the `[severity_overrides]` table to reclassify a rule's findings before
the `--fail-on` threshold is applied. Severity values must be one of
`critical`, `high`, `medium`, or `low`:

```toml
[severity_overrides]
"WRD-525" = "high"
"WRD-720" = "low"
```
