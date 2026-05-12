# Rules Overview

Warden includes 53 detection rules organized into eight categories. Rules are identified by a code prefixed with `WRD-`.

## Rule Numbering

The hundreds digit indicates the category:

| Prefix | Category | Rules |
|--------|----------|-------|
| 1xx | [Injection](./injection.md) | WRD-101, WRD-110 to WRD-113, WRD-130 |
| 2xx | [Triggers](./triggers.md) | WRD-201 to WRD-203 |
| 3xx | [Supply Chain](./supply-chain.md) | WRD-301, WRD-302, WRD-310, WRD-311, WRD-313, WRD-314, WRD-324, WRD-331 to WRD-333, WRD-335, WRD-345 |
| 4xx | [Permissions](./permissions.md) | WRD-421, WRD-422, WRD-424, WRD-440 |
| 5xx | [AI Security](./ai-security.md) | WRD-510, WRD-511, WRD-521, WRD-522, WRD-525, WRD-526, WRD-527, WRD-540 |
| 6xx | [Steganography](./steganography.md) | WRD-602, WRD-621 |
| 7xx | [Integrity](./integrity.md) | WRD-701, WRD-712, WRD-714, WRD-715, WRD-721 to WRD-723, WRD-730 |
| 8xx | [Logic](./logic.md) | WRD-801, WRD-802, WRD-810 to WRD-812, WRD-815 to WRD-817, WRD-823 to WRD-825, WRD-830, WRD-840 to WRD-843 |

## Severity Encoding

Severity is encoded in the last two digits of the rule number:

| Last two digits | Severity |
|-----------------|----------|
| X01 - X09 | Critical |
| X10 - X19 | High |
| X20 - X29 | Medium |
| X30 - X39 | Low |
| X40 - X49 | Info |

Examples:
- `WRD-101`: Injection, Critical (01)
- `WRD-110`: Injection, High (10)
- `WRD-311`: Supply Chain, High (11) // third-party unpinned actions
- `WRD-830`: Logic, Low (30)
- `WRD-842`: Logic, Info (42)

## Severity Definitions

**Critical** - Direct code execution, secret exfiltration, or full repository compromise possible. Fix immediately. Block merges.

**High** - Significant attack surface with likely exploitability under common conditions. Fix before merge.

**Medium** - Increased risk that requires specific conditions to exploit, or defense-in-depth concern. Fix in near term.

**Low** - Minor hardening gap or best-practice deviation. Address when convenient.

**Info** - Informational signal or documentation gap. Does not block; surfaces hygiene improvements.

## Suppressing Rules

Suppress rules globally via `.warden.toml` in the repository root (or any
parent directory of the scan target). The config file has just two fields:

```toml
# Suppress specific rules
disabled_rules = ["WRD-730", "WRD-840"]

# Override severities
[severity_overrides]
"WRD-332" = "info"
```

`disabled_rules` removes those rule IDs from every scan. There is no
per-file suppression and no category-level toggle in v1.0.

## Custom Severity Overrides

Use the `[severity_overrides]` table to reclassify a rule's findings before
the `--fail-on` threshold is applied. Severity values must be one of
`critical`, `high`, `medium`, `low`, or `info`:

```toml
[severity_overrides]
"WRD-525" = "high"
"WRD-723" = "low"
```
