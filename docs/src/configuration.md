# Configuration (`.warden.toml`)

Warden reads an optional `.warden.toml` file from the scan target directory
(or any parent, walking up toward the filesystem root). The file has just
two fields: `disabled_rules` and `severity_overrides`.

## Example

```toml
# Rule IDs to disable entirely. These rules will not run and their
# findings will not appear in any output.
disabled_rules = ["WRD-710", "WRD-201"]

# Override the severity reported for a given rule. Valid values:
# "critical", "high", "medium", "low".
[severity_overrides]
"WRD-322" = "low"
"WRD-101" = "critical"
```

## Fields

| Field | Type | Description |
| --- | --- | --- |
| `disabled_rules` | `string[]` | Rule IDs to skip. Matched exactly against `WRD-NNN`. |
| `severity_overrides` | `{ string: string }` | Map rule ID to a replacement severity. |

## Lookup behavior

Warden starts at the scan target path and walks upward looking for a
`.warden.toml`. The first one it finds wins; parent configs are not merged.
Remote scans (`warden scan owner/repo`) do not read any local config.

## Interaction with `--fail-on`

Severity overrides are applied **before** the `--fail-on` threshold is
evaluated, so downgrading a rule to `low` will prevent it from failing CI
when `--fail-on high` is in effect.
