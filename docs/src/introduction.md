# Introduction

Warden is a static analysis tool for GitHub Actions workflows. It scans `.github/workflows/*.yml` files and reports security vulnerabilities before they reach production.

## What Warden Does

GitHub Actions workflows run with elevated privileges, access secrets, and interact with your supply chain. Misconfigured workflows are a leading source of CI/CD security incidents. Warden catches these issues at the source.

Warden detects:

- **Script injection** via untrusted `github.event` inputs interpolated into `run:` steps
- **Dangerous trigger configurations** like `pull_request_target` combined with checkout of untrusted code
- **Supply chain attacks** via unpinned actions, known-vulnerable actions, impostor commits, and runtime binary fetches
- **Permission and secret misuse** including secrets in run blocks, exfiltration patterns, and debug logging
- **AI-specific risks** like AI config poisoning via fork checkouts and MCP config injection
- **Steganographic payloads** hidden via invisible Unicode characters or IOC patterns (reverse shells, C2 domains)
- **Integrity failures** such as toJSON(secrets) exposure, credential leakage in artifacts, and insecure commands
- **Logic flaws** including self-hosted runners on PRs, confused deputy attacks, cache poisoning, and spoofable bot checks

## Rule Numbering

Rules are grouped by category using hundreds:

| Range | Category |
|-------|----------|
| 100s | Injection |
| 200s | Triggers |
| 300s | Supply Chain |
| 400s | Permissions |
| 500s | AI Security |
| 600s | Steganography |
| 700s | Integrity |
| 800s | Logic |

Severity is encoded in the tens/units digit of the rule number. See [Rules Overview](./rules/index.md) for details.

## Binary and Crate

- Binary name: `warden`
- Crate name: `wardenscan`
- Language: Rust
- Total rules: 53

## Source

Warden is open source. Contributions and rule proposals are welcome via GitHub issues.
