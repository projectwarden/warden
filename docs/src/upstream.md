# Supply chain auditing

`warden upstream` extends warden beyond your own workflow files. It walks
your project's dependency manifests, resolves each direct dependency back to
its source repository on GitHub, and runs the full 53-rule detector against
the workflow files in each of those upstream repos. If one of your
dependencies has a vulnerable CI/CD setup (expression injection, unpinned
third-party actions, cache poisoning, secret exfiltration, etc.) you'll
see it in the audit output.

## Supported manifests

| Ecosystem | File                  | Notes                                    |
| --------- | --------------------- | ---------------------------------------- |
| npm       | `package.json`        | `dependencies` + `devDependencies`       |
| PyPI      | `Pipfile.lock`        | Preferred over `requirements.txt`        |
| PyPI      | `requirements.txt`    | Fallback when no lockfile                |
| Go        | `go.mod`              | Skips `// indirect` unless `--depth 2`   |
| crates.io | `Cargo.toml`          | `[dependencies]` + `[dev-dependencies]`  |

## Usage

```sh
warden upstream <path> \
    [--concurrency N] \
    [--format console|json|sarif|markdown] \
    [--fail-on critical|high|medium|low|none] \
    [--depth 1|2] \
    [--github-token TOKEN]
```

### Examples

```sh
# Audit direct deps in the current directory
warden upstream .

# Shallow transitive walk (deps-of-deps, deduplicated, capped at 500)
warden upstream . --depth 2

# JSON output for pipelines
warden upstream . --format json > audit.json

# CI: exit non-zero if any dep has a high-severity finding
warden upstream . --fail-on high
```

## Performance and rate limits

Workers run in a `std::thread::scope` pool (no tokio) and share the existing
`reqwest::blocking` client. The default concurrency is 8. Each worker sleeps
~100ms between requests to avoid hammering registries.

The GitHub API is the bottleneck: unauthenticated callers get 60 requests per
hour, authenticated ones 5000. Always set `GITHUB_TOKEN` (or `--github-token`)
for anything beyond a handful of deps; warden will warn you if you have more
than 30 deps and no token.

## Limitations

- Only GitHub-hosted source repos are scanned. Packages whose `repository`
  metadata points at GitLab, Bitbucket, or a custom Gitea instance are
  skipped with a stderr warning.
- `--depth 2` is the hard ceiling to prevent combinatorial explosion. Total
  deps across both levels are capped at 500.
- Path-only and git-only Cargo deps (no `version` field) are skipped because
  they can't be resolved through crates.io.
