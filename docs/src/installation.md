# Installation

## cargo install

Requires Rust 1.70 or later. Install via crates.io:

```bash
cargo install wardenscan
```

The binary is installed as `warden` in `~/.cargo/bin/`. Ensure that directory is in your `PATH`.

Verify the installation:

```bash
warden --version
```

## Pre-built Binaries

Pre-built binaries for Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64) are available on the [GitHub Releases](https://github.com/projectwarden/warden/releases) page.

Download, extract, and place the binary in a directory on your `PATH`:

```bash
# Linux x86_64 example
curl -Lo warden.tar.gz https://github.com/projectwarden/warden/releases/latest/download/warden-linux-x86_64.tar.gz
tar xf warden.tar.gz
sudo mv warden /usr/local/bin/
```

## Docker

A minimal Docker image is available:

```bash
docker pull ghcr.io/projectwarden/warden:latest
```

Run a scan by mounting your repository:

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/projectwarden/warden:latest scan /repo
```

To output SARIF:

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/projectwarden/warden:latest scan /repo --format sarif > results.sarif
```

## GitHub Action

Add warden to any workflow to scan on every push and pull request. See the [GitHub Action guide](./guides/github-action.md) for full configuration.

```yaml
- name: Run warden
  uses: projectwarden/warden@v1
  with:
    path: .github/workflows
    fail-on: high
```

## Updating

```bash
cargo install wardenscan --force
```

Or pull the latest Docker image:

```bash
docker pull ghcr.io/projectwarden/warden:latest
```
