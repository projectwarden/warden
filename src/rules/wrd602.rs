use regex::Regex;

use crate::rules::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

struct IocPattern {
    pattern: &'static str,
    title: &'static str,
    description: &'static str,
}

const IOC_PATTERNS: &[IocPattern] = &[
    IocPattern {
        pattern: r"(?i)\beval\b.*\bbase64",
        title: "eval with base64 encoding",
        description: "Combination of eval and base64 is commonly used to obfuscate \
                      malicious payloads.",
    },
    IocPattern {
        pattern: r"(?i)\bbase64\s+(?:-d|--decode)\b",
        title: "Base64 decode in workflow",
        description: "Base64 decoding in a workflow may indicate obfuscated commands.",
    },
    IocPattern {
        pattern: r"(?i)\b(?:nc|ncat|netcat)\s+-[a-z]*l",
        title: "Netcat listener",
        description: "A netcat listener suggests a reverse shell or backdoor.",
    },
    IocPattern {
        pattern: r"(?i)/dev/tcp/",
        title: "Bash /dev/tcp reverse shell",
        description: "Use of /dev/tcp/ is a common bash reverse shell technique.",
    },
    IocPattern {
        pattern: r"(?i)\bmkfifo\b.*\b(?:nc|ncat)\b",
        title: "Named pipe with netcat (reverse shell)",
        description: "mkfifo combined with netcat is a known reverse shell pattern.",
    },
    IocPattern {
        pattern: r"(?i)python[23]?\s+-c\s+.*(?:socket|subprocess|import\s+os)",
        title: "Python one-liner with network/process access",
        description: "Python one-liner using socket or subprocess may indicate a reverse shell.",
    },
    IocPattern {
        pattern: r"(?i)\bcurl\b.*\|\s*(?:sh|bash|zsh|python)",
        title: "Pipe curl to shell",
        description: "Piping curl output directly to a shell interpreter allows remote \
                      code execution.",
    },
    IocPattern {
        pattern: r"(?i)\bwget\b.*\|\s*(?:sh|bash|zsh|python)",
        title: "Pipe wget to shell",
        description: "Piping wget output directly to a shell interpreter allows remote \
                      code execution.",
    },
    IocPattern {
        pattern: r"(?i)(?:ngrok|localtunnel|serveo|bore\.pub|localhost\.run)",
        title: "Tunneling service reference",
        description: "Reference to a tunneling service may indicate data exfiltration \
                      or C2 communication.",
    },
    IocPattern {
        pattern: r"(?i)(?:pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|file\.io)",
        title: "Known paste/file sharing service",
        description: "Reference to a paste or file sharing service may indicate \
                      data exfiltration.",
    },
    IocPattern {
        pattern: r"(?i)(?:burpcollaborator\.net|interact\.sh|oastify\.com|canarytokens\.com)",
        title: "Known C2/callback domain",
        description: "Reference to a known out-of-band interaction or C2 domain.",
    },
    IocPattern {
        pattern: r"(?i)\bchmod\s+\+x\b.*&&.*\./",
        title: "Download and execute pattern",
        description: "chmod +x followed by execution suggests a downloaded payload.",
    },
    IocPattern {
        pattern: r"(?i)\bdd\b.*\bif=/dev/",
        title: "dd reading from device",
        description: "Reading raw data from devices may indicate data theft or disk access.",
    },
];

// ---------------------------------------------------------------------------
// V2: raw-text regex scan. IoC patterns can hide in any string, comment,
// or name so there is no single typed surface to walk.
// ---------------------------------------------------------------------------

pub struct Wrd602;

impl Rule for Wrd602 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-602",
            name: "Workflow Embedded IOC",
            default_severity: Severity::Critical,
            description: "Suspicious patterns that may indicate malicious activity, including \
                          obfuscated payloads, reverse shells, and C2 communication.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let content = &ctx.loaded.raw;

        for ioc in IOC_PATTERNS {
            let re = match Regex::new(ioc.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for m in re.find_iter(content) {
                let start = m.start();
                let end = m.end();
                let line = line_number_at_offset(content, start);
                let span = Span::new(start, end, line, 1, line, 1);
                findings.push(RuleFinding {
                    rule_id: "WRD-602",
                    severity: Severity::Critical,
                    title: ioc.title.to_string(),
                    description: ioc.description.to_string(),
                    primary: span,
                    related: Vec::new(),
                    remediation: "Investigate the flagged pattern. If it is not intentional, \
                                  remove it immediately and audit recent changes to the workflow."
                        .to_string(),
                });
            }
        }

        findings
    }
}
