use crate::rules::{line_number_at_offset, AuditCtx, Rule, RuleFinding, RuleMeta, Severity};
use crate::yamlpath::Span;

/// Suspicious invisible or zero-width Unicode characters.
const INVISIBLE_CHARS: &[(char, &str)] = &[
    ('\u{200B}', "Zero Width Space"),
    ('\u{200C}', "Zero Width Non-Joiner"),
    ('\u{200D}', "Zero Width Joiner"),
    ('\u{200E}', "Left-to-Right Mark"),
    ('\u{200F}', "Right-to-Left Mark"),
    ('\u{202A}', "Left-to-Right Embedding"),
    ('\u{202B}', "Right-to-Left Embedding"),
    ('\u{202C}', "Pop Directional Formatting"),
    ('\u{202D}', "Left-to-Right Override"),
    ('\u{202E}', "Right-to-Left Override"),
    ('\u{2060}', "Word Joiner"),
    ('\u{2061}', "Function Application"),
    ('\u{2062}', "Invisible Times"),
    ('\u{2063}', "Invisible Separator"),
    ('\u{2064}', "Invisible Plus"),
    ('\u{FEFF}', "Zero Width No-Break Space / BOM"),
    ('\u{00AD}', "Soft Hyphen"),
    ('\u{034F}', "Combining Grapheme Joiner"),
    ('\u{061C}', "Arabic Letter Mark"),
    ('\u{2066}', "Left-to-Right Isolate"),
    ('\u{2067}', "Right-to-Left Isolate"),
    ('\u{2068}', "First Strong Isolate"),
    ('\u{2069}', "Pop Directional Isolate"),
    ('\u{FE00}', "Variation Selector-1"),
    ('\u{180E}', "Mongolian Vowel Separator"),
];

// ---------------------------------------------------------------------------
// V2: raw-byte scan of `ctx.loaded.raw`. Invisible unicode chars can appear
// anywhere (comments, names, strings) so there is no useful typed surface
// to walk. Span is line-only since the offending char has no YAML path.
// ---------------------------------------------------------------------------

pub struct Wrd621;

impl Rule for Wrd621 {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: "WRD-621",
            name: "Suspicious Invisible Unicode",
            default_severity: Severity::Medium,
            description: "Invisible Unicode characters detected in workflow file. These can \
                          hide malicious commands, alter string comparisons, or use \
                          bidirectional text overrides to disguise code.",
        }
    }

    fn audit(&self, ctx: &AuditCtx) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let content = &ctx.loaded.raw;

        for (i, ch) in content.char_indices() {
            for &(invisible_char, name) in INVISIBLE_CHARS {
                if ch == invisible_char {
                    // Skip BOM at the very start of the file.
                    if invisible_char == '\u{FEFF}' && i == 0 {
                        continue;
                    }
                    let line = line_number_at_offset(content, i);
                    let ch_end = i + ch.len_utf8();
                    let span = Span::new(i, ch_end, line, 1, line, 1);
                    findings.push(RuleFinding {
                        rule_id: "WRD-621",
                        severity: Severity::Medium,
                        title: format!(
                            "Invisible Unicode character: {} (U+{:04X})",
                            name, invisible_char as u32
                        ),
                        description: format!(
                            "Found invisible Unicode character '{}' (U+{:04X}) at line {}. \
                             Invisible characters can hide malicious commands or alter the \
                             visible meaning of code.",
                            name, invisible_char as u32, line
                        ),
                        primary: span,
                        related: Vec::new(),
                        remediation: "Remove all invisible Unicode characters from workflow \
                                      files. Use a hex editor or 'cat -v' to inspect the file."
                            .to_string(),
                    });
                }
            }
        }

        findings
    }
}
