use crate::rules::{line_number_at_offset, Finding, Rule};
use crate::scanner::Workflow;

/// WRD-601: Unicode steganography.
/// Detects invisible Unicode characters in workflow files that could hide
/// malicious commands or alter visible behavior.
pub struct Wrd601;

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

impl Rule for Wrd601 {
    fn id(&self) -> &str {
        "WRD-601"
    }

    fn name(&self) -> &str {
        "Unicode Steganography"
    }

    fn severity(&self) -> &str {
        "critical"
    }

    fn description(&self) -> &str {
        "Invisible Unicode characters detected in workflow file. These can hide \
         malicious commands, alter string comparisons, or use bidirectional text \
         overrides to disguise code."
    }

    fn check(&self, workflow: &Workflow) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = &workflow.content;

        for (i, ch) in content.char_indices() {
            for &(invisible_char, name) in INVISIBLE_CHARS {
                if ch == invisible_char {
                    // Skip BOM at very start of file
                    if invisible_char == '\u{FEFF}' && i == 0 {
                        continue;
                    }

                    let line = line_number_at_offset(content, i);
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
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
                        file: workflow.path.clone(),
                        line,
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
