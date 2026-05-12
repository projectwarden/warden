//! Semantic queries against parsed bash scripts.
//!
//! Currently provides:
//! - [`find_special_file_writes`] for `>> $GITHUB_ENV`, `>> $GITHUB_PATH`,
//!   `>> $GITHUB_OUTPUT` (and the unbraced `${GITHUB_*}` forms). This is
//!   the syntactic shape that injection rules WRD-101, 110, 111, 112, 120
//!   currently grep for; tree-sitter version eliminates false positives on
//!   `echo "x >> $GITHUB_ENV"` (string literal) etc.

use tree_sitter::Node;

use super::parser::walk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubSpecialFile {
    Env,
    Path,
    Output,
}

impl GithubSpecialFile {
    pub fn name(&self) -> &'static str {
        match self {
            GithubSpecialFile::Env => "GITHUB_ENV",
            GithubSpecialFile::Path => "GITHUB_PATH",
            GithubSpecialFile::Output => "GITHUB_OUTPUT",
        }
    }

    fn from_var_name(s: &str) -> Option<Self> {
        match s {
            "GITHUB_ENV" => Some(Self::Env),
            "GITHUB_PATH" => Some(Self::Path),
            "GITHUB_OUTPUT" => Some(Self::Output),
            _ => None,
        }
    }
}

/// One identified write to a GitHub Actions special-file destination.
#[derive(Debug, Clone)]
pub struct SpecialFileWrite {
    pub file: GithubSpecialFile,
    /// Byte range of the redirection target node within the original script.
    pub byte_start_in_script: usize,
    pub byte_end_in_script: usize,
}

/// Scan a bash AST and return every redirection that targets `$GITHUB_ENV`,
/// `$GITHUB_PATH`, or `$GITHUB_OUTPUT`.
pub fn find_special_file_writes(root: Node, source: &str) -> Vec<SpecialFileWrite> {
    let mut out = Vec::new();
    walk(root, |n| {
        // tree-sitter-bash uses a `file_redirect` node with a child that is
        // either a `simple_expansion` ($VAR) or `expansion` (${VAR}).
        if n.kind() != "file_redirect" {
            return;
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if let Some(write) = child_destination(child, source) {
                out.push(write);
            }
        }
    });
    out
}

fn child_destination(node: Node, source: &str) -> Option<SpecialFileWrite> {
    match node.kind() {
        "simple_expansion" => {
            // $VARNAME
            // The variable_name child holds the identifier text.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_name" {
                    let text = node_text(child, source)?;
                    if let Some(file) = GithubSpecialFile::from_var_name(text) {
                        return Some(SpecialFileWrite {
                            file,
                            byte_start_in_script: node.start_byte(),
                            byte_end_in_script: node.end_byte(),
                        });
                    }
                }
            }
            None
        }
        "expansion" => {
            // ${VARNAME}
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_name" {
                    let text = node_text(child, source)?;
                    if let Some(file) = GithubSpecialFile::from_var_name(text) {
                        return Some(SpecialFileWrite {
                            file,
                            byte_start_in_script: node.start_byte(),
                            byte_end_in_script: node.end_byte(),
                        });
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    let bytes = source.as_bytes();
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= bytes.len() {
        std::str::from_utf8(&bytes[start..end]).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse_bash;
    use super::*;

    fn writes(script: &str) -> Vec<SpecialFileWrite> {
        let tree = parse_bash(script).expect("parse");
        find_special_file_writes(tree.root_node(), script)
    }

    #[test]
    fn detects_env_redirect() {
        let s = "echo \"FOO=bar\" >> $GITHUB_ENV";
        let w = writes(s);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].file, GithubSpecialFile::Env);
    }

    #[test]
    fn detects_path_braced() {
        let s = "echo \"/usr/local/bin\" >> ${GITHUB_PATH}";
        let w = writes(s);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].file, GithubSpecialFile::Path);
    }

    #[test]
    fn detects_output() {
        let s = "echo \"key=val\" >> $GITHUB_OUTPUT";
        let w = writes(s);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].file, GithubSpecialFile::Output);
    }

    #[test]
    fn ignores_string_literal_mention() {
        // The whole thing is one echo argument; no redirect node.
        let s = "echo 'x >> $GITHUB_ENV is not actually a redirect'";
        let w = writes(s);
        assert!(w.is_empty(), "should not match string-literal mention");
    }

    #[test]
    fn ignores_unrelated_redirects() {
        let s = "echo hi >> /tmp/file";
        let w = writes(s);
        assert!(w.is_empty());
    }

    #[test]
    fn detects_multiple_writes_in_script() {
        let s = "echo a >> $GITHUB_ENV\necho b >> $GITHUB_PATH\necho c >> $GITHUB_OUTPUT";
        let w = writes(s);
        assert_eq!(w.len(), 3);
    }
}
