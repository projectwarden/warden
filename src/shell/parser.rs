use std::cell::RefCell;

use tree_sitter::{Node, Parser, Tree};

thread_local! {
    /// One bash parser per thread, reused across every `run:` block in the
    /// scan. Allocating a fresh `Parser` + calling `set_language` once per
    /// run block was a measurable perf cost on large monorepos (flagged by
    /// the foundation review).
    static BASH_PARSER: RefCell<Option<Parser>> = const { RefCell::new(None) };
}

/// Parse a bash script into a tree-sitter [`Tree`].
///
/// Returns `None` if tree-sitter is unable to set the language (in practice
/// this never happens for the ABI-matched grammar, but we handle it
/// defensively rather than panicking from a rule).
pub fn parse_bash(source: &str) -> Option<Tree> {
    BASH_PARSER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut parser = Parser::new();
            parser.set_language(&tree_sitter_bash::language()).ok()?;
            *slot = Some(parser);
        }
        slot.as_mut().and_then(|p| p.parse(source, None))
    })
}

/// Walk every descendant node of `root` (depth-first, pre-order) including
/// `root` itself. Returned via callback to avoid lifetime juggling on a
/// borrowed cursor.
pub fn walk<'a, F>(root: Node<'a>, mut visit: F)
where
    F: FnMut(Node<'a>),
{
    fn go<'a, F: FnMut(Node<'a>)>(n: Node<'a>, visit: &mut F) {
        visit(n);
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            go(child, visit);
        }
    }
    go(root, &mut visit);
}
