use std::fmt;

/// AST for a GitHub Actions expression (the contents of `${{ ... }}`).
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Literal),
    /// A bare identifier // root context name (`github`, `env`, `secrets`,
    /// `inputs`, `matrix`, `needs`, `vars`, `runner`, `job`, `steps`, ...).
    Identifier(String),
    /// `expr.field`
    Field(Box<Expr>, String),
    /// `expr[expr]` // computed index access.
    Index(Box<Expr>, Box<Expr>),
    /// `expr.*` // wildcard array projection.
    Star(Box<Expr>),
    /// `name(args...)` // function call.
    Call(String, Vec<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    And,
    Or,
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BinaryOp::Eq => "==",
            BinaryOp::NotEq => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::LtEq => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::GtEq => ">=",
            BinaryOp::And => "&&",
            BinaryOp::Or => "||",
        })
    }
}

/// One step in a flattened context path. See [`Expr::as_path`].
#[derive(Debug, Clone, PartialEq)]
pub enum PathSeg {
    Root(String),
    Field(String),
    IndexNum(i64),
    IndexString(String),
    /// Index into the path with a runtime-computed expression. Treated as
    /// a wildcard for taint matching.
    IndexDynamic,
    Star,
}

impl Expr {
    /// Flatten a property/index/star chain rooted at an identifier into a
    /// `Vec<PathSeg>`. Returns `None` if the expression contains anything
    /// other than a pure access chain (e.g. function calls, operators).
    ///
    /// `format(github.event.x, ...)` returns None, but the embedded
    /// `github.event.x` argument can be reached by walking sub-expressions
    /// with [`Expr::all_paths`].
    pub fn as_path(&self) -> Option<Vec<PathSeg>> {
        let mut out = Vec::new();
        fn go(e: &Expr, out: &mut Vec<PathSeg>) -> bool {
            match e {
                Expr::Identifier(s) => {
                    out.push(PathSeg::Root(s.clone()));
                    true
                }
                Expr::Field(inner, name) => {
                    if !go(inner, out) {
                        return false;
                    }
                    out.push(PathSeg::Field(name.clone()));
                    true
                }
                Expr::Index(inner, idx) => {
                    if !go(inner, out) {
                        return false;
                    }
                    let seg = match idx.as_ref() {
                        Expr::Literal(Literal::Number(n)) => PathSeg::IndexNum(*n as i64),
                        Expr::Literal(Literal::String(s)) => PathSeg::IndexString(s.clone()),
                        _ => PathSeg::IndexDynamic,
                    };
                    out.push(seg);
                    true
                }
                Expr::Star(inner) => {
                    if !go(inner, out) {
                        return false;
                    }
                    out.push(PathSeg::Star);
                    true
                }
                _ => false,
            }
        }
        if go(self, &mut out) {
            Some(out)
        } else {
            None
        }
    }

    /// Walk the AST and return every sub-expression that flattens to a
    /// path (i.e. could be a context read). Useful for taint analysis on
    /// expressions wrapped in calls or operators.
    pub fn all_paths(&self) -> Vec<Vec<PathSeg>> {
        let mut out = Vec::new();
        self.collect_paths(&mut out);
        out
    }

    fn collect_paths(&self, out: &mut Vec<Vec<PathSeg>>) {
        if let Some(path) = self.as_path() {
            out.push(path);
            return;
        }
        match self {
            Expr::Call(_, args) => {
                for a in args {
                    a.collect_paths(out);
                }
            }
            Expr::Unary(_, inner) => inner.collect_paths(out),
            Expr::Binary(_, l, r) => {
                l.collect_paths(out);
                r.collect_paths(out);
            }
            Expr::Field(inner, _) | Expr::Star(inner) => inner.collect_paths(out),
            Expr::Index(inner, idx) => {
                inner.collect_paths(out);
                idx.collect_paths(out);
            }
            _ => {}
        }
    }
}

/// Display a path back as a dotted GHA expression for readable diagnostics.
pub fn path_to_string(path: &[PathSeg]) -> String {
    let mut s = String::new();
    for (i, seg) in path.iter().enumerate() {
        match seg {
            PathSeg::Root(r) => s.push_str(r),
            PathSeg::Field(f) => {
                if i > 0 {
                    s.push('.');
                }
                s.push_str(f);
            }
            PathSeg::IndexNum(n) => {
                s.push_str(&format!("[{n}]"));
            }
            PathSeg::IndexString(k) => {
                s.push_str(&format!("['{k}']"));
            }
            PathSeg::IndexDynamic => s.push_str("[*]"),
            PathSeg::Star => s.push_str(".*"),
        }
    }
    s
}
