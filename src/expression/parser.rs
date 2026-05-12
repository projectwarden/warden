use std::fmt;

use super::ast::{BinaryOp, Expr, Literal, UnaryOp};
use super::lexer::{tokenize, LexError, Token};

#[derive(Debug, Clone)]
pub enum ParseError {
    Lex(LexError),
    Unexpected { found: String, expected: String },
    Eof { expected: String },
    Trailing { token: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Lex(l) => write!(f, "{l}"),
            ParseError::Unexpected { found, expected } => {
                write!(f, "expected {expected}, got {found}")
            }
            ParseError::Eof { expected } => {
                write!(f, "unexpected end of input, expected {expected}")
            }
            ParseError::Trailing { token } => write!(f, "trailing token {token}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::Lex(e)
    }
}

/// Parse a full GitHub Actions expression (the contents of `${{ ... }}`).
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let toks = tokenize(input)?;
    let mut p = Parser::new(&toks);
    let expr = p.parse_expr()?;
    if p.pos != toks.len() {
        return Err(ParseError::Trailing {
            token: token_name(&toks[p.pos]),
        });
    }
    Ok(expr)
}

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(toks: &'a [Token]) -> Self {
        Self { toks, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, want: &Token) -> bool {
        if self.peek() == Some(want) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, want: &Token, label: &str) -> Result<(), ParseError> {
        if !self.eat(want) {
            return Err(self.unexpected(label));
        }
        Ok(())
    }

    fn unexpected(&self, expected: &str) -> ParseError {
        match self.toks.get(self.pos) {
            Some(t) => ParseError::Unexpected {
                found: token_name(t),
                expected: expected.to_string(),
            },
            None => ParseError::Eof {
                expected: expected.to_string(),
            },
        }
    }

    // expr := or_expr
    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_or()
    }

    // or := and ('||' and)*
    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while self.eat(&Token::OrOr) {
            let right = self.parse_and()?;
            left = Expr::Binary(BinaryOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // and := not ('&&' not)*
    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while self.eat(&Token::AndAnd) {
            let right = self.parse_not()?;
            left = Expr::Binary(BinaryOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // not := '!' not | comparison
    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if self.eat(&Token::Bang) {
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnaryOp::Not, Box::new(inner)));
        }
        self.parse_comparison()
    }

    // comparison := primary (cmp_op primary)?
    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_primary()?;
        let op = match self.peek() {
            Some(Token::Eq) => Some(BinaryOp::Eq),
            Some(Token::NotEq) => Some(BinaryOp::NotEq),
            Some(Token::Lt) => Some(BinaryOp::Lt),
            Some(Token::LtEq) => Some(BinaryOp::LtEq),
            Some(Token::Gt) => Some(BinaryOp::Gt),
            Some(Token::GtEq) => Some(BinaryOp::GtEq),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let right = self.parse_primary()?;
            return Ok(Expr::Binary(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }

    // primary := literal | call_or_path | '(' expr ')'
    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.bump();
                let inner = self.parse_expr()?;
                self.expect(&Token::RParen, "')'")?;
                self.parse_postfix(inner)
            }
            Some(Token::Number(n)) => {
                let v = *n;
                self.bump();
                Ok(Expr::Literal(Literal::Number(v)))
            }
            Some(Token::String(s)) => {
                let v = s.clone();
                self.bump();
                Ok(Expr::Literal(Literal::String(v)))
            }
            Some(Token::True) => {
                self.bump();
                Ok(Expr::Literal(Literal::Bool(true)))
            }
            Some(Token::False) => {
                self.bump();
                Ok(Expr::Literal(Literal::Bool(false)))
            }
            Some(Token::Null) => {
                self.bump();
                Ok(Expr::Literal(Literal::Null))
            }
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.bump();
                if self.peek() == Some(&Token::LParen) {
                    self.bump();
                    let args = self.parse_call_args()?;
                    self.expect(&Token::RParen, "')'")?;
                    let call = Expr::Call(name, args);
                    self.parse_postfix(call)
                } else {
                    let base = Expr::Identifier(name);
                    self.parse_postfix(base)
                }
            }
            _ => Err(self.unexpected("expression")),
        }
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut args = Vec::new();
        if self.peek() == Some(&Token::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        Ok(args)
    }

    // postfix := ( '.' ident | '.' '*' | '[' expr ']' )*
    fn parse_postfix(&mut self, mut base: Expr) -> Result<Expr, ParseError> {
        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    self.bump();
                    match self.peek() {
                        Some(Token::Star) => {
                            self.bump();
                            base = Expr::Star(Box::new(base));
                        }
                        Some(Token::Ident(name)) => {
                            let name = name.clone();
                            self.bump();
                            base = Expr::Field(Box::new(base), name);
                        }
                        _ => return Err(self.unexpected("identifier or '*' after '.'")),
                    }
                }
                Some(Token::LBracket) => {
                    self.bump();
                    let idx = self.parse_expr()?;
                    self.expect(&Token::RBracket, "']'")?;
                    base = Expr::Index(Box::new(base), Box::new(idx));
                }
                _ => break,
            }
        }
        Ok(base)
    }
}

fn token_name(t: &Token) -> String {
    match t {
        Token::Number(n) => format!("number {n}"),
        Token::String(s) => format!("string '{s}'"),
        Token::True => "true".into(),
        Token::False => "false".into(),
        Token::Null => "null".into(),
        Token::Ident(s) => format!("identifier '{s}'"),
        Token::LParen => "'('".into(),
        Token::RParen => "')'".into(),
        Token::LBracket => "'['".into(),
        Token::RBracket => "']'".into(),
        Token::Dot => "'.'".into(),
        Token::Star => "'*'".into(),
        Token::Comma => "','".into(),
        Token::Eq => "'=='".into(),
        Token::NotEq => "'!='".into(),
        Token::Lt => "'<'".into(),
        Token::LtEq => "'<='".into(),
        Token::Gt => "'>'".into(),
        Token::GtEq => "'>='".into(),
        Token::AndAnd => "'&&'".into(),
        Token::OrOr => "'||'".into(),
        Token::Bang => "'!'".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::ast::PathSeg;
    use super::*;

    #[test]
    fn simple_path() {
        let e = parse("github.event.issue.body").unwrap();
        let path = e.as_path().unwrap();
        assert_eq!(
            path,
            vec![
                PathSeg::Root("github".into()),
                PathSeg::Field("event".into()),
                PathSeg::Field("issue".into()),
                PathSeg::Field("body".into()),
            ]
        );
    }

    #[test]
    fn star_in_path() {
        let e = parse("github.event.commits.*.message").unwrap();
        let path = e.as_path().unwrap();
        assert!(path.contains(&PathSeg::Star));
    }

    #[test]
    fn function_call_with_tainted_arg() {
        let e = parse("format('hi {0}', github.event.issue.body)").unwrap();
        // The whole expr is NOT a path (it's a call).
        assert!(e.as_path().is_none());
        // But all_paths picks up the embedded path.
        let paths = e.all_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0][0], PathSeg::Root("github".into()));
    }

    #[test]
    fn comparison_with_two_paths() {
        let e = parse("github.actor == 'octocat'").unwrap();
        let paths = e.all_paths();
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn logical_and_or() {
        let e = parse("contains(secrets.GITHUB_TOKEN, 'ghp_') || env.DEBUG == 'true'").unwrap();
        let paths = e.all_paths();
        // secrets.GITHUB_TOKEN, env.DEBUG
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn unary_not() {
        let e = parse("!cancelled()").unwrap();
        match e {
            Expr::Unary(UnaryOp::Not, inner) => match *inner {
                Expr::Call(name, _) => assert_eq!(name, "cancelled"),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn parens() {
        let e = parse("(github.actor == 'a') && (github.event.action == 'opened')").unwrap();
        // Two paths embedded.
        assert_eq!(e.all_paths().len(), 2);
    }

    #[test]
    fn computed_index() {
        let e = parse("matrix.os[0]").unwrap();
        let path = e.as_path().unwrap();
        assert!(matches!(path.last(), Some(PathSeg::IndexNum(0))));
    }

    #[test]
    fn string_index() {
        let e = parse("github.event['pull_request'].body").unwrap();
        let path = e.as_path().unwrap();
        assert!(path
            .iter()
            .any(|s| matches!(s, PathSeg::IndexString(k) if k == "pull_request")));
    }

    #[test]
    fn precedence_and_over_or() {
        let e = parse("a || b && c").unwrap();
        // `b && c` should bind tighter, so it's `a || (b && c)`.
        match e {
            Expr::Binary(BinaryOp::Or, _, right) => match *right {
                Expr::Binary(BinaryOp::And, _, _) => (),
                _ => panic!("expected AND on the right"),
            },
            _ => panic!("expected OR at the top"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("github..event").is_err());
        assert!(parse("github.").is_err());
        assert!(parse("(unclosed").is_err());
        assert!(parse("foo bar").is_err()); // trailing token
    }
}
