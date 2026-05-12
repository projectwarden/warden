use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    Number(f64),
    String(String),
    True,
    False,
    Null,

    // Identifiers / context names
    Ident(String),

    // Punctuation
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    Star,
    Comma,

    // Operators
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    AndAnd,
    OrOr,
    Bang,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lex error at {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for LexError {}

pub fn tokenize(src: &str) -> Result<Vec<Token>, LexError> {
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];

        // Whitespace
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Punctuation
        match b {
            b'(' => {
                out.push(Token::LParen);
                i += 1;
                continue;
            }
            b')' => {
                out.push(Token::RParen);
                i += 1;
                continue;
            }
            b'[' => {
                out.push(Token::LBracket);
                i += 1;
                continue;
            }
            b']' => {
                out.push(Token::RBracket);
                i += 1;
                continue;
            }
            b'.' => {
                out.push(Token::Dot);
                i += 1;
                continue;
            }
            b'*' => {
                out.push(Token::Star);
                i += 1;
                continue;
            }
            b',' => {
                out.push(Token::Comma);
                i += 1;
                continue;
            }
            _ => {}
        }

        // Multi-byte operators
        if b == b'=' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            out.push(Token::Eq);
            i += 2;
            continue;
        }
        if b == b'!' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            out.push(Token::NotEq);
            i += 2;
            continue;
        }
        if b == b'<' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                out.push(Token::LtEq);
                i += 2;
            } else {
                out.push(Token::Lt);
                i += 1;
            }
            continue;
        }
        if b == b'>' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                out.push(Token::GtEq);
                i += 2;
            } else {
                out.push(Token::Gt);
                i += 1;
            }
            continue;
        }
        if b == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&' {
            out.push(Token::AndAnd);
            i += 2;
            continue;
        }
        if b == b'|' && i + 1 < bytes.len() && bytes[i + 1] == b'|' {
            out.push(Token::OrOr);
            i += 2;
            continue;
        }
        if b == b'!' {
            out.push(Token::Bang);
            i += 1;
            continue;
        }

        // String literal: single-quoted, '' as escaped quote.
        // Walks UTF-8 chars, not bytes, so multi-byte chars in the body
        // are preserved (e.g. `'héllo'`).
        if b == b'\'' {
            let start = i;
            i += 1;
            let mut s = String::new();
            loop {
                if i >= bytes.len() {
                    return Err(LexError {
                        message: "unterminated string".into(),
                        offset: start,
                    });
                }
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        s.push('\'');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                // Decode one UTF-8 char from `bytes[i..]`.
                let rest = match std::str::from_utf8(&bytes[i..]) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(LexError {
                            message: "invalid UTF-8 in string literal".into(),
                            offset: i,
                        });
                    }
                };
                let ch = rest.chars().next().unwrap();
                s.push(ch);
                i += ch.len_utf8();
            }
            out.push(Token::String(s));
            continue;
        }

        // Number literal: -?digits with optional fractional part.
        // Note: a leading '-' is NOT consumed here; GHA treats it as a unary
        // op only in expressions. Real workflows don't really use negatives.
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'.' {
                let mut j = i + 1;
                if j < bytes.len() && bytes[j].is_ascii_digit() {
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    i = j;
                }
            }
            let text = std::str::from_utf8(&bytes[start..i]).unwrap();
            let value: f64 = text.parse().map_err(|_| LexError {
                message: format!("invalid number literal '{text}'"),
                offset: start,
            })?;
            out.push(Token::Number(value));
            continue;
        }

        // Identifier or keyword.
        if is_ident_start(b) {
            let start = i;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let text = std::str::from_utf8(&bytes[start..i]).unwrap();
            let tok = match text {
                "true" => Token::True,
                "false" => Token::False,
                "null" => Token::Null,
                _ => Token::Ident(text.to_string()),
            };
            out.push(tok);
            continue;
        }

        return Err(LexError {
            message: format!("unexpected character {:?}", b as char),
            offset: i,
        });
    }

    Ok(out)
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_idents() {
        let toks = tokenize("github.event.issue.body").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Ident("github".into()),
                Token::Dot,
                Token::Ident("event".into()),
                Token::Dot,
                Token::Ident("issue".into()),
                Token::Dot,
                Token::Ident("body".into()),
            ]
        );
    }

    #[test]
    fn string_escapes() {
        let toks = tokenize("'it''s here'").unwrap();
        assert_eq!(toks, vec![Token::String("it's here".into())]);
    }

    #[test]
    fn comparison_operators() {
        let toks = tokenize("a == b && !c != d").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Ident("a".into()),
                Token::Eq,
                Token::Ident("b".into()),
                Token::AndAnd,
                Token::Bang,
                Token::Ident("c".into()),
                Token::NotEq,
                Token::Ident("d".into()),
            ]
        );
    }

    #[test]
    fn numbers_and_bools() {
        let toks = tokenize("1 2.5 true false null").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Number(1.0),
                Token::Number(2.5),
                Token::True,
                Token::False,
                Token::Null,
            ]
        );
    }

    #[test]
    fn star_token() {
        let toks = tokenize("github.event.commits.*.message").unwrap();
        assert!(toks.contains(&Token::Star));
    }

    #[test]
    fn string_with_multibyte_chars_preserved() {
        // Regression: cast-to-char on a UTF-8 lead byte produced garbage.
        let toks = tokenize("'héllo ☕'").unwrap();
        assert_eq!(toks, vec![Token::String("héllo ☕".into())]);
    }

    #[test]
    fn string_with_only_multibyte() {
        let toks = tokenize("'☕'").unwrap();
        assert_eq!(toks, vec![Token::String("☕".into())]);
    }
}
