use crate::lexer::{Span, Token, TokenKind};

/// Cursor-based token stream helper matching Caddy's `caddyfile.Dispenser`.
#[derive(Debug, Clone)]
pub struct Dispenser {
    tokens: Vec<Token>,
    cursor: usize,
    nesting: usize,
}

impl Dispenser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            cursor: 0,
            nesting: 0,
        }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn current(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    pub fn span(&self) -> Span {
        self.current().map(|t| t.span).unwrap_or_default()
    }

    pub fn line(&self) -> usize {
        self.span().line
    }

    pub fn nesting(&self) -> usize {
        self.nesting
    }

    /// Moves forward to the next token. Returns false if EOF reached.
    pub fn next(&mut self) -> bool {
        while self.cursor < self.tokens.len() {
            let tok = &self.tokens[self.cursor];
            match tok.kind {
                TokenKind::Eof => return false,
                TokenKind::BlockOpen => {
                    self.nesting += 1;
                    self.cursor += 1;
                    return true;
                }
                TokenKind::BlockClose => {
                    if self.nesting > 0 {
                        self.nesting -= 1;
                    }
                    self.cursor += 1;
                    return true;
                }
                TokenKind::Newline => {
                    self.cursor += 1;
                }
                TokenKind::Literal(_) => {
                    self.cursor += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Returns the string value of the current token (if it's a literal or brace).
    pub fn val(&self) -> &str {
        if self.cursor == 0 || self.cursor > self.tokens.len() {
            return "";
        }
        match &self.tokens[self.cursor - 1].kind {
            TokenKind::Literal(s) => s.as_str(),
            TokenKind::BlockOpen => "{",
            TokenKind::BlockClose => "}",
            TokenKind::Newline => "\n",
            TokenKind::Eof => "",
        }
    }

    /// Peeks at the next token string without advancing.
    pub fn peek_val(&self) -> Option<&str> {
        let mut idx = self.cursor;
        while idx < self.tokens.len() {
            match &self.tokens[idx].kind {
                TokenKind::Newline => {
                    idx += 1;
                }
                TokenKind::Literal(s) => return Some(s.as_str()),
                TokenKind::BlockOpen => return Some("{"),
                TokenKind::BlockClose => return Some("}"),
                TokenKind::Eof => return None,
            }
        }
        None
    }

    /// Checks if the next non-newline token is on the current line.
    pub fn is_next_on_same_line(&self) -> bool {
        if self.cursor >= self.tokens.len() {
            return false;
        }
        let cur_line = if self.cursor > 0 {
            self.tokens[self.cursor - 1].span.line
        } else {
            1
        };

        if let Some(tok) = self.tokens.get(self.cursor) {
            tok.span.line == cur_line
                && tok.kind != TokenKind::Newline
                && tok.kind != TokenKind::Eof
        } else {
            false
        }
    }

    /// Consumes the next token IF it is on the same line.
    pub fn next_arg(&mut self) -> Option<String> {
        if self.is_next_on_same_line() {
            let tok = &self.tokens[self.cursor];
            match &tok.kind {
                TokenKind::Literal(s) => {
                    let res = s.clone();
                    self.cursor += 1;
                    Some(res)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Consumes all remaining arguments on the current line.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while let Some(arg) = self.next_arg() {
            args.push(arg);
        }
        args
    }

    /// Checks if a block `{` begins next on the current line or following line.
    pub fn next_is_block_open(&self) -> bool {
        let mut idx = self.cursor;
        while idx < self.tokens.len() {
            match &self.tokens[idx].kind {
                TokenKind::Newline => idx += 1,
                TokenKind::BlockOpen => return true,
                _ => return false,
            }
        }
        false
    }
}
