use crate::error::{ParseError, ParseResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Literal(String),
    BlockOpen,  // {
    BlockClose, // }
    Newline,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

pub struct Lexer<'a> {
    _input: &'a str,
    chars: Vec<(usize, char)>, // (byte_offset, char)
    cursor: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let chars: Vec<(usize, char)> = input.char_indices().collect();
        Self {
            _input: input,
            chars,
            cursor: 0,
            line: 1,
            col: 1,
        }
    }

    fn current_span(&self) -> Span {
        Span {
            line: self.line,
            col: self.col,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.cursor).map(|&(_, c)| c)
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.cursor + 1).map(|&(_, c)| c)
    }

    fn advance(&mut self) -> Option<char> {
        if let Some(&(_, c)) = self.chars.get(self.cursor) {
            self.cursor += 1;
            if c == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            Some(c)
        } else {
            None
        }
    }

    /// Tokenizes the entire input into a vector of Tokens.
    pub fn tokenize(&mut self) -> ParseResult<Vec<Token>> {
        let mut tokens = Vec::new();
        let mut last_was_newline = true; // suppress leading newlines

        while let Some(c) = self.peek() {
            // Whitespace (non-newline)
            if c == ' ' || c == '\t' || c == '\r' {
                self.advance();
                continue;
            }

            // Line continuation with backslash \
            if c == '\\' {
                if let Some(next_c) = self.peek_next() {
                    if next_c == '\n' || (next_c == '\r' && self.chars.get(self.cursor + 2).map(|&(_, ch)| ch) == Some('\n')) {
                        self.advance(); // consume \
                        if self.peek() == Some('\r') { self.advance(); }
                        self.advance(); // consume \n
                        continue;
                    }
                }
            }

            // Newline
            if c == '\n' {
                let span = self.current_span();
                self.advance();
                if !last_was_newline {
                    tokens.push(Token {
                        kind: TokenKind::Newline,
                        span,
                    });
                    last_was_newline = true;
                }
                continue;
            }

            // Comments (# to end of line)
            if c == '#' {
                while let Some(nc) = self.peek() {
                    if nc == '\n' {
                        break;
                    }
                    self.advance();
                }
                continue;
            }

            // Block open { (only if standalone, not {placeholder})
            if c == '{' {
                let is_standalone = match self.peek_next() {
                    Some(' ') | Some('\t') | Some('\r') | Some('\n') | None => true,
                    _ => false,
                };
                if is_standalone {
                    let span = self.current_span();
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::BlockOpen,
                        span,
                    });
                    last_was_newline = false;
                    continue;
                }
            }

            // Block close } (only if standalone, not {placeholder})
            if c == '}' {
                let is_standalone = match self.peek_next() {
                    Some(' ') | Some('\t') | Some('\r') | Some('\n') | None => true,
                    _ => false,
                };
                if is_standalone {
                    let span = self.current_span();
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::BlockClose,
                        span,
                    });
                    last_was_newline = false;
                    continue;
                }
            }

            // Double-quoted strings
            if c == '"' {
                let span = self.current_span();
                let lit = self.read_quoted_string()?;
                tokens.push(Token {
                    kind: TokenKind::Literal(lit),
                    span,
                });
                last_was_newline = false;
                continue;
            }

            // Raw backtick strings
            if c == '`' {
                let span = self.current_span();
                let lit = self.read_raw_string()?;
                tokens.push(Token {
                    kind: TokenKind::Literal(lit),
                    span,
                });
                last_was_newline = false;
                continue;
            }

            // Heredoc: <<EOF ... EOF
            if c == '<' && self.peek_next() == Some('<') {
                let span = self.current_span();
                let lit = self.read_heredoc()?;
                tokens.push(Token {
                    kind: TokenKind::Literal(lit),
                    span,
                });
                last_was_newline = false;
                continue;
            }

            // Unquoted literal token
            let span = self.current_span();
            let lit = self.read_unquoted_literal();
            tokens.push(Token {
                kind: TokenKind::Literal(lit),
                span,
            });
            last_was_newline = false;
        }

        // Emit final Newline if needed, then Eof
        if !tokens.is_empty() && tokens.last().map(|t| &t.kind) != Some(&TokenKind::Newline) {
            tokens.push(Token {
                kind: TokenKind::Newline,
                span: self.current_span(),
            });
        }

        tokens.push(Token {
            kind: TokenKind::Eof,
            span: self.current_span(),
        });

        Ok(tokens)
    }

    fn read_quoted_string(&mut self) -> ParseResult<String> {
        let span = self.current_span();
        self.advance(); // consume opening "
        let mut s = String::new();

        while let Some(c) = self.advance() {
            if c == '"' {
                return Ok(s);
            }
            if c == '\\' {
                if let Some(esc) = self.advance() {
                    match esc {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        other => {
                            s.push('\\');
                            s.push(other);
                        }
                    }
                } else {
                    return Err(ParseError::UnexpectedEof("Unterminated escape sequence in string".into()));
                }
            } else {
                s.push(c);
            }
        }

        Err(ParseError::Syntax {
            line: span.line,
            col: span.col,
            message: "Unterminated double-quoted string".into(),
        })
    }

    fn read_raw_string(&mut self) -> ParseResult<String> {
        let span = self.current_span();
        self.advance(); // consume opening `
        let mut s = String::new();

        while let Some(c) = self.advance() {
            if c == '`' {
                return Ok(s);
            }
            s.push(c);
        }

        Err(ParseError::Syntax {
            line: span.line,
            col: span.col,
            message: "Unterminated backtick string".into(),
        })
    }

    fn read_heredoc(&mut self) -> ParseResult<String> {
        let span = self.current_span();
        self.advance(); // <
        self.advance(); // <

        // Read marker (e.g. EOF) until newline
        let mut marker = String::new();
        while let Some(c) = self.peek() {
            if c == '\n' || c == '\r' {
                break;
            }
            marker.push(c);
            self.advance();
        }
        let marker = marker.trim().to_string();
        if marker.is_empty() {
            return Err(ParseError::Syntax {
                line: span.line,
                col: span.col,
                message: "Missing heredoc delimiter after '<<'".into(),
            });
        }

        // Consume newline after marker
        if self.peek() == Some('\r') { self.advance(); }
        if self.peek() == Some('\n') { self.advance(); }

        let mut content = String::new();
        let mut current_line = String::new();

        while let Some(c) = self.advance() {
            if c == '\n' {
                let trimmed = current_line.trim_start();
                if trimmed.starts_with(&marker) {
                    let rest = &trimmed[marker.len()..];
                    if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('\r') {
                        let rewind_count = rest.chars().count() + 1; // +1 for '\n'
                        self.cursor = self.cursor.saturating_sub(rewind_count);
                        if content.ends_with('\n') { content.pop(); }
                        if content.ends_with('\r') { content.pop(); }
                        return Ok(content);
                    }
                }
                content.push_str(&current_line);
                content.push('\n');
                current_line.clear();
            } else {
                current_line.push(c);
            }
        }

        // Check if EOF was reached on the marker line
        let trimmed = current_line.trim_start();
        if trimmed.starts_with(&marker) {
            let rest = &trimmed[marker.len()..];
            if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('\r') {
                let rewind_count = rest.chars().count();
                self.cursor = self.cursor.saturating_sub(rewind_count);
                if content.ends_with('\n') { content.pop(); }
                if content.ends_with('\r') { content.pop(); }
                return Ok(content);
            }
        }

        Err(ParseError::Syntax {
            line: span.line,
            col: span.col,
            message: format!("Unterminated heredoc, expected end marker '{}'", marker),
        })
    }

    fn read_unquoted_literal(&mut self) -> String {
        let mut s = String::new();
        let mut brace_depth = 0;

        while let Some(c) = self.peek() {
            if c == '{' {
                let is_standalone = match self.peek_next() {
                    Some(' ') | Some('\t') | Some('\r') | Some('\n') | None => true,
                    _ => false,
                };
                if is_standalone && brace_depth == 0 {
                    break;
                }
                brace_depth += 1;
            } else if c == '}' {
                if brace_depth > 0 {
                    brace_depth -= 1;
                } else {
                    break;
                }
            } else if brace_depth == 0
                && (c == ' '
                    || c == '\t'
                    || c == '\r'
                    || c == '\n'
                    || c == '"'
                    || c == '`'
                    || c == '#')
            {
                break;
            }
            s.push(c);
            self.advance();
        }

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tokens() {
        let input = "localhost:8080 {\n  respond \"hello world\" 200\n}";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].kind, TokenKind::Literal("localhost:8080".into()));
        assert_eq!(tokens[1].kind, TokenKind::BlockOpen);
        assert_eq!(tokens[2].kind, TokenKind::Newline);
        assert_eq!(tokens[3].kind, TokenKind::Literal("respond".into()));
        assert_eq!(tokens[4].kind, TokenKind::Literal("hello world".into()));
        assert_eq!(tokens[5].kind, TokenKind::Literal("200".into()));
        assert_eq!(tokens[6].kind, TokenKind::Newline);
        assert_eq!(tokens[7].kind, TokenKind::BlockClose);
    }

    #[test]
    fn test_comments_and_continuation() {
        let input = "# comment\nexample.com \\\n  {\n  # inner comment\n  respond 200\n}";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].kind, TokenKind::Literal("example.com".into()));
        assert_eq!(tokens[1].kind, TokenKind::BlockOpen);
        assert_eq!(tokens[2].kind, TokenKind::Newline);
        assert_eq!(tokens[3].kind, TokenKind::Literal("respond".into()));
        assert_eq!(tokens[4].kind, TokenKind::Literal("200".into()));
    }

    #[test]
    fn test_heredoc() {
        let input = "respond <<EOF\nline1\nline2\nEOF 200";
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens[0].kind, TokenKind::Literal("respond".into()));
        assert_eq!(tokens[1].kind, TokenKind::Literal("line1\nline2".into()));
        assert_eq!(tokens[2].kind, TokenKind::Literal("200".into()));
    }
}
