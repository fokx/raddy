use crate::ast::*;
use crate::error::{ParseError, ParseResult};
use crate::lexer::{Token, TokenKind};

pub struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn peek_skip_newlines(&self) -> Option<&Token> {
        let mut idx = self.cursor;
        while let Some(tok) = self.tokens.get(idx) {
            if tok.kind != TokenKind::Newline {
                return Some(tok);
            }
            idx += 1;
        }
        None
    }

    fn advance(&mut self) -> Option<Token> {
        if self.cursor < self.tokens.len() {
            let tok = self.tokens[self.cursor].clone();
            self.cursor += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn skip_newlines(&mut self) {
        while let Some(tok) = self.peek() {
            if tok.kind == TokenKind::Newline {
                self.advance();
            } else {
                break;
            }
        }
    }

    pub fn parse(&mut self) -> ParseResult<Caddyfile> {
        let mut caddyfile = Caddyfile::default();
        self.skip_newlines();

        // 1. Check for global options block at top
        if let Some(tok) = self.peek() {
            if tok.kind == TokenKind::BlockOpen {
                let span = tok.span;
                self.advance(); // consume {
                let options = self.parse_directive_list(true)?;
                caddyfile.global_options = Some(GlobalOptionsNode { options, span });
                self.skip_newlines();
            }
        }

        // 2. Parse top-level blocks: snippets (name), named routes &(name), or site blocks
        while let Some(tok) = self.peek_skip_newlines() {
            if tok.kind == TokenKind::Eof {
                break;
            }

            self.skip_newlines();
            if self.peek().map(|t| &t.kind) == Some(&TokenKind::Eof) {
                break;
            }

            let first_tok = match self.peek() {
                Some(t) => t.clone(),
                None => break,
            };

            if let TokenKind::Literal(ref text) = first_tok.kind {
                // Reject request matchers defined globally
                if text.starts_with('@') {
                    return Err(ParseError::Syntax {
                        line: first_tok.span.line,
                        col: first_tok.span.col,
                        message: format!("request matchers may not be defined globally, they must be in a site block; found {}, at Caddyfile:{}", text, first_tok.span.line),
                    });
                }

                // Top-level import: import <path/snippet> [args...]
                if text == "import" {
                    let dir = self.parse_directive_line()?;
                    caddyfile.imports.push(dir);
                    self.skip_newlines();
                    continue;
                }

                // Snippet: (name)
                if text.starts_with('(') && text.ends_with(')') {
                    let name = text[1..text.len() - 1].trim().to_string();
                    let span = first_tok.span;
                    self.advance(); // consume (name)
                    self.skip_newlines();

                    let directives = self.expect_block()?;
                    caddyfile.snippets.insert(name.clone(), SnippetNode {
                        name,
                        directives,
                        span,
                    });
                    self.skip_newlines();
                    continue;
                }

                // Named route: &(name)
                if text.starts_with("&(") && text.ends_with(')') {
                    let name = text[2..text.len() - 1].trim().to_string();
                    let span = first_tok.span;
                    if caddyfile.named_routes.contains_key(&name) {
                        return Err(ParseError::Syntax {
                            line: span.line,
                            col: span.col,
                            message: format!("cannot have duplicate named_routes: {}", name),
                        });
                    }
                    self.advance(); // consume &(name)
                    self.skip_newlines();

                    let directives = self.expect_block()?;
                    caddyfile.named_routes.insert(name.clone(), NamedRouteNode {
                        name,
                        directives,
                        span,
                    });
                    self.skip_newlines();
                    continue;
                }
            }

            // Otherwise, it's a Site Block (or single-line site block)
            let site = self.parse_site_block()?;
            caddyfile.site_blocks.push(site);
            self.skip_newlines();
        }

        Ok(caddyfile)
    }

    fn parse_site_block(&mut self) -> ParseResult<SiteBlockNode> {
        let mut addresses: Vec<String> = Vec::new();
        let span = self.peek().map(|t| t.span).unwrap_or_default();

        // Read address tokens until BlockOpen or Newline (single-line)
        while let Some(tok) = self.peek().cloned() {
            match &tok.kind {
                TokenKind::BlockOpen => {
                    self.advance(); // consume {
                    break;
                }
                TokenKind::Newline => {
                    // Check if { is on next line
                    self.advance();
                    self.skip_newlines();
                    if self.peek().map(|t| &t.kind) == Some(&TokenKind::BlockOpen) {
                        self.advance(); // consume {
                        break;
                    } else {
                        // Braceless site block: directives continue until EOF
                        if addresses.len() == 1 {
                            let known = [
                                "handle", "handle_path", "handle_response", "route", "respond",
                                "reverse_proxy", "redir", "file_server", "header", "encode",
                                "tls", "root", "log", "log_name", "log_skip", "log_append", "try_files", "rewrite", "invoke"
                            ];
                            if known.contains(&addresses[0].as_str()) {
                                return Err(ParseError::Syntax {
                                    line: span.line,
                                    col: span.col,
                                    message: format!("Caddyfile:{}: parsed '{}' as a site address, but it is a known directive; directives must appear in a site block", span.line, addresses[0]),
                                });
                            }
                        }
                        let directives = self.parse_directive_list(false)?;
                        return Ok(SiteBlockNode {
                            addresses,
                            directives,
                            span,
                        });
                    }
                }
                TokenKind::Literal(addr) => {
                    let clean = addr.trim_end_matches(',').trim();
                    if !clean.is_empty() {
                        addresses.push(clean.to_string());
                    }
                    self.advance();

                    // Check if next token on same line is a directive for single-line site block
                    // Single-line example: `localhost:8080 respond "hello" 200`
                    // In this case, we have 1 address, and the next token is NOT a comma or block open
                    if !addresses.is_empty() && self.peek().map(|t| &t.kind) != Some(&TokenKind::BlockOpen) {
                        // If next token is on the same line and is a known directive or not an address with comma:
                        if let Some(next) = self.peek() {
                            if next.kind != TokenKind::Newline && next.kind != TokenKind::BlockOpen {
                                // If the previous addr token didn't end with comma, it might be single-line directive!
                                if !addr.ends_with(',') {
                                    let directive = self.parse_directive_line()?;
                                    return Ok(SiteBlockNode {
                                        addresses,
                                        directives: vec![directive],
                                        span,
                                    });
                                }
                            }
                        }
                    }
                }
                TokenKind::BlockClose => {
                    return Err(ParseError::Syntax {
                        line: tok.span.line,
                        col: tok.span.col,
                        message: "Unexpected '}' in site address".into(),
                    });
                }
                TokenKind::Eof => {
                    return Err(ParseError::UnexpectedEof("Unexpected EOF in site address".into()));
                }
            }
        }

        if addresses.is_empty() {
            return Err(ParseError::Syntax {
                line: span.line,
                col: span.col,
                message: "Site block must have at least one address".into(),
            });
        }

        let directives = self.parse_directive_list(true)?;
        Ok(SiteBlockNode {
            addresses,
            directives,
            span,
        })
    }

    fn expect_block(&mut self) -> ParseResult<Vec<DirectiveNode>> {
        self.skip_newlines();
        match self.peek() {
            Some(Token {
                kind: TokenKind::BlockOpen,
                ..
            }) => {
                self.advance();
                self.parse_directive_list(true)
            }
            Some(t) => Err(ParseError::Syntax {
                line: t.span.line,
                col: t.span.col,
                message: format!("Expected '{{', found {:?}", t.kind),
            }),
            None => Err(ParseError::UnexpectedEof("Expected '{', reached EOF".into())),
        }
    }

    fn parse_directive_list(&mut self, stop_at_block_close: bool) -> ParseResult<Vec<DirectiveNode>> {
        let mut directives = Vec::new();
        self.skip_newlines();

        while let Some(tok) = self.peek() {
            if tok.kind == TokenKind::Eof {
                if stop_at_block_close {
                    return Err(ParseError::UnexpectedEof("Unclosed block, expected '}'".into()));
                }
                break;
            }

            if tok.kind == TokenKind::BlockClose {
                if stop_at_block_close {
                    self.advance(); // consume }
                    break;
                } else {
                    return Err(ParseError::Syntax {
                        line: tok.span.line,
                        col: tok.span.col,
                        message: "Unexpected '}'".into(),
                    });
                }
            }

            if tok.kind == TokenKind::Newline {
                self.advance();
                continue;
            }

            let dir = self.parse_directive_line()?;
            directives.push(dir);
            self.skip_newlines();
        }

        Ok(directives)
    }

    fn parse_directive_line(&mut self) -> ParseResult<DirectiveNode> {
        let first = match self.advance() {
            Some(t) => t,
            None => return Err(ParseError::UnexpectedEof("Expected directive name".into())),
        };

        let span = first.span;
        let name = match first.kind {
            TokenKind::Literal(s) => s,
            other => {
                return Err(ParseError::Syntax {
                    line: span.line,
                    col: span.col,
                    message: format!("Expected directive name, found {:?}", other),
                });
            }
        };

        let mut matcher = None;
        let mut args = Vec::new();
        let mut block = None;

        // Collect arguments on the same line
        while let Some(tok) = self.peek().cloned() {
            if tok.kind == TokenKind::Newline {
                self.advance(); // consume newline
                break;
            }

            if tok.kind == TokenKind::BlockOpen {
                self.advance(); // consume {
                let sub_directives = self.parse_directive_list(true)?;
                block = Some(sub_directives);
                break;
            }

            if tok.kind == TokenKind::BlockClose {
                break;
            }

            if let TokenKind::Literal(val) = &tok.kind {
                let val_str = val.clone();
                self.advance();

                // Check if first arg is a matcher: @name, /path*, or *
                let can_have_matcher = name != "import"
                    && name != "order"
                    && name != "admin"
                    && name != "email"
                    && name != "auto_https"
                    && name != "log";
                if can_have_matcher && matcher.is_none() && args.is_empty() && (val_str.starts_with('@') || val_str.starts_with('/') || val_str == "*") {
                    matcher = Some(val_str);
                } else {
                    args.push(val_str);
                }
            } else {
                break;
            }
        }

        // If line ended, check if a block begins on next line
        if block.is_none() {
            let mut idx = self.cursor;
            while let Some(t) = self.tokens.get(idx) {
                if t.kind == TokenKind::Newline {
                    idx += 1;
                } else {
                    break;
                }
            }
            if let Some(t) = self.tokens.get(idx) {
                if t.kind == TokenKind::BlockOpen {
                    self.cursor = idx + 1; // consume up through {
                    let sub_directives = self.parse_directive_list(true)?;
                    block = Some(sub_directives);
                }
            }
        }

        // If directive is "root" and matcher was set but args is empty,
        // then the "matcher" is actually the path (e.g. `root /var/www/html`)!
        if name == "root" && args.is_empty() && matcher.is_some() {
            args.push(matcher.take().unwrap());
        }

        Ok(DirectiveNode {
            name,
            matcher,
            args,
            block,
            span,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;

    #[test]
    fn test_parse_simple_site() {
        let input = "localhost:8080 {\n  respond \"hello\" 200\n}";
        let tokens = Lexer::new(input).tokenize().unwrap();
        let mut parser = Parser::new(tokens);
        let caddyfile = parser.parse().unwrap();

        assert_eq!(caddyfile.site_blocks.len(), 1);
        let site = &caddyfile.site_blocks[0];
        assert_eq!(site.addresses, vec!["localhost:8080"]);
        assert_eq!(site.directives.len(), 1);
        assert_eq!(site.directives[0].name, "respond");
        assert_eq!(site.directives[0].args, vec!["hello", "200"]);
    }

    #[test]
    fn test_parse_global_options_and_snippets() {
        let input = r#"
{
    email admin@example.com
    auto_https off
}

(logging) {
    log {
        output stdout
        format json
    }
}

example.com {
    import logging
    reverse_proxy localhost:8000
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let mut parser = Parser::new(tokens);
        let caddyfile = parser.parse().unwrap();

        assert!(caddyfile.global_options.is_some());
        assert_eq!(caddyfile.snippets.len(), 1);
        assert_eq!(caddyfile.site_blocks.len(), 1);
    }
}
