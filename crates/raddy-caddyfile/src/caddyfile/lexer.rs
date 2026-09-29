// Copyright 2015 Matthew Holt and The Caddy Authors
// Ported to Rust for Raddy

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Token {
    pub file: String,
    pub imports: Vec<String>,
    pub line: usize,
    pub text: String,
    pub was_quoted: Option<char>,
    pub heredoc_marker: Option<String>,
    pub snippet_name: Option<String>,
}

impl Token {
    pub fn quoted(&self) -> bool {
        self.was_quoted.is_some()
    }

    pub fn num_line_breaks(&self) -> usize {
        let mut line_breaks = self.text.matches('\n').count();
        if self.was_quoted == Some('<') {
            line_breaks += 2;
        }
        line_breaks
    }
}

pub fn is_open_curly_brace(t: &Token) -> bool {
    t.text == "{" && t.was_quoted.is_none()
}

pub fn is_close_curly_brace(t: &Token) -> bool {
    t.text == "}" && t.was_quoted.is_none()
}

pub fn is_next_on_new_line(t1: &Token, t2: &Token) -> bool {
    if t1.file != t2.file {
        return true;
    }
    if t1.imports.len() != t2.imports.len() {
        return true;
    }
    for (im1, im2) in t1.imports.iter().zip(t2.imports.iter()) {
        if im1 != im2 {
            return true;
        }
    }
    t1.line + t1.num_line_breaks() < t2.line
}

pub fn tokenize(input: &[u8], filename: &str) -> Result<Vec<Token>, String> {
    let mut lex = Lexer::new(input, filename);
    let mut tokens = Vec::new();
    while let Some(tok) = lex.next_token()? {
        tokens.push(tok);
    }
    Ok(tokens)
}

struct Lexer<'a> {
    filename: &'a str,
    chars: Vec<char>,
    cursor: usize,
    line: usize,
    skipped_lines: usize,
    token: Token,
}

impl<'a> Lexer<'a> {
    fn new(input: &[u8], filename: &'a str) -> Self {
        // Decode bytes as UTF-8 losslessly as chars (handling UTF-8 encoding)
        let s = match std::str::from_utf8(input) {
            Ok(valid) => valid.to_string(),
            Err(_) => {
                // Decode byte by byte / lossy or latin1/utf8 fallback
                // In Go, `[]byte` with arbitrary bytes when passed to bufio.Reader
                // uses utf8.DecodeRune which replaces invalid UTF-8 bytes with RuneError (\u{FFFD}).
                let mut out = String::new();
                let mut rest = input;
                while !rest.is_empty() {
                    match std::str::from_utf8(rest) {
                        Ok(v) => {
                            out.push_str(v);
                            break;
                        }
                        Err(e) => {
                            let valid_up_to = e.valid_up_to();
                            if valid_up_to > 0 {
                                out.push_str(std::str::from_utf8(&rest[..valid_up_to]).unwrap());
                            }
                            out.push('\u{FFFD}');
                            let error_len = e.error_len().unwrap_or(1);
                            rest = &rest[valid_up_to + error_len..];
                        }
                    }
                }
                out
            }
        };

        let mut chars: Vec<char> = s.chars().collect();
        // Discard BOM if present
        if chars.first() == Some(&'\u{FEFF}') {
            chars.remove(0);
        }

        Self {
            filename,
            chars,
            cursor: 0,
            line: 1,
            skipped_lines: 0,
            token: Token::default(),
        }
    }

    fn read_char(&mut self) -> Option<char> {
        if self.cursor < self.chars.len() {
            let ch = self.chars[self.cursor];
            self.cursor += 1;
            Some(ch)
        } else {
            None
        }
    }

    fn next_token(&mut self) -> Result<Option<Token>, String> {
        let mut val: Vec<char> = Vec::new();
        let mut comment = false;
        let mut quoted = false;
        let mut bt_quoted = false;
        let mut in_heredoc = false;
        let mut heredoc_escaped = false;
        let mut escaped = false;
        let mut heredoc_marker = String::new();

        loop {
            let ch_opt = self.read_char();
            let ch = match ch_opt {
                Some(c) => c,
                None => {
                    // EOF reached
                    if !val.is_empty() {
                        if in_heredoc {
                            return Err(format!(
                                "incomplete heredoc <<{} on line #{}, expected ending marker {}",
                                heredoc_marker,
                                self.line + self.skipped_lines,
                                heredoc_marker
                            ));
                        }
                        self.token.file = self.filename.to_string();
                        self.token.text = val.into_iter().collect();
                        self.token.was_quoted = None;
                        self.token.heredoc_marker = if heredoc_marker.is_empty() {
                            None
                        } else {
                            Some(heredoc_marker)
                        };
                        return Ok(Some(self.token.clone()));
                    }
                    return Ok(None);
                }
            };

            // Detect start of heredoc
            let is_prefix_ll = val.len() >= 2 && val[0] == '<' && val[1] == '<';
            if (!quoted && !bt_quoted) && (!in_heredoc && !heredoc_escaped) && is_prefix_ll {
                if ch == ' ' {
                    self.token.file = self.filename.to_string();
                    self.token.text = val.into_iter().collect();
                    self.token.was_quoted = None;
                    self.token.heredoc_marker = None;
                    return Ok(Some(self.token.clone()));
                }

                if ch == '\r' {
                    continue;
                }

                if ch == '\n' {
                    if val.len() == 2 {
                        return Err(format!(
                            "missing opening heredoc marker on line #{}; must contain only alphanumeric characters, dashes and underscores; got empty string",
                            self.line
                        ));
                    }

                    if val.len() >= 3 && val[2] == '<' {
                        return Err(format!(
                            "too many '<' for heredoc on line #{}; only use two, for example <<END",
                            self.line
                        ));
                    }

                    heredoc_marker = val[2..].iter().collect();
                    let valid_marker = !heredoc_marker.is_empty()
                        && heredoc_marker
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
                    if !valid_marker {
                        return Err(format!(
                            "heredoc marker on line #{} must contain only alphanumeric characters, dashes and underscores; got '{}'",
                            self.line, heredoc_marker
                        ));
                    }

                    in_heredoc = true;
                    self.skipped_lines += 1;
                    val.clear();
                    continue;
                }

                val.push(ch);
                continue;
            }

            // Heredoc content reading
            if in_heredoc {
                val.push(ch);

                if ch == '\n' {
                    self.skipped_lines += 1;
                }

                let marker_chars: Vec<char> = heredoc_marker.chars().collect();
                if val.len() >= marker_chars.len() && val.ends_with(&marker_chars) {
                    let final_val = finalize_heredoc(&val, &heredoc_marker, self.line)?;
                    self.line += self.skipped_lines;
                    self.skipped_lines = 0;

                    self.token.file = self.filename.to_string();
                    self.token.text = final_val;
                    self.token.was_quoted = Some('<');
                    self.token.heredoc_marker = Some(heredoc_marker);
                    return Ok(Some(self.token.clone()));
                }

                continue;
            }

            // Backslash escape outside bt_quoted
            if !escaped && !bt_quoted && ch == '\\' {
                escaped = true;
                continue;
            }

            if quoted || bt_quoted {
                if quoted && escaped {
                    if ch != '"' {
                        val.push('\\');
                    }
                    escaped = false;
                } else if (quoted && ch == '"') || (bt_quoted && ch == '`') {
                    self.token.file = self.filename.to_string();
                    self.token.text = val.into_iter().collect();
                    self.token.was_quoted = Some(ch);
                    self.token.heredoc_marker = None;
                    return Ok(Some(self.token.clone()));
                }

                if ch == '\n' {
                    self.line += 1 + self.skipped_lines;
                    self.skipped_lines = 0;
                }

                val.push(ch);
                continue;
            }

            if ch.is_whitespace() {
                if ch == '\r' {
                    continue;
                }

                if ch == '\n' {
                    if escaped {
                        self.skipped_lines += 1;
                        escaped = false;
                    } else {
                        self.line += 1 + self.skipped_lines;
                        self.skipped_lines = 0;
                    }
                    comment = false;
                }

                if !val.is_empty() {
                    self.token.file = self.filename.to_string();
                    self.token.text = val.into_iter().collect();
                    self.token.was_quoted = None;
                    self.token.heredoc_marker = None;
                    return Ok(Some(self.token.clone()));
                }

                continue;
            }

            if ch == '#' && val.is_empty() {
                comment = true;
            }
            if comment {
                continue;
            }

            if val.is_empty() {
                self.token = Token {
                    file: self.filename.to_string(),
                    line: self.line,
                    ..Default::default()
                };
                if ch == '"' {
                    quoted = true;
                    continue;
                }
                if ch == '`' {
                    bt_quoted = true;
                    continue;
                }
            }

            if escaped {
                if ch == '<' {
                    heredoc_escaped = true;
                } else {
                    val.push('\\');
                }
                escaped = false;
            }

            val.push(ch);
        }
    }
}

fn finalize_heredoc(val: &[char], marker: &str, line: usize) -> Result<String, String> {
    let string_val: String = val.iter().collect();

    let last_newline = match string_val.rfind('\n') {
        Some(idx) => idx as isize,
        None => -1,
    };

    let (content_with_nl, last_line_and_marker) = if last_newline >= 0 {
        string_val.split_at((last_newline + 1) as usize)
    } else {
        ("", string_val.as_str())
    };

    let padding_to_strip = if last_line_and_marker.len() >= marker.len() {
        &last_line_and_marker[..last_line_and_marker.len() - marker.len()]
    } else {
        ""
    };

    let lines: Vec<&str> = if last_newline >= 0 {
        content_with_nl.split('\n').collect()
    } else {
        vec![""]
    };

    let mut out = String::new();
    let num_lines = if !lines.is_empty() {
        lines.len() - 1
    } else {
        0
    };

    for (line_num, line_text) in lines[..num_lines].iter().enumerate() {
        if *line_text == "" || *line_text == "\r" {
            out.push('\n');
            continue;
        }

        if !line_text.starts_with(padding_to_strip) {
            let clean_line_text = line_text.trim_end_matches(['\r', '\n']);
            return Err(format!(
                "mismatched leading whitespace in heredoc <<{} on line #{} [{}], expected whitespace [{}] to match the closing marker",
                marker,
                line + line_num + 1,
                clean_line_text,
                padding_to_strip
            ));
        }

        let stripped = &line_text[padding_to_strip.len()..];
        let cleaned = stripped.replace('\r', "");
        out.push_str(&cleaned);
        out.push('\n');
    }

    if out.ends_with('\n') {
        out.pop();
    }

    Ok(out)
}
