// Copyright 2015 Matthew Holt and The Caddy Authors
// Ported to Rust for Raddy

use super::lexer::{
    is_close_curly_brace, is_next_on_new_line, is_open_curly_brace, tokenize, Token,
};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct DispenserError {
    message: String,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl DispenserError {
    pub fn new(message: String) -> Self {
        Self {
            message,
            source: None,
        }
    }

    pub fn with_source(
        message: String,
        source: Box<dyn Error + Send + Sync + 'static>,
    ) -> Self {
        Self {
            message,
            source: Some(source),
        }
    }
}

impl fmt::Display for DispenserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for DispenserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|s| &**s as &(dyn Error + 'static))
    }
}

#[derive(Debug, Clone)]
pub struct Dispenser {
    pub tokens: Vec<Token>,
    pub cursor: isize,
    pub nesting: isize,
}

pub fn new_dispenser(tokens: Vec<Token>) -> Dispenser {
    Dispenser {
        tokens,
        cursor: -1,
        nesting: 0,
    }
}

pub fn new_test_dispenser(input: &str) -> Dispenser {
    let tokens = tokenize(input.as_bytes(), "Testfile").expect("getting all tokens from input");
    new_dispenser(tokens)
}

impl Dispenser {
    pub fn new(tokens: Vec<Token>) -> Self {
        new_dispenser(tokens)
    }

    pub fn from_input(input: &str) -> Result<Self, String> {
        let tokens = tokenize(input.as_bytes(), "Caddyfile")?;
        Ok(new_dispenser(tokens))
    }

    pub fn cursor(&self) -> isize {
        self.cursor
    }

    pub fn nesting(&self) -> isize {
        self.nesting
    }

    pub fn reset(&mut self) {
        self.cursor = -1;
        self.nesting = 0;
    }

    pub fn token(&self) -> Token {
        if self.cursor < 0 || (self.cursor as usize) >= self.tokens.len() {
            Token::default()
        } else {
            self.tokens[self.cursor as usize].clone()
        }
    }

    pub fn val(&self) -> &str {
        if self.cursor < 0 || (self.cursor as usize) >= self.tokens.len() {
            ""
        } else {
            &self.tokens[self.cursor as usize].text
        }
    }

    pub fn val_raw(&self) -> String {
        if self.cursor < 0 || (self.cursor as usize) >= self.tokens.len() {
            return String::new();
        }
        let tok = &self.tokens[self.cursor as usize];
        if let Some(quote) = tok.was_quoted {
            if quote != '<' {
                return format!("{}{}{}", quote, tok.text, quote);
            }
        }
        tok.text.clone()
    }

    pub fn line(&self) -> usize {
        if self.cursor < 0 || (self.cursor as usize) >= self.tokens.len() {
            0
        } else {
            self.tokens[self.cursor as usize].line
        }
    }

    pub fn file(&self) -> &str {
        if self.cursor < 0 || (self.cursor as usize) >= self.tokens.len() {
            ""
        } else {
            &self.tokens[self.cursor as usize].file
        }
    }

    pub fn next(&mut self) -> bool {
        if self.cursor < (self.tokens.len() as isize) - 1 {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    pub fn prev(&mut self) -> bool {
        if self.cursor > -1 {
            self.cursor -= 1;
            self.cursor > -1
        } else {
            false
        }
    }

    pub fn next_on_same_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= (self.tokens.len() as isize) - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if !is_next_on_new_line(curr, next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    pub fn next_arg(&mut self) -> bool {
        if !self.next_on_same_line() {
            return false;
        }
        if is_open_curly_brace(&self.token()) {
            self.cursor -= 1;
            return false;
        }
        true
    }

    pub fn next_line(&mut self) -> bool {
        if self.cursor < 0 {
            self.cursor += 1;
            return true;
        }
        if self.cursor >= (self.tokens.len() as isize) - 1 {
            return false;
        }
        let curr = &self.tokens[self.cursor as usize];
        let next = &self.tokens[(self.cursor + 1) as usize];
        if is_next_on_new_line(curr, next) {
            self.cursor += 1;
            return true;
        }
        false
    }

    pub fn next_block(&mut self, initial_nesting_level: isize) -> bool {
        if self.nesting > initial_nesting_level {
            if !self.next() {
                return false;
            }
            if is_close_curly_brace(&self.token()) && !self.next_on_same_line() {
                self.nesting -= 1;
            } else if is_open_curly_brace(&self.token()) && !self.next_on_same_line() {
                self.nesting += 1;
            }
            return self.nesting > initial_nesting_level;
        }
        if !self.next_on_same_line() {
            return false;
        }
        if !is_open_curly_brace(&self.token()) {
            self.cursor -= 1;
            return false;
        }
        self.next();
        if is_close_curly_brace(&self.token()) {
            return false;
        }
        self.nesting += 1;
        true
    }

    pub fn args(&mut self, targets: &mut [&mut String]) -> bool {
        for target in targets.iter_mut() {
            if !self.next_arg() {
                return false;
            }
            **target = self.val().to_string();
        }
        true
    }

    pub fn all_args(&mut self, targets: &mut [&mut String]) -> bool {
        if !self.args(targets) {
            return false;
        }
        if self.next_arg() {
            self.prev();
            return false;
        }
        true
    }

    pub fn count_remaining_args(&mut self) -> usize {
        let mut count = 0;
        while self.next_arg() {
            count += 1;
        }
        for _ in 0..count {
            self.prev();
        }
        count
    }

    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val().to_string());
        }
        args
    }

    pub fn remaining_args_raw(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.val_raw());
        }
        args
    }

    pub fn remaining_args_as_tokens(&mut self) -> Vec<Token> {
        let mut args = Vec::new();
        while self.next_arg() {
            args.push(self.token());
        }
        args
    }

    pub fn arg_err(&self) -> DispenserError {
        if is_open_curly_brace(&self.token()) {
            self.err("unexpected token '{', expecting argument")
        } else {
            self.errf(&format!(
                "wrong argument count or unexpected line ending after '{}'",
                self.val()
            ))
        }
    }

    pub fn syntax_err(&self, expected: &str) -> DispenserError {
        let msg = format!(
            "syntax error: unexpected token '{}', expecting '{}', at {}:{} import chain: ['{}']",
            self.val(),
            expected,
            self.file(),
            self.line(),
            self.token().imports.join("','")
        );
        DispenserError::new(msg)
    }

    pub fn eof_err(&self) -> DispenserError {
        self.err("unexpected EOF")
    }

    pub fn err(&self, msg: &str) -> DispenserError {
        self.wrap_err_msg(msg)
    }

    pub fn errf(&self, format: &str) -> DispenserError {
        self.wrap_err_msg(format)
    }

    pub fn wrap_err(&self, err: Box<dyn Error + Send + Sync + 'static>) -> DispenserError {
        let full_msg = if !self.token().imports.is_empty() {
            format!(
                "{}, at {}:{} import chain ['{}']",
                err,
                self.file(),
                self.line(),
                self.token().imports.join("','")
            )
        } else {
            format!("{}, at {}:{}", err, self.file(), self.line())
        };
        DispenserError::with_source(full_msg, err)
    }

    fn wrap_err_msg(&self, msg: &str) -> DispenserError {
        let full_msg = if !self.token().imports.is_empty() {
            format!(
                "{}, at {}:{} import chain ['{}']",
                msg,
                self.file(),
                self.line(),
                self.token().imports.join("','")
            )
        } else {
            format!("{}, at {}:{}", msg, self.file(), self.line())
        };
        DispenserError::new(full_msg)
    }
}
