//! Raddy Caddyfile parser and adapter crate
//! Handles lexing, token dispensing, AST building, preprocessor expansion,
//! and adaptation of Caddyfile configurations to Raddy's internal JSON config.

pub mod adapter;
pub mod ast;
pub mod dispenser;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod preprocessor;

pub use adapter::Adapter;
pub use ast::Caddyfile;
pub use dispenser::Dispenser;
pub use error::{ParseError, ParseResult};
pub use lexer::{Lexer, Span, Token, TokenKind};
pub use parser::Parser;
pub use preprocessor::Preprocessor;

use std::path::Path;
use raddy_core::config::Config;

/// Parses a Caddyfile string into an AST without preprocessor expansion or adaptation.
pub fn parse_caddyfile(input: &str) -> ParseResult<Caddyfile> {
    let mut lexer = Lexer::new(input);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(tokens);
    parser.parse()
}

/// Parses a Caddyfile from a string, runs preprocessor expansion (snippets and relative imports),
/// and adapts the AST into a Raddy internal `Config`.
pub fn adapt_caddyfile(input: &str, base_dir: impl AsRef<Path>) -> ParseResult<Config> {
    let raw_cf = parse_caddyfile(input)?;
    let mut prep = Preprocessor::new(raw_cf.snippets.clone(), base_dir);
    let expanded_cf = prep.expand_caddyfile(raw_cf)?;
    let mut adapter = Adapter::new();
    adapter.adapt(&expanded_cf)
}

/// Reads a Caddyfile from disk, runs preprocessor expansion, and adapts it into a Raddy internal `Config`.
pub fn adapt_caddyfile_from_file(path: impl AsRef<Path>) -> ParseResult<Config> {
    let path_ref = path.as_ref();
    let content = std::fs::read_to_string(path_ref).map_err(|e| ParseError::Import(format!(
        "Failed to read Caddyfile at '{}': {}",
        path_ref.display(),
        e
    )))?;

    let base_dir = path_ref.parent().unwrap_or_else(|| Path::new("."));
    adapt_caddyfile(&content, base_dir)
}
