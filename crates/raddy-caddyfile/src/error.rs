use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParseError {
    #[error("Parse error at line {line}, col {col}: {message}")]
    Syntax {
        line: usize,
        col: usize,
        message: String,
    },

    #[error("Unexpected end of file: {0}")]
    UnexpectedEof(String),

    #[error("Import error: {0}")]
    Import(String),

    #[error("Adaptation error at line {line}: {message}")]
    Adaptation { line: usize, message: String },
}

pub type ParseResult<T> = std::result::Result<T, ParseError>;
