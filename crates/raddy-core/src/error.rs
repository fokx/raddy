use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Handler error: {0}")]
    Handler(String),

    #[error("Matcher error: {0}")]
    Matcher(String),

    #[error("Module error: {0}")]
    Module(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
