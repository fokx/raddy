use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("Core error: {0}")]
    Core(#[from] raddy_core::CoreError),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("HTTP/3 error: {0}")]
    Http3(String),
}

pub type Result<T> = std::result::Result<T, HttpServerError>;
