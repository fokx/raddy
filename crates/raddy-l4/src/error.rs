use thiserror::Error;

#[derive(Error, Debug)]
pub enum Layer4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("No upstreams available")]
    NoUpstreamsAvailable,

    #[error("Matching timeout exceeded")]
    MatchingTimeout,

    #[error("Connection closed by peer")]
    ConnectionClosed,

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Layer4Error>;
