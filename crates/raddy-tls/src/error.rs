use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("ACME error: {0}")]
    Acme(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, TlsError>;
