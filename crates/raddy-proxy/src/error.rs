use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("No healthy upstreams available")]
    NoHealthyUpstreams,

    #[error("Upstream IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("Transport error connecting to '{upstream}': {message}")]
    Transport { upstream: String, message: String },

    #[error("Core error: {0}")]
    Core(#[from] raddy_core::CoreError),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
