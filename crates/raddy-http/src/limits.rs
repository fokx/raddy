use async_trait::async_trait;
use http::StatusCode;
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;

/// Enforces maximum request body size limits.
pub struct RequestBodyLimitHandler {
    pub max_size: usize,
}

impl RequestBodyLimitHandler {
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }

    /// Parses human-readable sizes like "10mb", "500kb", "1gb" into bytes.
    pub fn parse_size(s: &str) -> usize {
        let s = s.trim().to_lowercase();
        if let Some(stripped) = s.strip_suffix("gb") {
            stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024 * 1024
        } else if let Some(stripped) = s.strip_suffix("mb") {
            stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024
        } else if let Some(stripped) = s.strip_suffix("kb") {
            stripped.trim().parse::<usize>().unwrap_or(0) * 1024
        } else if let Some(stripped) = s.strip_suffix('b') {
            stripped.trim().parse::<usize>().unwrap_or(0)
        } else {
            s.parse::<usize>().unwrap_or(0)
        }
    }
}

#[async_trait]
impl Handler for RequestBodyLimitHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if ctx.body.len() > self.max_size {
            ctx.set_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "413 Payload Too Large (max allowed: {} bytes)\n",
                    self.max_size
                ),
            );
        }
        Ok(())
    }
}
