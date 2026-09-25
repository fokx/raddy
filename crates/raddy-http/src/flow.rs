use async_trait::async_trait;
use http::StatusCode;
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;

/// Abort handler: immediately terminates the request.
pub struct AbortHandler;

#[async_trait]
impl Handler for AbortHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        ctx.status = Some(StatusCode::BAD_REQUEST);
        ctx.response_body = Some(bytes::Bytes::new());
        ctx.response_written = true;
        Ok(())
    }
}

/// Error handler: synthesizes an error response code and message.
pub struct ErrorHandler {
    pub status: StatusCode,
    pub message: String,
}

impl ErrorHandler {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

#[async_trait]
impl Handler for ErrorHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let msg = if self.message.is_empty() {
            format!("{}\n", self.status)
        } else {
            format!("{}\n", self.message)
        };
        ctx.set_response(self.status, msg);
        Ok(())
    }
}
