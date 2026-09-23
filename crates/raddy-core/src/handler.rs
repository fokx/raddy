use async_trait::async_trait;
use http::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;
use crate::context::Context;
use crate::error::Result;
use crate::placeholder::eval_placeholders;

/// Async request handler interface.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, ctx: &mut Context) -> Result<()>;
}

/// Static response handler (for `respond`, `error`).
#[derive(Debug, Clone)]
pub struct StaticResponseHandler {
    pub status_code: StatusCode,
    pub body: String,
    pub close: bool,
}

#[async_trait]
impl Handler for StaticResponseHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let evaluated_body = eval_placeholders(&self.body, ctx);
        ctx.set_response(self.status_code, evaluated_body);
        if self.close {
            ctx.response_headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("close"),
            );
        }
        Ok(())
    }
}

/// Redirect handler (for `redir`).
#[derive(Debug, Clone)]
pub struct RedirectHandler {
    pub location: String,
    pub status_code: StatusCode,
}

#[async_trait]
impl Handler for RedirectHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let loc = eval_placeholders(&self.location, ctx);
        if let Ok(val) = http::HeaderValue::try_from(loc) {
            ctx.response_headers.insert(http::header::LOCATION, val);
        }
        ctx.status = Some(self.status_code);
        ctx.response_written = true;
        Ok(())
    }
}

/// Rewrite handler (for `rewrite`, `uri`).
#[derive(Debug, Clone)]
pub struct RewriteHandler {
    pub uri_template: Option<String>,
    pub strip_path_prefix: Option<String>,
    pub strip_path_suffix: Option<String>,
}

#[async_trait]
impl Handler for RewriteHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let mut path = ctx.uri.path().to_string();

        if let Some(ref prefix) = self.strip_path_prefix {
            if let Some(stripped) = path.strip_prefix(prefix) {
                path = if stripped.starts_with('/') {
                    stripped.to_string()
                } else {
                    format!("/{}", stripped)
                };
            }
        }

        if let Some(ref suffix) = self.strip_path_suffix {
            if let Some(stripped) = path.strip_suffix(suffix) {
                path = stripped.to_string();
            }
        }

        if let Some(ref tmpl) = self.uri_template {
            path = eval_placeholders(tmpl, ctx);
        }

        let query = ctx.uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let new_uri_str = format!("{}{}", path, query);
        if let Ok(new_uri) = new_uri_str.parse::<http::Uri>() {
            ctx.uri = new_uri;
        }

        Ok(())
    }
}

/// Headers handler (for `header`, `request_header`).
#[derive(Debug, Clone)]
pub struct HeadersHandler {
    pub set_response_headers: HashMap<String, String>,
    pub delete_response_headers: Vec<String>,
    pub set_request_headers: HashMap<String, String>,
    pub delete_request_headers: Vec<String>,
}

#[async_trait]
impl Handler for HeadersHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // Request headers
        for name in &self.delete_request_headers {
            if let Ok(hdr) = http::HeaderName::try_from(name.as_str()) {
                ctx.headers.remove(&hdr);
            }
        }
        for (name, val) in &self.set_request_headers {
            let evaluated = eval_placeholders(val, ctx);
            if let (Ok(h_name), Ok(h_val)) = (
                http::HeaderName::try_from(name.as_str()),
                http::HeaderValue::try_from(evaluated),
            ) {
                ctx.headers.insert(h_name, h_val);
            }
        }

        // Response headers
        for name in &self.delete_response_headers {
            if let Ok(hdr) = http::HeaderName::try_from(name.as_str()) {
                ctx.response_headers.remove(&hdr);
            }
        }
        for (name, val) in &self.set_response_headers {
            let evaluated = eval_placeholders(val, ctx);
            if let (Ok(h_name), Ok(h_val)) = (
                http::HeaderName::try_from(name.as_str()),
                http::HeaderValue::try_from(evaluated),
            ) {
                ctx.response_headers.insert(h_name, h_val);
            }
        }

        Ok(())
    }
}

/// Sets custom variables in the request context (for `vars`).
#[derive(Debug, Clone)]
pub struct VarsHandler {
    pub vars: HashMap<String, String>,
}

#[async_trait]
impl Handler for VarsHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        for (k, v) in &self.vars {
            let evaluated = eval_placeholders(v, ctx);
            ctx.set_var(k.clone(), evaluated);
        }
        Ok(())
    }
}

/// A chain of handlers executed sequentially.
pub struct HandlerChain {
    pub handlers: Vec<Arc<dyn Handler>>,
}

impl HandlerChain {
    pub fn new(handlers: Vec<Arc<dyn Handler>>) -> Self {
        Self { handlers }
    }

    pub async fn execute(&self, ctx: &mut Context) -> Result<()> {
        for handler in &self.handlers {
            handler.handle(ctx).await?;
            if ctx.response_written {
                break;
            }
        }
        Ok(())
    }
}
