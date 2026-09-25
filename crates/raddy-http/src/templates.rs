use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::HeaderValue;
use minijinja::{context, Environment};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;

/// Template evaluation handler using MiniJinja (Jinja2 compatible).
pub struct TemplatesHandler;

impl TemplatesHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TemplatesHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Handler for TemplatesHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let body = match ctx.response_body.take() {
            Some(b) if !b.is_empty() => b,
            other => {
                ctx.response_body = other;
                return Ok(());
            }
        };

        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                // Not UTF-8 text, pass through unaltered
                ctx.response_body = Some(body);
                return Ok(());
            }
        };

        // Check if there are template tags {{ or {%
        if !body_str.contains("{{") && !body_str.contains("{%") {
            ctx.response_body = Some(body);
            return Ok(());
        }

        let env = Environment::new();
        let tmpl_res = env.template_from_str(body_str);
        let tmpl = match tmpl_res {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Template parse error: {}", e);
                ctx.response_body = Some(body);
                return Ok(());
            }
        };

        let host = ctx.headers.get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| ctx.uri.host())
            .unwrap_or("localhost")
            .to_string();
        let path = ctx.uri.path().to_string();
        let query = ctx.uri.query().unwrap_or("").to_string();
        let method = ctx.method.as_str().to_string();
        let remote_ip = ctx.remote_addr.map(|a| a.ip().to_string()).unwrap_or_default();
        let vars = ctx.vars.clone();

        let req_ctx = context! {
            req => context! {
                host => host,
                path => path,
                query => query,
                method => method,
            },
            remote_ip => remote_ip,
            vars => vars,
        };

        match tmpl.render(req_ctx) {
            Ok(rendered) => {
                let rendered_bytes = Bytes::from(rendered);
                if let Ok(len_val) = HeaderValue::from_str(&rendered_bytes.len().to_string()) {
                    ctx.response_headers.insert(CONTENT_LENGTH, len_val);
                }
                ctx.response_body = Some(rendered_bytes);
            }
            Err(e) => {
                tracing::warn!("Template render error: {}", e);
                ctx.response_body = Some(body);
            }
        }

        Ok(())
    }

    fn is_response_transformer(&self) -> bool {
        true
    }
}

