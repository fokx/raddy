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

    /// Indicates whether this handler transforms an already-generated response
    /// (e.g. `templates`, `encode`, response `headers`).
    fn is_response_transformer(&self) -> bool {
        false
    }
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
#[derive(Debug, Clone, Default)]
pub struct RewriteHandler {
    pub uri_template: Option<String>,
    pub strip_path_prefix: Option<String>,
    pub strip_path_suffix: Option<String>,
    pub search: Option<String>,
    pub replace: Option<String>,
}

#[async_trait]
impl Handler for RewriteHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if let (Some(search), Some(replace)) = (&self.search, &self.replace) {
            let full_uri = ctx.uri.to_string();
            let new_full = full_uri.replace(search, replace);
            if let Ok(u) = new_full.parse::<http::Uri>() {
                ctx.uri = u;
                return Ok(());
            }
        }

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

        let mut query = ctx.uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

        if let Some(ref tmpl) = self.uri_template {
            let evaluated = eval_placeholders(tmpl, ctx);
            if let Some((p, q)) = evaluated.split_once('?') {
                path = p.to_string();
                query = format!("?{}", q);
            } else {
                path = evaluated;
            }
        }

        let new_uri_str = format!("{}{}", path, query);
        if let Ok(new_uri) = new_uri_str.parse::<http::Uri>() {
            ctx.uri = new_uri;
        }

        Ok(())
    }
}

/// Changes the HTTP method of the request.
#[derive(Debug, Clone)]
pub struct MethodHandler {
    pub method: String,
}

#[async_trait]
impl Handler for MethodHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let evaluated = eval_placeholders(&self.method, ctx);
        if let Ok(m) = http::Method::try_from(evaluated.as_str()) {
            ctx.method = m;
        }
        Ok(())
    }
}

/// Rewrites URI to the first matching file that exists on disk.
#[derive(Debug, Clone)]
pub struct TryFilesHandler {
    pub try_files: Vec<String>,
}

#[async_trait]
impl Handler for TryFilesHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let root = ctx.get_var("root").unwrap_or(".");
        let root_path = std::path::Path::new(root);

        for pat in &self.try_files {
            let evaluated = eval_placeholders(pat, ctx);
            if evaluated.starts_with('=') {
                if let Ok(code) = evaluated[1..].parse::<u16>() {
                    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::NOT_FOUND);
                    ctx.status = Some(status);
                    ctx.set_var("err.status_code", code.to_string());
                    ctx.set_var("err.status_text", status.canonical_reason().unwrap_or("").to_string());
                    ctx.set_var("err.message", format!("HTTP error {}", code));
                    return Ok(());
                }
            }

            let (file_part, query_part) = match evaluated.split_once('?') {
                Some((f, q)) => (f, Some(q)),
                None => (evaluated.as_str(), None),
            };

            let clean_file = file_part.trim_start_matches('/');
            let target_path = root_path.join(clean_file);

            let exists = if file_part.ends_with('/') {
                target_path.is_dir()
            } else {
                target_path.is_file() || target_path.exists()
            };

            if exists {
                let new_query = if let Some(q) = query_part {
                    format!("?{}", q)
                } else {
                    ctx.uri.query().map(|q| format!("?{}", q)).unwrap_or_default()
                };
                let new_uri_str = format!("{}{}", file_part, new_query);
                if let Ok(new_uri) = new_uri_str.parse::<http::Uri>() {
                    ctx.uri = new_uri;
                }
                ctx.set_var("file_match.relative", file_part.to_string());
                break;
            }
        }
        Ok(())
    }
}

/// Headers handler (for `header`, `request_header`).
#[derive(Debug, Clone, Default)]
pub struct HeadersHandler {
    pub set_response_headers: HashMap<String, String>,
    pub default_response_headers: HashMap<String, String>,
    pub delete_response_headers: Vec<String>,
    pub set_request_headers: HashMap<String, String>,
    pub delete_request_headers: Vec<String>,
}

#[async_trait]
impl Handler for HeadersHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // Request headers
        for name in &self.delete_request_headers {
            if name.contains('*') {
                let pat = name.to_lowercase();
                let to_remove: Vec<_> = ctx.headers.keys()
                    .filter(|k| glob_match_hdr(&pat, k.as_str()))
                    .cloned()
                    .collect();
                for k in to_remove {
                    ctx.headers.remove(&k);
                }
            } else if let Ok(hdr) = http::HeaderName::try_from(name.as_str()) {
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
            if name.contains('*') {
                let pat = name.to_lowercase();
                let to_remove: Vec<_> = ctx.response_headers.keys()
                    .filter(|k| glob_match_hdr(&pat, k.as_str()))
                    .cloned()
                    .collect();
                for k in to_remove {
                    ctx.response_headers.remove(&k);
                }
            } else if let Ok(hdr) = http::HeaderName::try_from(name.as_str()) {
                ctx.response_headers.remove(&hdr);
            }
        }
        for (name, val) in &self.default_response_headers {
            if let Ok(h_name) = http::HeaderName::try_from(name.as_str()) {
                if !ctx.response_headers.contains_key(&h_name) {
                    let evaluated = eval_placeholders(val, ctx);
                    if let Ok(h_val) = http::HeaderValue::try_from(evaluated) {
                        ctx.response_headers.insert(h_name, h_val);
                    }
                }
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

    fn is_response_transformer(&self) -> bool {
        !self.set_response_headers.is_empty()
            || !self.default_response_headers.is_empty()
            || !self.delete_response_headers.is_empty()
    }
}

fn glob_match_hdr(pat: &str, s: &str) -> bool {
    let s = s.to_lowercase();
    if pat == "*" {
        return true;
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        s.starts_with(prefix)
    } else if let Some(suffix) = pat.strip_prefix('*') {
        s.ends_with(suffix)
    } else {
        s == pat
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
