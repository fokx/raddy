use std::collections::HashMap;
use http::{HeaderMap, HeaderName, HeaderValue};
use raddy_core::context::Context;
use raddy_core::placeholder::eval_placeholders;

/// Rules for mutating request headers before sending upstream (`header_up`)
/// and mutating response headers before sending to client (`header_down`).
#[derive(Debug, Clone, Default)]
pub struct HeaderMutator {
    pub header_up_set: HashMap<String, String>,
    pub header_up_delete: Vec<String>,
    pub header_down_set: HashMap<String, String>,
    pub header_down_delete: Vec<String>,
}

impl HeaderMutator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mutates the request headers before forwarding to upstream.
    pub fn apply_header_up(&self, headers: &mut HeaderMap, ctx: &Context) {
        // 1. Apply delete rules
        for name in &self.header_up_delete {
            if let Ok(h_name) = HeaderName::try_from(name.as_str()) {
                headers.remove(&h_name);
            }
        }

        // 2. Auto proxy headers (if not already set or deleted)
        if !self.header_up_delete.iter().any(|d| d.eq_ignore_ascii_case("X-Forwarded-For")) {
            if let Some(client_ip) = ctx.remote_addr.map(|a| a.ip().to_string()) {
                let existing = headers
                    .get("X-Forwarded-For")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| format!("{}, {}", s, client_ip))
                    .unwrap_or(client_ip);

                if let Ok(val) = HeaderValue::try_from(existing) {
                    headers.insert(HeaderName::from_static("x-forwarded-for"), val);
                }
            }
        }

        if !self.header_up_delete.iter().any(|d| d.eq_ignore_ascii_case("X-Forwarded-Proto")) {
            let scheme = if ctx.tls_server_name.is_some() { "https" } else { "http" };
            headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                HeaderValue::from_static(scheme),
            );
        }

        if !self.header_up_delete.iter().any(|d| d.eq_ignore_ascii_case("X-Forwarded-Host")) {
            if let Some(host) = headers.get(http::header::HOST).cloned() {
                headers.insert(HeaderName::from_static("x-forwarded-host"), host);
            }
        }

        // 3. Apply custom header_up rules (with placeholder evaluation)
        for (name, tmpl) in &self.header_up_set {
            let val_str = eval_placeholders(tmpl, ctx);
            if let (Ok(h_name), Ok(h_val)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(val_str),
            ) {
                headers.insert(h_name, h_val);
            }
        }
    }

    /// Mutates the response headers before returning to the downstream client.
    pub fn apply_header_down(&self, headers: &mut HeaderMap, ctx: &Context) {
        // 1. Apply delete rules
        for name in &self.header_down_delete {
            if let Ok(h_name) = HeaderName::try_from(name.as_str()) {
                headers.remove(&h_name);
            }
        }

        // 2. Apply custom header_down rules
        for (name, tmpl) in &self.header_down_set {
            let val_str = eval_placeholders(tmpl, ctx);
            if let (Ok(h_name), Ok(h_val)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(val_str),
            ) {
                headers.insert(h_name, h_val);
            }
        }
    }
}
