use std::collections::HashMap;
use http::{HeaderMap, HeaderName, HeaderValue};
use raddy_core::context::Context;
use raddy_core::placeholder::{eval_placeholders, PlaceholderProvider};

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
            let host_val = headers.get(http::header::HOST).cloned().or_else(|| {
                ctx.get_placeholder("hostport")
                    .or_else(|| ctx.get_placeholder("host"))
                    .and_then(|h| HeaderValue::try_from(h).ok())
            });
            if let Some(host) = host_val {
                headers.insert(HeaderName::from_static("x-forwarded-host"), host);
            }
        }

        // 3. Apply custom header_up rules (with placeholder evaluation)
        for (name, tmpl) in &self.header_up_set {
            let mut val_str = eval_placeholders(tmpl, ctx);
            if val_str.is_empty() && name.eq_ignore_ascii_case("x-forwarded-host") {
                val_str = ctx
                    .get_placeholder("hostport")
                    .or_else(|| ctx.get_placeholder("host"))
                    .unwrap_or_default();
            }
            if let Ok(h_name) = HeaderName::try_from(name.as_str()) {
                if val_str.is_empty() {
                    headers.remove(&h_name);
                } else if let Ok(h_val) = HeaderValue::try_from(val_str) {
                    headers.insert(h_name, h_val);
                }
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
            if let Ok(h_name) = HeaderName::try_from(name.as_str()) {
                if val_str.is_empty() {
                    headers.remove(&h_name);
                } else if let Ok(h_val) = HeaderValue::try_from(val_str) {
                    headers.insert(h_name, h_val);
                }
            }
        }
    }
}

/// Strips hop-by-hop headers from an upstream response, preserving Upgrade on 101.
pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap, is_101: bool) {
    let mut to_remove = Vec::new();
    if let Some(conn_val) = headers.get(http::header::CONNECTION).and_then(|v| v.to_str().ok()) {
        for part in conn_val.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("upgrade") {
                to_remove.push(trimmed.to_lowercase());
            }
        }
    }

    for name in to_remove {
        if let Ok(h) = HeaderName::try_from(name.as_str()) {
            headers.remove(&h);
        }
    }

    let hop_headers = [
        "alt-svc",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ];

    for &h in &hop_headers {
        headers.remove(HeaderName::from_static(h));
    }

    if !is_101 {
        headers.remove(http::header::CONNECTION);
        headers.remove(http::header::UPGRADE);
    } else {
        headers.insert(http::header::CONNECTION, HeaderValue::from_static("Upgrade"));
    }
}
