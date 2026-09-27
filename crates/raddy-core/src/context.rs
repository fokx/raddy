use std::collections::HashMap;
use std::net::SocketAddr;
use http::{HeaderMap, Method, StatusCode, Uri};
use bytes::Bytes;
use crate::placeholder::PlaceholderProvider;

/// Request/Response Context flowing through the middleware and handler chain.
#[derive(Debug, Clone)]
pub struct Context {
    // Request metadata
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub remote_addr: Option<SocketAddr>,
    pub tls_server_name: Option<String>,
    pub body: Bytes,

    // Variables set by middleware/directives (e.g. `vars`, `root`, etc.)
    pub vars: HashMap<String, String>,

    // Response state
    pub status: Option<StatusCode>,
    pub response_headers: HeaderMap,
    pub response_body: Option<Bytes>,
    pub response_written: bool,

    // Logging control state
    pub log_skip: bool,
    pub log_name: Option<String>,
    pub log_appends: HashMap<String, serde_json::Value>,
}

impl Context {
    pub fn new(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            method,
            uri,
            headers,
            remote_addr: None,
            tls_server_name: None,
            body,
            vars: HashMap::new(),
            status: None,
            response_headers: HeaderMap::new(),
            response_body: None,
            response_written: false,
            log_skip: false,
            log_name: None,
            log_appends: HashMap::new(),
        }
    }

    pub fn set_var(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.vars.insert(key.into(), val.into());
    }

    pub fn get_var(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }

    pub fn set_response(&mut self, status: StatusCode, body: impl Into<Bytes>) {
        self.status = Some(status);
        self.response_body = Some(body.into());
        self.response_written = true;
    }
}

impl PlaceholderProvider for Context {
    fn get_placeholder(&self, key: &str) -> Option<String> {
        match key {
            "host" => self
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(':').next().unwrap_or(s).to_string())
                .or_else(|| self.uri.host().map(|h| h.to_string())),

            "path" => Some(self.uri.path().to_string()),

            "method" => Some(self.method.as_str().to_string()),

            "query" => self.uri.query().map(|q| q.to_string()),

            "scheme" => self.uri.scheme_str().map(|s| s.to_string()).or_else(|| {
                if self.tls_server_name.is_some() {
                    Some("https".to_string())
                } else {
                    Some("http".to_string())
                }
            }),

            "remote_host" => self.remote_addr.map(|a| a.ip().to_string()),
            "remote_port" => self.remote_addr.map(|a| a.port().to_string()),

            k if k.starts_with("header.") || k.starts_with("http.request.header.") => {
                let header_name = if let Some(stripped) = k.strip_prefix("header.") {
                    stripped
                } else {
                    k.strip_prefix("http.request.header.").unwrap_or(k)
                };
                self.headers.get(header_name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
            }

            k if k.starts_with("resp.header.") => {
                let header_name = k.strip_prefix("resp.header.")?;
                self.response_headers.get(header_name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
            }

            k if k.starts_with("vars.") => {
                let var_name = k.strip_prefix("vars.")?;
                self.vars.get(var_name).cloned()
            }

            _ => self.vars.get(key).cloned(),
        }
    }
}
