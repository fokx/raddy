use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use bytes::Bytes;
use crate::placeholder::PlaceholderProvider;

/// Request/Response Context flowing through the middleware and handler chain.
#[derive(Debug, Clone)]
pub struct Context {
    // Request metadata
    pub method: Method,
    pub uri: Uri,
    pub orig_uri: Uri,
    pub headers: HeaderMap,
    pub remote_addr: Option<SocketAddr>,
    pub tls_server_name: Option<String>,
    pub body: Bytes,
    pub extensions: Arc<Mutex<http::Extensions>>,

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
    pub fn new(method: Method, uri: Uri, mut headers: HeaderMap, body: Bytes) -> Self {
        // Synthesize Host header if missing (e.g. from HTTP/2 or HTTP/3 where :authority is in uri)
        if !headers.contains_key(http::header::HOST) {
            if let Some(auth) = uri.authority() {
                if let Ok(val) = HeaderValue::try_from(auth.as_str()) {
                    headers.insert(http::header::HOST, val);
                }
            } else if let Some(h) = uri.host() {
                if let Ok(val) = HeaderValue::try_from(h) {
                    headers.insert(http::header::HOST, val);
                }
            }
        }
        let orig_uri = uri.clone();
        Self {
            method,
            uri,
            orig_uri,
            headers,
            remote_addr: None,
            tls_server_name: None,
            body,
            extensions: Arc::new(Mutex::new(http::Extensions::new())),
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

    pub fn get_extension<T: Clone + Send + Sync + 'static>(&self) -> Option<T> {
        self.extensions.lock().ok()?.get::<T>().cloned()
    }

    pub fn remove_extension<T: Send + Sync + 'static>(&self) -> Option<T> {
        self.extensions.lock().ok()?.remove::<T>()
    }

    pub fn insert_extension<T: Clone + Send + Sync + 'static>(&self, val: T) {
        if let Ok(mut ext) = self.extensions.lock() {
            ext.insert(val);
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
            "host" | "http.request.host" => self
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(':').next().unwrap_or(s).to_string())
                .or_else(|| self.uri.host().map(|h| h.to_string())),

            "hostport" | "http.request.hostport" => self
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .or_else(|| self.uri.authority().map(|a| a.as_str().to_string())),

            "port" | "http.request.port" => self
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(':').nth(1).map(|p| p.to_string()))
                .or_else(|| self.uri.port_u16().map(|p| p.to_string())),

            "uri" | "http.request.uri" => {
                let s = self
                    .uri
                    .path_and_query()
                    .map(|pq| {
                        let str_val = pq.as_str();
                        if str_val.starts_with('/') {
                            str_val.to_string()
                        } else {
                            format!("/{}", str_val)
                        }
                    })
                    .unwrap_or_else(|| {
                        let p = self.uri.path();
                        let p = if p.is_empty() { "/" } else { p };
                        if let Some(q) = self.uri.query() {
                            format!("{}?{}", p, q)
                        } else {
                            p.to_string()
                        }
                    });
                Some(s)
            }

            "path" | "http.request.uri.path" => {
                let p = self.uri.path();
                if p.is_empty() {
                    Some("/".to_string())
                } else {
                    Some(p.to_string())
                }
            }

            "orig_uri" | "http.request.orig_uri" => {
                let s = self
                    .orig_uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| self.orig_uri.path().to_string());
                Some(s)
            }

            "orig_uri.path" | "http.request.orig_uri.path" => {
                let p = self.orig_uri.path();
                if p.is_empty() {
                    Some("/".to_string())
                } else {
                    Some(p.to_string())
                }
            }

            "method" | "http.request.method" => Some(self.method.as_str().to_string()),

            "query" | "http.request.uri.query" => self.uri.query().map(|q| q.to_string()),

            "scheme" | "http.request.scheme" => self.uri.scheme_str().map(|s| s.to_string()).or_else(|| {
                if self.tls_server_name.is_some() {
                    Some("https".to_string())
                } else {
                    Some("http".to_string())
                }
            }),

            "remote_host" | "http.request.remote.host" | "client_ip" => self.remote_addr.map(|a| a.ip().to_string()),
            "remote_port" | "http.request.remote.port" => self.remote_addr.map(|a| a.port().to_string()),

            k if k.starts_with("query.") || k.starts_with("http.request.uri.query.") => {
                let param = if let Some(stripped) = k.strip_prefix("query.") {
                    stripped
                } else {
                    k.strip_prefix("http.request.uri.query.").unwrap_or(k)
                };
                let val = self.uri.query().and_then(|q| {
                    for pair in q.split('&') {
                        let mut parts = pair.splitn(2, '=');
                        if let Some(k) = parts.next() {
                            if k == param {
                                return Some(parts.next().unwrap_or("").to_string());
                            }
                        }
                    }
                    None
                }).unwrap_or_default();
                Some(val)
            }

            k if k.starts_with("header.") || k.starts_with("http.request.header.") => {
                let header_name = if let Some(stripped) = k.strip_prefix("header.") {
                    stripped
                } else {
                    k.strip_prefix("http.request.header.").unwrap_or(k)
                };
                let val = self.headers.get(header_name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                Some(val)
            }

            k if k.starts_with("resp.header.") || k.starts_with("http.response.header.") => {
                let header_name = if let Some(stripped) = k.strip_prefix("resp.header.") {
                    stripped
                } else {
                    k.strip_prefix("http.response.header.").unwrap_or(k)
                };
                let val = self.response_headers.get(header_name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                Some(val)
            }

            k if k.starts_with("vars.") => {
                let var_name = k.strip_prefix("vars.")?;
                self.vars.get(var_name).cloned()
            }

            _ => self.vars.get(key).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::placeholder::eval_placeholders;

    #[test]
    fn test_context_redirect_uri_placeholder() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, "hkg.eeeu.de".parse().unwrap());
        let uri = Uri::from_static("/");
        let ctx = Context::new(Method::GET, uri, headers, Bytes::new());

        let evaluated = eval_placeholders("https://{host}{uri}", &ctx);
        assert_eq!(evaluated, "https://hkg.eeeu.de/");
    }

    #[test]
    fn test_context_redirect_uri_with_path_and_query() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, "hkg.eeeu.de:80".parse().unwrap());
        let uri = Uri::from_static("/search?q=rust&category=network");
        let ctx = Context::new(Method::GET, uri, headers, Bytes::new());

        let evaluated = eval_placeholders("https://{host}{uri}", &ctx);
        assert_eq!(evaluated, "https://hkg.eeeu.de/search?q=rust&category=network");
        assert_eq!(ctx.get_placeholder("host"), Some("hkg.eeeu.de".to_string()));
        assert_eq!(ctx.get_placeholder("port"), Some("80".to_string()));
        assert_eq!(ctx.get_placeholder("query.q"), Some("rust".to_string()));
        assert_eq!(ctx.get_placeholder("query.category"), Some("network".to_string()));
        assert_eq!(ctx.get_placeholder("path"), Some("/search".to_string()));
    }
}
