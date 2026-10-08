use async_trait::async_trait;
use base64::prelude::*;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderName, HeaderValue, StatusCode};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use std::collections::HashMap;

/// HTTP Basic Authentication handler.
pub struct BasicAuthHandler {
    pub users: HashMap<String, String>,
    pub realm: String,
}

impl BasicAuthHandler {
    pub fn new(users: HashMap<String, String>, realm: Option<String>) -> Self {
        Self {
            users,
            realm: realm.unwrap_or_else(|| "Restricted".into()),
        }
    }

    fn verify_credentials(&self, auth_header: &str) -> bool {
        let stripped = match auth_header.strip_prefix("Basic ") {
            Some(s) => s.trim(),
            None => return false,
        };

        let decoded = match BASE64_STANDARD.decode(stripped) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => return false,
            },
            Err(_) => return false,
        };

        let (username, password) = match decoded.split_once(':') {
            Some((u, p)) => (u, p),
            None => return false,
        };

        if let Some(expected) = self.users.get(username) {
            if expected.starts_with("$2a$")
                || expected.starts_with("$2b$")
                || expected.starts_with("$2y$")
            {
                bcrypt::verify(password, expected).unwrap_or(false)
            } else {
                expected == password
            }
        } else {
            false
        }
    }
}

#[async_trait]
impl Handler for BasicAuthHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let auth_val = ctx.headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

        let authenticated = match auth_val {
            Some(h) => self.verify_credentials(h),
            None => false,
        };

        if !authenticated {
            ctx.set_response(StatusCode::UNAUTHORIZED, "401 Unauthorized\n");
            let realm_header = format!("Basic realm=\"{}\"", self.realm);
            if let Ok(val) = HeaderValue::from_str(&realm_header) {
                ctx.response_headers.insert(WWW_AUTHENTICATE, val);
            }
        }

        Ok(())
    }
}

/// Forward authentication handler (delegates auth to an external service).
pub struct ForwardAuthHandler {
    pub upstream: String,
    pub uri_override: Option<String>,
    pub copy_headers: Vec<String>,
}

impl ForwardAuthHandler {
    pub fn new(
        upstream: impl Into<String>,
        uri_override: Option<String>,
        copy_headers: Vec<String>,
    ) -> Self {
        Self {
            upstream: upstream.into(),
            uri_override,
            copy_headers,
        }
    }
}

#[async_trait]
impl Handler for ForwardAuthHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let auth_url = if let Some(ref uri) = self.uri_override {
            format!("{}{}", self.upstream.trim_end_matches('/'), uri)
        } else {
            self.upstream.clone()
        };

        let client = reqwest::Client::new();
        let mut req_builder = client.get(&auth_url);

        // Forward headers to auth upstream
        for (k, v) in &ctx.headers {
            req_builder = req_builder.header(k.as_str(), v.as_bytes());
        }

        match req_builder.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    // Copy configured headers into client request
                    for header_name in &self.copy_headers {
                        if let Some(val) = resp.headers().get(header_name.as_str()) {
                            if let Ok(k) = HeaderName::from_bytes(header_name.as_bytes()) {
                                ctx.headers.insert(k, val.clone());
                            }
                        }
                    }
                    Ok(())
                } else {
                    // Forward rejection status and headers downstream
                    ctx.status = Some(
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::UNAUTHORIZED),
                    );
                    for (k, v) in resp.headers() {
                        if let Ok(hdr) = HeaderName::from_bytes(k.as_str().as_bytes()) {
                            ctx.response_headers.insert(hdr, v.clone());
                        }
                    }
                    let body = resp.bytes().await.unwrap_or_default();
                    ctx.response_body = Some(body);
                    ctx.response_written = true;
                    Ok(())
                }
            }
            Err(e) => {
                tracing::error!("Forward auth error querying '{}': {}", auth_url, e);
                ctx.set_response(
                    StatusCode::BAD_GATEWAY,
                    format!("502 Bad Gateway: Forward auth failed: {}\n", e),
                );
                Ok(())
            }
        }
    }
}
