use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, ETAG};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use raddy_core::placeholder::eval_placeholders;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct ReplacementRule {
    pub search: String,
    pub replace: String,
    pub regex: Option<Regex>,
}

#[derive(Debug, Clone, Default)]
pub struct ReplaceHandler {
    pub rules: Vec<ReplacementRule>,
    pub content_types: Vec<String>,
    pub stream: bool,
}

impl ReplaceHandler {
    pub fn new(rules: Vec<ReplacementRule>, content_types: Vec<String>, stream: bool) -> Self {
        Self {
            rules,
            content_types,
            stream,
        }
    }
}

#[async_trait]
impl Handler for ReplaceHandler {
    fn is_response_transformer(&self) -> bool {
        true
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let body = match ctx.response_body.take() {
            Some(b) if !b.is_empty() => b,
            other => {
                ctx.response_body = other;
                return Ok(());
            }
        };

        // If Content-Encoding is present (and not "identity"), response is compressed.
        // We cannot perform string replacements on compressed bodies.
        if let Some(enc) = ctx
            .response_headers
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
        {
            if enc != "identity" && !enc.is_empty() {
                ctx.response_body = Some(body);
                return Ok(());
            }
        }

        // If content_types are specified, verify Content-Type header matches
        if !self.content_types.is_empty() {
            let ct = ctx
                .response_headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let matched = self.content_types.iter().any(|allowed| {
                if let Some(prefix) = allowed.strip_suffix('*') {
                    ct.starts_with(prefix)
                } else {
                    ct.contains(allowed)
                }
            });
            if !matched {
                ctx.response_body = Some(body);
                return Ok(());
            }
        }

        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                // Non UTF-8 binary payload, pass through unaltered
                ctx.response_body = Some(body);
                return Ok(());
            }
        };

        let mut result = body_str.to_string();
        for rule in &self.rules {
            let replace_val = eval_placeholders(&rule.replace, ctx);
            if let Some(ref re) = rule.regex {
                result = re.replace_all(&result, replace_val.as_str()).to_string();
            } else {
                let search_val = eval_placeholders(&rule.search, ctx);
                result = result.replace(&search_val, &replace_val);
            }
        }

        let result_bytes = Bytes::from(result);
        if let Ok(len_val) = HeaderValue::from_str(&result_bytes.len().to_string()) {
            ctx.response_headers.insert(CONTENT_LENGTH, len_val);
        }
        // Remove ETag header since body was modified
        ctx.response_headers.remove(ETAG);

        ctx.response_body = Some(result_bytes);
        Ok(())
    }
}
