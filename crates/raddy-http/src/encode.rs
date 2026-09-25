use std::io::Write;
use async_trait::async_trait;
use bytes::Bytes;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH};
use http::HeaderValue;
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;

/// Supported compression algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionFormat {
    Zstd,
    Gzip,
    Deflate,
}

/// Middleware handler that compresses response bodies according to client Accept-Encoding.
pub struct EncodeHandler {
    pub formats: Vec<CompressionFormat>,
}

impl EncodeHandler {
    pub fn new(formats: Vec<CompressionFormat>) -> Self {
        Self { formats }
    }

    pub fn from_format_names(names: &[String]) -> Self {
        let mut formats = Vec::new();
        for name in names {
            match name.to_lowercase().as_str() {
                "zstd" => formats.push(CompressionFormat::Zstd),
                "gzip" | "gz" => formats.push(CompressionFormat::Gzip),
                "deflate" => formats.push(CompressionFormat::Deflate),
                _ => {}
            }
        }
        if formats.is_empty() {
            formats = vec![CompressionFormat::Zstd, CompressionFormat::Gzip];
        }
        Self { formats }
    }
}

#[async_trait]
impl Handler for EncodeHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // If response is already written and has a body, check if we should compress it
        let body = match ctx.response_body.take() {
            Some(b) if !b.is_empty() => b,
            other => {
                ctx.response_body = other;
                return Ok(());
            }
        };

        // Don't re-compress if Content-Encoding is already set
        if ctx.response_headers.contains_key(CONTENT_ENCODING) {
            ctx.response_body = Some(body);
            return Ok(());
        }

        // Parse Accept-Encoding header from request
        let accept_encoding = ctx
            .headers
            .get(ACCEPT_ENCODING)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let mut chosen_format = None;
        for fmt in &self.formats {
            match fmt {
                CompressionFormat::Zstd if accept_encoding.contains("zstd") => {
                    chosen_format = Some(CompressionFormat::Zstd);
                    break;
                }
                CompressionFormat::Gzip if accept_encoding.contains("gzip") => {
                    chosen_format = Some(CompressionFormat::Gzip);
                    break;
                }
                CompressionFormat::Deflate if accept_encoding.contains("deflate") => {
                    chosen_format = Some(CompressionFormat::Deflate);
                    break;
                }
                _ => {}
            }
        }

        let compressed_body = match chosen_format {
            Some(CompressionFormat::Zstd) => {
                match zstd::encode_all(&body[..], 3) {
                    Ok(compressed) => {
                        ctx.response_headers.insert(
                            CONTENT_ENCODING,
                            HeaderValue::from_static("zstd"),
                        );
                        Bytes::from(compressed)
                    }
                    Err(e) => {
                        tracing::warn!("Zstd compression failed: {}", e);
                        body
                    }
                }
            }
            Some(CompressionFormat::Gzip) => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                if encoder.write_all(&body).is_ok() && encoder.flush().is_ok() {
                    match encoder.finish() {
                        Ok(compressed) => {
                            ctx.response_headers.insert(
                                CONTENT_ENCODING,
                                HeaderValue::from_static("gzip"),
                            );
                            Bytes::from(compressed)
                        }
                        Err(_) => body,
                    }
                } else {
                    body
                }
            }
            Some(CompressionFormat::Deflate) => {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                if encoder.write_all(&body).is_ok() && encoder.flush().is_ok() {
                    match encoder.finish() {
                        Ok(compressed) => {
                            ctx.response_headers.insert(
                                CONTENT_ENCODING,
                                HeaderValue::from_static("deflate"),
                            );
                            Bytes::from(compressed)
                        }
                        Err(_) => body,
                    }
                } else {
                    body
                }
            }
            None => body,
        };

        if let Ok(len_val) = HeaderValue::from_str(&compressed_body.len().to_string()) {
            ctx.response_headers.insert(CONTENT_LENGTH, len_val);
        }

        ctx.response_body = Some(compressed_body);
        Ok(())
    }

    fn is_response_transformer(&self) -> bool {
        true
    }
}

