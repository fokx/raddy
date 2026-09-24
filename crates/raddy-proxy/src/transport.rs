use std::time::Duration;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use crate::error::{ProxyError, Result};

/// HTTP Transport for sending requests to upstream backends.
pub struct HttpTransport {
    pub dial_timeout: Duration,
    pub response_timeout: Duration,
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
        }
    }
}

impl HttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forwards an HTTP request to an upstream address and returns the response.
    pub async fn round_trip(
        &self,
        dial_addr: &str,
        method: Method,
        uri: &Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        // 1. Resolve host and port from dial string
        let target_addr = if dial_addr.contains(':') {
            dial_addr.to_string()
        } else {
            format!("{}:80", dial_addr)
        };

        // 2. Connect to upstream TCP with timeout
        let stream = tokio::time::timeout(self.dial_timeout, TcpStream::connect(&target_addr))
            .await
            .map_err(|_| ProxyError::Transport {
                upstream: target_addr.clone(),
                message: "Connection timed out".into(),
            })?
            .map_err(|e| ProxyError::Transport {
                upstream: target_addr.clone(),
                message: format!("Connection failed: {}", e),
            })?;

        let io = TokioIo::new(stream);

        // 3. Perform HTTP/1.1 handshake
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Transport {
                upstream: target_addr.clone(),
                message: format!("Handshake failed: {}", e),
            })?;

        // Spawn connection background worker
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("Upstream connection closed: {}", err);
            }
        });

        // 4. Build upstream request
        let mut req_builder = Request::builder()
            .method(method)
            .uri(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

        for (k, v) in headers {
            if let Some(name) = k {
                req_builder = req_builder.header(name, v);
            }
        }

        let upstream_req = req_builder
            .body(Full::new(body))
            .map_err(|e| ProxyError::Transport {
                upstream: target_addr.clone(),
                message: format!("Failed to build request: {}", e),
            })?;

        // 5. Send request and receive response with timeout
        let resp: Response<hyper::body::Incoming> = tokio::time::timeout(
            self.response_timeout,
            sender.send_request(upstream_req),
        )
        .await
        .map_err(|_| ProxyError::Transport {
            upstream: target_addr.clone(),
            message: "Response timed out".into(),
        })?
        .map_err(|e| ProxyError::Transport {
            upstream: target_addr.clone(),
            message: format!("Failed sending request: {}", e),
        })?;

        let (parts, incoming_body) = resp.into_parts();

        // 6. Read response body
        let body_bytes = incoming_body
            .collect()
            .await
            .map_err(|e| ProxyError::Transport {
                upstream: target_addr.clone(),
                message: format!("Error reading response body: {}", e),
            })?
            .to_bytes();

        Ok((parts.status, parts.headers, body_bytes))
    }
}
