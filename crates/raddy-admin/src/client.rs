use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;

use crate::address::{parse_admin_addr, ParsedAdminAddr};
use crate::error::{AdminError, Result};

/// Response received from an Admin API request.
#[derive(Debug, Clone)]
pub struct AdminResponse {
    pub status: http::StatusCode,
    pub body: Bytes,
}

impl AdminResponse {
    /// Returns true if the status code is 2xx.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    /// Returns the response body as a UTF-8 string.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Deserializes the JSON body.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(AdminError::Json)
    }
}

/// HTTP client for interacting with the Raddy Admin API over TCP or Unix domain sockets.
pub struct AdminClient {
    address: String,
}

impl AdminClient {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }

    /// Sends an HTTP request to the configured Admin API address.
    pub async fn send(&self, req: http::Request<Bytes>) -> Result<AdminResponse> {
        let parsed = parse_admin_addr(&self.address)?;
        match parsed {
            ParsedAdminAddr::Tcp(tcp_addr) => {
                let stream = tokio::net::TcpStream::connect(&tcp_addr).await.map_err(|e| {
                    AdminError::Internal(format!(
                        "Failed to connect to Admin API at TCP {}: {}",
                        tcp_addr, e
                    ))
                })?;
                let io = TokioIo::new(stream);
                Self::send_over_io(io, req, &tcp_addr).await
            }
            #[cfg(unix)]
            ParsedAdminAddr::Unix { path, .. } => {
                let stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
                    AdminError::Internal(format!(
                        "Failed to connect to Admin API at unix socket {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                let io = TokioIo::new(stream);
                Self::send_over_io(io, req, "localhost").await
            }
            #[cfg(not(unix))]
            ParsedAdminAddr::Unix { .. } => {
                Err(AdminError::Internal(
                    "Unix domain sockets are not supported on this operating system".into(),
                ))
            }
        }
    }

    async fn send_over_io<T>(
        io: TokioIo<T>,
        req: http::Request<Bytes>,
        default_host: &str,
    ) -> Result<AdminResponse>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| {
            AdminError::Internal(format!("HTTP handshake failed: {}", e))
        })?;

        tokio::spawn(async move {
            let _ = conn.await;
        });

        let (parts, body) = req.into_parts();
        let mut builder = http::Request::builder()
            .method(parts.method)
            .uri(parts.uri);

        for (k, v) in parts.headers.iter() {
            builder = builder.header(k, v);
        }

        if !parts.headers.contains_key(http::header::HOST) {
            builder = builder.header(http::header::HOST, default_host);
        }

        let hyper_req = builder.body(Full::new(body)).map_err(|e| {
            AdminError::Internal(format!("Failed to build HTTP request: {}", e))
        })?;

        let resp = sender.send_request(hyper_req).await.map_err(|e| {
            AdminError::Internal(format!("Admin API request failed: {}", e))
        })?;

        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| AdminError::Internal(format!("Failed to read response body: {}", e)))?
            .to_bytes();

        Ok(AdminResponse {
            status,
            body: body_bytes,
        })
    }

    /// Performs a GET request on the specified path.
    pub async fn get(&self, path: &str) -> Result<AdminResponse> {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(path)
            .body(Bytes::new())
            .map_err(|e| AdminError::Internal(e.to_string()))?;
        self.send(req).await
    }

    /// Performs a POST request on the specified path with an optional content type and payload.
    pub async fn post(
        &self,
        path: &str,
        body: impl Into<Bytes>,
        content_type: Option<&str>,
    ) -> Result<AdminResponse> {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(path);
        if let Some(ct) = content_type {
            builder = builder.header(http::header::CONTENT_TYPE, ct);
        }
        let req = builder
            .body(body.into())
            .map_err(|e| AdminError::Internal(e.to_string()))?;
        self.send(req).await
    }
}
