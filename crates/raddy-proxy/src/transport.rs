use crate::error::{ProxyError, Result};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Parsed upstream destination with TLS flag, host, port, normalized dial address, and host header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub is_tls: bool,
    pub host: String,
    pub port: u16,
    pub dial_addr: String,
    pub host_header: String,
}

/// Parses an upstream address string, stripping http:// and https:// schemes and extracting host and port.
pub fn parse_upstream_target(addr: &str, default_tls: bool) -> UpstreamTarget {
    let s = addr.trim();
    let (scheme, rest) = if let Some(stripped) = s.strip_prefix("https://") {
        (Some("https"), stripped)
    } else if let Some(stripped) = s.strip_prefix("http://") {
        (Some("http"), stripped)
    } else {
        (None, s)
    };

    let host_and_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);

    let (host, port) = if host_and_port.starts_with('[') {
        if let Some(bracket_end) = host_and_port.find(']') {
            let host_part = &host_and_port[1..bracket_end];
            let after_bracket = &host_and_port[bracket_end + 1..];
            let port = if let Some(colon_pos) = after_bracket.find(':') {
                after_bracket[colon_pos + 1..].parse::<u16>().ok()
            } else {
                None
            };
            (host_part.to_string(), port)
        } else {
            (host_and_port.to_string(), None)
        }
    } else if host_and_port.starts_with(':') {
        let port = host_and_port[1..].parse::<u16>().ok();
        ("127.0.0.1".to_string(), port)
    } else if let Some((h, p_str)) = host_and_port.rsplit_once(':') {
        if let Ok(p) = p_str.parse::<u16>() {
            (h.to_string(), Some(p))
        } else {
            (host_and_port.to_string(), None)
        }
    } else {
        (host_and_port.to_string(), None)
    };

    let is_tls = match scheme {
        Some("https") => true,
        Some("http") => false,
        _ => default_tls || port == Some(443),
    };

    let final_port = port.unwrap_or(if is_tls { 443 } else { 80 });

    let dial_addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, final_port)
    } else {
        format!("{}:{}", host, final_port)
    };

    let host_header = if (is_tls && final_port == 443) || (!is_tls && final_port == 80) {
        host.clone()
    } else {
        dial_addr.clone()
    };

    UpstreamTarget {
        is_tls,
        host,
        port: final_port,
        dial_addr,
        host_header,
    }
}

/// Parses duration strings like "10s", "500ms", "1m", "2h".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        num.parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(num) = s.strip_suffix('s') {
        num.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(num) = s.strip_suffix('h') {
        num.parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

/// An upstream stream that is either plaintext TCP or TLS-encrypted TCP.
pub enum UpstreamStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for UpstreamStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
pub(crate) struct NoVerifyServerCert;

impl rustls::client::danger::ServerCertVerifier for NoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// HTTP Transport for sending requests to upstream backends.
#[derive(Clone)]
pub struct HttpTransport {
    pub dial_timeout: Duration,
    pub response_timeout: Duration,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub tls_insecure_skip_verify: bool,
    tls_connector: Arc<parking_lot::RwLock<Option<Arc<TlsConnector>>>>,
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
            tls: false,
            tls_server_name: None,
            tls_insecure_skip_verify: false,
            tls_connector: Arc::new(parking_lot::RwLock::new(None)),
        }
    }
}

impl HttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create_tls_connector(&self) -> Result<Arc<TlsConnector>> {
        if let Some(conn) = self.tls_connector.read().as_ref() {
            return Ok(conn.clone());
        }

        let mut lock = self.tls_connector.write();
        if let Some(conn) = lock.as_ref() {
            return Ok(conn.clone());
        }

        let client_config = if self.tls_insecure_skip_verify {
            let mut cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifyServerCert))
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            cfg
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                let _ = root_store.add(cert);
            }
            if root_store.is_empty() {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            cfg
        };

        let connector = Arc::new(TlsConnector::from(Arc::new(client_config)));
        *lock = Some(connector.clone());
        Ok(connector)
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
        self.round_trip_with_tls(dial_addr, self.tls, method, uri, headers, body)
            .await
    }

    /// Forwards an HTTP request to an upstream address with explicit TLS override.
    pub async fn round_trip_with_tls(
        &self,
        dial_addr: &str,
        force_tls: bool,
        method: Method,
        uri: &Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        // 1. Resolve host and port from dial string
        let target = parse_upstream_target(dial_addr, force_tls);

        // 2. Connect to upstream TCP with timeout
        let tcp_stream =
            tokio::time::timeout(self.dial_timeout, TcpStream::connect(&target.dial_addr))
                .await
                .map_err(|_| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: "Connection timed out".into(),
                })?
                .map_err(|e| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: format!("Connection failed: {}", e),
                })?;

        let _ = tcp_stream.set_nodelay(true);

        // 3. Establish TLS if needed
        let stream = if target.is_tls {
            let connector = self.get_or_create_tls_connector()?;
            let sni = self.tls_server_name.as_deref().unwrap_or(&target.host);
            let server_name =
                ServerName::try_from(sni.to_string()).map_err(|e| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: format!("Invalid TLS server name '{}': {}", sni, e),
                })?;

            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: format!("TLS handshake failed: {}", e),
                })?;

            UpstreamStream::Tls(tls_stream)
        } else {
            UpstreamStream::Plain(tcp_stream)
        };

        let io = TokioIo::new(stream);

        // 4. Perform HTTP/1.1 handshake
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Transport {
                upstream: target.dial_addr.clone(),
                message: format!("Handshake failed: {}", e),
            })?;

        // Spawn connection background worker
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("Upstream connection closed: {}", err);
            }
        });

        // 5. Build upstream request
        let mut req_builder = Request::builder()
            .method(method)
            .uri(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

        let mut has_host = false;
        for (k, v) in headers {
            if let Some(name) = k {
                if name == http::header::HOST {
                    has_host = true;
                }
                req_builder = req_builder.header(name, v);
            }
        }

        // HTTP/1.1 requires a Host header. Ensure one is present if not set by headers.
        if !has_host {
            let host_to_send = uri
                .authority()
                .map(|a| a.as_str())
                .or_else(|| uri.host())
                .unwrap_or(&target.host_header);
            req_builder = req_builder.header(http::header::HOST, host_to_send);
        }

        let upstream_req =
            req_builder
                .body(Full::new(body))
                .map_err(|e| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: format!("Failed to build request: {}", e),
                })?;

        // 6. Send request and receive response with timeout
        let resp: Response<hyper::body::Incoming> =
            tokio::time::timeout(self.response_timeout, sender.send_request(upstream_req))
                .await
                .map_err(|_| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: "Response timed out".into(),
                })?
                .map_err(|e| ProxyError::Transport {
                    upstream: target.dial_addr.clone(),
                    message: format!("Failed sending request: {}", e),
                })?;

        let (parts, incoming_body) = resp.into_parts();

        // 7. Read response body
        let body_bytes = incoming_body
            .collect()
            .await
            .map_err(|e| ProxyError::Transport {
                upstream: target.dial_addr.clone(),
                message: format!("Error reading response body: {}", e),
            })?
            .to_bytes();

        Ok((parts.status, parts.headers, body_bytes))
    }
}
