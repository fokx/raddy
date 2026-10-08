use super::acl::{AclRule, check_early_domain_rules, is_host_allowed};
use crate::error::{ProxyError, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub auth_header: Option<String>,
}

impl UpstreamProxy {
    pub fn parse(raw_url: &str, disable_insecure_check: bool) -> Result<Self> {
        let parsed = url::Url::parse(raw_url).map_err(|e| {
            ProxyError::Core(raddy_core::CoreError::Config(format!(
                "Invalid upstream proxy URL '{}': {}",
                raw_url, e
            )))
        })?;

        let scheme = parsed.scheme().to_lowercase();
        let host = parsed
            .host_str()
            .ok_or_else(|| {
                ProxyError::Core(raddy_core::CoreError::Config(
                    "Missing host in upstream proxy URL".into(),
                ))
            })?
            .to_string();

        let is_local = is_localhost(&host);
        if !disable_insecure_check && !is_local && scheme != "https" {
            return Err(ProxyError::Core(raddy_core::CoreError::Config(
                "insecure schemes are only allowed to localhost upstreams".into(),
            )));
        }

        if scheme != "http" && scheme != "https" && scheme != "socks5" {
            return Err(ProxyError::Core(raddy_core::CoreError::Config(format!(
                "scheme {} is not supported for upstream proxy",
                scheme
            ))));
        }

        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            "socks5" => 1080,
            _ => 80,
        };
        let port = parsed.port().unwrap_or(default_port);

        let auth_header = if !parsed.username().is_empty() {
            let pass = parsed.password().unwrap_or("");
            let cred = BASE64.encode(format!("{}:{}", parsed.username(), pass));
            Some(format!("Basic {}", cred))
        } else {
            None
        };

        Ok(Self {
            scheme,
            host,
            port,
            auth_header,
        })
    }
}

pub fn is_localhost(host: &str) -> bool {
    let clean = host.trim_matches('[').trim_matches(']');
    clean.eq_ignore_ascii_case("localhost") || clean == "127.0.0.1" || clean == "::1"
}

/// Dials target direct or via upstream proxy.
pub async fn dial_target(
    host: &str,
    port: u16,
    dial_timeout: Duration,
    allowed_ports: &[u16],
    acl_rules: &[AclRule],
    upstream: Option<&UpstreamProxy>,
) -> Result<BoxedStream> {
    if let Some(ups) = upstream {
        dial_via_upstream(host, port, dial_timeout, ups).await
    } else {
        dial_direct(host, port, dial_timeout, allowed_ports, acl_rules).await
    }
}

pub async fn dial_direct(
    host: &str,
    port: u16,
    dial_timeout: Duration,
    allowed_ports: &[u16],
    acl_rules: &[AclRule],
) -> Result<BoxedStream> {
    // 1. Port restriction check
    if !allowed_ports.is_empty() && !allowed_ports.contains(&port) {
        return Err(ProxyError::Core(raddy_core::CoreError::Handler(format!(
            "port {} is not allowed",
            port
        ))));
    }

    // 2. Early domain match
    if let Some(allowed) = check_early_domain_rules(acl_rules, host) {
        if !allowed {
            return Err(ProxyError::Core(raddy_core::CoreError::Handler(format!(
                "disallowed host {}",
                host
            ))));
        }
    }

    // 3. DNS lookup
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            ProxyError::Core(raddy_core::CoreError::Handler(format!(
                "lookup of {} failed: {}",
                host, e
            )))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(ProxyError::Core(raddy_core::CoreError::Handler(format!(
            "lookup of {} returned no addresses",
            host
        ))));
    }

    // 4. Try connecting to each allowed IP address
    let mut any_ip_allowed = false;
    for addr in addrs {
        if !is_host_allowed(acl_rules, host, addr.ip()) {
            continue;
        }
        any_ip_allowed = true;

        match tokio::time::timeout(dial_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(Box::new(stream));
            }
            Ok(Err(e)) => {
                tracing::debug!("Failed to connect to {}: {}", addr, e);
            }
            Err(_) => {
                tracing::debug!("Timeout connecting to {}", addr);
            }
        }
    }

    if !any_ip_allowed {
        Err(ProxyError::Core(raddy_core::CoreError::Handler(format!(
            "no allowed IP addresses for {}",
            host
        ))))
    } else {
        Err(ProxyError::Core(raddy_core::CoreError::Handler(format!(
            "failed to connect to any resolved address for {}:{}",
            host, port
        ))))
    }
}

pub async fn dial_via_upstream(
    target_host: &str,
    target_port: u16,
    dial_timeout: Duration,
    upstream: &UpstreamProxy,
) -> Result<BoxedStream> {
    let ups_addr = format!("{}:{}", upstream.host, upstream.port);
    let tcp_stream = tokio::time::timeout(dial_timeout, TcpStream::connect(&ups_addr))
        .await
        .map_err(|_| ProxyError::Transport {
            upstream: ups_addr.clone(),
            message: "Connection timeout to upstream proxy".into(),
        })?
        .map_err(|e| ProxyError::Transport {
            upstream: ups_addr.clone(),
            message: format!("Connection failed to upstream proxy: {}", e),
        })?;

    let _ = tcp_stream.set_nodelay(true);

    if upstream.scheme == "socks5" {
        return connect_socks5(tcp_stream, target_host, target_port).await;
    }

    // Connect via HTTP/HTTPS CONNECT
    let mut stream: BoxedStream = if upstream.scheme == "https" {
        let is_local = is_localhost(&upstream.host);
        let client_config = if is_local {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifyServerCert))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                let _ = root_store.add(cert);
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(upstream.host.clone()).map_err(|e| {
            ProxyError::Core(raddy_core::CoreError::Config(format!(
                "Invalid upstream TLS server name '{}': {}",
                upstream.host, e
            )))
        })?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| ProxyError::Transport {
                upstream: ups_addr.clone(),
                message: format!("TLS handshake failed with upstream: {}", e),
            })?;

        Box::new(tls_stream)
    } else {
        Box::new(tcp_stream)
    };

    // Issue HTTP CONNECT request to upstream proxy
    let target = format!("{}:{}", target_host, target_port);
    let mut connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
    if let Some(ref auth) = upstream.auth_header {
        connect_req.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
    }
    connect_req.push_str("\r\n");

    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| ProxyError::Transport {
            upstream: ups_addr.clone(),
            message: format!("Failed to write CONNECT request to upstream: {}", e),
        })?;
    stream.flush().await?;

    // Read response line and headers
    let mut resp_buf = Vec::new();
    let mut temp = [0u8; 1024];
    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(ProxyError::Transport {
                upstream: ups_addr.clone(),
                message: "Unexpected EOF from upstream proxy".into(),
            });
        }
        resp_buf.extend_from_slice(&temp[..n]);

        if let Some(header_end) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = String::from_utf8_lossy(&resp_buf[..header_end]);
            let status_line = header_str.lines().next().unwrap_or("");
            if !status_line.contains(" 200") && !status_line.contains(" 2") {
                return Err(ProxyError::Transport {
                    upstream: ups_addr.clone(),
                    message: format!("Upstream proxy rejected CONNECT: {}", status_line),
                });
            }
            break;
        }
        if resp_buf.len() > 65536 {
            return Err(ProxyError::Transport {
                upstream: ups_addr.clone(),
                message: "Upstream proxy response headers too large".into(),
            });
        }
    }

    Ok(stream)
}

async fn connect_socks5(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedStream> {
    // 1. Initial greeting: NO_AUTH
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(ProxyError::Transport {
            upstream: "socks5".into(),
            message: format!("SOCKS5 auth negotiation failed: {:?}", resp),
        });
    }

    // 2. CONNECT command: 0x05 0x01 (connect) 0x00 (rsv)
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03);
        req.push(target_host.len() as u8);
        req.extend_from_slice(target_host.as_bytes());
    }
    req.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&req).await?;

    // 3. Response: 0x05 REP 0x00 ATYP ...
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        return Err(ProxyError::Transport {
            upstream: "socks5".into(),
            message: format!("SOCKS5 connect failed with status code {}", resp[1]),
        });
    }

    // Skip bound address
    match resp[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        _ => {}
    }

    Ok(Box::new(stream))
}

use crate::transport::NoVerifyServerCert;
