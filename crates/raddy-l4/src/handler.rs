use crate::context::ConnectionContext;
use crate::error::{Layer4Error, Result};
use raddy_core::config::Layer4HandlerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Dynamic runtime state of an upstream backend.
#[derive(Debug)]
pub struct UpstreamState {
    pub dial_addr: String,
    pub healthy: parking_lot::RwLock<bool>,
    pub active_conns: AtomicUsize,
    pub fail_count: AtomicUsize,
}

impl UpstreamState {
    pub fn new(dial_addr: String) -> Self {
        Self {
            dial_addr,
            healthy: parking_lot::RwLock::new(true),
            active_conns: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
        }
    }
}

/// Upstream Selection Policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionPolicy {
    RoundRobin,
    Random,
    LeastConn,
    IpHash,
}

/// Layer 4 Reverse Proxy Handler.
pub struct ProxyHandler {
    pub upstreams: Vec<Arc<UpstreamState>>,
    pub selection_policy: SelectionPolicy,
    pub proxy_protocol_version: Option<u8>,
    pub round_robin_idx: AtomicUsize,
    pub health_interval: Option<Duration>,
    pub health_timeout: Duration,
    pub use_tls: bool,
    pub tls_insecure: bool,
}

impl ProxyHandler {
    pub fn from_config(cfg: &Layer4HandlerConfig) -> Result<Self> {
        let mut upstreams_list = Vec::new();

        // Parse upstreams from various Caddy formats:
        // 1. "upstreams": [ { "dial": ["host:port"] } ]
        // 2. "upstreams": [ "host:port" ]
        // 3. "upstream": "host:port" or [ ... ]
        // 4. "to": [ "host:port" ]
        if let Some(ups_val) = cfg.details.get("upstreams").or_else(|| cfg.details.get("upstream")) {
            if let Some(arr) = ups_val.as_array() {
                for item in arr {
                    if let Some(obj) = item.as_object() {
                        if let Some(dial_arr) = obj.get("dial").and_then(|d| d.as_array()) {
                            for d in dial_arr {
                                if let Some(s) = d.as_str() {
                                    upstreams_list.push(s.to_string());
                                }
                            }
                        } else if let Some(dial_str) = obj.get("dial").and_then(|d| d.as_str()) {
                            upstreams_list.push(dial_str.to_string());
                        }
                    } else if let Some(s) = item.as_str() {
                        upstreams_list.push(s.to_string());
                    }
                }
            } else if let Some(s) = ups_val.as_str() {
                upstreams_list.push(s.to_string());
            }
        } else if let Some(to_val) = cfg.details.get("to") {
            if let Some(arr) = to_val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        upstreams_list.push(s.to_string());
                    }
                }
            } else if let Some(s) = to_val.as_str() {
                upstreams_list.push(s.to_string());
            }
        }

        let policy_str = cfg
            .details
            .get("lb_policy")
            .or_else(|| cfg.details.get("load_balancing"))
            .and_then(|v| {
                if let Some(obj) = v.as_object() {
                    obj.get("selection_policy")
                        .and_then(|sp| sp.as_object())
                        .and_then(|o| o.get("policy"))
                        .and_then(|p| p.as_str())
                        .or_else(|| obj.get("policy").and_then(|p| p.as_str()))
                } else {
                    v.as_str()
                }
            })
            .unwrap_or("round_robin");

        let selection_policy = match policy_str {
            "random" => SelectionPolicy::Random,
            "least_conn" => SelectionPolicy::LeastConn,
            "ip_hash" => SelectionPolicy::IpHash,
            _ => SelectionPolicy::RoundRobin,
        };

        let proxy_protocol_version = cfg
            .details
            .get("proxy_protocol")
            .and_then(|v| v.as_str())
            .and_then(|s| match s {
                "v1" | "1" => Some(1),
                "v2" | "2" => Some(2),
                _ => None,
            });

        let use_tls = cfg
            .details
            .get("tls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tls_insecure = cfg
            .details
            .get("tls_insecure")
            .or_else(|| cfg.details.get("insecure"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let states: Vec<Arc<UpstreamState>> = upstreams_list
            .into_iter()
            .map(|u| Arc::new(UpstreamState::new(u)))
            .collect();

        let handler = Self {
            upstreams: states,
            selection_policy,
            proxy_protocol_version,
            round_robin_idx: AtomicUsize::new(0),
            health_interval: None,
            health_timeout: Duration::from_secs(3),
            use_tls,
            tls_insecure,
        };

        Ok(handler)
    }

    pub fn select_upstream(&self, ctx: &ConnectionContext) -> Option<Arc<UpstreamState>> {
        if self.upstreams.is_empty() {
            return None;
        }

        let healthy_upstreams: Vec<&Arc<UpstreamState>> = self
            .upstreams
            .iter()
            .filter(|u| *u.healthy.read())
            .collect();

        let pool = if healthy_upstreams.is_empty() {
            // Fallback to all upstreams if all marked unhealthy
            self.upstreams.iter().collect::<Vec<_>>()
        } else {
            healthy_upstreams
        };

        if pool.is_empty() {
            return None;
        }

        match self.selection_policy {
            SelectionPolicy::RoundRobin => {
                let idx = self.round_robin_idx.fetch_add(1, Ordering::Relaxed) % pool.len();
                Some(pool[idx].clone())
            }
            SelectionPolicy::Random => {
                let idx = (rand::random::<usize>()) % pool.len();
                Some(pool[idx].clone())
            }
            SelectionPolicy::LeastConn => {
                let mut best = pool[0];
                let mut min_conns = best.active_conns.load(Ordering::Relaxed);
                for u in &pool[1..] {
                    let c = u.active_conns.load(Ordering::Relaxed);
                    if c < min_conns {
                        min_conns = c;
                        best = u;
                    }
                }
                Some(best.clone())
            }
            SelectionPolicy::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                ctx.remote_addr.ip().hash(&mut hasher);
                let idx = (hasher.finish() as usize) % pool.len();
                Some(pool[idx].clone())
            }
        }
    }

    /// Proxies a TCP stream bidirectionally.
    pub async fn handle_tcp<S>(&self, mut client_stream: S, ctx: &ConnectionContext) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let upstream = self
            .select_upstream(ctx)
            .ok_or(Layer4Error::NoUpstreamsAvailable)?;

        upstream.active_conns.fetch_add(1, Ordering::Relaxed);
        let dial_target = resolve_dial_address(&upstream.dial_addr);

        tracing::debug!(
            "Layer 4 proxying connection from {} to upstream '{}'",
            ctx.remote_addr,
            dial_target
        );

        let upstream_conn_res = TcpStream::connect(&dial_target).await;
        let mut upstream_conn = match upstream_conn_res {
            Ok(conn) => {
                upstream.fail_count.store(0, Ordering::Relaxed);
                *upstream.healthy.write() = true;
                conn
            }
            Err(e) => {
                upstream.fail_count.fetch_add(1, Ordering::Relaxed);
                *upstream.healthy.write() = false;
                upstream.active_conns.fetch_sub(1, Ordering::Relaxed);
                tracing::warn!(
                    "Failed to connect to Layer 4 upstream '{}': {}",
                    dial_target,
                    e
                );
                return Err(Layer4Error::Io(e));
            }
        };

        // If PROXY protocol requested, write header
        if let Some(ver) = self.proxy_protocol_version {
            if let Err(e) = write_proxy_protocol_header(
                &mut upstream_conn,
                ver,
                ctx.remote_addr,
                ctx.local_addr,
            )
            .await
            {
                upstream.active_conns.fetch_sub(1, Ordering::Relaxed);
                return Err(Layer4Error::Io(e));
            }
        }

        // Bidirectional copy
        let res = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_conn).await;
        upstream.active_conns.fetch_sub(1, Ordering::Relaxed);

        match res {
            Ok((from_client, from_upstream)) => {
                tracing::debug!(
                    "Layer 4 session finished: client sent {} bytes, upstream sent {} bytes",
                    from_client,
                    from_upstream
                );
                Ok(())
            }
            Err(e) => {
                tracing::debug!("Layer 4 proxy connection closed with: {}", e);
                Ok(())
            }
        }
    }

    /// Proxies a UDP datagram to upstream and sends response back.
    pub async fn handle_udp(
        &self,
        downstream_socket: &UdpSocket,
        packet: &[u8],
        client_addr: SocketAddr,
        ctx: &ConnectionContext,
    ) -> Result<()> {
        let upstream = self
            .select_upstream(ctx)
            .ok_or(Layer4Error::NoUpstreamsAvailable)?;

        let dial_target = resolve_dial_address(&upstream.dial_addr);
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        upstream_socket.connect(&dial_target).await?;

        upstream_socket.send(packet).await?;

        // Wait for response with timeout
        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(Duration::from_secs(5), upstream_socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                downstream_socket.send_to(&buf[..n], client_addr).await?;
                Ok(())
            }
            Ok(Err(e)) => Err(Layer4Error::Io(e)),
            Err(_) => {
                // Timeout waiting for upstream response
                Ok(())
            }
        }
    }
}

/// Generates and sends a PROXY protocol v1 or v2 header.
async fn write_proxy_protocol_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> std::io::Result<()> {
    if version == 1 {
        let proto_str = match (client_addr, server_addr) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
            (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
            _ => "UNKNOWN",
        };
        let line = format!(
            "PROXY {} {} {} {} {}\r\n",
            proto_str,
            client_addr.ip(),
            server_addr.ip(),
            client_addr.port(),
            server_addr.port()
        );
        writer.write_all(line.as_bytes()).await?;
    } else if version == 2 {
        let mut header = Vec::with_capacity(32);
        // Signature
        header.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        // Version 2, Command Proxy (0x21)
        header.push(0x21);

        match (client_addr, server_addr) {
            (SocketAddr::V4(c), SocketAddr::V4(s)) => {
                // Family AF_INET (0x10) | Transport STREAM (0x01) => 0x11
                header.push(0x11);
                // Length (12 bytes)
                header.extend_from_slice(&12u16.to_be_bytes());
                header.extend_from_slice(&c.ip().octets());
                header.extend_from_slice(&s.ip().octets());
                header.extend_from_slice(&c.port().to_be_bytes());
                header.extend_from_slice(&s.port().to_be_bytes());
            }
            (SocketAddr::V6(c), SocketAddr::V6(s)) => {
                // Family AF_INET6 (0x20) | Transport STREAM (0x01) => 0x21
                header.push(0x21);
                // Length (36 bytes)
                header.extend_from_slice(&36u16.to_be_bytes());
                header.extend_from_slice(&c.ip().octets());
                header.extend_from_slice(&s.ip().octets());
                header.extend_from_slice(&c.port().to_be_bytes());
                header.extend_from_slice(&s.port().to_be_bytes());
            }
            _ => {
                // Unknown (0x00)
                header.push(0x00);
                header.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        writer.write_all(&header).await?;
    }
    Ok(())
}

fn resolve_dial_address(dial: &str) -> String {
    let clean = dial.trim();
    if let Some(stripped) = clean.strip_prefix("tcp://").or_else(|| clean.strip_prefix("udp://")) {
        stripped.to_string()
    } else {
        clean.to_string()
    }
}

/// Echo Handler (RFC 862).
pub struct EchoHandler;

impl EchoHandler {
    pub async fn handle_tcp<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut r, mut w) = tokio::io::split(&mut stream);
        let _ = tokio::io::copy(&mut r, &mut w).await;
        Ok(())
    }

    pub async fn handle_udp(
        &self,
        socket: &UdpSocket,
        packet: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        socket.send_to(packet, client_addr).await?;
        Ok(())
    }
}

/// Close Handler.
pub struct CloseHandler;

impl CloseHandler {
    pub async fn handle_tcp<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let _ = stream.shutdown().await;
        Ok(())
    }

    pub async fn handle_udp(&self) -> Result<()> {
        Ok(())
    }
}

/// Bandwidth Throttle Handler.
pub struct ThrottleHandler {
    pub bytes_per_second: u64,
}

impl ThrottleHandler {
    pub fn from_config(cfg: &Layer4HandlerConfig) -> Self {
        let bytes_per_second = cfg
            .details
            .get("bytes_per_second")
            .or_else(|| cfg.details.get("rate"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1024 * 1024); // default 1 MB/s
        Self { bytes_per_second }
    }
}

/// Sets connection context variables.
pub struct VarsHandler {
    pub vars: HashMap<String, String>,
}

impl VarsHandler {
    pub fn from_config(cfg: &Layer4HandlerConfig) -> Self {
        let mut vars = HashMap::new();
        if let Some(obj) = cfg.details.get("vars").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    vars.insert(k.clone(), s.to_string());
                }
            }
        }
        Self { vars }
    }

    pub fn apply(&self, ctx: &mut ConnectionContext) {
        for (k, v) in &self.vars {
            ctx.set_var(k, v);
        }
    }
}
