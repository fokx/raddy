use crate::context::ConnectionContext;
use crate::error::{Layer4Error, Result};
use crate::route::CompiledRoute;
use crate::stream::PrefixedStream;
use raddy_core::config::{Config, Layer4Server};
use raddy_tls::TlsManager;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

/// Represents a single Layer 4 server instance bound to one or more network listeners.
pub struct Layer4ServerInstance {
    pub name: String,
    pub listen_addrs: Vec<String>,
    pub routes: Arc<Vec<CompiledRoute>>,
    pub matching_timeout: Duration,
    pub idle_timeout: Duration,
    tcp_listeners: Vec<TcpListener>,
    udp_sockets: Vec<Arc<UdpSocket>>,
}

impl Layer4ServerInstance {
    pub fn new(
        name: impl Into<String>,
        server_cfg: &Layer4Server,
        tls_manager: Option<Arc<TlsManager>>,
    ) -> Result<Self> {
        let name = name.into();
        let mut routes = Vec::new();
        for r_cfg in &server_cfg.routes {
            routes.push(CompiledRoute::compile(r_cfg, tls_manager.clone())?);
        }

        let matching_timeout = server_cfg
            .matching_timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(3));

        let idle_timeout = server_cfg
            .idle_timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(30));

        let listen_addrs = if server_cfg.listen.is_empty() {
            vec![":2222".to_string()]
        } else {
            server_cfg.listen.clone()
        };

        Ok(Self {
            name,
            listen_addrs,
            routes: Arc::new(routes),
            matching_timeout,
            idle_timeout,
            tcp_listeners: Vec::new(),
            udp_sockets: Vec::new(),
        })
    }

    /// Binds all configured network listeners (TCP and UDP).
    pub async fn bind(&mut self) -> Result<()> {
        for addr_str in &self.listen_addrs {
            let (is_udp, is_tcp, target_addr) = parse_listen_addr(addr_str);

            if is_tcp {
                if target_addr.starts_with(':') {
                    let port: u16 = target_addr[1..].parse().map_err(|e| {
                        Layer4Error::Config(format!("Invalid port in '{}': {}", target_addr, e))
                    })?;
                    // Bind IPv4
                    let v4_addr = SocketAddr::from(([0, 0, 0, 0], port));
                    match bind_tcp_listener(v4_addr, false) {
                        Ok(l) => self.tcp_listeners.push(l),
                        Err(e) => {
                            tracing::warn!("Failed to bind TCP IPv4 on {}: {}", v4_addr, e);
                        }
                    }
                    // Bind IPv6
                    let v6_addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
                    if let Ok(l) = bind_tcp_listener(v6_addr, true) {
                        self.tcp_listeners.push(l);
                    }
                } else {
                    let parsed: SocketAddr = target_addr.parse().map_err(|e| {
                        Layer4Error::Config(format!(
                            "Invalid socket address '{}': {}",
                            target_addr, e
                        ))
                    })?;
                    let l = bind_tcp_listener(parsed, parsed.is_ipv6())?;
                    self.tcp_listeners.push(l);
                }
            }

            if is_udp {
                let resolved_addr = if target_addr.starts_with(':') {
                    format!("0.0.0.0{}", target_addr)
                } else {
                    target_addr.clone()
                };
                let parsed: SocketAddr = resolved_addr.parse().map_err(|e| {
                    Layer4Error::Config(format!(
                        "Invalid UDP socket address '{}': {}",
                        resolved_addr, e
                    ))
                })?;
                let sock = UdpSocket::bind(parsed).await?;
                self.udp_sockets.push(Arc::new(sock));
            }
        }

        if self.tcp_listeners.is_empty() && self.udp_sockets.is_empty() {
            return Err(Layer4Error::Config(format!(
                "Server '{}' could not bind to any listener address in {:?}",
                self.name, self.listen_addrs
            )));
        }

        tracing::info!(
            "Layer 4 server '{}' successfully bound to {:?}",
            self.name,
            self.listen_addrs
        );

        Ok(())
    }

    /// Runs the server event loop until shutdown signal is received.
    pub async fn run(self, shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut set = tokio::task::JoinSet::new();

        // 1. Spawn TCP listeners
        for listener in self.tcp_listeners {
            let routes = self.routes.clone();
            let matching_timeout = self.matching_timeout;
            let mut conn_shutdown_rx = shutdown_rx.clone();

            set.spawn(async move {
                let local_addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                };

                loop {
                    tokio::select! {
                        accept_res = listener.accept() => {
                            match accept_res {
                                Ok((mut stream, remote_addr)) => {
                                    let routes_task = routes.clone();
                                    tokio::spawn(async move {
                                        let mut ctx = ConnectionContext::new(remote_addr, local_addr);
                                        // Check if any route needs payload data
                                        let needs_payload = routes_task.iter().any(|r| r.requires_payload());

                                        let mut prefetched = Vec::new();
                                        if needs_payload {
                                            let mut buf = vec![0u8; 4096];
                                            match tokio::time::timeout(matching_timeout, stream.read(&mut buf)).await {
                                                Ok(Ok(n)) if n > 0 => {
                                                    prefetched.extend_from_slice(&buf[..n]);
                                                }
                                                Ok(Ok(_)) => {
                                                    // EOF reached before data
                                                    return;
                                                }
                                                Ok(Err(e)) => {
                                                    tracing::debug!("Layer 4 read error from {}: {}", remote_addr, e);
                                                    return;
                                                }
                                                Err(_) => {
                                                    // Matching timeout, continue with empty prefetched
                                                }
                                            }
                                        }

                                        // Find first matching route
                                        let matched_route = routes_task.iter().find(|r| r.matches(&mut ctx, &prefetched));

                                        if let Some(route) = matched_route {
                                            let wrapped = PrefixedStream::new(stream, prefetched);
                                            if let Err(e) = route.execute_tcp(wrapped, &mut ctx).await {
                                                tracing::debug!("Layer 4 route error for {}: {}", remote_addr, e);
                                            }
                                        } else {
                                            tracing::debug!("Layer 4: No matching route for connection from {}", remote_addr);
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("Layer 4 accept error on {}: {}", local_addr, e);
                                }
                            }
                        }
                        _ = conn_shutdown_rx.changed() => {
                            if *conn_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        // 2. Spawn UDP sockets
        for socket in self.udp_sockets {
            let routes = self.routes.clone();
            let mut conn_shutdown_rx = shutdown_rx.clone();

            set.spawn(async move {
                let local_addr = match socket.local_addr() {
                    Ok(a) => a,
                    Err(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                };
                let mut buf = vec![0u8; 65535];

                loop {
                    tokio::select! {
                        recv_res = socket.recv_from(&mut buf) => {
                            match recv_res {
                                Ok((n, remote_addr)) => {
                                    let packet = buf[..n].to_vec();
                                    let routes_task = routes.clone();
                                    let sock_task = socket.clone();
                                    tokio::spawn(async move {
                                        let mut ctx = ConnectionContext::new(remote_addr, local_addr);
                                        let matched_route = routes_task.iter().find(|r| r.matches(&mut ctx, &packet));
                                        if let Some(route) = matched_route {
                                            let _ = route.execute_udp(&sock_task, &packet, remote_addr, &mut ctx).await;
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("Layer 4 UDP recv error on {}: {}", local_addr, e);
                                }
                            }
                        }
                        _ = conn_shutdown_rx.changed() => {
                            if *conn_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        // Wait for shutdown signal
        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                tracing::debug!("Layer 4 listener task exit: {}", e);
            }
        }

        tracing::info!("Layer 4 server '{}' gracefully shut down", self.name);
        Ok(())
    }
}

/// Helper to parse duration strings like "3s", "30s", "500ms".
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        num.parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(num) = s.strip_suffix('s') {
        num.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn parse_listen_addr(addr: &str) -> (bool, bool, String) {
    let trimmed = addr.trim();
    if let Some(rest) = trimmed.strip_prefix("udp/") {
        (true, false, rest.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("tcp/") {
        (false, true, rest.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("tcp+udp/") {
        (true, true, rest.to_string())
    } else {
        // Default to TCP
        (false, true, trimmed.to_string())
    }
}

fn bind_tcp_listener(addr: SocketAddr, v6_only: bool) -> Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(v6_only);
    }
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

/// Coordinates and manages all running Layer 4 server instances.
pub struct Layer4Manager {
    servers: Vec<Layer4ServerInstance>,
}

impl Layer4Manager {
    pub async fn from_config(
        config: &Config,
        tls_manager: Option<Arc<TlsManager>>,
    ) -> Result<Self> {
        let mut servers = Vec::new();
        if let Some(l4_app) = config.layer4_app() {
            for (name, srv_cfg) in &l4_app.servers {
                let instance =
                    Layer4ServerInstance::new(name, srv_cfg, tls_manager.clone())?;
                servers.push(instance);
            }
        }
        Ok(Self { servers })
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    pub async fn bind_all(&mut self) -> Result<()> {
        for server in &mut self.servers {
            server.bind().await?;
        }
        Ok(())
    }

    pub fn spawn_all(self) -> (tokio::task::JoinSet<Result<()>>, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut join_set = tokio::task::JoinSet::new();
        for server in self.servers {
            let rx = shutdown_rx.clone();
            join_set.spawn(async move { server.run(rx).await });
        }
        (join_set, shutdown_tx)
    }

    pub fn spawn_all_detached(self) -> watch::Sender<bool> {
        let (join_set, shutdown_tx) = self.spawn_all();
        tokio::spawn(async move {
            let mut set = join_set;
            while let Some(res) = set.join_next().await {
                if let Err(e) = res {
                    tracing::error!("Layer 4 server error: {}", e);
                }
            }
        });
        shutdown_tx
    }
}
