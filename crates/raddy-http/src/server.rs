use std::net::SocketAddr;
use std::sync::Arc;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use raddy_core::config::Config;
use raddy_core::module::ModuleRegistry;
use raddy_tls::TlsManager;

use crate::error::{HttpServerError, Result};
use crate::router::{compile_virtual_host_router, VirtualHostRouter};
use crate::service::handle_request;

/// A running HTTP or HTTPS server instance bound to a TCP address (and optionally a UDP address for HTTP/3).
pub struct HttpServerInstance {
    pub name: String,
    pub listen_addr: String,
    pub router: Arc<VirtualHostRouter>,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub quic_server_config: Option<quinn::ServerConfig>,
    pub quic_endpoint: Option<quinn::Endpoint>,
    pub protocols: Vec<String>,
    pub alt_svc_port: Option<u16>,
    pub challenge_store: Option<raddy_tls::acme::Http01ChallengeStore>,
    listener: Option<TcpListener>,
    local_addr: Option<SocketAddr>,
}

impl HttpServerInstance {
    pub fn new(name: impl Into<String>, listen_addr: impl Into<String>, router: VirtualHostRouter) -> Self {
        Self {
            name: name.into(),
            listen_addr: listen_addr.into(),
            router: Arc::new(router),
            tls_acceptor: None,
            quic_server_config: None,
            quic_endpoint: None,
            protocols: vec!["h1".into(), "h2".into(), "h3".into()],
            alt_svc_port: None,
            challenge_store: None,
            listener: None,
            local_addr: None,
        }
    }

    pub fn with_challenge_store(mut self, store: raddy_tls::acme::Http01ChallengeStore) -> Self {
        self.challenge_store = Some(store);
        self
    }

    pub fn with_tls_acceptor(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    pub fn with_quic_config(mut self, config: quinn::ServerConfig) -> Self {
        self.quic_server_config = Some(config);
        self
    }

    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols = protocols;
        self
    }

    /// Binds the TCP listener (and UDP endpoint for HTTP/3 if configured).
    pub async fn bind(&mut self) -> Result<()> {
        let addr_str = if self.listen_addr.starts_with(':') {
            format!("0.0.0.0{}", self.listen_addr)
        } else {
            self.listen_addr.clone()
        };

        let sock_addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| HttpServerError::Server(format!("Failed to resolve address: {}", addr_str)))?;

        let domain = if sock_addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };

        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        let _ = socket.set_reuse_port(true);
        socket.set_nonblocking(true)?;
        socket.bind(&sock_addr.into())?;
        socket.listen(1024)?;

        let std_listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(std_listener)?;
        let local_addr = listener.local_addr()?;
        self.local_addr = Some(local_addr);
        self.listener = Some(listener);

        // Bind QUIC UDP endpoint on the same address if TLS and h3 are enabled
        if self.tls_acceptor.is_some() && self.protocols.iter().any(|p| p == "h3") {
            if let Some(quic_cfg) = self.quic_server_config.take() {
                match quinn::Endpoint::server(quic_cfg, local_addr) {
                    Ok(ep) => {
                        tracing::info!("Server '{}' [HTTP/3 QUIC] successfully bound to UDP {}", self.name, local_addr);
                        self.quic_endpoint = Some(ep);
                        self.alt_svc_port = Some(local_addr.port());
                    }
                    Err(e) => {
                        tracing::warn!("Failed to bind QUIC endpoint on UDP {}: {}", local_addr, e);
                    }
                }
            }
        }

        let proto = if self.tls_acceptor.is_some() {
            if self.quic_endpoint.is_some() { "HTTPS (HTTP/1.1, HTTP/2, HTTP/3)" } else { "HTTPS (HTTP/1.1, HTTP/2)" }
        } else {
            "HTTP (HTTP/1.1, HTTP/2 Cleartext)"
        };
        tracing::info!("Server '{}' [{}] successfully bound to {}", self.name, proto, local_addr);
        Ok(())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Runs the connection acceptance loop until shutdown is signaled.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            HttpServerError::Server("Server instance not bound. Call bind() first.".into())
        })?;

        let router = self.router.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let challenge_store = self.challenge_store.clone();
        let auto_builder = Builder::new(TokioExecutor::new());
        let alt_svc_port = self.alt_svc_port;
        let quic_endpoint = self.quic_endpoint;

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((tcp_stream, remote_addr)) => {
                            let router_clone = router.clone();
                            let builder = auto_builder.clone();
                            let acceptor_opt = tls_acceptor.clone();
                            let challenge_store_clone = challenge_store.clone();
                            let mut conn_shutdown_rx = shutdown_rx.clone();

                            tokio::spawn(async move {
                                if let Some(acceptor) = acceptor_opt {
                                    // TLS handshake (HTTP/1.1 or HTTP/2)
                                    let tls_stream = match acceptor.accept(tcp_stream).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::debug!("TLS handshake failed: {}", e);
                                            return;
                                        }
                                    };
                                    let io = TokioIo::new(tls_stream);
                                    let cstore = challenge_store_clone.clone();
                                    let service = hyper::service::service_fn(move |req| {
                                        let r = router_clone.clone();
                                        let cs = cstore.clone();
                                        async move {
                                            handle_request(req, Some(remote_addr), r, alt_svc_port, cs).await
                                        }
                                    });

                                    let conn = builder.serve_connection_with_upgrades(io, service).into_owned();
                                    tokio::pin!(conn);
                                    tokio::select! {
                                        res = &mut conn => {
                                            if let Err(err) = res {
                                                tracing::debug!("HTTPS connection error: {}", err);
                                            }
                                        }
                                        _ = conn_shutdown_rx.changed() => {
                                            conn.as_mut().graceful_shutdown();
                                            let _ = conn.await;
                                        }
                                    }
                                } else {
                                    // Cleartext HTTP (HTTP/1.1 or HTTP/2 cleartext)
                                    let io = TokioIo::new(tcp_stream);
                                    let cstore = challenge_store_clone.clone();
                                    let service = hyper::service::service_fn(move |req| {
                                        let r = router_clone.clone();
                                        let cs = cstore.clone();
                                        async move {
                                            handle_request(req, Some(remote_addr), r, None, cs).await
                                        }
                                    });

                                    let conn = builder.serve_connection_with_upgrades(io, service).into_owned();
                                    tokio::pin!(conn);
                                    tokio::select! {
                                        res = &mut conn => {
                                            if let Err(err) = res {
                                                tracing::debug!("HTTP connection error: {}", err);
                                            }
                                        }
                                        _ = conn_shutdown_rx.changed() => {
                                            conn.as_mut().graceful_shutdown();
                                            let _ = conn.await;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("TCP accept error on {}: {}", self.listen_addr, e);
                        }
                    }
                }

                Some(incoming) = async {
                    if let Some(ref ep) = quic_endpoint {
                        ep.accept().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    let router_clone = router.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                let remote = conn.remote_address();
                                if let Err(e) = crate::http3::serve_h3_connection(conn, remote, router_clone).await {
                                    tracing::debug!("H3 connection error from {}: {}", remote, e);
                                }
                            }
                            Err(e) => {
                                tracing::debug!("QUIC handshake failed: {}", e);
                            }
                        }
                    });
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Server '{}' on {} shutting down gracefully", self.name, self.listen_addr);
                        if let Some(ep) = quic_endpoint {
                            ep.close(0u32.into(), b"server shutdown");
                        }
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Manager responsible for instantiating and coordinating HTTP/HTTPS servers from configuration.
pub struct ServerManager {
    servers: Vec<HttpServerInstance>,
    shutdown_tx: watch::Sender<bool>,
    tls_manager: Option<Arc<TlsManager>>,
    pending_acme: Vec<String>,
}

impl ServerManager {
    pub async fn from_config(
        config: &Config,
        registry: &ModuleRegistry,
        tls_manager: Option<Arc<TlsManager>>,
    ) -> Result<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let mut servers = Vec::new();
        let mut pending_acme = Vec::new();

        if let Some(http) = config.http_app() {
            for (name, srv_cfg) in &http.servers {
                let vhost_router = compile_virtual_host_router(srv_cfg, registry)?;
                let listen_addr = srv_cfg.listen.first().cloned().unwrap_or_else(|| ":80".into());
                let is_tls = listen_addr.ends_with(":443") || srv_cfg.tls_connection_policies.is_some();
                let protocols = srv_cfg.protocols.clone().unwrap_or_else(|| vec!["h1".into(), "h2".into(), "h3".into()]);

                let mut instance = HttpServerInstance::new(name, listen_addr, vhost_router).with_protocols(protocols);

                if let Some(ref tls) = tls_manager {
                    instance = instance.with_challenge_store(tls.challenge_store());
                }

                if is_tls {
                    if let Some(ref tls) = tls_manager {
                        // Provision certificates for all hosts configured on this server
                        for route in &srv_cfg.routes {
                            if let Some(ref matchers) = route.r#match {
                                for m in matchers {
                                    if let Some(ref hosts) = m.host {
                                        for h in hosts {
                                            if h != "*" && !h.is_empty() {
                                                let force_internal = srv_cfg
                                                    .tls_connection_policies
                                                    .as_ref()
                                                    .map(|pols| pols.iter().any(|p| {
                                                        p.certificate_selection
                                                             .as_ref()
                                                             .and_then(|cs| cs.any_tag.as_ref())
                                                             .map(|tags| tags.iter().any(|t| t == "internal"))
                                                             .unwrap_or(false)
                                                     }))
                                                    .unwrap_or(false);

                                                if force_internal || raddy_tls::manager::is_local_or_private(h) {
                                                    if let Err(e) = tls.provision_identifier(h, true).await {
                                                        tracing::warn!("Failed to auto-provision internal cert for '{}': {}", h, e);
                                                    }
                                                } else if tls.cert_exists(h).await {
                                                    if let Err(e) = tls.provision_identifier(h, false).await {
                                                        tracing::warn!("Failed to load cached cert for '{}': {}", h, e);
                                                    }
                                                } else {
                                                    // Queue for ACME provisioning once listeners are bound and running!
                                                    if !pending_acme.contains(h) {
                                                        pending_acme.push(h.clone());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if let Ok(acceptor) = tls.build_tls_acceptor() {
                            instance = instance.with_tls_acceptor(acceptor);
                        }

                        if let Ok(rustls_cfg) = tls.build_server_config() {
                            if let Ok(quic_cfg) = crate::http3::build_quic_server_config(&rustls_cfg) {
                                instance = instance.with_quic_config(quic_cfg);
                            }
                        }
                    }
                }

                servers.push(instance);
            }
        }


        Ok(Self {
            servers,
            shutdown_tx,
            tls_manager,
            pending_acme,
        })
    }

    pub fn servers_mut(&mut self) -> &mut [HttpServerInstance] {
        &mut self.servers
    }

    pub fn servers(&self) -> &[HttpServerInstance] {
        &self.servers
    }

    pub fn tls_manager(&self) -> Option<Arc<TlsManager>> {
        self.tls_manager.clone()
    }

    /// Binds all servers to their respective ports.
    pub async fn bind_all(&mut self) -> Result<()> {
        for srv in &mut self.servers {
            srv.bind().await?;
        }
        Ok(())
    }

    /// Spawns background tasks running all server instances.
    pub fn spawn_all(self) -> (tokio::task::JoinSet<Result<()>>, watch::Sender<bool>) {
        let mut join_set = tokio::task::JoinSet::new();
        let shutdown_tx = self.shutdown_tx.clone();

        for srv in self.servers {
            let rx = shutdown_tx.subscribe();
            join_set.spawn(async move {
                srv.run(rx).await
            });
        }

        (join_set, shutdown_tx)
    }

    /// Spawns background tasks running all server instances detached into the Tokio runtime.
    pub fn spawn_all_detached(self) -> watch::Sender<bool> {
        let shutdown_tx = self.shutdown_tx.clone();

        for srv in self.servers {
            let rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                if let Err(e) = srv.run(rx).await {
                    tracing::debug!("Server error: {}", e);
                }
            });
        }

        shutdown_tx
    }

    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn pending_acme(&self) -> &[String] {
        &self.pending_acme
    }

    pub async fn provision_pending_acme(&self, tls: &Arc<TlsManager>) -> Result<()> {
        for identifier in &self.pending_acme {
            if let Err(e) = tls.provision_identifier(identifier, false).await {
                tracing::warn!("Failed to auto-provision ACME certificate for '{}': {}", identifier, e);
            }
        }
        Ok(())
    }
}


