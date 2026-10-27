use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use raddy_core::config::Config;
use raddy_core::module::ModuleRegistry;
use raddy_tls::TlsManager;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::error::{HttpServerError, Result};
use crate::router::{VirtualHostRouter, compile_virtual_host_router};
use crate::service::handle_request;

struct ConnTracker {
    count: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

impl ConnTracker {
    fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn enter(self: &Arc<Self>) -> ConnGuard {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ConnGuard {
            tracker: self.clone(),
        }
    }

    async fn wait_zero(&self) {
        while self.count.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            self.notify.notified().await;
        }
    }
}

struct ConnGuard {
    tracker: Arc<ConnTracker>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self
            .tracker
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            self.tracker.notify.notify_waiters();
        }
    }
}

/// A running HTTP or HTTPS server instance bound to a TCP address (and optionally a UDP address for HTTP/3).
pub struct HttpServerInstance {
    pub name: String,
    pub listen_addr: String,
    pub listen_addrs: Vec<String>,
    pub router: Arc<VirtualHostRouter>,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub quic_server_config: Option<quinn::ServerConfig>,
    pub quic_endpoint: Option<quinn::Endpoint>,
    pub quic_endpoints: Vec<quinn::Endpoint>,
    pub protocols: Vec<String>,
    pub alt_svc_port: Option<u16>,
    pub challenge_store: Option<raddy_tls::acme::Http01ChallengeStore>,
    pub log_pipeline: Option<Arc<crate::logging::LogPipeline>>,
    pub server_logs: Option<raddy_core::config::ServerLogConfig>,
    listeners: Vec<TcpListener>,
    local_addrs: Vec<SocketAddr>,
}

impl HttpServerInstance {
    pub fn new(
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        router: VirtualHostRouter,
    ) -> Self {
        let addr = listen_addr.into();
        Self {
            name: name.into(),
            listen_addr: addr.clone(),
            listen_addrs: vec![addr],
            router: Arc::new(router),
            tls_acceptor: None,
            quic_server_config: None,
            quic_endpoint: None,
            quic_endpoints: Vec::new(),
            protocols: vec!["h1".into(), "h2".into(), "h3".into()],
            alt_svc_port: None,
            challenge_store: None,
            log_pipeline: None,
            server_logs: None,
            listeners: Vec::new(),
            local_addrs: Vec::new(),
        }
    }

    pub fn with_listen_addrs(mut self, addrs: Vec<String>) -> Self {
        if !addrs.is_empty() {
            self.listen_addr = addrs[0].clone();
            self.listen_addrs = addrs;
        }
        self
    }

    pub fn with_logging(
        mut self,
        pipeline: Arc<crate::logging::LogPipeline>,
        logs: Option<raddy_core::config::ServerLogConfig>,
    ) -> Self {
        self.log_pipeline = Some(pipeline);
        self.server_logs = logs;
        self
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

    /// Binds the TCP listeners (supporting dual-stack IPv4/IPv6) and UDP endpoints for HTTP/3 if configured.
    pub async fn bind(&mut self) -> Result<()> {
        let mut bound_listeners = Vec::new();
        let mut bound_addrs = Vec::new();

        let addrs_to_bind = if !self.listen_addrs.is_empty() {
            self.listen_addrs.clone()
        } else {
            vec![self.listen_addr.clone()]
        };

        for listen_spec in &addrs_to_bind {
            if listen_spec.starts_with(':') {
                let port: u16 = listen_spec[1..].parse().map_err(|e| {
                    HttpServerError::Server(format!(
                        "Invalid port in listen_addr '{}': {}",
                        listen_spec, e
                    ))
                })?;

                // 1. Bind IPv4 (0.0.0.0:port)
                let v4_addr = SocketAddr::from(([0, 0, 0, 0], port));
                match bind_tcp_listener(v4_addr, false) {
                    Ok(l) => {
                        let addr = l.local_addr()?;
                        bound_addrs.push(addr);
                        bound_listeners.push(l);
                    }
                    Err(e) => {
                        tracing::debug!("IPv4 bind on 0.0.0.0:{} failed: {}", port, e);
                    }
                }

                // Effective port if ephemeral port (0) was specified
                let effective_port = bound_addrs.last().map(|a| a.port()).unwrap_or(port);

                // 2. Bind IPv6 ([::]:effective_port) with v6_only = true so it coexists cleanly with IPv4
                let v6_addr = SocketAddr::from(([0u16; 8], effective_port));
                match bind_tcp_listener(v6_addr, true) {
                    Ok(l) => {
                        let addr = l.local_addr()?;
                        bound_addrs.push(addr);
                        bound_listeners.push(l);
                    }
                    Err(e) => {
                        tracing::debug!("IPv6 bind on [::]:{} failed: {}", effective_port, e);
                    }
                }
            } else {
                let addrs = tokio::net::lookup_host(listen_spec).await?;
                let mut bound_any = false;
                let mut last_err = None;
                for addr in addrs {
                    let v6_only = addr.is_ipv6();
                    match bind_tcp_listener(addr, v6_only) {
                        Ok(l) => {
                            bound_addrs.push(l.local_addr()?);
                            bound_listeners.push(l);
                            bound_any = true;
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
                if !bound_any {
                    if let Some(err) = last_err {
                        return Err(err);
                    }
                }
            }
        }

        if bound_listeners.is_empty() {
            return Err(HttpServerError::Server(format!(
                "Failed to bind any TCP listener for '{}'",
                self.listen_addr
            )));
        }

        self.listeners = bound_listeners;
        self.local_addrs = bound_addrs.clone();

        // Bind QUIC UDP endpoints for all bound addresses if TLS and h3 are enabled
        if self.tls_acceptor.is_some() && self.protocols.iter().any(|p| p == "h3") {
            if let Some(quic_cfg) = self.quic_server_config.take() {
                for &bound_addr in &self.local_addrs {
                    match quinn::Endpoint::server(quic_cfg.clone(), bound_addr) {
                        Ok(ep) => {
                            tracing::info!(
                                "Server '{}' [HTTP/3 QUIC] successfully bound to UDP {}",
                                self.name,
                                bound_addr
                            );
                            if self.quic_endpoint.is_none() {
                                self.quic_endpoint = Some(ep.clone());
                            }
                            self.quic_endpoints.push(ep);
                            if self.alt_svc_port.is_none() {
                                self.alt_svc_port = Some(bound_addr.port());
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to bind QUIC endpoint on UDP {}: {}",
                                bound_addr,
                                e
                            );
                        }
                    }
                }
            }
        }

        let proto = if self.tls_acceptor.is_some() {
            if !self.quic_endpoints.is_empty() || self.quic_endpoint.is_some() {
                "HTTPS (HTTP/1.1, HTTP/2, HTTP/3)"
            } else {
                "HTTPS (HTTP/1.1, HTTP/2)"
            }
        } else {
            "HTTP (HTTP/1.1, HTTP/2 Cleartext)"
        };
        let addrs_str = self
            .local_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(
            "Server '{}' [{}] successfully bound to {}",
            self.name,
            proto,
            addrs_str
        );
        Ok(())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addrs.first().copied()
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// Runs the connection acceptance loop until shutdown is signaled.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let listeners = std::mem::take(&mut self.listeners);
        if listeners.is_empty() {
            return Err(HttpServerError::Server(
                "Server instance not bound. Call bind() first.".into(),
            ));
        }

        let router = self.router.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let challenge_store = self.challenge_store.clone();
        let auto_builder = Builder::new(TokioExecutor::new());
        let alt_svc_port = self.alt_svc_port;
        let log_pipeline = self.log_pipeline.clone();
        let server_logs = self.server_logs.clone();

        let tracker = Arc::new(ConnTracker::new());
        let mut set = tokio::task::JoinSet::new();

        for listener in listeners {
            let router_clone = router.clone();
            let tls_acceptor_clone = tls_acceptor.clone();
            let challenge_store_clone = challenge_store.clone();
            let auto_builder_clone = auto_builder.clone();
            let alt_svc_port_val = alt_svc_port;
            let log_pipeline_clone = log_pipeline.clone();
            let server_logs_clone = server_logs.clone();
            let mut conn_shutdown_rx = shutdown_rx.clone();
            let listen_addr_str = self.listen_addr.clone();
            let tracker_task = tracker.clone();

            set.spawn(async move {
                loop {
                    tokio::select! {
                        res = listener.accept() => {
                            match res {
                                Ok((tcp_stream, remote_addr)) => {
                                    let router_task = router_clone.clone();
                                    let builder_task = auto_builder_clone.clone();
                                    let acceptor_task = tls_acceptor_clone.clone();
                                    let challenge_store_task = challenge_store_clone.clone();
                                    let log_pipe_task = log_pipeline_clone.clone();
                                    let srv_logs_task = server_logs_clone.clone();
                                    let mut per_conn_shutdown_rx = conn_shutdown_rx.clone();
                                    let guard = tracker_task.enter();

                                    tokio::spawn(async move {
                                        let _guard = guard;
                                        if let Some(acceptor) = acceptor_task {
                                            // TLS handshake (HTTP/1.1 or HTTP/2)
                                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                                Ok(s) => s,
                                                Err(e) => {
                                                    tracing::debug!("TLS handshake failed: {}", e);
                                                    return;
                                                }
                                            };
                                            let tls_sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                                            let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol();
                                            if negotiated_alpn == Some(b"acme-tls/1") {
                                                tracing::info!(
                                                    "Completed ACME TLS-ALPN-01 handshake for SNI {:?} from {}",
                                                    tls_sni,
                                                    remote_addr
                                                );
                                                return;
                                            }
                                            let io = TokioIo::new(tls_stream);
                                            let cstore = challenge_store_task.clone();
                                            let lp = log_pipe_task.clone();
                                            let sl = srv_logs_task.clone();
                                            let service = hyper::service::service_fn(move |req| {
                                                let r = router_task.clone();
                                                let cs = cstore.clone();
                                                let pipe = lp.clone();
                                                let logs = sl.clone();
                                                let sni = tls_sni.clone();
                                                async move {
                                                    handle_request(req, Some(remote_addr), r, alt_svc_port_val, cs, pipe, logs, sni).await
                                                }
                                            });

                                            let conn = builder_task.serve_connection_with_upgrades(io, service).into_owned();
                                            tokio::pin!(conn);
                                            tokio::select! {
                                                res = &mut conn => {
                                                    if let Err(err) = res {
                                                        tracing::debug!("HTTPS connection error: {}", err);
                                                    }
                                                }
                                                _ = per_conn_shutdown_rx.changed() => {
                                                    conn.as_mut().graceful_shutdown();
                                                    let _ = conn.await;
                                                }
                                            }
                                        } else {
                                            // Cleartext HTTP (HTTP/1.1 or HTTP/2 cleartext)
                                            let io = TokioIo::new(tcp_stream);
                                            let cstore = challenge_store_task.clone();
                                            let lp = log_pipe_task.clone();
                                            let sl = srv_logs_task.clone();
                                            let service = hyper::service::service_fn(move |req| {
                                                let r = router_task.clone();
                                                let cs = cstore.clone();
                                                let pipe = lp.clone();
                                                let logs = sl.clone();
                                                async move {
                                                    handle_request(req, Some(remote_addr), r, None, cs, pipe, logs, None).await
                                                }
                                            });

                                            let conn = builder_task.serve_connection_with_upgrades(io, service).into_owned();
                                            tokio::pin!(conn);
                                            tokio::select! {
                                                res = &mut conn => {
                                                    if let Err(err) = res {
                                                        tracing::debug!("HTTP connection error: {}", err);
                                                    }
                                                }
                                                _ = per_conn_shutdown_rx.changed() => {
                                                    conn.as_mut().graceful_shutdown();
                                                    let _ = conn.await;
                                                }
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("TCP accept error on {}: {}", listen_addr_str, e);
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

        let quic_endpoints = if !self.quic_endpoints.is_empty() {
            std::mem::take(&mut self.quic_endpoints)
        } else if let Some(ep) = self.quic_endpoint.take() {
            vec![ep]
        } else {
            Vec::new()
        };

        let mut quic_set = tokio::task::JoinSet::new();
        for ep in quic_endpoints.clone() {
            let router_clone = router.clone();
            let lp = log_pipeline.clone();
            let sl = server_logs.clone();
            let mut ep_shutdown_rx = shutdown_rx.clone();
            let tracker_clone = tracker.clone();
            quic_set.spawn(async move {
                loop {
                    tokio::select! {
                        Some(incoming) = ep.accept() => {
                            let router_task = router_clone.clone();
                            let lp_task = lp.clone();
                            let sl_task = sl.clone();
                            let guard = tracker_clone.enter();
                            tokio::spawn(async move {
                                let _guard = guard;
                                match incoming.await {
                                    Ok(conn) => {
                                        let remote = conn.remote_address();
                                        if let Err(e) = crate::http3::serve_h3_connection(conn, remote, router_task, lp_task, sl_task).await {
                                            tracing::debug!("H3 connection error from {}: {}", remote, e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("QUIC handshake failed: {}", e);
                                    }
                                }
                            });
                        }
                        _ = ep_shutdown_rx.changed() => {
                            if *ep_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Server '{}' on {} shutting down gracefully", self.name, self.listen_addr);
                        for ep in &quic_endpoints {
                            ep.close(0u32.into(), b"server shutdown");
                        }
                        break;
                    }
                }
            }
        }

        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                tracing::error!("TCP accept task join error: {}", e);
            }
        }

        while let Some(res) = quic_set.join_next().await {
            if let Err(e) = res {
                tracing::error!("QUIC accept task join error: {}", e);
            }
        }

        // Wait for all in-flight connections to complete (eternal grace period)
        tracker.wait_zero().await;

        Ok(())
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
        let log_pipeline = Arc::new(crate::logging::LogPipeline::from_config(config));

        if let Some(http) = config.http_app() {
            for (name, srv_cfg) in &http.servers {
                let vhost_router = compile_virtual_host_router(srv_cfg, registry)?;
                let listen_addrs = srv_cfg.listen.clone();
                let listen_addr = listen_addrs
                    .first()
                    .cloned()
                    .unwrap_or_else(|| ":80".into());
                let is_tls = listen_addrs.iter().any(|l| l.ends_with(":443"))
                    || srv_cfg.tls_connection_policies.is_some();
                let protocols = srv_cfg
                    .protocols
                    .clone()
                    .unwrap_or_else(|| vec!["h1".into(), "h2".into(), "h3".into()]);

                let mut instance = HttpServerInstance::new(name, listen_addr, vhost_router)
                    .with_listen_addrs(listen_addrs)
                    .with_protocols(protocols)
                    .with_logging(log_pipeline.clone(), srv_cfg.logs.clone());

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
                                                    .map(|pols| {
                                                        pols.iter().any(|p| {
                                                            p.certificate_selection
                                                                .as_ref()
                                                                .and_then(|cs| cs.any_tag.as_ref())
                                                                .map(|tags| {
                                                                    tags.iter()
                                                                        .any(|t| t == "internal")
                                                                })
                                                                .unwrap_or(false)
                                                        })
                                                    })
                                                    .unwrap_or(false);

                                                if force_internal
                                                    || raddy_tls::manager::is_local_or_private(h)
                                                {
                                                    if let Err(e) =
                                                        tls.provision_identifier(h, true).await
                                                    {
                                                        tracing::warn!(
                                                            "Failed to auto-provision internal cert for '{}': {}",
                                                            h,
                                                            e
                                                        );
                                                    }
                                                } else if tls.cert_exists(h).await {
                                                    if let Err(e) =
                                                        tls.provision_identifier(h, false).await
                                                    {
                                                        tracing::warn!(
                                                            "Failed to load cached cert for '{}': {}",
                                                            h,
                                                            e
                                                        );
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
                            if let Ok(quic_cfg) =
                                crate::http3::build_quic_server_config(&rustls_cfg)
                            {
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
            join_set.spawn(async move { srv.run(rx).await });
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
                tracing::warn!(
                    "Failed to auto-provision ACME certificate for '{}': {}",
                    identifier,
                    e
                );
            }
        }
        Ok(())
    }
}
