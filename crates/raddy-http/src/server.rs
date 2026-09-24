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

/// A running HTTP or HTTPS server instance bound to a TCP address.
pub struct HttpServerInstance {
    pub name: String,
    pub listen_addr: String,
    pub router: Arc<VirtualHostRouter>,
    pub tls_acceptor: Option<TlsAcceptor>,
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
            listener: None,
            local_addr: None,
        }
    }

    pub fn with_tls_acceptor(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Binds the TCP listener.
    pub async fn bind(&mut self) -> Result<()> {
        let addr = if self.listen_addr.starts_with(':') {
            format!("0.0.0.0{}", self.listen_addr)
        } else {
            self.listen_addr.clone()
        };

        let listener = TcpListener::bind(&addr).await?;
        let local_addr = listener.local_addr()?;
        self.local_addr = Some(local_addr);
        self.listener = Some(listener);

        let proto = if self.tls_acceptor.is_some() { "HTTPS" } else { "HTTP" };
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
        let auto_builder = Builder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((tcp_stream, remote_addr)) => {
                            let router_clone = router.clone();
                            let builder = auto_builder.clone();
                            let acceptor_opt = tls_acceptor.clone();

                            tokio::spawn(async move {
                                if let Some(acceptor) = acceptor_opt {
                                    // TLS handshake
                                    let tls_stream = match acceptor.accept(tcp_stream).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::debug!("TLS handshake failed: {}", e);
                                            return;
                                        }
                                    };
                                    let io = TokioIo::new(tls_stream);
                                    let service = hyper::service::service_fn(move |req| {
                                        let r = router_clone.clone();
                                        async move {
                                            handle_request(req, Some(remote_addr), r).await
                                        }
                                    });

                                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                                        tracing::debug!("HTTPS connection error: {}", err);
                                    }
                                } else {
                                    // Cleartext HTTP
                                    let io = TokioIo::new(tcp_stream);
                                    let service = hyper::service::service_fn(move |req| {
                                        let r = router_clone.clone();
                                        async move {
                                            handle_request(req, Some(remote_addr), r).await
                                        }
                                    });

                                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                                        tracing::debug!("HTTP connection error: {}", err);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("TCP accept error on {}: {}", self.listen_addr, e);
                        }
                    }
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Server '{}' on {} shutting down gracefully", self.name, self.listen_addr);
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
}

impl ServerManager {
    pub async fn from_config(
        config: &Config,
        registry: &ModuleRegistry,
        tls_manager: Option<Arc<TlsManager>>,
    ) -> Result<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let mut servers = Vec::new();

        if let Some(http) = config.http_app() {
            for (name, srv_cfg) in &http.servers {
                let vhost_router = compile_virtual_host_router(srv_cfg, registry)?;
                let listen_addr = srv_cfg.listen.first().cloned().unwrap_or_else(|| ":80".into());
                let is_tls = listen_addr.ends_with(":443") || srv_cfg.tls_connection_policies.is_some();

                let mut instance = HttpServerInstance::new(name, listen_addr, vhost_router);

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

                                                if let Err(e) = tls.provision_identifier(h, force_internal).await {
                                                    tracing::warn!("Failed to auto-provision cert for '{}': {}", h, e);
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
                    }
                }

                servers.push(instance);
            }
        }

        Ok(Self {
            servers,
            shutdown_tx,
            tls_manager,
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

    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}
