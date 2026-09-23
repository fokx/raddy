use std::net::SocketAddr;
use std::sync::Arc;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use raddy_core::config::Config;
use raddy_core::module::ModuleRegistry;

use crate::error::{HttpServerError, Result};
use crate::router::{compile_virtual_host_router, VirtualHostRouter};
use crate::service::handle_request;

/// A running HTTP server instance bound to a TCP address.
pub struct HttpServerInstance {
    pub name: String,
    pub listen_addr: String,
    pub router: Arc<VirtualHostRouter>,
    listener: Option<TcpListener>,
    local_addr: Option<SocketAddr>,
}

impl HttpServerInstance {
    pub fn new(name: impl Into<String>, listen_addr: impl Into<String>, router: VirtualHostRouter) -> Self {
        Self {
            name: name.into(),
            listen_addr: listen_addr.into(),
            router: Arc::new(router),
            listener: None,
            local_addr: None,
        }
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

        tracing::info!("Server '{}' successfully bound to {}", self.name, local_addr);
        Ok(())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Runs the HTTP connection acceptance loop until shutdown is signaled.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            HttpServerError::Server("Server instance not bound. Call bind() first.".into())
        })?;

        let router = self.router.clone();
        let auto_builder = Builder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((tcp_stream, remote_addr)) => {
                            let io = TokioIo::new(tcp_stream);
                            let router_clone = router.clone();
                            let builder = auto_builder.clone();

                            tokio::spawn(async move {
                                let service = hyper::service::service_fn(move |req| {
                                    let r = router_clone.clone();
                                    async move {
                                        handle_request(req, Some(remote_addr), r).await
                                    }
                                });

                                if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                                    tracing::debug!("Connection error: {}", err);
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

/// Manager responsible for instantiating and coordinating HTTP servers from configuration.
pub struct ServerManager {
    servers: Vec<HttpServerInstance>,
    shutdown_tx: watch::Sender<bool>,
}

impl ServerManager {
    pub fn from_config(config: &Config, registry: &ModuleRegistry) -> Result<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let mut servers = Vec::new();

        if let Some(http) = config.http_app() {
            for (name, srv_cfg) in &http.servers {
                let vhost_router = compile_virtual_host_router(srv_cfg, registry)?;
                let listen_addr = srv_cfg.listen.first().cloned().unwrap_or_else(|| ":80".into());
                let instance = HttpServerInstance::new(name, listen_addr, vhost_router);
                servers.push(instance);
            }
        }

        Ok(Self {
            servers,
            shutdown_tx,
        })
    }

    pub fn servers_mut(&mut self) -> &mut [HttpServerInstance] {
        &mut self.servers
    }

    pub fn servers(&self) -> &[HttpServerInstance] {
        &self.servers
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
