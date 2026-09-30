use std::sync::Arc;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::watch;
use raddy_core::config::Config;
use raddy_core::module::ModuleRegistry;
use raddy_http::server::ServerManager;
use raddy_tls::TlsManager;

use crate::error::{AdminError, Result};

/// Shared state for the Admin API and server lifecycle.
pub struct AppState {
    pub config: ArcSwap<Config>,
    pub registry: Arc<ModuleRegistry>,
    pub tls_manager: Option<Arc<TlsManager>>,
    pub active_shutdown: Arc<Mutex<Option<watch::Sender<bool>>>>,
    pub admin_shutdown: Arc<Mutex<Option<watch::Sender<bool>>>>,
    pub exit_notify: Arc<tokio::sync::Notify>,
}

impl AppState {
    pub fn new(
        initial_config: Config,
        registry: Arc<ModuleRegistry>,
        tls_manager: Option<Arc<TlsManager>>,
    ) -> Self {
        Self {
            config: ArcSwap::new(Arc::new(initial_config)),
            registry,
            tls_manager,
            active_shutdown: Arc::new(Mutex::new(None)),
            admin_shutdown: Arc::new(Mutex::new(None)),
            exit_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Performs zero-downtime hot reload:
    /// 1. Validates and compiles new server instances from `new_config`.
    /// 2. Binds listeners for new servers. If binding fails, aborts reload and leaves old servers running.
    /// 3. Gracefully drains old servers via watch shutdown signal.
    /// 4. Spawns new server background tasks.
    /// 5. Atomically stores `new_config` in `ArcSwap`.
    pub async fn reload(&self, new_config: Config) -> Result<()> {
        let mut server_manager = ServerManager::from_config(
            &new_config,
            &self.registry,
            self.tls_manager.clone(),
        )
        .await
        .map_err(AdminError::HttpServer)?;

        // Attempt binding first. If this fails, the old server continues serving without interruption.
        server_manager.bind_all().await.map_err(AdminError::HttpServer)?;

        let pending_acme = server_manager.pending_acme().to_vec();

        // Gracefully drain existing servers
        {
            let mut lock = self.active_shutdown.lock();
            if let Some(old_tx) = lock.take() {
                let _ = old_tx.send(true);
            }

            // Spawn new servers detached
            let new_shutdown_tx = server_manager.spawn_all_detached();
            *lock = Some(new_shutdown_tx);
        }

        // Atomically swap in the new configuration
        self.config.store(Arc::new(new_config));
        tokio::task::yield_now().await;
        tracing::info!("Configuration successfully reloaded and swapped");

        // Now that port 80 & 443 listeners are bound and running,
        // provision any pending public ACME certificates.
        if let Some(ref tls) = self.tls_manager {
            if !pending_acme.is_empty() {
                for h in pending_acme {
                    let tls_clone = tls.clone();
                    let h_clone = h.clone();
                    tracing::info!("Beginning ACME automated certificate provisioning for '{}'...", h);
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        tls.provision_identifier(&h, false),
                    ).await {
                        Ok(Ok(())) => {
                            tracing::info!("ACME certificate ready and installed for '{}'", h_clone);
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Failed to auto-provision ACME cert for '{}': {}", h_clone, e);
                        }
                        Err(_) => {
                            tracing::info!("ACME provisioning for '{}' taking longer than 30s, continuing in background...", h_clone);
                            tokio::spawn(async move {
                                if let Err(e) = tls_clone.provision_identifier(&h_clone, false).await {
                                    tracing::error!("Background auto-provisioning failed for '{}': {}", h_clone, e);
                                } else {
                                    tracing::info!("Background auto-provisioning succeeded for '{}'", h_clone);
                                }
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Gracefully stops all active HTTP/HTTPS servers.
    pub fn stop_servers(&self) {
        let mut lock = self.active_shutdown.lock();
        if let Some(tx) = lock.take() {
            let _ = tx.send(true);
            tracing::info!("Shutdown signal sent to all running servers");
        }
    }

    /// Gracefully stops the entire application (servers and admin API).
    pub fn stop_all(&self) {
        self.stop_servers();
        let mut lock = self.admin_shutdown.lock();
        if let Some(tx) = lock.take() {
            let _ = tx.send(true);
            tracing::info!("Shutdown signal sent to admin server");
        }
        self.exit_notify.notify_waiters();
    }
}
