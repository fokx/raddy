use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::api::build_admin_router;
use crate::error::{AdminError, Result};
use crate::state::AppState;

/// Running Admin API HTTP server.
pub struct AdminServer {
    pub listen_addr: String,
    pub state: Arc<AppState>,
    listener: Option<TcpListener>,
    local_addr: Option<SocketAddr>,
}

impl AdminServer {
    pub fn new(listen_addr: impl Into<String>, state: Arc<AppState>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            state,
            listener: None,
            local_addr: None,
        }
    }

    /// Binds the Admin TCP listener.
    pub async fn bind(&mut self) -> Result<()> {
        let addr = if self.listen_addr.starts_with(':') {
            format!("127.0.0.1{}", self.listen_addr)
        } else {
            self.listen_addr.clone()
        };

        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            AdminError::Internal(format!("Failed to bind Admin API on {}: {}", addr, e))
        })?;

        let local_addr = listener.local_addr().map_err(|e| {
            AdminError::Internal(format!("Failed to query Admin local_addr: {}", e))
        })?;
        self.local_addr = Some(local_addr);
        self.listener = Some(listener);

        tracing::info!("Admin API successfully bound on http://{}", local_addr);
        Ok(())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Runs the Admin HTTP API until shutdown is signaled.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let listener = match self.listener.take() {
            Some(l) => l,
            None => {
                self.bind().await?;
                self.listener.take().unwrap()
            }
        };

        let local_addr = self.local_addr.unwrap_or_else(|| listener.local_addr().unwrap());
        tracing::info!("Admin API running on http://{}", local_addr);

        let app = build_admin_router(self.state.clone());

        // Wire admin shutdown receiver into state
        {
            let (admin_tx, mut rx) = watch::channel(false);
            *self.state.admin_shutdown.lock() = Some(admin_tx);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {},
                        _ = rx.changed() => {},
                    }
                    tracing::info!("Admin API shutting down gracefully");
                })
                .await
                .map_err(|e| AdminError::Internal(format!("Admin server error: {}", e)))?;
        }

        Ok(())
    }
}
