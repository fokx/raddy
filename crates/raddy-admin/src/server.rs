use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::watch;

use crate::address::{parse_admin_addr, ParsedAdminAddr};
use crate::api::build_admin_router;
use crate::error::{AdminError, Result};
use crate::state::AppState;

enum BoundListener {
    Tcp(TcpListener, SocketAddr),
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        path: PathBuf,
    },
}

/// Running Admin API HTTP server.
pub struct AdminServer {
    pub listen_addr: String,
    pub state: Arc<AppState>,
    listener: Option<BoundListener>,
    local_addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
}

impl AdminServer {
    pub fn new(listen_addr: impl Into<String>, state: Arc<AppState>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            state,
            listener: None,
            local_addr: None,
            unix_path: None,
        }
    }

    /// Returns the local TCP socket address if listening over TCP.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Returns the socket path if listening over a Unix domain socket.
    pub fn socket_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    /// Binds the Admin listener (TCP or Unix socket).
    pub async fn bind(&mut self) -> Result<()> {
        let parsed = parse_admin_addr(&self.listen_addr)?;
        match parsed {
            ParsedAdminAddr::Tcp(addr) => {
                let listener = TcpListener::bind(&addr).await.map_err(|e| {
                    AdminError::Internal(format!("Failed to bind Admin API on {}: {}", addr, e))
                })?;

                let local_addr = listener.local_addr().map_err(|e| {
                    AdminError::Internal(format!("Failed to query Admin local_addr: {}", e))
                })?;
                self.local_addr = Some(local_addr);
                self.listener = Some(BoundListener::Tcp(listener, local_addr));

                tracing::info!("Admin API successfully bound on http://{}", local_addr);
                Ok(())
            }
            #[cfg(unix)]
            ParsedAdminAddr::Unix { path, mode } => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }

                if std::fs::symlink_metadata(&path).is_ok() {
                    // Check if an active process is currently listening on this socket
                    let in_use = match tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        tokio::net::UnixStream::connect(&path),
                    )
                    .await
                    {
                        Ok(Ok(_stream)) => true,
                        _ => false,
                    };

                    if in_use {
                        return Err(AdminError::Internal(format!(
                            "Failed to bind Admin API on unix socket {}: socket is actively in use by another running process (e.g. another Raddy or Caddy instance)",
                            path.display()
                        )));
                    } else {
                        tracing::info!(
                            "Found residual unix socket file at '{}' with no active process listening. Safely removing stale socket.",
                            path.display()
                        );
                        if let Err(e) = std::fs::remove_file(&path) {
                            tracing::warn!(
                                "Failed to remove residual unix socket file at '{}': {}",
                                path.display(),
                                e
                            );
                        }
                    }
                }

                let listener = UnixListener::bind(&path).map_err(|e| {
                    AdminError::Internal(format!(
                        "Failed to bind Admin API on unix socket {}: {}",
                        path.display(),
                        e
                    ))
                })?;

                if let Some(mode_val) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode_val)) {
                        tracing::warn!(
                            "Failed to set socket permissions 0{:o} on {}: {}",
                            mode_val,
                            path.display(),
                            e
                        );
                    }
                }

                self.unix_path = Some(path.clone());
                self.listener = Some(BoundListener::Unix {
                    listener,
                    path: path.clone(),
                });

                tracing::info!("Admin API successfully bound on unix/{}", path.display());
                Ok(())
            }
            #[cfg(not(unix))]
            ParsedAdminAddr::Unix { .. } => {
                Err(AdminError::Internal(
                    "Unix domain sockets are not supported on this operating system".into(),
                ))
            }
        }
    }

    /// Runs the Admin HTTP API until shutdown is signaled.
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let bound = match self.listener.take() {
            Some(b) => b,
            None => {
                self.bind().await?;
                self.listener.take().unwrap()
            }
        };

        let app = build_admin_router(self.state.clone());

        // Wire admin shutdown receiver into state
        let (admin_tx, mut rx) = watch::channel(false);
        *self.state.admin_shutdown.lock() = Some(admin_tx);

        let shutdown_signal = async move {
            tokio::select! {
                _ = shutdown_rx.changed() => {},
                _ = rx.changed() => {},
            }
            tracing::info!("Admin API shutting down gracefully");
        };

        match bound {
            BoundListener::Tcp(listener, local_addr) => {
                tracing::info!("Admin API running on http://{}", local_addr);
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal)
                    .await
                    .map_err(|e| AdminError::Internal(format!("Admin server error: {}", e)))?;
            }
            #[cfg(unix)]
            BoundListener::Unix { listener, path } => {
                tracing::info!("Admin API running on unix/{}", path.display());
                let res = axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal)
                    .await
                    .map_err(|e| AdminError::Internal(format!("Admin server error: {}", e)));
                let _ = std::fs::remove_file(&path);
                res?;
            }
        }

        Ok(())
    }
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        if let Some(ref path) = self.unix_path {
            let _ = std::fs::remove_file(path);
        }
    }
}
