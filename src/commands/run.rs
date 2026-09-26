use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use notify::Watcher;
use raddy_admin::{AdminServer, AppState as AdminAppState};
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::config::Config;
use raddy_core::module::ModuleRegistry;
use raddy_tls::TlsManager;

use crate::commands::config_ops::load_or_adapt;
use crate::commands::info::print_environ;

/// Executes `raddy run` command.
pub async fn run_command(
    config: &Path,
    adapter: Option<&str>,
    pidfile: Option<&Path>,
    watch: bool,
    environ: bool,
) -> Result<()> {
    if environ {
        print_environ();
    }

    if let Some(p) = pidfile {
        std::fs::write(p, std::process::id().to_string())
            .with_context(|| format!("Failed to write pidfile to '{}'", p.display()))?;
    }

    let initial_config = load_or_adapt(config, adapter)?;
    let res = run_server_loop(initial_config, config, adapter, watch).await;

    if let Some(p) = pidfile {
        let _ = std::fs::remove_file(p);
    }

    res
}

/// Executes `raddy file-server` quick launch command.
pub async fn file_server_command(
    listen: &str,
    root: &Path,
    browse: bool,
    access_log: bool,
) -> Result<()> {
    let browse_str = if browse { "browse" } else { "" };
    let log_str = if access_log { "log" } else { "" };

    let caddyfile_content = format!(
        "{listen} {{\n\troot * \"{root}\"\n\tfile_server {browse_str}\n\t{log_str}\n}}\n",
        listen = listen,
        root = root.display(),
        browse_str = browse_str,
        log_str = log_str,
    );

    let config = adapt_caddyfile(&caddyfile_content, root)
        .map_err(|e| anyhow::anyhow!("Failed to compile file-server config: {}", e))?;

    tracing::info!("Starting instant file server for '{}' on http://{}", root.display(), listen);
    run_server_loop(config, Path::new(""), None, false).await
}

async fn run_server_loop(
    initial_config: Config,
    config_path: &Path,
    adapter: Option<&str>,
    watch: bool,
) -> Result<()> {
    let registry = Arc::new(ModuleRegistry::new());

    let admin_listen = initial_config
        .admin
        .as_ref()
        .and_then(|a| a.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:2019".into());
    let admin_disabled = initial_config
        .admin
        .as_ref()
        .and_then(|a| a.disabled)
        .unwrap_or(false);

    tracing::info!("Raddy server initializing...");
    let (email, ca_url, staging) = if let Some(tls) = initial_config.tls_app() {
        let is_staging = tls.staging.unwrap_or(false)
            || tls.acme_ca.as_deref().map(|ca| ca.contains("staging")).unwrap_or(false);
        (tls.email, tls.acme_ca, is_staging)
    } else {
        let is_staging = std::env::var("RADDY_ACME_STAGING")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        (
            std::env::var("RADDY_ACME_EMAIL").ok(),
            std::env::var("RADDY_ACME_CA").ok(),
            is_staging,
        )
    };

    let tls_manager = if let Some(ref ca) = ca_url {
        Arc::new(TlsManager::new_with_ca(email, ca.clone())?)
    } else {
        Arc::new(TlsManager::new(email, staging)?)
    };
    let state = Arc::new(AdminAppState::new(
        initial_config.clone(),
        registry,
        Some(tls_manager),
    ));

    // Initial server start
    state.reload(initial_config).await?;

    let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);
    let admin_task = if !admin_disabled {
        let mut admin_server = AdminServer::new(admin_listen, state.clone());
        match admin_server.bind().await {
            Ok(_) => {
                let rx = admin_shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = admin_server.run(rx).await {
                        tracing::warn!("Admin server error: {}", e);
                    }
                }))
            }
            Err(e) => {
                tracing::warn!("Failed to bind Admin API: {}. Running without Admin API.", e);
                None
            }
        }
    } else {
        None
    };

    // Setup file watcher if --watch is requested
    let mut _watcher_holder = None;
    if watch && config_path.exists() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() {
                    let _ = tx.blocking_send(());
                }
            }
        })
        .context("Failed to initialize file watcher")?;

        watcher
            .watch(config_path, notify::RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch config at '{}'", config_path.display()))?;
        _watcher_holder = Some(watcher);

        let watch_path = PathBuf::from(config_path);
        let watch_adapter = adapter.map(|s| s.to_string());
        let watch_state = state.clone();

        tokio::spawn(async move {
            while (rx.recv().await).is_some() {
                // Debounce 100ms
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Drain any additional events
                while rx.try_recv().is_ok() {}

                tracing::info!("Config file '{}' modified, auto-reloading...", watch_path.display());
                match load_or_adapt(&watch_path, watch_adapter.as_deref()) {
                    Ok(new_cfg) => {
                        if let Err(e) = watch_state.reload(new_cfg).await {
                            tracing::error!("Failed to hot reload modified config: {}", e);
                        } else {
                            tracing::info!("Successfully reloaded configuration from '{}'", watch_path.display());
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading modified config: {}", e);
                    }
                }
            }
        });

        tracing::info!("Watching '{}' for changes", config_path.display());
    }

    tracing::info!("Raddy server running. Press Ctrl+C to stop.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received interrupt signal, initiating graceful shutdown...");
        }
        _ = state.exit_notify.notified() => {
            tracing::info!("Received stop signal via Admin API, exiting...");
        }
    }

    let _ = admin_shutdown_tx.send(true);
    state.stop_all();

    if let Some(task) = admin_task {
        let _ = task.await;
    }

    tracing::info!("Raddy server stopped.");
    Ok(())
}
