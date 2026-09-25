use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use raddy_caddyfile::adapt_caddyfile_from_file;
use raddy_core::module::ModuleRegistry;

#[derive(Parser, Debug)]
#[command(name = "raddy", version, about = "Raddy - Fast, extensible web server in Rust (Caddy compatible)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Adapts a Caddyfile to Raddy internal JSON configuration (like caddy adapt)
    Adapt {
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Format output with nice indentation
        #[arg(short, long, default_value_t = true)]
        pretty: bool,
    },

    /// Validates a Caddyfile without starting the server
    Validate {
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,
    },

    /// Runs Raddy with the specified configuration file
    Run {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,
    },

    /// Sends a configuration reload request to a running Raddy instance via Admin API
    Reload {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Admin API address
        #[arg(short, long, default_value = "http://127.0.0.1:2019")]
        address: String,
    },

    /// Sends a stop request to a running Raddy instance via Admin API
    Stop {
        /// Admin API address
        #[arg(short, long, default_value = "http://127.0.0.1:2019")]
        address: String,
    },

    /// Formats or inspects a Caddyfile
    Fmt {
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Adapt { config, pretty } => {
            let internal_config = load_or_adapt(&config)?;
            let json = if pretty {
                serde_json::to_string_pretty(&internal_config)?
            } else {
                serde_json::to_string(&internal_config)?
            };
            println!("{}", json);
        }

        Commands::Validate { config } => {
            let internal_config = load_or_adapt(&config)?;
            let http_app = internal_config.http_app();
            let server_count = http_app.as_ref().map(|a| a.servers.len()).unwrap_or(0);
            println!(
                "Valid configuration: {} server(s) configured.",
                server_count
            );
        }

        Commands::Run { config } => {
            let internal_config = load_or_adapt(&config)?;
            let registry = std::sync::Arc::new(ModuleRegistry::new());

            let admin_listen = internal_config.admin.as_ref()
                .and_then(|a| a.listen.clone())
                .unwrap_or_else(|| "127.0.0.1:2019".into());
            let admin_disabled = internal_config.admin.as_ref()
                .and_then(|a| a.disabled)
                .unwrap_or(false);

            tracing::info!("Raddy server initializing...");
            let tls_manager = std::sync::Arc::new(raddy_tls::TlsManager::new(None, true)?);
            let state = std::sync::Arc::new(raddy_admin::AppState::new(
                internal_config.clone(),
                registry,
                Some(tls_manager),
            ));

            // Start HTTP/HTTPS servers
            state.reload(internal_config).await?;

            let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);
            let admin_task = if !admin_disabled {
                let mut admin_server = raddy_admin::AdminServer::new(admin_listen, state.clone());
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

            tracing::info!("Raddy server running. Press Ctrl+C to stop.");

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received interrupt signal, initiating graceful shutdown...");
                }
            }

            let _ = admin_shutdown_tx.send(true);
            state.stop_all();

            if let Some(task) = admin_task {
                let _ = task.await;
            }

            tracing::info!("Raddy server stopped.");
        }

        Commands::Reload { config, address } => {
            let content = std::fs::read_to_string(&config)?;
            let is_json = config.extension().and_then(|e| e.to_str()) == Some("json");
            let content_type = if is_json { "application/json" } else { "text/caddyfile" };

            let client = reqwest::Client::new();
            let url = format!("{}/load", address.trim_end_matches('/'));
            tracing::info!("Sending reload request to {}...", url);

            let resp = client.post(&url)
                .header("content-type", content_type)
                .body(content)
                .send()
                .await?;

            if resp.status().is_success() {
                println!("Successfully reloaded configuration via Admin API.");
            } else {
                let err_text = resp.text().await?;
                eprintln!("Failed to reload configuration: {}", err_text);
                std::process::exit(1);
            }
        }

        Commands::Stop { address } => {
            let client = reqwest::Client::new();
            let url = format!("{}/stop", address.trim_end_matches('/'));
            tracing::info!("Sending stop request to {}...", url);

            let resp = client.post(&url).send().await?;
            if resp.status().is_success() {
                println!("Stop signal accepted by Admin API.");
            } else {
                let err_text = resp.text().await?;
                eprintln!("Failed to stop server: {}", err_text);
                std::process::exit(1);
            }
        }

        Commands::Fmt { config } => {
            let content = std::fs::read_to_string(&config)?;
            let ast = raddy_caddyfile::parse_caddyfile(&content)?;
            println!("Successfully parsed Caddyfile AST with {} site block(s)", ast.site_blocks.len());
        }
    }

    Ok(())
}

fn load_or_adapt(path: &Path) -> anyhow::Result<raddy_core::Config> {
    if !path.exists() {
        anyhow::bail!("Configuration file not found: {}", path.display());
    }

    // If file ends with .json, parse directly
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        let content = std::fs::read_to_string(path)?;
        let config: raddy_core::Config = serde_json::from_str(&content)?;
        return Ok(config);
    }

    // Otherwise adapt from Caddyfile
    let config = adapt_caddyfile_from_file(path)
        .map_err(|e| anyhow::anyhow!("Caddyfile adaptation error: {}", e))?;
    Ok(config)
}
