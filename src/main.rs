use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use raddy_caddyfile::adapt_caddyfile_from_file;
use raddy_core::module::ModuleRegistry;
use raddy_core::state::AppState;
use raddy_http::server::ServerManager;

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
            let state = AppState::new(internal_config);
            let running_cfg = state.config();
            let registry = ModuleRegistry::new();

            tracing::info!("Raddy server initializing...");
            let tls_manager = std::sync::Arc::new(raddy_tls::TlsManager::new(None, true)?);
            let mut manager = ServerManager::from_config(&running_cfg, &registry, Some(tls_manager)).await?;

            manager.bind_all().await?;
            for srv in manager.servers() {
                if let Some(local) = srv.local_addr() {
                    let proto = if srv.tls_acceptor.is_some() { "https" } else { "http" };
                    tracing::info!("Server '{}' listening on {}://{}", srv.name, proto, local);
                }
            }

            let (mut join_set, shutdown_tx) = manager.spawn_all();
            tracing::info!("Raddy server running. Press Ctrl+C to stop.");

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received interrupt signal, initiating graceful shutdown...");
                    let _ = shutdown_tx.send(true);
                }
            }

            while let Some(res) = join_set.join_next().await {
                if let Err(e) = res {
                    tracing::error!("Server task error: {}", e);
                }
            }

            tracing::info!("Raddy server stopped.");
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
