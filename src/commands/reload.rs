use anyhow::{Context, Result, bail};
use std::path::Path;

/// Executes `raddy reload` via Admin API.
pub async fn reload_command(
    config: &Path,
    adapter: Option<&str>,
    address: &str,
    _force: bool,
) -> Result<()> {
    if !config.exists() {
        bail!("Configuration file not found: {}", config.display());
    }

    let is_json = match adapter {
        Some("json") => true,
        Some("caddyfile") => false,
        _ => config.extension().and_then(|ext| ext.to_str()) == Some("json"),
    };

    let (content, content_type) = if is_json {
        let content = std::fs::read_to_string(config)
            .with_context(|| format!("Failed to read '{}'", config.display()))?;
        (content, "application/json")
    } else {
        let cfg = raddy_caddyfile::adapt_caddyfile_from_file(config)
            .map_err(|e| anyhow::anyhow!("Failed to adapt Caddyfile '{}': {}", config.display(), e))?;
        let json_str = serde_json::to_string(&cfg)
            .context("Failed to serialize adapted configuration to JSON")?;
        (json_str, "application/json")
    };

    let target_addr = if address == "http://127.0.0.1:2019" || address == "127.0.0.1:2019" {
        if let Ok(cfg) = crate::commands::config_ops::load_or_adapt(config, adapter) {
            cfg.admin
                .and_then(|a| a.listen)
                .unwrap_or_else(|| address.to_string())
        } else {
            address.to_string()
        }
    } else {
        address.to_string()
    };

    let client = raddy_admin::AdminClient::new(&target_addr);
    tracing::info!("Sending reload request to {}...", target_addr);

    let mut req_builder = http::Request::builder()
        .method(http::Method::POST)
        .uri("/load")
        .header(http::header::CONTENT_TYPE, content_type);
    if _force {
        req_builder = req_builder.header("cache-control", "must-revalidate");
    }

    let req = req_builder
        .body(bytes::Bytes::from(content))
        .context("Failed to construct reload HTTP request")?;

    let resp = client
        .send(req)
        .await
        .with_context(|| format!("Failed to connect to Raddy Admin API at '{}'", target_addr))?;

    if resp.is_success() {
        println!("Successfully reloaded configuration via Admin API.");
        Ok(())
    } else {
        bail!("Failed to reload configuration: {}", resp.text());
    }
}
