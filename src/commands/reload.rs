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

    let content = std::fs::read_to_string(config)
        .with_context(|| format!("Failed to read '{}'", config.display()))?;

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

    let client = reqwest::Client::new();
    let url = format!("{}/load", address.trim_end_matches('/'));
    tracing::info!("Sending reload request to {}...", url);

    let mut req = client
        .post(&url)
        .header("content-type", content_type);
    if _force {
        req = req.header("cache-control", "must-revalidate");
    }

    let resp = req
        .body(content)
        .send()
        .await
        .with_context(|| format!("Failed to connect to Raddy Admin API at '{}'", url))?;

    if resp.status().is_success() {
        println!("Successfully reloaded configuration via Admin API.");
        Ok(())
    } else {
        let err = resp.text().await.unwrap_or_default();
        bail!("Failed to reload configuration: {}", err);
    }
}
