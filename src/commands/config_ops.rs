use std::path::Path;
use anyhow::{bail, Context, Result};
use raddy_caddyfile::{adapt_caddyfile_from_file, format_caddyfile_str};
use raddy_core::config::Config;

/// Loads or adapts a configuration from a file path.
/// Automatically detects JSON vs Caddyfile or adheres to `--adapter`.
pub fn load_or_adapt(path: &Path, adapter: Option<&str>) -> Result<Config> {
    if !path.exists() {
        bail!("Configuration file not found: {}", path.display());
    }

    let is_json = match adapter {
        Some("json") => true,
        Some("caddyfile") => false,
        _ => path.extension().and_then(|ext| ext.to_str()) == Some("json"),
    };

    if is_json {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JSON config at '{}'", path.display()))?;
        let config: Config = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse JSON config at '{}'", path.display()))?;
        Ok(config)
    } else {
        adapt_caddyfile_from_file(path)
            .map_err(|e| anyhow::anyhow!("Caddyfile adaptation error in '{}': {}", path.display(), e))
    }
}

/// Executes `raddy adapt` command.
pub fn adapt_command(
    config: &Path,
    adapter: Option<&str>,
    pretty: bool,
    validate: bool,
) -> Result<()> {
    let internal_config = load_or_adapt(config, adapter)?;

    if validate {
        validate_config(&internal_config)?;
    }

    let json = if pretty {
        serde_json::to_string_pretty(&internal_config)?
    } else {
        serde_json::to_string(&internal_config)?
    };

    println!("{}", json);
    Ok(())
}

/// Executes `raddy validate` command.
pub fn validate_command(config: &Path, adapter: Option<&str>) -> Result<()> {
    let internal_config = load_or_adapt(config, adapter)?;
    validate_config(&internal_config)?;

    let http_app = internal_config.http_app();
    let server_count = http_app.as_ref().map(|a| a.servers.len()).unwrap_or(0);
    let route_count: usize = http_app
        .as_ref()
        .map(|a| a.servers.values().map(|s| s.routes.len()).sum())
        .unwrap_or(0);

    println!("Valid configuration");
    println!("  Servers : {}", server_count);
    println!("  Routes  : {}", route_count);
    Ok(())
}

/// Performs sanity checks on adapted configuration.
fn validate_config(config: &Config) -> Result<()> {
    if let Some(http) = config.http_app() {
        for (name, srv) in &http.servers {
            if srv.listen.is_empty() {
                bail!("Server '{}' has no listen addresses configured", name);
            }
        }
    }
    Ok(())
}

/// Executes `raddy fmt` command.
pub fn fmt_command(config: &Path, overwrite: bool) -> Result<()> {
    if !config.exists() {
        bail!("Caddyfile not found at: {}", config.display());
    }

    let content = std::fs::read_to_string(config)
        .with_context(|| format!("Failed to read '{}'", config.display()))?;

    let formatted = format_caddyfile_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to format Caddyfile: {}", e))?;

    if overwrite {
        if content != formatted {
            std::fs::write(config, &formatted)
                .with_context(|| format!("Failed to write formatted file to '{}'", config.display()))?;
            println!("Formatted '{}'", config.display());
        } else {
            println!("'{}' already formatted", config.display());
        }
    } else {
        print!("{}", formatted);
    }

    Ok(())
}
