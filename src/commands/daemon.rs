use anyhow::{Context, Result, bail};
use std::path::Path;

/// Executes `raddy start` (daemon background launch).
pub async fn start_command(
    config: &Path,
    adapter: Option<&str>,
    pidfile: Option<&Path>,
    watch: bool,
    ca: Option<String>,
    staging: bool,
    debug: bool,
) -> Result<()> {
    let current_exe =
        std::env::current_exe().context("Failed to determine current executable path")?;
    let mut cmd = std::process::Command::new(current_exe);
    cmd.arg("run").arg("--config").arg(config);

    if let Some(a) = adapter {
        cmd.arg("--adapter").arg(a);
    }
    if let Some(p) = pidfile {
        cmd.arg("--pidfile").arg(p);
    }
    if watch {
        cmd.arg("--watch");
    }
    if let Some(ref c) = ca {
        cmd.arg("--ca").arg(c);
    }
    if staging {
        cmd.arg("--staging");
    }
    if debug {
        cmd.arg("--debug");
    }

    cmd.stdin(std::process::Stdio::null());

    let child = cmd
        .spawn()
        .context("Failed to spawn background Raddy process")?;
    let pid = child.id();

    // Poll the Admin API to verify readiness
    let admin_address = if let Ok(cfg) = crate::commands::config_ops::load_or_adapt(config, adapter) {
        cfg.admin.and_then(|a| a.listen).unwrap_or_else(|| "127.0.0.1:2019".into())
    } else {
        "127.0.0.1:2019".into()
    };
    let client = raddy_admin::AdminClient::new(&admin_address);
    let mut ready = false;

    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(resp) = client.get("/").await {
            if resp.is_success() {
                ready = true;
                break;
            }
        }
    }

    if ready {
        println!("Successfully started Raddy in the background (PID {})", pid);
    } else {
        println!(
            "Raddy background process started with PID {}, but Admin API did not respond within 4s",
            pid
        );
    }

    Ok(())
}

/// Executes `raddy stop` via Admin API.
pub async fn stop_command(address: &str) -> Result<()> {
    let target_addr = if address == "http://127.0.0.1:2019" || address == "127.0.0.1:2019" {
        if Path::new("Caddyfile").exists() {
            if let Ok(cfg) = crate::commands::config_ops::load_or_adapt(Path::new("Caddyfile"), None) {
                cfg.admin.and_then(|a| a.listen).unwrap_or_else(|| address.to_string())
            } else {
                address.to_string()
            }
        } else {
            address.to_string()
        }
    } else {
        address.to_string()
    };

    let client = raddy_admin::AdminClient::new(&target_addr);
    tracing::info!("Sending stop request to {}...", target_addr);

    let resp = client
        .post("/stop", bytes::Bytes::new(), None)
        .await
        .with_context(|| format!("Failed to connect to Raddy Admin API at '{}'", target_addr))?;

    if resp.is_success() {
        println!("Stop signal accepted by Admin API.");
        Ok(())
    } else {
        bail!("Failed to stop Raddy via Admin API: {}", resp.text());
    }
}
