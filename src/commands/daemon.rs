use std::path::Path;
use anyhow::{bail, Context, Result};

/// Executes `raddy start` (daemon background launch).
pub async fn start_command(
    config: &Path,
    adapter: Option<&str>,
    pidfile: Option<&Path>,
    watch: bool,
) -> Result<()> {
    let current_exe = std::env::current_exe().context("Failed to determine current executable path")?;
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

    cmd.stdin(std::process::Stdio::null());

    let child = cmd.spawn().context("Failed to spawn background Raddy process")?;
    let pid = child.id();

    // Poll the Admin API to verify readiness
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()?;
    let mut ready = false;

    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(resp) = client.get("http://127.0.0.1:2019/").send().await {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
    }

    if ready {
        println!("Successfully started Raddy in the background (PID {})", pid);
    } else {
        println!("Raddy background process started with PID {}, but Admin API did not respond within 4s", pid);
    }

    Ok(())
}

/// Executes `raddy stop` via Admin API.
pub async fn stop_command(address: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/stop", address.trim_end_matches('/'));
    tracing::info!("Sending stop request to {}...", url);

    let resp = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to Raddy Admin API at '{}'", url))?;

    if resp.status().is_success() {
        println!("Stop signal accepted by Admin API.");
        Ok(())
    } else {
        let err = resp.text().await.unwrap_or_default();
        bail!("Failed to stop Raddy via Admin API: {}", err);
    }
}
