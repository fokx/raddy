//! systemd service manager notifications (`sd_notify`).

#[cfg(unix)]
pub use sd_notify::{NotifyState, notify};

#[cfg(not(unix))]
#[derive(Clone, Debug)]
pub enum NotifyState<'a> {
    Ready,
    Reloading,
    Stopping,
    Status(&'a str),
    MonotonicUsec(i128),
}

#[cfg(not(unix))]
impl NotifyState<'_> {
    pub fn monotonic_usec_now() -> std::io::Result<Self> {
        Ok(NotifyState::MonotonicUsec(0))
    }
}

#[cfg(not(unix))]
pub fn notify(_state: &[NotifyState]) -> std::io::Result<()> {
    Ok(())
}

const STATUS_SERVING: &str = "Serving HTTP requests";
const STATUS_CONFIG_ERROR: &str = "Config error; running on previous config";
const STATUS_SHUTTING_DOWN: &str = "Shutting down";

fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("NOTIFY_SOCKET").is_some_and(|v| !v.is_empty())
    })
}

fn send(states: &[NotifyState]) {
    if !enabled() {
        return;
    }

    if let Err(err) = notify(states) {
        tracing::warn!("systemd notification failed: {err}");
    }
}

pub fn notify_serving() {
    send(&[NotifyState::Ready, NotifyState::Status(STATUS_SERVING)]);
}

pub fn notify_config_error() {
    send(&[NotifyState::Ready, NotifyState::Status(STATUS_CONFIG_ERROR)]);
}

pub fn notify_reloading() {
    if let Ok(monotonic_usec) = NotifyState::monotonic_usec_now() {
        send(&[
            NotifyState::Reloading,
            monotonic_usec,
            NotifyState::Status("Reloading configuration"),
        ]);
    }
}

pub fn notify_stopping() {
    send(&[NotifyState::Stopping, NotifyState::Status(STATUS_SHUTTING_DOWN)]);
}
