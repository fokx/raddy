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
