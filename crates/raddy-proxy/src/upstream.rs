use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents an upstream destination with concurrency tracking and health state.
#[derive(Debug)]
pub struct Upstream {
    pub dial: String,
    pub host: String,
    pub port: u16,
    pub is_tls: bool,
    is_healthy: AtomicBool,
    active_requests: AtomicUsize,
    fail_count: AtomicUsize,
    unhealthy_until: AtomicI64,
}

impl Upstream {
    pub fn new(dial: impl Into<String>) -> Self {
        let raw = dial.into();
        let target = crate::transport::parse_upstream_target(&raw, false);
        Self {
            dial: target.dial_addr,
            host: target.host,
            port: target.port,
            is_tls: target.is_tls,
            is_healthy: AtomicBool::new(true),
            active_requests: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
            unhealthy_until: AtomicI64::new(0),
        }
    }

    pub fn with_tls(mut self, tls: bool) -> Self {
        self.is_tls = tls;
        self
    }

    /// Determines if the upstream is currently healthy and eligible for requests.
    pub fn is_available(&self) -> bool {
        if !self.is_healthy.load(Ordering::Relaxed) {
            return false;
        }

        let until = self.unhealthy_until.load(Ordering::Relaxed);
        if until > 0 {
            let now = current_time_secs();
            if now < until {
                return false;
            } else {
                // Cooldown period expired, tentatively allow requests
                self.unhealthy_until.store(0, Ordering::Relaxed);
                self.fail_count.store(0, Ordering::Relaxed);
            }
        }

        true
    }

    pub fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    pub fn inc_active(&self) -> usize {
        self.active_requests.fetch_add(1, Ordering::SeqCst)
    }

    pub fn dec_active(&self) {
        self.active_requests.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::Relaxed);
        if healthy {
            self.fail_count.store(0, Ordering::Relaxed);
            self.unhealthy_until.store(0, Ordering::Relaxed);
        }
    }

    pub fn record_success(&self) {
        self.fail_count.store(0, Ordering::Relaxed);
        self.unhealthy_until.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self, max_fails: usize, fail_duration_secs: u64) {
        let fails = self.fail_count.fetch_add(1, Ordering::Relaxed) + 1;
        if max_fails > 0 && fails >= max_fails {
            let until = current_time_secs() + fail_duration_secs as i64;
            self.unhealthy_until.store(until, Ordering::Relaxed);
            tracing::warn!(
                "Upstream '{}' marked passively unhealthy until unix timestamp {}",
                self.dial,
                until
            );
        }
    }
}

fn current_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
