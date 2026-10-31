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

fn resolve_env_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = remaining.find('{') {
        out.push_str(&remaining[..start]);
        let after_brace = &remaining[start + 1..];
        if let Some(end) = after_brace.find('}') {
            let inner = &after_brace[..end];
            let (is_env, var_spec) = if let Some(stripped) = inner.strip_prefix('$') {
                (true, stripped)
            } else if let Some(stripped) = inner.strip_prefix("env.") {
                (true, stripped)
            } else {
                (false, "")
            };

            if is_env {
                let (var_name, default_val) = if let Some((v, d)) = var_spec.split_once(':') {
                    (v, Some(d))
                } else {
                    (var_spec, None)
                };

                let val = std::env::var(var_name).ok();
                match (val, default_val) {
                    (Some(v), Some(d)) => {
                        if v.is_empty() {
                            out.push_str(d);
                        } else {
                            out.push_str(&v);
                        }
                    }
                    (Some(v), None) => out.push_str(&v),
                    (None, Some(d)) => out.push_str(d),
                    (None, None) => {}
                }
            } else {
                out.push('{');
                out.push_str(inner);
                out.push('}');
            }
            remaining = &after_brace[end + 1..];
        } else {
            out.push('{');
            remaining = after_brace;
        }
    }
    out.push_str(remaining);
    out
}

impl Upstream {
    pub fn new(dial: impl Into<String>) -> Self {
        let mut raw = dial.into();
        if raw.contains("{env.") || raw.contains("{$") {
            raw = resolve_env_string(&raw);
        }
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
        if fail_duration_secs == 0 {
            return;
        }
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
