use async_trait::async_trait;
use http::{HeaderValue, StatusCode};
use raddy_core::config::MatcherSet;
use raddy_core::context::Context;
use raddy_core::error::{CoreError, Result};
use raddy_core::handler::Handler;
use raddy_core::matcher::{CompiledMatcherSet, Matcher};
use raddy_core::placeholder::eval_placeholders;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Sliding window rate limiter implemented as a ring buffer of event timestamps.
///
/// Matches github.com/mholt/caddy-ratelimit's ring buffer algorithm:
/// - A ring buffer of capacity `max_events`.
/// - `cursor` points to the oldest timestamp in the ring buffer.
/// - If `now - ring[cursor] > window`, the request is allowed, the reservation
///   is placed at `cursor`, and `cursor` is advanced.
/// - Otherwise, the request is rejected and the remaining wait duration
///   `(ring[cursor] + window - now)` is returned.
#[derive(Debug, Clone)]
pub struct RingBufferRateLimiter {
    pub window: Duration,
    pub ring: Vec<Option<Instant>>,
    pub cursor: usize,
}

impl RingBufferRateLimiter {
    pub fn new(max_events: usize, window: Duration) -> Self {
        Self {
            window,
            ring: vec![None; max_events],
            cursor: 0,
        }
    }

    /// Evaluates if an event is allowed at `now`.
    ///
    /// If allowed, makes an immediate reservation and returns `Duration::ZERO`.
    /// If not allowed, returns the duration to wait before the next event is permitted.
    pub fn when(&mut self, now: Instant) -> Duration {
        if self.ring.is_empty() {
            // max_events == 0 means no requests allowed
            return if self.window.is_zero() {
                Duration::from_secs(1)
            } else {
                self.window
            };
        }

        if self.window.is_zero() {
            return Duration::ZERO;
        }

        let oldest_opt = self.ring[self.cursor];
        let allowed = match oldest_opt {
            None => true,
            Some(oldest) => now.duration_since(oldest) > self.window,
        };

        if allowed {
            self.ring[self.cursor] = Some(now);
            self.advance();
            Duration::ZERO
        } else {
            let oldest = oldest_opt.unwrap();
            let expires_at = oldest + self.window;
            expires_at.saturating_duration_since(now)
        }
    }

    fn advance(&mut self) {
        if !self.ring.is_empty() {
            self.cursor = (self.cursor + 1) % self.ring.len();
        }
    }

    /// Maximum events permitted within the sliding window.
    pub fn max_events(&self) -> usize {
        self.ring.len()
    }

    /// Dynamically resizes the ring buffer while preserving recent event history.
    pub fn set_max_events(&mut self, new_max: usize) {
        let old_len = self.ring.len();
        if new_max == old_len {
            return;
        }

        // Collect existing events in chronological order (oldest to newest)
        let mut events = Vec::new();
        if old_len > 0 {
            for i in 0..old_len {
                let idx = (self.cursor + i) % old_len;
                if let Some(t) = self.ring[idx] {
                    events.push(t);
                }
            }
        }

        let mut new_ring = vec![None; new_max];
        if new_max > 0 {
            if events.len() <= new_max {
                // Expanding or events fit:
                // Place empty slots first, then the events in chronological order
                let offset = new_max - events.len();
                for (i, t) in events.into_iter().enumerate() {
                    new_ring[offset + i] = Some(t);
                }
                self.cursor = 0;
            } else {
                // Shrinking: keep only the newest `new_max` events
                let skip = events.len() - new_max;
                for (i, t) in events.into_iter().skip(skip).enumerate() {
                    new_ring[i] = Some(t);
                }
                self.cursor = 0;
            }
        }

        self.ring = new_ring;
    }

    /// Updates the sliding window duration.
    pub fn set_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// Returns whether all events in the ring buffer have expired past `window`.
    pub fn is_expired(&self, now: Instant) -> bool {
        if self.ring.is_empty() {
            return true;
        }
        let newest_idx = if self.cursor == 0 {
            self.ring.len() - 1
        } else {
            self.cursor - 1
        };

        match self.ring[newest_idx] {
            None => true,
            Some(newest) => now.duration_since(newest) > self.window,
        }
    }

    /// Counts how many events are within the sliding window from `now`.
    pub fn count_in_window(&self, now: Instant) -> usize {
        let mut count = 0;
        for entry in &self.ring {
            if let Some(t) = entry {
                if now.duration_since(*t) <= self.window {
                    count += 1;
                }
            }
        }
        count
    }
}

/// A collection of rate limiters for a specific zone, keyed by client identifier.
#[derive(Debug)]
pub struct ZoneRateLimiter {
    limiters: Mutex<HashMap<String, RingBufferRateLimiter>>,
}

impl Default for ZoneRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneRateLimiter {
    pub fn new() -> Self {
        Self {
            limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Evaluates rate limit for `key` at timestamp `now`.
    pub fn when(
        &self,
        key: &str,
        now: Instant,
        max_events: usize,
        window: Duration,
    ) -> Duration {
        let mut map = self.limiters.lock().unwrap();
        let limiter = map
            .entry(key.to_string())
            .or_insert_with(|| RingBufferRateLimiter::new(max_events, window));
        limiter.when(now)
    }

    /// Updates existing rate limiters with new maximum events and window settings.
    pub fn update_all(&self, max_events: usize, window: Duration) {
        let mut map = self.limiters.lock().unwrap();
        for limiter in map.values_mut() {
            limiter.set_max_events(max_events);
            limiter.set_window(window);
        }
    }

    /// Sweeps expired rate limiters from memory.
    pub fn sweep(&self, now: Instant) {
        let mut map = self.limiters.lock().unwrap();
        map.retain(|_, rl| !rl.is_expired(now));
    }

    /// Returns the number of active tracked keys in this zone.
    pub fn keys_count(&self) -> usize {
        self.limiters.lock().unwrap().len()
    }

    /// Clears all keys in this zone.
    pub fn clear(&self) {
        self.limiters.lock().unwrap().clear();
    }
}

/// Global registry of rate limit zones persisting state across configuration reloads.
static GLOBAL_RATE_LIMIT_ZONES: LazyLock<Mutex<HashMap<String, Arc<ZoneRateLimiter>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Clears global rate limit zones (primarily for testing).
pub fn clear_global_rate_limit_zones() {
    let mut map = GLOBAL_RATE_LIMIT_ZONES.lock().unwrap();
    map.clear();
}

/// Masks an IP address key to a network prefix if configured.
///
/// Matches github.com/mholt/caddy-ratelimit's `applyNetworkPrefix`:
/// - IPv4 keys masked with `ipv4_prefix` CIDR bits (e.g. 24 -> 192.168.1.0/24)
/// - IPv6 keys masked with `ipv6_prefix` CIDR bits (e.g. 64 -> 2001:db8::/64)
/// - If non-IP or prefix is 0, returns key unchanged.
pub fn apply_network_prefix(key: &str, ipv4_prefix: usize, ipv6_prefix: usize) -> String {
    if ipv4_prefix == 0 && ipv6_prefix == 0 {
        return key.to_string();
    }

    let trimmed = key.trim();
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if ipv4_prefix > 0 && ipv4_prefix <= 32 {
                    if let Ok(net) = ipnet::Ipv4Net::new(v4, ipv4_prefix as u8) {
                        return net.trunc().to_string();
                    }
                }
            }
            std::net::IpAddr::V6(v6) => {
                if ipv6_prefix > 0 && ipv6_prefix <= 128 {
                    if let Ok(net) = ipnet::Ipv6Net::new(v6, ipv6_prefix as u8) {
                        return net.trunc().to_string();
                    }
                }
            }
        }
    }

    key.to_string()
}

/// Parses human-readable duration strings like "30s", "1m", "500ms", "1h".
pub fn parse_duration_str(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }

    if let Some(num) = s.strip_suffix("ns") {
        num.trim().parse::<u64>().ok().map(Duration::from_nanos)
    } else if let Some(num) = s.strip_suffix("us").or_else(|| s.strip_suffix("µs")) {
        num.trim().parse::<u64>().ok().map(Duration::from_micros)
    } else if let Some(num) = s.strip_suffix("ms") {
        num.trim().parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(num) = s.strip_suffix('s') {
        num.trim()
            .parse::<f64>()
            .ok()
            .map(Duration::from_secs_f64)
    } else if let Some(num) = s.strip_suffix('m') {
        num.trim()
            .parse::<f64>()
            .ok()
            .map(|m| Duration::from_secs_f64(m * 60.0))
    } else if let Some(num) = s.strip_suffix('h') {
        num.trim()
            .parse::<f64>()
            .ok()
            .map(|h| Duration::from_secs_f64(h * 3600.0))
    } else if let Some(num) = s.strip_suffix('d') {
        num.trim()
            .parse::<f64>()
            .ok()
            .map(|d| Duration::from_secs_f64(d * 86400.0))
    } else if let Ok(val) = s.parse::<u64>() {
        if val > 1_000_000_000 {
            Some(Duration::from_nanos(val))
        } else {
            Some(Duration::from_secs(val))
        }
    } else {
        None
    }
}

/// Parses duration from arbitrary JSON value (string, seconds number, nanoseconds number).
pub fn parse_duration_val(val: &serde_json::Value) -> Option<Duration> {
    match val {
        serde_json::Value::String(s) => parse_duration_str(s),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > 1_000_000_000 {
                    Some(Duration::from_nanos(u))
                } else {
                    Some(Duration::from_secs(u))
                }
            } else if let Some(f) = n.as_f64() {
                Some(Duration::from_secs_f64(f))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Rate limit zone definition.
#[derive(Clone)]
pub struct RateLimitZone {
    pub name: String,
    pub key: String,
    pub max_events: usize,
    pub window: Duration,
    pub ipv4_prefix: usize,
    pub ipv6_prefix: usize,
    pub matchers: Vec<Arc<CompiledMatcherSet>>,
    pub zone_limiter: Arc<ZoneRateLimiter>,
}

impl RateLimitZone {
    /// Permissiveness value used to sort rate limits (events per second).
    pub fn permissiveness(&self) -> f64 {
        let secs = self.window.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.max_events as f64 / secs
        }
    }
}

/// Distributed rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct DistributedRateLimitingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge_age: Option<String>,
}

/// Rate limit handler module implementing `github.com/mholt/caddy-ratelimit`.
#[derive(Clone)]
pub struct RateLimitHandler {
    pub zones: Vec<RateLimitZone>,
    pub sweep_interval: Duration,
    pub jitter: f64,
    pub log_key: bool,
    pub disable_metrics: bool,
    pub distributed: Option<DistributedRateLimitingConfig>,
    pub storage: Option<serde_json::Value>,
}

impl RateLimitHandler {
    /// Builds `RateLimitHandler` from parsed details map.
    pub fn from_config(details: &HashMap<String, serde_json::Value>) -> Result<Self> {
        let mut zones = Vec::new();

        // 1. Check for "rate_limits" or "zones" object
        let zones_obj = details
            .get("rate_limits")
            .or_else(|| details.get("zones"))
            .and_then(|v| v.as_object());

        if let Some(map) = zones_obj {
            for (name, zone_val) in map {
                let zone = Self::parse_zone(name, zone_val)?;
                zones.push(zone);
            }
        } else if details.contains_key("window")
            || details.contains_key("max_events")
            || details.contains_key("events")
        {
            // Shorthand single zone at top-level
            let dummy_val = serde_json::to_value(details)
                .map_err(|e| CoreError::Config(format!("Invalid rate limit details: {}", e)))?;
            let zone = Self::parse_zone("default", &dummy_val)?;
            zones.push(zone);
        }

        // Sort zones from tightest (or permissive depending on issue #10 order)
        // caddy-ratelimit: sort.Slice(..., func(i, j) { return permissiveness[i] > permissiveness[j] })
        zones.sort_by(|a, b| {
            b.permissiveness()
                .partial_cmp(&a.permissiveness())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let jitter = details
            .get("jitter")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if jitter < 0.0 {
            return Err(CoreError::Config("jitter must be at least zero".into()));
        }

        let sweep_interval = details
            .get("sweep_interval")
            .and_then(parse_duration_val)
            .unwrap_or(Duration::from_secs(60));

        let log_key = details
            .get("log_key")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let disable_metrics = details
            .get("disable_metrics")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let distributed = details
            .get("distributed")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let storage = details.get("storage").cloned();

        let handler = Self {
            zones,
            sweep_interval,
            jitter,
            log_key,
            disable_metrics,
            distributed,
            storage,
        };

        // Spawn periodic background cleaner task for expired keys
        let sweep_zones: Vec<Arc<ZoneRateLimiter>> =
            handler.zones.iter().map(|z| z.zone_limiter.clone()).collect();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sweep_interval);
            loop {
                ticker.tick().await;
                let now = Instant::now();
                for zl in &sweep_zones {
                    zl.sweep(now);
                }
            }
        });

        Ok(handler)
    }

    fn parse_zone(name: &str, val: &serde_json::Value) -> Result<RateLimitZone> {
        let key = val
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let window = val
            .get("window")
            .and_then(parse_duration_val)
            .ok_or_else(|| {
                CoreError::Config(format!(
                    "Rate limit zone '{}' requires a valid 'window' duration",
                    name
                ))
            })?;

        let max_events = val
            .get("max_events")
            .or_else(|| val.get("events"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .ok_or_else(|| {
                CoreError::Config(format!(
                    "Rate limit zone '{}' requires a valid 'max_events' integer",
                    name
                ))
            })?;

        if window.is_zero() || max_events == 0 {
            return Err(CoreError::Config(
                "a rate limit zone requires both a window and maximum events".to_string(),
            ));
        }

        let ipv4_prefix = val
            .get("ipv4_prefix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        if ipv4_prefix > 32 {
            return Err(CoreError::Config(
                "ipv4_prefix must be between 0 and 32".to_string(),
            ));
        }

        let ipv6_prefix = val
            .get("ipv6_prefix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        if ipv6_prefix > 128 {
            return Err(CoreError::Config(
                "ipv6_prefix must be between 0 and 128".to_string(),
            ));
        }

        // Matchers
        let mut matchers = Vec::new();
        if let Some(match_val) = val.get("match") {
            if let Ok(matcher_sets) = serde_json::from_value::<Vec<MatcherSet>>(match_val.clone()) {
                for ms in matcher_sets {
                    matchers.push(Arc::new(CompiledMatcherSet::from_config(&ms)));
                }
            }
        }

        // Persist rate limiter state across reloads via GLOBAL_RATE_LIMIT_ZONES
        let zone_limiter = {
            let mut global = GLOBAL_RATE_LIMIT_ZONES.lock().unwrap();
            if let Some(existing) = global.get(name) {
                existing.update_all(max_events, window);
                existing.clone()
            } else {
                let new_limiter = Arc::new(ZoneRateLimiter::new());
                global.insert(name.to_string(), new_limiter.clone());
                new_limiter
            }
        };

        Ok(RateLimitZone {
            name: name.to_string(),
            key,
            max_events,
            window,
            ipv4_prefix,
            ipv6_prefix,
            matchers,
            zone_limiter,
        })
    }

    /// Manually triggers sweeping of expired keys across all zones.
    pub fn sweep(&self) {
        let now = Instant::now();
        for zone in &self.zones {
            zone.zone_limiter.sweep(now);
        }
    }
}

#[async_trait]
impl Handler for RateLimitHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let now = Instant::now();

        for zone in &self.zones {
            // Check request matchers if defined for this zone
            if !zone.matchers.is_empty() {
                let mut matched = false;
                for m in &zone.matchers {
                    if m.matches(ctx) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
            }

            // Key evaluation with placeholder interpolation
            let raw_key = if zone.key.is_empty() {
                "".to_string()
            } else {
                eval_placeholders(&zone.key, ctx)
            };

            let expanded_key =
                apply_network_prefix(&raw_key, zone.ipv4_prefix, zone.ipv6_prefix);

            let wait = zone
                .zone_limiter
                .when(&expanded_key, now, zone.max_events, zone.window);

            if wait > Duration::ZERO {
                // Rate limit exceeded!
                let wait_with_jitter = if self.jitter > 0.0 {
                    let j = wait.mul_f64(fastrand::f64() * self.jitter);
                    wait + j
                } else {
                    wait
                };

                // Retry-After calculation: wait.Seconds() + 0.5 rounded to ceil
                let retry_after_secs = (wait_with_jitter.as_secs_f64() + 0.5).floor() as u64;
                let retry_after_secs = retry_after_secs.max(1);

                if let Ok(val) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    ctx.response_headers.insert(http::header::RETRY_AFTER, val);
                }

                // Placeholder and variable updates
                ctx.set_var("http.rate_limit.exceeded.name", &zone.name);
                ctx.set_var("err.status_code", "429");
                ctx.set_var("http.error.status_code", "429");
                ctx.set_var("err.status_text", "Too Many Requests");
                ctx.set_var("http.error.status_text", "Too Many Requests");
                ctx.set_var(
                    "err.message",
                    format!("Rate limit exceeded for zone {}", zone.name),
                );
                ctx.set_var(
                    "http.error.message",
                    format!("Rate limit exceeded for zone {}", zone.name),
                );

                let remote_str = ctx
                    .remote_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                if self.log_key {
                    tracing::info!(
                        zone = %zone.name,
                        wait = ?wait_with_jitter,
                        remote_ip = %remote_str,
                        key = %expanded_key,
                        "rate limit exceeded"
                    );
                } else {
                    tracing::info!(
                        zone = %zone.name,
                        wait = ?wait_with_jitter,
                        remote_ip = %remote_str,
                        "rate limit exceeded"
                    );
                }

                ctx.set_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "429 Too Many Requests\n",
                );
                return Ok(());
            }
        }

        Ok(())
    }
}

// Module registration for compile-time inventory discovery
inventory::submit! {
    raddy_core::module::ModuleRegistration {
        id: "rate_limit",
        factory: |cfg| {
            let details = serde_json::from_value::<HashMap<String, serde_json::Value>>(cfg)
                .map_err(|e| CoreError::Config(format!("Invalid rate_limit module config: {}", e)))?;
            let handler = RateLimitHandler::from_config(&details)?;
            Ok(Arc::new(handler))
        },
    }
}

inventory::submit! {
    raddy_core::module::ModuleRegistration {
        id: "http.handlers.rate_limit",
        factory: |cfg| {
            let details = serde_json::from_value::<HashMap<String, serde_json::Value>>(cfg)
                .map_err(|e| CoreError::Config(format!("Invalid rate_limit module config: {}", e)))?;
            let handler = RateLimitHandler::from_config(&details)?;
            Ok(Arc::new(handler))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method, Uri};

    #[test]
    fn test_apply_network_prefix_parity() {
        let tests = [
            ("ipv6 /64 full addr", "2001:db8:1234:5678:9abc:def0:1234:5678", 0, 64, "2001:db8:1234:5678::/64"),
            ("ipv6 /64 all ones host", "2001:db8:1234:5678:ffff:ffff:ffff:ffff", 0, 64, "2001:db8:1234:5678::/64"),
            ("ipv6 /64 short addr", "2001:db8:1234:5678::1", 0, 64, "2001:db8:1234:5678::/64"),
            ("ipv6 /48", "2001:db8:1234:5678::1", 0, 48, "2001:db8:1234::/48"),
            ("ipv6 /128", "2001:db8:1234:5678::1", 0, 128, "2001:db8:1234:5678::1/128"),
            ("ipv4 /24", "192.168.1.100", 24, 0, "192.168.1.0/24"),
            ("ipv4 /8", "10.0.0.50", 8, 0, "10.0.0.0/8"),
            ("ipv4 /32", "172.16.5.4", 32, 0, "172.16.5.4/32"),
            ("ipv6 with both configured", "2001:db8::1", 24, 64, "2001:db8::/64"),
            ("ipv4 with both configured", "192.168.1.100", 24, 64, "192.168.1.0/24"),
            ("ipv4 unchanged when only ipv6 configured", "192.168.1.100", 0, 64, "192.168.1.100"),
            ("ipv6 unchanged when only ipv4 configured", "2001:db8::1", 24, 0, "2001:db8::1"),
            ("ipv6 no prefix", "2001:db8::1", 0, 0, "2001:db8::1"),
            ("ipv4 no prefix", "192.168.1.100", 0, 0, "192.168.1.100"),
            ("static key", "static", 0, 64, "static"),
            ("placeholder key", "{http.request.uri}", 0, 64, "{http.request.uri}"),
            ("empty key", "", 0, 64, ""),
        ];

        for (name, key, ipv4_p, ipv6_p, expected) in tests {
            let res = apply_network_prefix(key, ipv4_p, ipv6_p);
            assert_eq!(res, expected, "Failed case: {}", name);
        }
    }

    #[test]
    fn test_ring_buffer_sliding_window_logic() {
        let window = Duration::from_secs(10);
        let max_events = 3;
        let mut limiter = RingBufferRateLimiter::new(max_events, window);

        let t0 = Instant::now();
        // Request 1: Allowed
        assert_eq!(limiter.when(t0), Duration::ZERO);
        // Request 2 at t0 + 1s: Allowed
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(limiter.when(t1), Duration::ZERO);
        // Request 3 at t0 + 2s: Allowed
        let t2 = t0 + Duration::from_secs(2);
        assert_eq!(limiter.when(t2), Duration::ZERO);

        // Request 4 at t0 + 3s: Rejection! Exceeded max_events in window
        let t3 = t0 + Duration::from_secs(3);
        let wait = limiter.when(t3);
        assert!(wait > Duration::ZERO);
        // Oldest was at t0, window is 10s, now is t0 + 3s -> wait should be 7s
        assert_eq!(wait, Duration::from_secs(7));

        // After window expires for oldest (at t0 + 10.5s): Allowed
        let t4 = t0 + Duration::from_millis(10500);
        assert_eq!(limiter.when(t4), Duration::ZERO);

        // Next request at t0 + 10.6s should see oldest at t1 (t0 + 1s)
        // t1 + 10s = t0 + 11s -> wait should be ~0.4s
        let t5 = t0 + Duration::from_millis(10600);
        let wait2 = limiter.when(t5);
        assert!(wait2 > Duration::ZERO);
        assert_eq!(wait2, Duration::from_millis(400));
    }

    #[test]
    fn test_ring_buffer_resize() {
        let window = Duration::from_secs(10);
        let mut limiter = RingBufferRateLimiter::new(2, window);
        let t0 = Instant::now();
        limiter.when(t0);
        limiter.when(t0 + Duration::from_secs(1));

        // Increasing capacity to 4
        limiter.set_max_events(4);
        assert_eq!(limiter.max_events(), 4);
        // Should now have capacity for 2 more requests
        assert_eq!(limiter.when(t0 + Duration::from_secs(2)), Duration::ZERO);
        assert_eq!(limiter.when(t0 + Duration::from_secs(3)), Duration::ZERO);
        // Now full (4 events)
        assert!(limiter.when(t0 + Duration::from_secs(4)) > Duration::ZERO);

        // Decreasing capacity to 2
        limiter.set_max_events(2);
        assert_eq!(limiter.max_events(), 2);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_str("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration_str("1m"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration_str("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration_str("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration_str("1d"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration_str("1.5s"), Some(Duration::from_millis(1500)));
        assert_eq!(parse_duration_str(""), None);

        let json_num = serde_json::json!(30);
        assert_eq!(parse_duration_val(&json_num), Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn test_rate_limit_handler_e2e_rejection_and_headers() {
        clear_global_rate_limit_zones();

        let details = HashMap::from([
            (
                "rate_limits".to_string(),
                serde_json::json!({
                    "zone_test": {
                        "key": "test_key",
                        "window": "10s",
                        "max_events": 2
                    }
                }),
            ),
        ]);

        let handler = RateLimitHandler::from_config(&details).unwrap();

        // Request 1: Allowed
        let mut ctx1 = Context::new(Method::GET, Uri::from_static("/test"), HeaderMap::new(), Bytes::new());
        handler.handle(&mut ctx1).await.unwrap();
        assert!(!ctx1.response_written);
        assert_eq!(ctx1.status, None);

        // Request 2: Allowed
        let mut ctx2 = Context::new(Method::GET, Uri::from_static("/test"), HeaderMap::new(), Bytes::new());
        handler.handle(&mut ctx2).await.unwrap();
        assert!(!ctx2.response_written);

        // Request 3: Exceeded -> 429
        let mut ctx3 = Context::new(Method::GET, Uri::from_static("/test"), HeaderMap::new(), Bytes::new());
        handler.handle(&mut ctx3).await.unwrap();
        assert!(ctx3.response_written);
        assert_eq!(ctx3.status, Some(StatusCode::TOO_MANY_REQUESTS));
        assert!(ctx3.response_headers.contains_key(http::header::RETRY_AFTER));
        let retry_val = ctx3.response_headers.get(http::header::RETRY_AFTER).unwrap().to_str().unwrap();
        let retry_secs = retry_val.parse::<u64>().unwrap();
        assert!(retry_secs >= 1 && retry_secs <= 11);

        // Context variable check
        assert_eq!(
            ctx3.get_var("http.rate_limit.exceeded.name"),
            Some("zone_test")
        );
        assert_eq!(ctx3.get_var("err.status_code"), Some("429"));
    }

    #[tokio::test]
    async fn test_distinct_keys() {
        clear_global_rate_limit_zones();

        let details = HashMap::from([
            (
                "rate_limits".to_string(),
                serde_json::json!({
                    "per_user": {
                        "key": "{header.x-user-id}",
                        "window": "10s",
                        "max_events": 1
                    }
                }),
            ),
        ]);

        let handler = RateLimitHandler::from_config(&details).unwrap();

        // User A: Request 1 allowed
        let mut h_a = HeaderMap::new();
        h_a.insert("x-user-id", "alice".parse().unwrap());
        let mut ctx_a1 = Context::new(Method::GET, Uri::from_static("/"), h_a.clone(), Bytes::new());
        handler.handle(&mut ctx_a1).await.unwrap();
        assert!(!ctx_a1.response_written);

        // User B: Request 1 allowed (independent key!)
        let mut h_b = HeaderMap::new();
        h_b.insert("x-user-id", "bob".parse().unwrap());
        let mut ctx_b1 = Context::new(Method::GET, Uri::from_static("/"), h_b, Bytes::new());
        handler.handle(&mut ctx_b1).await.unwrap();
        assert!(!ctx_b1.response_written);

        // User A: Request 2 rejected (exceeded)
        let mut ctx_a2 = Context::new(Method::GET, Uri::from_static("/"), h_a, Bytes::new());
        handler.handle(&mut ctx_a2).await.unwrap();
        assert!(ctx_a2.response_written);
        assert_eq!(ctx_a2.status, Some(StatusCode::TOO_MANY_REQUESTS));
    }
}
