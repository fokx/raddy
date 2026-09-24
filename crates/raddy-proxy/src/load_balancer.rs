use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use raddy_core::context::Context;
use raddy_core::placeholder::PlaceholderProvider;

use crate::upstream::Upstream;

/// Load balancing algorithm trait.
pub trait LoadBalancer: Send + Sync {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], ctx: &Context) -> Option<&'a Arc<Upstream>>;
}

/// Round Robin load balancer.
#[derive(Default)]
pub struct RoundRobin {
    index: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LoadBalancer for RoundRobin {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], _ctx: &Context) -> Option<&'a Arc<Upstream>> {
        let available: Vec<&'a Arc<Upstream>> = upstreams.iter().filter(|u| u.is_available()).collect();
        if available.is_empty() {
            return None;
        }

        let next = self.index.fetch_add(1, Ordering::Relaxed);
        Some(available[next % available.len()])
    }
}

/// Least Connections load balancer.
#[derive(Default)]
pub struct LeastConn;

impl LoadBalancer for LeastConn {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], _ctx: &Context) -> Option<&'a Arc<Upstream>> {
        upstreams
            .iter()
            .filter(|u| u.is_available())
            .min_by_key(|u| u.active_requests())
    }
}

/// Random selection load balancer.
#[derive(Default)]
pub struct Random;

impl LoadBalancer for Random {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], _ctx: &Context) -> Option<&'a Arc<Upstream>> {
        let available: Vec<&'a Arc<Upstream>> = upstreams.iter().filter(|u| u.is_available()).collect();
        if available.is_empty() {
            return None;
        }
        let rand_idx = fast_rand(available.len());
        Some(available[rand_idx])
    }
}

/// Consistent IP Hash load balancer based on client IP (`{remote_host}`).
#[derive(Default)]
pub struct IpHash;

impl LoadBalancer for IpHash {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], ctx: &Context) -> Option<&'a Arc<Upstream>> {
        let available: Vec<&'a Arc<Upstream>> = upstreams.iter().filter(|u| u.is_available()).collect();
        if available.is_empty() {
            return None;
        }

        let key = ctx.get_placeholder("remote_host").unwrap_or_else(|| "default_ip".into());
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish() as usize;

        Some(available[hash % available.len()])
    }
}

/// Consistent URI Hash load balancer based on path (`{path}`).
#[derive(Default)]
pub struct UriHash;

impl LoadBalancer for UriHash {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], ctx: &Context) -> Option<&'a Arc<Upstream>> {
        let available: Vec<&'a Arc<Upstream>> = upstreams.iter().filter(|u| u.is_available()).collect();
        if available.is_empty() {
            return None;
        }

        let key = ctx.uri.path();
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish() as usize;

        Some(available[hash % available.len()])
    }
}

/// First available upstream (failover policy).
#[derive(Default)]
pub struct First;

impl LoadBalancer for First {
    fn select<'a>(&self, upstreams: &'a [Arc<Upstream>], _ctx: &Context) -> Option<&'a Arc<Upstream>> {
        upstreams.iter().find(|u| u.is_available())
    }
}

/// Factory function to parse load balancing policy from string.
pub fn parse_load_balancer(policy: &str) -> Box<dyn LoadBalancer> {
    match policy.to_lowercase().as_str() {
        "least_conn" => Box::new(LeastConn),
        "ip_hash" => Box::new(IpHash),
        "uri_hash" => Box::new(UriHash),
        "first" => Box::new(First),
        "random" => Box::new(Random),
        _ => Box::new(RoundRobin::new()), // default: round_robin
    }
}

fn fast_rand(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize)
        .unwrap_or(0);
    nanos % limit
}
