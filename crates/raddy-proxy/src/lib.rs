//! Raddy Reverse Proxy crate
//! Provides upstream connection pooling, load balancing algorithms,
//! active and passive health checks, header manipulation (header_up, header_down),
//! and retry policies.

pub mod error;
pub mod forward;
pub mod headers;
pub mod health;
pub mod load_balancer;
pub mod proxy;
pub mod transport;
pub mod upstream;

pub use error::{ProxyError, Result};
pub use forward::{
    AclDecision, AclRule, AclRuleConfig, AuthConfig, AuthError, ForwardProxyConfig,
    ForwardProxyHandler, ProbeResistanceConfig, UpstreamProxy,
};
pub use headers::{strip_hop_by_hop_headers, HeaderMutator};
pub use health::{ActiveHealthConfig, PassiveHealthConfig};
pub use load_balancer::{
    parse_load_balancer, First, IpHash, LeastConn, LoadBalancer, Random, RoundRobin, UriHash,
    WeightedRoundRobin,
};
pub use proxy::ReverseProxyHandler;
pub use transport::HttpTransport;
pub use upstream::Upstream;

use std::collections::HashMap;
use std::sync::Arc;

/// Builds a `ReverseProxyHandler` from a JSON configuration value (matching Caddy's reverse_proxy schema).
pub fn build_reverse_proxy_from_config(details: &HashMap<String, serde_json::Value>) -> raddy_core::error::Result<ReverseProxyHandler> {
    // 1. Parse upstreams
    let mut upstreams = Vec::new();
    if let Some(arr) = details.get("upstreams").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(dial) = item.get("dial").and_then(|d| d.as_str()) {
                upstreams.push(Arc::new(Upstream::new(dial)));
            }
        }
    }

    // 2. Parse load balancing policy
    let lb_policy_str = details
        .get("lb_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("round_robin");
    let load_balancer = parse_load_balancer(lb_policy_str);

    // 3. Parse header mutator rules
    let mut mutator = HeaderMutator::new();
    if let Some(headers_obj) = details.get("headers").and_then(|v| v.as_object()) {
        // request headers (header_up)
        if let Some(req_obj) = headers_obj.get("request").and_then(|v| v.as_object()) {
            if let Some(set_map) = req_obj.get("set").and_then(|v| v.as_object()) {
                for (k, v) in set_map {
                    if let Some(s) = v.as_str() {
                        mutator.header_up_set.insert(k.clone(), s.to_string());
                    }
                }
            }
            if let Some(del_arr) = req_obj.get("delete").and_then(|v| v.as_array()) {
                for v in del_arr {
                    if let Some(s) = v.as_str() {
                        mutator.header_up_delete.push(s.to_string());
                    }
                }
            }
        }

        // response headers (header_down)
        if let Some(resp_obj) = headers_obj.get("response").and_then(|v| v.as_object()) {
            if let Some(set_map) = resp_obj.get("set").and_then(|v| v.as_object()) {
                for (k, v) in set_map {
                    if let Some(s) = v.as_str() {
                        mutator.header_down_set.insert(k.clone(), s.to_string());
                    }
                }
            }
            if let Some(del_arr) = resp_obj.get("delete").and_then(|v| v.as_array()) {
                for v in del_arr {
                    if let Some(s) = v.as_str() {
                        mutator.header_down_delete.push(s.to_string());
                    }
                }
            }
        }
    }

    let handler = ReverseProxyHandler::new(upstreams, load_balancer, mutator);
    Ok(handler)
}
