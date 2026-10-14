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
pub use headers::{HeaderMutator, strip_hop_by_hop_headers};
pub use health::{ActiveHealthConfig, PassiveHealthConfig};
pub use load_balancer::{
    First, IpHash, LeastConn, LoadBalancer, Random, RoundRobin, UriHash, WeightedRoundRobin,
    parse_load_balancer,
};
pub use proxy::ReverseProxyHandler;
pub use transport::{HttpTransport, UpstreamResponseBody};
pub use upstream::Upstream;

use std::collections::HashMap;
use std::sync::Arc;

/// Builds a `ReverseProxyHandler` from a JSON configuration value (matching Caddy's reverse_proxy schema).
pub fn build_reverse_proxy_from_config(
    details: &HashMap<String, serde_json::Value>,
) -> raddy_core::error::Result<ReverseProxyHandler> {
    // 1. Parse upstreams
    let mut upstreams = Vec::new();
    let mut any_upstream_tls = false;
    if let Some(arr) = details.get("upstreams").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(dial) = item.get("dial").and_then(|d| d.as_str()) {
                let ups = Upstream::new(dial);
                if ups.is_tls {
                    any_upstream_tls = true;
                }
                upstreams.push(Arc::new(ups));
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

    // 4. Parse transport configuration
    let mut transport = HttpTransport::new();
    if let Some(trans_obj) = details.get("transport").and_then(|v| v.as_object()) {
        if let Some(dt) = trans_obj.get("dial_timeout").and_then(|v| v.as_str()) {
            if let Some(d) = crate::transport::parse_duration(dt) {
                transport.dial_timeout = d;
            }
        }
        if let Some(rt) = trans_obj
            .get("response_timeout")
            .or_else(|| trans_obj.get("response_header_timeout"))
            .and_then(|v| v.as_str())
        {
            if let Some(d) = crate::transport::parse_duration(rt) {
                transport.response_timeout = d;
            }
        }
        if let Some(tls_val) = trans_obj.get("tls") {
            transport.tls = true;
            if let Some(tls_obj) = tls_val.as_object() {
                if let Some(sn) = tls_obj.get("server_name").and_then(|v| v.as_str()) {
                    transport.tls_server_name = Some(sn.to_string());
                }
                if let Some(skip) = tls_obj
                    .get("insecure_skip_verify")
                    .and_then(|v| v.as_bool())
                {
                    transport.tls_insecure_skip_verify = skip;
                }
            }
        }
    }
    if any_upstream_tls {
        transport.tls = true;
    }

    // 5. Parse retries
    let retries = details
        .get("retries")
        .or_else(|| details.get("lb_retries"))
        .or_else(|| {
            details
                .get("load_balancing")
                .and_then(|v| v.get("retries"))
        })
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    // 6. Parse passive health check
    let passive_obj = details
        .get("health_checks")
        .and_then(|v| v.get("passive"))
        .and_then(|v| v.as_object());

    let fail_duration_val = details
        .get("fail_duration")
        .or_else(|| passive_obj.and_then(|p| p.get("fail_duration")));

    let fail_duration_secs = if let Some(v) = fail_duration_val {
        if let Some(s) = v.as_str() {
            crate::transport::parse_duration(s)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        } else if let Some(n) = v.as_u64() {
            if n > 1_000_000_000 {
                n / 1_000_000_000
            } else {
                n
            }
        } else {
            0
        }
    } else {
        0
    };

    let max_fails = details
        .get("max_fails")
        .or_else(|| passive_obj.and_then(|p| p.get("max_fails")))
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as usize;

    let unhealthy_status_codes: Vec<u16> = details
        .get("unhealthy_status")
        .or_else(|| passive_obj.and_then(|p| p.get("unhealthy_status")))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_u64().map(|c| c as u16))
                .collect()
        })
        .unwrap_or_default();

    let passive_health = crate::health::PassiveHealthConfig {
        max_fails,
        fail_duration_secs,
        unhealthy_status_codes,
    };

    let handler = ReverseProxyHandler::new(upstreams, load_balancer, mutator)
        .with_transport(transport)
        .with_retries(retries)
        .with_passive_health(passive_health);
    Ok(handler)
}
