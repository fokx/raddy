use http::{HeaderMap, HeaderValue, Method, Uri};
use raddy_core::Context;
use raddy_proxy::{
    LeastConn, LoadBalancer, RoundRobin, Upstream, WeightedRoundRobin, strip_hop_by_hop_headers,
};
use std::sync::Arc;

fn dummy_ctx() -> Context {
    Context::new(
        Method::GET,
        Uri::from_static("http://example.com/"),
        HeaderMap::new(),
        bytes::Bytes::new(),
    )
}

#[test]
fn test_round_robin_policy() {
    let pool = vec![
        Arc::new(Upstream::new("0.0.0.1:80")),
        Arc::new(Upstream::new("0.0.0.2:80")),
        Arc::new(Upstream::new("0.0.0.3:80")),
    ];

    let rr = RoundRobin::new();
    let ctx = dummy_ctx();

    // First selected host is index 1 because counter starts at 0 and increments before select
    let u1 = rr.select(&pool, &ctx).unwrap();
    assert_eq!(u1.dial, "0.0.0.2:80");

    let u2 = rr.select(&pool, &ctx).unwrap();
    assert_eq!(u2.dial, "0.0.0.3:80");

    let u3 = rr.select(&pool, &ctx).unwrap();
    assert_eq!(u3.dial, "0.0.0.1:80");

    // Mark host 1 as down
    pool[1].set_healthy(false);
    let u4 = rr.select(&pool, &ctx).unwrap();
    assert_eq!(u4.dial, "0.0.0.3:80");

    // Mark host 1 back up
    pool[1].set_healthy(true);
}

#[test]
fn test_least_conn_policy() {
    let pool = vec![
        Arc::new(Upstream::new("0.0.0.1:80")),
        Arc::new(Upstream::new("0.0.0.2:80")),
        Arc::new(Upstream::new("0.0.0.3:80")),
    ];

    let lc = LeastConn;
    let ctx = dummy_ctx();

    // Assign active requests
    pool[0].inc_active();
    pool[0].inc_active();
    pool[1].inc_active();

    // Host 2 has 0 active requests, so it should be selected
    let u = lc.select(&pool, &ctx).unwrap();
    assert_eq!(u.dial, "0.0.0.3:80");
}

#[test]
fn test_weighted_round_robin_policy() {
    let pool = vec![
        Arc::new(Upstream::new("0.0.0.1:80")),
        Arc::new(Upstream::new("0.0.0.2:80")),
        Arc::new(Upstream::new("0.0.0.3:80")),
    ];

    let wrr = WeightedRoundRobin::new(vec![3, 2, 1]);
    let ctx = dummy_ctx();

    let mut counts = std::collections::HashMap::new();
    for _ in 0..6 {
        let u = wrr.select(&pool, &ctx).unwrap();
        *counts.entry(u.dial.clone()).or_insert(0) += 1;
    }

    assert_eq!(counts.get("0.0.0.1:80"), Some(&3));
    assert_eq!(counts.get("0.0.0.2:80"), Some(&2));
    assert_eq!(counts.get("0.0.0.3:80"), Some(&1));
}

#[test]
fn test_hop_by_hop_101_strips_headers_preserves_upgrade() {
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("connection", HeaderValue::from_static("Upgrade"));
    headers.insert("alt-svc", HeaderValue::from_static("h2=\"evil.com:443\""));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=999"));
    headers.insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"phish\""),
    );

    strip_hop_by_hop_headers(&mut headers, true);

    assert_eq!(
        headers.get("upgrade"),
        Some(&HeaderValue::from_static("websocket"))
    );
    assert_eq!(
        headers.get("connection"),
        Some(&HeaderValue::from_static("Upgrade"))
    );
    assert_eq!(headers.get("alt-svc"), None);
    assert_eq!(headers.get("keep-alive"), None);
    assert_eq!(headers.get("proxy-authenticate"), None);
}

#[test]
fn test_hop_by_hop_101_strips_connection_named_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert(
        "connection",
        HeaderValue::from_static("Upgrade, X-Custom-ID"),
    );
    headers.insert(
        "x-custom-id",
        HeaderValue::from_static("should-be-stripped"),
    );

    strip_hop_by_hop_headers(&mut headers, true);

    assert_eq!(
        headers.get("upgrade"),
        Some(&HeaderValue::from_static("websocket"))
    );
    assert_eq!(
        headers.get("connection"),
        Some(&HeaderValue::from_static("Upgrade"))
    );
    assert_eq!(headers.get("x-custom-id"), None);
}

#[test]
fn test_hop_by_hop_200_strips_all() {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/plain"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("connection", HeaderValue::from_static("Upgrade"));
    headers.insert("alt-svc", HeaderValue::from_static("h2=\"evil.com:443\""));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=999"));

    strip_hop_by_hop_headers(&mut headers, false);

    assert_eq!(
        headers.get("content-type"),
        Some(&HeaderValue::from_static("text/plain"))
    );
    assert_eq!(headers.get("upgrade"), None);
    assert_eq!(headers.get("connection"), None);
    assert_eq!(headers.get("alt-svc"), None);
    assert_eq!(headers.get("keep-alive"), None);
}
