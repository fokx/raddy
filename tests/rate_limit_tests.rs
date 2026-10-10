use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, header};
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::context::Context;
use raddy_core::module::ModuleRegistry;
use raddy_http::ratelimit::clear_global_rate_limit_zones;
use raddy_http::router::compile_virtual_host_router;
use std::net::SocketAddr;
use std::path::Path;

#[tokio::test]
async fn test_caddyfile_rate_limit_adaptation() {
    clear_global_rate_limit_zones();

    let caddyfile = r#"
    localhost:8080 {
        rate_limit {
            zone login_limit {
                match {
                    method POST
                }
                key {remote_host}
                window 30s
                events 5
                ipv4_prefix 24
                ipv6_prefix 64
            }
            zone api_limit {
                key {http.request.uri}
                window 1m
                events 100
            }
            jitter 0.2
            sweep_interval 45s
            log_key
            disable_metrics
            distributed {
                read_interval 10s
                write_interval 5s
                purge_age 1h
            }
        }
        respond "OK" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().expect("Missing http app");
    let server = http_app.servers.values().next().expect("Missing server");

    // Verify directive ordering: rate_limit should be in route
    let route = server.routes.iter().find(|r| {
        r.handle.iter().any(|h| h.handler == "rate_limit")
    }).expect("rate_limit handler not found in routes");

    let rl_handler_cfg = route.handle.iter().find(|h| h.handler == "rate_limit").unwrap();
    assert_eq!(rl_handler_cfg.details.get("log_key"), Some(&serde_json::json!(true)));
    assert_eq!(rl_handler_cfg.details.get("disable_metrics"), Some(&serde_json::json!(true)));
    assert_eq!(rl_handler_cfg.details.get("jitter"), Some(&serde_json::json!(0.2)));
    assert_eq!(rl_handler_cfg.details.get("sweep_interval"), Some(&serde_json::json!("45s")));

    let zones = rl_handler_cfg.details.get("rate_limits").and_then(|v| v.as_object()).unwrap();
    assert!(zones.contains_key("login_limit"));
    assert!(zones.contains_key("api_limit"));

    let login_zone = &zones["login_limit"];
    assert_eq!(login_zone.get("key"), Some(&serde_json::json!("{remote_host}")));
    assert_eq!(login_zone.get("window"), Some(&serde_json::json!("30s")));
    assert_eq!(login_zone.get("max_events"), Some(&serde_json::json!(5)));
    assert_eq!(login_zone.get("ipv4_prefix"), Some(&serde_json::json!(24)));
    assert_eq!(login_zone.get("ipv6_prefix"), Some(&serde_json::json!(64)));

    // Verify matcher in zone
    assert!(login_zone.get("match").is_some());
}

#[tokio::test]
async fn test_caddyfile_rate_limit_execution_parity() {
    clear_global_rate_limit_zones();

    let caddyfile = r#"
    localhost:8080 {
        rate_limit {
            zone api_zone {
                match {
                    method GET
                }
                key static
                window 60s
                events 3
            }
        }
        respond "Hello Rate Limited" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().unwrap();
    let server = http_app.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();

    let vh_router = compile_virtual_host_router(server, &registry).expect("Failed to compile virtual host router");

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost:8080".parse().unwrap());

    // Request 1 (GET): Allowed -> 200 OK
    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    vh_router.route_request(&mut ctx1).await.unwrap();
    assert_eq!(ctx1.status, Some(StatusCode::OK));

    // Request 2 (GET): Allowed -> 200 OK
    let mut ctx2 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    vh_router.route_request(&mut ctx2).await.unwrap();
    assert_eq!(ctx2.status, Some(StatusCode::OK));

    // Request 3 (GET): Allowed -> 200 OK
    let mut ctx3 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    vh_router.route_request(&mut ctx3).await.unwrap();
    assert_eq!(ctx3.status, Some(StatusCode::OK));

    // Request 4 (GET): Exceeded (max_events = 3) -> 429 Too Many Requests
    let mut ctx4 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    vh_router.route_request(&mut ctx4).await.unwrap();
    assert_eq!(ctx4.status, Some(StatusCode::TOO_MANY_REQUESTS));
    assert!(ctx4.response_headers.contains_key(http::header::RETRY_AFTER));
    let retry_after = ctx4.response_headers.get(http::header::RETRY_AFTER).unwrap().to_str().unwrap();
    let retry_secs = retry_after.parse::<u64>().unwrap();
    assert!(retry_secs >= 1 && retry_secs <= 60);
    assert_eq!(ctx4.get_var("http.rate_limit.exceeded.name"), Some("api_zone"));

    // Request 5 (POST): The rate limit zone only matches GET! POST should pass through!
    let mut ctx_post = Context::new(Method::POST, Uri::from_static("/"), headers, Bytes::new());
    vh_router.route_request(&mut ctx_post).await.unwrap();
    assert_eq!(ctx_post.status, Some(StatusCode::OK));
}

#[tokio::test]
async fn test_caddyfile_rate_limit_ipv4_subnet_grouping() {
    clear_global_rate_limit_zones();

    let caddyfile = r#"
    localhost:8080 {
        rate_limit {
            zone subnet_limit {
                key {remote_host}
                window 30s
                events 2
                ipv4_prefix 24
            }
        }
        respond "OK" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().unwrap();
    let server = http_app.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let vh_router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost:8080".parse().unwrap());

    // Client 1: 192.168.1.10
    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    ctx1.remote_addr = Some("192.168.1.10:12345".parse::<SocketAddr>().unwrap());
    vh_router.route_request(&mut ctx1).await.unwrap();
    assert_eq!(ctx1.status, Some(StatusCode::OK));

    // Client 2: 192.168.1.50 (same /24 subnet! Should count against the same bucket)
    let mut ctx2 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    ctx2.remote_addr = Some("192.168.1.50:54321".parse::<SocketAddr>().unwrap());
    vh_router.route_request(&mut ctx2).await.unwrap();
    assert_eq!(ctx2.status, Some(StatusCode::OK));

    // Client 3: 192.168.1.99 (same /24 subnet! Exceeds limit of 2)
    let mut ctx3 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    ctx3.remote_addr = Some("192.168.1.99:9999".parse::<SocketAddr>().unwrap());
    vh_router.route_request(&mut ctx3).await.unwrap();
    assert_eq!(ctx3.status, Some(StatusCode::TOO_MANY_REQUESTS));

    // Client 4: 10.0.0.1 (different subnet! Should have independent limit)
    let mut ctx4 = Context::new(Method::GET, Uri::from_static("/"), headers, Bytes::new());
    ctx4.remote_addr = Some("10.0.0.1:1111".parse::<SocketAddr>().unwrap());
    vh_router.route_request(&mut ctx4).await.unwrap();
    assert_eq!(ctx4.status, Some(StatusCode::OK));
}

#[tokio::test]
async fn test_rate_limit_state_persistence_across_reloads() {
    clear_global_rate_limit_zones();

    // Configuration 1: 2 events per 30s
    let caddyfile1 = r#"
    localhost:8080 {
        rate_limit {
            zone reload_test {
                key static
                window 30s
                events 2
            }
        }
        respond "Config 1" 200
    }
    "#;

    let config1 = adapt_caddyfile(caddyfile1, Path::new(".")).unwrap();
    let registry = ModuleRegistry::new();
    let router1 = compile_virtual_host_router(config1.http_app().unwrap().servers.values().next().unwrap(), &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost:8080".parse().unwrap());

    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    router1.route_request(&mut ctx1).await.unwrap();
    assert_eq!(ctx1.status, Some(StatusCode::OK));

    let mut ctx2 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    router1.route_request(&mut ctx2).await.unwrap();
    assert_eq!(ctx2.status, Some(StatusCode::OK));

    // Now reload with Configuration 2 (same zone name "reload_test", limit still 2)
    let caddyfile2 = r#"
    localhost:8080 {
        rate_limit {
            zone reload_test {
                key static
                window 30s
                events 2
            }
        }
        respond "Config 2" 200
    }
    "#;

    let config2 = adapt_caddyfile(caddyfile2, Path::new(".")).unwrap();
    let router2 = compile_virtual_host_router(config2.http_app().unwrap().servers.values().next().unwrap(), &registry).unwrap();

    // Request on new router should STILL be rate limited because state persisted!
    let mut ctx3 = Context::new(Method::GET, Uri::from_static("/"), headers, Bytes::new());
    router2.route_request(&mut ctx3).await.unwrap();
    assert_eq!(ctx3.status, Some(StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn test_caddyfile_rate_limit_before_basic_auth_order() {
    let caddyfile = r#"
    localhost:8080 {
        basic_auth {
            bob $2a$14$V0Q4aKzJ0X9z9H1o0.kObe1kH4yG9wXbHk3y/7o3m9cO2s2.5b1v.
        }
        rate_limit {
            zone auth_limit {
                key static
                window 10s
                events 5
            }
        }
        respond "Protected" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().unwrap();
    let server = http_app.servers.values().next().unwrap();

    // Check directive execution order in routes: rate_limit must appear before basic_auth
    let mut rate_limit_idx = None;
    let mut basic_auth_idx = None;

    for (i, r) in server.routes.iter().enumerate() {
        for h in &r.handle {
            if h.handler == "rate_limit" && rate_limit_idx.is_none() {
                rate_limit_idx = Some(i);
            }
            if h.handler == "basic_auth" && basic_auth_idx.is_none() {
                basic_auth_idx = Some(i);
            }
        }
    }

    assert!(rate_limit_idx.is_some(), "rate_limit route missing");
    assert!(basic_auth_idx.is_some(), "basic_auth route missing");
    assert!(
        rate_limit_idx.unwrap() < basic_auth_idx.unwrap(),
        "rate_limit ({}) must run BEFORE basic_auth ({})",
        rate_limit_idx.unwrap(),
        basic_auth_idx.unwrap()
    );
}
