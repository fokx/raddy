use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, header};
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::context::Context;
use raddy_core::module::ModuleRegistry;
use raddy_http::router::compile_virtual_host_router;
use std::path::Path;

#[tokio::test]
async fn test_caddyfile_cache_adaptation_minimal() {
    let caddyfile = r#"
    localhost:8080 {
        cache
        respond "Hello World" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().expect("Missing http app");
    let server = http_app.servers.values().next().expect("Missing server");

    let route = server.routes.iter().find(|r| {
        r.handle.iter().any(|h| h.handler == "cache")
    }).expect("cache handler not found in routes");

    let cache_h = route.handle.iter().find(|h| h.handler == "cache").unwrap();
    assert_eq!(cache_h.details.get("cache_name"), Some(&serde_json::json!("Souin")));
    assert_eq!(
        cache_h.details.get("ttl"),
        Some(&serde_json::json!({ "secs": 120, "nanos": 0 }))
    );
}

#[tokio::test]
async fn test_caddyfile_cache_adaptation_global_and_site_options() {
    let caddyfile = r#"
    {
        cache {
            cache_name GlobalCache
            ttl 600s
            stale 300s
            allowed_http_verbs GET POST
            allowed_additional_status_codes 203 404
            default_cache_control "public, max-age=3600"
            max_cacheable_body_bytes 5242880
            mode strict
            regex {
                exclude /api/v1/auth.*
            }
            key {
                disable_host
                disable_scheme
                sort_query
                headers Authorization X-User-ID
            }
            cache_keys {
                .*\.css {
                    disable_body
                    disable_query
                    hash
                }
            }
        }
    }

    example.com:8080 {
        cache {
            cache_name CustomSiteCache
            ttl 30s
        }
        respond "Site cached" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().expect("Missing http app");
    let server = http_app.servers.values().next().expect("Missing server");

    let route = server.routes.iter().find(|r| {
        r.handle.iter().any(|h| h.handler == "cache")
    }).expect("cache handler not found in routes");

    let cache_h = route.handle.iter().find(|h| h.handler == "cache").unwrap();
    assert_eq!(cache_h.details.get("cache_name"), Some(&serde_json::json!("CustomSiteCache")));
    // Overridden ttl in site block
    assert_eq!(
        cache_h.details.get("ttl"),
        Some(&serde_json::json!({ "secs": 30, "nanos": 0 }))
    );
    // Inherited stale from global block
    assert_eq!(
        cache_h.details.get("stale"),
        Some(&serde_json::json!({ "secs": 300, "nanos": 0 }))
    );
    // Inherited allowed verbs
    assert_eq!(
        cache_h.details.get("allowed_http_verbs"),
        Some(&serde_json::json!(["GET", "POST"]))
    );
    // Inherited status codes
    assert_eq!(
        cache_h.details.get("allowed_additional_status_codes"),
        Some(&serde_json::json!([203, 404]))
    );
    // Inherited regex exclude
    assert_eq!(
        cache_h.details.get("regex_exclude"),
        Some(&serde_json::json!("/api/v1/auth.*"))
    );
    // Inherited key configs
    let key = cache_h.details.get("key").unwrap();
    assert_eq!(key.get("disable_host"), Some(&serde_json::json!(true)));
    assert_eq!(key.get("sort_query"), Some(&serde_json::json!(true)));

    // Inherited cache_keys
    let cache_keys = cache_h.details.get("cache_keys").and_then(|v| v.as_array()).unwrap();
    assert_eq!(cache_keys.len(), 1);
    assert_eq!(cache_keys[0].get("pattern"), Some(&serde_json::json!(".*.css")));
}

#[tokio::test]
async fn test_cache_hit_miss_and_cache_status_headers() {
    let caddyfile = r#"
    localhost:8080 {
        route {
            cache {
                cache_name TestSouin
                ttl 300s
            }
            respond "Fresh Dynamic Payload" 200 {
                header Content-Type "text/plain"
                header Cache-Control "public, max-age=300"
                header ETag "\"tag-12345\""
            }
        }
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().unwrap();
    let server = http_app.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost:8080".parse().unwrap());

    // 1st Request: Cache Miss (Forward to responder)
    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/item"), headers.clone(), Bytes::new());
    router.route_request(&mut ctx1).await.unwrap();
    assert_eq!(ctx1.status, Some(StatusCode::OK));
    assert_eq!(ctx1.response_body.as_ref().map(|b| b.as_ref()), Some(b"Fresh Dynamic Payload".as_ref()));
    let cs1 = ctx1.response_headers.get("cache-status").expect("Cache-Status missing on miss").to_str().unwrap();
    assert!(cs1.contains("TestSouin"), "Expected cache name in Cache-Status: {}", cs1);
    assert!(cs1.contains("fwd=uri-miss"), "Expected uri-miss in Cache-Status: {}", cs1);

    // 2nd Request: Cache HIT! Served directly from memory
    let mut ctx2 = Context::new(Method::GET, Uri::from_static("/item"), headers.clone(), Bytes::new());
    router.route_request(&mut ctx2).await.unwrap();
    assert_eq!(ctx2.status, Some(StatusCode::OK));
    assert_eq!(ctx2.response_body.as_ref().map(|b| b.as_ref()), Some(b"Fresh Dynamic Payload".as_ref()));
    let cs2 = ctx2.response_headers.get("cache-status").expect("Cache-Status missing on hit").to_str().unwrap();
    assert!(cs2.contains("TestSouin"), "Expected cache name in Cache-Status: {}", cs2);
    assert!(cs2.contains("hit"), "Expected hit in Cache-Status: {}", cs2);
    assert!(ctx2.response_headers.contains_key(header::AGE), "Expected Age header on hit");

    // 3rd Request: Conditional Request with If-None-Match matching cached ETag -> 304 Not Modified
    let mut cond_headers = headers.clone();
    cond_headers.insert(header::IF_NONE_MATCH, "\"tag-12345\"".parse().unwrap());
    let mut ctx3 = Context::new(Method::GET, Uri::from_static("/item"), cond_headers, Bytes::new());
    router.route_request(&mut ctx3).await.unwrap();
    assert_eq!(ctx3.status, Some(StatusCode::NOT_MODIFIED));
    assert!(ctx3.response_body.as_ref().map(|b| b.is_empty()).unwrap_or(true));

    // 4th Request: HEAD method
    let mut ctx4 = Context::new(Method::HEAD, Uri::from_static("/item"), headers.clone(), Bytes::new());
    router.route_request(&mut ctx4).await.unwrap();
    assert_eq!(ctx4.status, Some(StatusCode::OK));
    assert!(ctx4.response_body.as_ref().map(|b| b.is_empty()).unwrap_or(true));
    let cs4 = ctx4.response_headers.get("cache-status").unwrap().to_str().unwrap();
    assert!(cs4.contains("hit"));

    // 5th Request: Client sends "Cache-Control: no-store" -> Bypass cache
    let mut no_store_headers = headers.clone();
    no_store_headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    let mut ctx5 = Context::new(Method::GET, Uri::from_static("/item"), no_store_headers, Bytes::new());
    router.route_request(&mut ctx5).await.unwrap();
    assert_eq!(ctx5.status, Some(StatusCode::OK));
    let cs5 = ctx5.response_headers.get("cache-status").unwrap().to_str().unwrap();
    assert!(cs5.contains("fwd=bypass"));
}

#[tokio::test]
async fn test_cache_keys_query_sorting_and_path_variations() {
    let caddyfile = r#"
    localhost:8080 {
        route {
            cache {
                cache_name SortQueryCache
                ttl 60s
                key {
                    sort_query
                }
            }
            respond "Result for {http.request.uri}" 200 {
                header Cache-Control "public, max-age=60"
            }
        }
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http_app = config.http_app().unwrap();
    let server = http_app.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost:8080".parse().unwrap());

    // Request with query params a=1&b=2
    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/search?a=1&b=2"), headers.clone(), Bytes::new());
    router.route_request(&mut ctx1).await.unwrap();
    assert_eq!(ctx1.status, Some(StatusCode::OK));
    let cs1 = ctx1.response_headers.get("cache-status").unwrap().to_str().unwrap();
    assert!(cs1.contains("fwd=uri-miss"));

    // Request with reversed query params b=2&a=1 -> Because sort_query is true, it MUST HIT the cache!
    let mut ctx2 = Context::new(Method::GET, Uri::from_static("/search?b=2&a=1"), headers.clone(), Bytes::new());
    router.route_request(&mut ctx2).await.unwrap();
    assert_eq!(ctx2.status, Some(StatusCode::OK));
    let cs2 = ctx2.response_headers.get("cache-status").unwrap().to_str().unwrap();
    assert!(cs2.contains("hit"), "Expected sorted query cache hit, got: {}", cs2);
    // Cached response body was from first request
    assert_eq!(ctx2.response_body.as_ref().map(|b| b.as_ref()), Some(b"Result for /search?a=1&b=2".as_ref()));
}
