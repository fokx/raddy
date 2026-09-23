use http::{HeaderMap, Method, StatusCode, Uri};
use bytes::Bytes;
use raddy_core::config::{HandlerConfig, HttpServer, MatcherSet, Route};
use raddy_core::context::Context;
use raddy_core::module::ModuleRegistry;
use raddy_http::router::compile_virtual_host_router;
use raddy_http::server::HttpServerInstance;

#[tokio::test]
async fn test_virtual_host_routing() {
    let mut server = HttpServer::default();
    server.listen = vec![":8080".into()];

    // Route 1: api.local -> "API Response"
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            host: Some(vec!["api.local".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "API Response")],
        terminal: Some(true),
        group: None,
    });

    // Route 2: site.local -> "Site Response"
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            host: Some(vec!["site.local".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "Site Response")],
        terminal: Some(true),
        group: None,
    });

    // Route 3: *.internal -> "Internal Gateway"
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            host: Some(vec!["*.internal".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "Internal Gateway")],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).expect("Failed to compile vhost router");

    // Test 1: api.local
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "api.local".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("API Response")));

    // Test 2: site.local
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "site.local".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Site Response")));

    // Test 3: admin.internal (wildcard)
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "admin.internal".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/dashboard"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Internal Gateway")));

    // Test 4: Unknown host -> 404
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "unknown.com".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn test_path_and_method_matchers() {
    let mut server = HttpServer::default();
    server.listen = vec![":80".into()];

    // GET /items -> List items
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            path: Some(vec!["/items".into()]),
            method: Some(vec!["GET".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "Item list")],
        terminal: Some(true),
        group: None,
    });

    // POST /items -> Item created
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            path: Some(vec!["/items".into()]),
            method: Some(vec!["POST".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 201)
            .with_field("body", "Item created")],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    // GET /items
    let mut ctx = Context::new(Method::GET, Uri::from_static("/items"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Item list")));

    // POST /items
    let mut ctx = Context::new(Method::POST, Uri::from_static("/items"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::CREATED));
    assert_eq!(ctx.response_body, Some(Bytes::from("Item created")));

    // DELETE /items -> Not matched -> 404
    let mut ctx = Context::new(Method::DELETE, Uri::from_static("/items"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn test_handle_group_mutual_exclusion() {
    let mut server = HttpServer::default();
    server.listen = vec![":80".into()];

    // Mutual exclusion group: group "main"
    // First handle matches /api/*
    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            path: Some(vec!["/api/*".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "API Endpoint")],
        terminal: Some(false),
        group: Some("group_main".into()),
    });

    // Second handle is fallback (matches everything in group "main")
    server.routes.push(Route {
        r#match: None,
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 200)
            .with_field("body", "Default Fallback")],
        terminal: Some(false),
        group: Some("group_main".into()),
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    // /api/test should only execute the first handle, NOT fallback
    let mut ctx = Context::new(Method::GET, Uri::from_static("/api/test"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.response_body, Some(Bytes::from("API Endpoint")));

    // /other should execute the fallback
    let mut ctx = Context::new(Method::GET, Uri::from_static("/other"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.response_body, Some(Bytes::from("Default Fallback")));
}

#[tokio::test]
async fn test_static_file_server() {
    let temp_dir = std::env::temp_dir().join("raddy_test_static");
    let _ = tokio::fs::create_dir_all(&temp_dir).await;

    let file_path = temp_dir.join("hello.txt");
    tokio::fs::write(&file_path, "Hello from static file!").await.unwrap();

    let mut server = HttpServer::default();
    server.listen = vec![":80".into()];
    server.routes.push(Route {
        r#match: None,
        handle: vec![HandlerConfig::new("file_server")
            .with_field("root", temp_dir.to_str().unwrap())
            .with_field("browse", true)],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    // 1. Fetch hello.txt
    let mut ctx = Context::new(Method::GET, Uri::from_static("/hello.txt"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Hello from static file!")));

    let etag = ctx.response_headers.get(http::header::ETAG).cloned().expect("Missing ETag");

    // 2. Fetch with If-None-Match matching etag -> 304 Not Modified
    let mut headers = HeaderMap::new();
    headers.insert(http::header::IF_NONE_MATCH, etag);
    let mut ctx = Context::new(Method::GET, Uri::from_static("/hello.txt"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::NOT_MODIFIED));

    // Cleanup
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_full_tcp_server_end_to_end() {
    let mut server = HttpServer::default();
    server.listen = vec!["127.0.0.1:0".into()]; // Bind to ephemeral port
    server.routes.push(Route {
        r#match: None,
        handle: vec![
            HandlerConfig::new("headers")
                .with_field("set_response_headers", serde_json::json!({ "X-Powered-By": "Raddy" })),
            HandlerConfig::new("static_response")
                .with_field("status_code", 200)
                .with_field("body", "Live TCP response!"),
        ],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    let mut instance = HttpServerInstance::new("test_srv", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind TCP listener");
    let bound_addr = instance.local_addr().expect("Missing local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    // Make an actual HTTP request to the running TCP server
    let client = reqwest::Client::new();
    let url = format!("http://{}/test", bound_addr);
    let resp = client.get(&url).send().await.expect("Failed to send HTTP request");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("X-Powered-By").and_then(|v| v.to_str().ok()),
        Some("Raddy")
    );
    let body = resp.text().await.expect("Failed to read body");
    assert_eq!(body, "Live TCP response!");

    // Gracefully shut down server
    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();
}
