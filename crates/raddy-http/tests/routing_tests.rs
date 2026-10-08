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

#[tokio::test]
async fn test_http_to_https_redirect_uri_evaluation() {
    let mut server = HttpServer::default();
    server.listen = vec![":80".into()];

    server.routes.push(Route {
        r#match: Some(vec![MatcherSet {
            host: Some(vec!["hkg.eeeu.de".into()]),
            ..Default::default()
        }]),
        handle: vec![HandlerConfig::new("static_response")
            .with_field("status_code", 308)
            .with_field("location", "https://{host}{uri}")],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).expect("Failed to compile vhost router");

    // Case 1: GET /
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "hkg.eeeu.de".parse().unwrap());
    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/"), headers.clone(), Bytes::new());
    vhost_router.route_request(&mut ctx1).await.unwrap();

    assert_eq!(ctx1.status, Some(StatusCode::PERMANENT_REDIRECT));
    assert_eq!(
        ctx1.response_headers.get(http::header::LOCATION).unwrap().to_str().unwrap(),
        "https://hkg.eeeu.de/"
    );

    // Case 2: GET /path/to/resource?foo=bar&baz=1
    let mut ctx2 = Context::new(
        Method::GET,
        Uri::from_static("/path/to/resource?foo=bar&baz=1"),
        headers,
        Bytes::new(),
    );
    vhost_router.route_request(&mut ctx2).await.unwrap();

    assert_eq!(ctx2.status, Some(StatusCode::PERMANENT_REDIRECT));
    assert_eq!(
        ctx2.response_headers.get(http::header::LOCATION).unwrap().to_str().unwrap(),
        "https://hkg.eeeu.de/path/to/resource?foo=bar&baz=1"
    );
}

#[tokio::test]
async fn test_user_caddyfile_live_file_server_and_handle_path() {
    use raddy_caddyfile::adapt_caddyfile;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!("raddy_test_user_cfg_{}", nanos));
    let www_dir = temp_root.join("www");
    let dl_dir = temp_root.join("dl");
    tokio::fs::create_dir_all(&www_dir).await.unwrap();
    tokio::fs::create_dir_all(&dl_dir).await.unwrap();

    // Write index.html in www_dir
    tokio::fs::write(www_dir.join("index.html"), "Welcome to laxccs.netlib.re!").await.unwrap();
    // Write download file in dl_dir
    tokio::fs::write(dl_dir.join("ajsdoasji"), "download payload").await.unwrap();
    // Create subdirectory 2 with file jai11
    tokio::fs::create_dir_all(dl_dir.join("2")).await.unwrap();
    tokio::fs::write(dl_dir.join("2").join("jai11"), "nested file").await.unwrap();
    // Write hidden .git directory in dl_dir
    tokio::fs::create_dir_all(dl_dir.join(".git")).await.unwrap();
    tokio::fs::write(dl_dir.join(".git").join("config"), "git config").await.unwrap();

    let caddyfile_text = format!(r#"
    :0 {{
        file_server {{
            root {}
        }}
        redir /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/ 308
        handle_path /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/* {{
            root /* {}
            file_server {{
                browse
                hide .git
            }}
        }}
    }}
    "#, www_dir.to_str().unwrap(), dl_dir.to_str().unwrap());

    let config = adapt_caddyfile(&caddyfile_text, ".").expect("Failed to adapt");
    let http = config.http_app().expect("Missing http app");
    let server_cfg = http.servers.values().next().expect("Missing server");

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(server_cfg, &registry).unwrap();

    let mut instance = HttpServerInstance::new("user_caddyfile_test", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind TCP listener");
    let bound_addr = instance.local_addr().expect("Missing local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();

    // 1. GET / -> serves /var/www/html/index.html!
    let resp = client.get(format!("http://{}/", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Welcome to laxccs.netlib.re!");

    // 2. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas -> 308 redirect
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        resp.headers().get("Location").unwrap().to_str().unwrap(),
        "/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/"
    );

    // 3. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/ajsdoasji -> serves /x/dl/ajsdoasji!
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/ajsdoasji", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "download payload");

    // 4. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/.git -> 404 Not Found (hide .git)
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/.git", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 5. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/ (directory listing) -> relative links and correct heading
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Index of /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/"), "header should contain full original path");
    assert!(body.contains("href=\"./ajsdoasji\""), "link to ajsdoasji must be relative (./ajsdoasji)");
    assert!(body.contains("href=\"./2/\""), "link to 2/ must be relative (./2/)");
    assert!(!body.contains(".git"), "listing should hide .git");
    assert!(!body.contains("Parent Directory"), "root of share should not have Parent Directory link");

    // 6. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2 (subfolder without slash) -> redirects to /fasd.../2/
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        resp.headers().get("Location").unwrap().to_str().unwrap(),
        "/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2/"
    );

    // 7. GET /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2/ -> lists jai11 and has Parent Directory link
    let resp = client.get(format!("http://{}/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2/", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Index of /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/2/"));
    assert!(body.contains("href=\"..\""), "subfolder must have Parent Directory link");
    assert!(body.contains("href=\"./jai11\""), "link to jai11 must be relative");

    // Cleanup
    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();
    let _ = tokio::fs::remove_dir_all(&temp_root).await;
}

#[tokio::test]
async fn test_large_file_streaming_and_range_requests() {
    use futures_util::StreamExt;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("raddy_test_large_file_{}", nanos));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    // Create a 256KB file (> 64KB STREAM_THRESHOLD)
    let file_size = 256 * 1024;
    let mut test_data = Vec::with_capacity(file_size);
    for i in 0..file_size {
        test_data.push((i % 251) as u8);
    }
    let file_path = temp_dir.join("large_payload.bin");
    tokio::fs::write(&file_path, &test_data).await.unwrap();

    let mut server = HttpServer::default();
    server.listen = vec![":80".into()];
    server.routes.push(Route {
        r#match: None,
        handle: vec![HandlerConfig::new("file_server")
            .with_field("root", temp_dir.to_str().unwrap())],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    // 1. GET full large file -> verify it is STREAMED (response_stream is Some, response_body is None)
    let mut ctx = Context::new(Method::GET, Uri::from_static("/large_payload.bin"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, None, "Large file must not be buffered into response_body");
    assert!(ctx.response_stream.is_some(), "Large file must be provided via response_stream");
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_LENGTH).unwrap(),
        &file_size.to_string()
    );
    assert_eq!(
        ctx.response_headers.get(http::header::ACCEPT_RANGES).unwrap(),
        "bytes"
    );

    // Consume the stream and verify all bytes match
    let mut streamed_bytes = Vec::new();
    let mut stream = ctx.response_stream.take().unwrap();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.unwrap();
        streamed_bytes.extend_from_slice(&chunk);
    }
    assert_eq!(streamed_bytes, test_data);

    // 2. HEAD request -> returns headers with Content-Length, empty body
    let mut ctx = Context::new(Method::HEAD, Uri::from_static("/large_payload.bin"), HeaderMap::new(), Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert!(ctx.response_stream.is_none(), "HEAD request must not open stream");
    assert_eq!(ctx.response_body, Some(Bytes::new()));
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_LENGTH).unwrap(),
        &file_size.to_string()
    );

    // 3. Partial Content: Range: bytes=100-199
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RANGE, "bytes=100-199".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/large_payload.bin"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::PARTIAL_CONTENT));
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_RANGE).unwrap(),
        &format!("bytes 100-199/{}", file_size)
    );
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_LENGTH).unwrap(),
        "100"
    );
    // 100 bytes is <= STREAM_THRESHOLD, so read into buffer
    assert_eq!(ctx.response_body.as_ref().unwrap().as_ref(), &test_data[100..=199]);

    // 4. Suffix Range: Range: bytes=-50 (last 50 bytes)
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RANGE, "bytes=-50".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/large_payload.bin"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::PARTIAL_CONTENT));
    let expected_start = file_size - 50;
    let expected_end = file_size - 1;
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_RANGE).unwrap(),
        &format!("bytes {}-{}/{}", expected_start, expected_end, file_size)
    );
    assert_eq!(ctx.response_body.as_ref().unwrap().as_ref(), &test_data[expected_start..=expected_end]);

    // 5. Invalid Range: Range: bytes=9999999- -> 416 Range Not Satisfiable
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RANGE, "bytes=9999999-".parse().unwrap());
    let mut ctx = Context::new(Method::GET, Uri::from_static("/large_payload.bin"), headers, Bytes::new());
    vhost_router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::RANGE_NOT_SATISFIABLE));
    assert_eq!(
        ctx.response_headers.get(http::header::CONTENT_RANGE).unwrap(),
        &format!("bytes */{}", file_size)
    );

    // 6. Live TCP end-to-end streaming over HTTP socket
    let mut instance = HttpServerInstance::new("large_file_tcp_test", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind TCP listener");
    let bound_addr = instance.local_addr().expect("Missing local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{}/large_payload.bin", bound_addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-length").unwrap(), &file_size.to_string());
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    let received_bytes = resp.bytes().await.unwrap();
    assert_eq!(received_bytes.as_ref(), &test_data[..]);

    // Range request over live HTTP socket
    let resp = client
        .get(format!("http://{}/large_payload.bin", bound_addr))
        .header("Range", "bytes=500-999")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resp.headers().get("content-range").unwrap(), &format!("bytes 500-999/{}", file_size));
    let received_chunk = resp.bytes().await.unwrap();
    assert_eq!(received_chunk.as_ref(), &test_data[500..=999]);

    // Cleanup
    shutdown_tx.send(true).unwrap();
    server_handle.await.unwrap().unwrap();
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}


