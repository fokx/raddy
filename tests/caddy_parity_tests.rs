use std::path::Path;
use bytes::Bytes;
use http::{header, HeaderMap, Method, StatusCode, Uri};
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::context::Context;
use raddy_core::module::ModuleRegistry;
use raddy_core::PlaceholderProvider;
use raddy_http::router::compile_virtual_host_router;

#[test]
fn test_placeholders_extended() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "app.example.com".parse().unwrap());
    headers.insert(header::COOKIE, "session_id=abc123xyz; theme=dark".parse().unwrap());

    let mut ctx = Context::new(
        Method::GET,
        "/static/css/style.min.css?v=1".parse::<Uri>().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("192.168.1.100:12345".parse().unwrap());

    // File path placeholders
    assert_eq!(ctx.get_placeholder("dir").as_deref(), Some("/static/css"));
    assert_eq!(ctx.get_placeholder("file").as_deref(), Some("style.min.css"));
    assert_eq!(ctx.get_placeholder("file.base").as_deref(), Some("style.min"));
    assert_eq!(ctx.get_placeholder("file.ext").as_deref(), Some(".css"));

    // Host labels placeholders (reverse indexed 0=com, 1=example, 2=app)
    assert_eq!(ctx.get_placeholder("labels.0").as_deref(), Some("com"));
    assert_eq!(ctx.get_placeholder("labels.1").as_deref(), Some("example"));
    assert_eq!(ctx.get_placeholder("labels.2").as_deref(), Some("app"));

    // Cookie placeholders
    assert_eq!(ctx.get_placeholder("cookie.session_id").as_deref(), Some("abc123xyz"));
    assert_eq!(ctx.get_placeholder("cookie.theme").as_deref(), Some("dark"));

    // Orig method placeholder
    assert_eq!(ctx.get_placeholder("orig_method").as_deref(), Some("GET"));

    // Method change updates method placeholder while preserving orig_method
    ctx.method = Method::POST;
    assert_eq!(ctx.get_placeholder("method").as_deref(), Some("POST"));
    assert_eq!(ctx.get_placeholder("orig_method").as_deref(), Some("GET"));
}

#[tokio::test]
async fn test_caddyfile_client_ip_private_ranges_and_not_matcher() {
    let caddyfile = r#"
    localhost:8080 {
        @internal client_ip private_ranges
        @not_internal not client_ip private_ranges

        handle @internal {
            respond "Internal access granted" 200
        }
        handle @not_internal {
            respond "External access" 403
        }
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    // 192.168.1.50 is private range
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx_internal = Context::new(
        Method::GET,
        "/".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx_internal.remote_addr = Some("192.168.1.50:5000".parse().unwrap());
    router.route_request(&mut ctx_internal).await.unwrap();
    assert_eq!(ctx_internal.status, Some(StatusCode::OK));
    assert_eq!(ctx_internal.response_body, Some(Bytes::from("Internal access granted")));

    // 8.8.8.8 is public range
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx_external = Context::new(
        Method::GET,
        "/".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx_external.remote_addr = Some("8.8.8.8:5000".parse().unwrap());
    router.route_request(&mut ctx_external).await.unwrap();
    assert_eq!(ctx_external.status, Some(StatusCode::FORBIDDEN));
    assert_eq!(ctx_external.response_body, Some(Bytes::from("External access")));
}

#[tokio::test]
async fn test_caddyfile_header_regexp_and_query_matchers() {
    let caddyfile = r#"
    localhost:8080 {
        @api {
            header_regexp Auth Authorization "^Bearer [A-Za-z0-9]+$"
            query action=delete
        }
        handle @api {
            respond "API Delete Authorized" 200
        }
        respond "Denied" 400
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    // Match both header_regexp and query
    let mut headers_ok = HeaderMap::new();
    headers_ok.insert(header::HOST, "localhost".parse().unwrap());
    headers_ok.insert(header::AUTHORIZATION, "Bearer tok123".parse().unwrap());
    let mut ctx_ok = Context::new(
        Method::GET,
        "/items?action=delete".parse().unwrap(),
        headers_ok,
        Bytes::new(),
    );
    ctx_ok.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx_ok).await.unwrap();
    assert_eq!(ctx_ok.status, Some(StatusCode::OK));
    assert_eq!(ctx_ok.response_body, Some(Bytes::from("API Delete Authorized")));

    // Fail header_regexp
    let mut headers_fail = HeaderMap::new();
    headers_fail.insert(header::HOST, "localhost".parse().unwrap());
    headers_fail.insert(header::AUTHORIZATION, "Basic user:pass".parse().unwrap());
    let mut ctx_fail = Context::new(
        Method::GET,
        "/items?action=delete".parse().unwrap(),
        headers_fail,
        Bytes::new(),
    );
    ctx_fail.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx_fail).await.unwrap();
    assert_eq!(ctx_fail.status, Some(StatusCode::BAD_REQUEST));
    assert_eq!(ctx_fail.response_body, Some(Bytes::from("Denied")));
}

#[tokio::test]
async fn test_caddyfile_vars_and_method_directives() {
    let caddyfile = r#"
    localhost:8080 {
        vars app_mode production
        method PUT
        respond "Method is {method}, mode is {vars.app_mode}" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx = Context::new(
        Method::GET,
        "/".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Method is PUT, mode is production")));
}

#[tokio::test]
async fn test_caddyfile_header_default_prefix() {
    let caddyfile = r#"
    localhost:8080 {
        header ?X-Custom-Fallback "DefaultValue"
        respond "OK" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx = Context::new(
        Method::GET,
        "/".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_headers.get("x-custom-fallback").unwrap(), "DefaultValue");
}

#[tokio::test]
async fn test_caddyfile_handle_errors() {
    let caddyfile = r#"
    localhost:8080 {
        handle_errors {
            respond "Custom error: status {err.status_code} ({err.status_text})" 200
        }
        error 404 "Page Not Found"
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx = Context::new(
        Method::GET,
        "/nonexistent".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(ctx.response_body, Some(Bytes::from("Custom error: status 404 (Not Found)")));
}

#[tokio::test]
async fn test_caddyfile_bind_and_global_default_bind() {
    let caddyfile = r#"
    {
        default_bind 127.0.0.2
    }
    site1.local:8080 {
        respond "site1" 200
    }
    site2.local:8080 {
        bind 127.0.0.3
        respond "site2" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();

    let srv1 = http.servers.get("srv_127.0.0.2:8080").unwrap();
    assert!(srv1.listen.contains(&"127.0.0.2:8080".to_string()));

    let srv2 = http.servers.get("srv_127.0.0.3:8080").unwrap();
    assert!(srv2.listen.contains(&"127.0.0.3:8080".to_string()));
}

#[tokio::test]
async fn test_caddyfile_php_fastcgi_adaptation() {
    let caddyfile = r#"
    localhost:8080 {
        php_fastcgi 127.0.0.1:9000
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    assert_eq!(server.routes.len(), 1);
    let handlers = &server.routes[0].handle;
    assert_eq!(handlers.len(), 2);
    assert_eq!(handlers[0].handler, "try_files");
    assert_eq!(handlers[1].handler, "reverse_proxy");
    assert_eq!(handlers[1].details.get("fastcgi"), Some(&serde_json::json!(true)));
}

#[test]
fn test_hash_password_bcrypt() {
    let password = "my_secret_password";
    let hash = bcrypt::hash(password, 4).unwrap();
    assert!(hash.starts_with("$2"));
    assert!(bcrypt::verify(password, &hash).unwrap());
    assert!(!bcrypt::verify("wrong_password", &hash).unwrap());
}

#[tokio::test]
async fn test_caddyfile_try_files_fallback() {
    let caddyfile = r#"
    localhost:8080 {
        root * tests
        try_files {path} =404
        file_server
    }
    "#;
    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let registry = ModuleRegistry::new();
    let router = compile_virtual_host_router(server, &registry).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx = Context::new(
        Method::GET,
        "/this_file_does_not_exist_xyz.html".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn test_admin_api_adapt_and_upstreams() {
    use std::sync::Arc;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use raddy_admin::{build_admin_router, AppState};

    let caddyfile = r#"
    localhost:8080 {
        reverse_proxy 127.0.0.1:8001 127.0.0.1:8002
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let state = Arc::new(AppState::new(config, Arc::new(ModuleRegistry::new()), None));
    let app = build_admin_router(state);

    // Test POST /adapt
    let adapt_req = Request::builder()
        .method("POST")
        .uri("/adapt")
        .header("content-type", "text/plain")
        .body(Body::from(caddyfile))
        .unwrap();

    let resp = app.clone().oneshot(adapt_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(val.get("apps").is_some());

    // Test GET /reverse_proxy/upstreams
    let upstreams_req = Request::builder()
        .method("GET")
        .uri("/reverse_proxy/upstreams")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(upstreams_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let upstreams: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(upstreams.len(), 2);
    assert_eq!(upstreams[0]["dial"], "127.0.0.1:8001");
    assert_eq!(upstreams[1]["dial"], "127.0.0.1:8002");
}

#[tokio::test]
async fn test_caddyfile_acme_challenges_and_http_port_adaptation() {
    let caddyfile = r#"
    {
        http_port 81
        challenges tls-alpn-01
    }
    :443, ams.eeeu.de:443 {
        respond "ok" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let tls = config.tls_app().unwrap();

    // Verify HTTP listener on port 81
    assert!(http.servers.contains_key("srv_:81"));
    let srv_81 = http.servers.get("srv_:81").unwrap();
    assert!(srv_81.listen.contains(&":81".to_string()));

    // Verify HTTPS listener on port 443
    assert!(http.servers.contains_key("srv_:443"));

    // Verify global TLS app challenges configuration
    assert_eq!(tls.challenges.as_ref().unwrap(), &vec!["tls-alpn-01".to_string()]);
}

#[tokio::test]
async fn test_caddyfile_site_level_tls_challenges() {
    let caddyfile = r#"
    example.com {
        tls {
            issuer acme {
                challenges tls-alpn-01
                disable_http_challenge
            }
        }
        respond "ok" 200
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let tls = config.tls_app().unwrap();

    assert_eq!(tls.challenges.as_ref().unwrap(), &vec!["tls-alpn-01".to_string()]);
    assert_eq!(tls.disable_http_challenge, Some(true));
}

