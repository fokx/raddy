use bytes::Bytes;
use flate2::read::GzDecoder;
use http::header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use raddy_core::context::Context;
use raddy_core::handler::Handler;
use raddy_http::auth::BasicAuthHandler;
use raddy_http::encode::{CompressionFormat, EncodeHandler};
use raddy_http::flow::{AbortHandler, ErrorHandler};
use raddy_http::limits::RequestBodyLimitHandler;
use raddy_http::map::MapHandler;
use raddy_http::replace::{ReplaceHandler, ReplacementRule};
use raddy_http::templates::TemplatesHandler;
use std::collections::HashMap;
use std::io::Read;

#[tokio::test]
async fn test_encode_gzip_and_zstd() {
    let handler = EncodeHandler::new(vec![CompressionFormat::Zstd, CompressionFormat::Gzip]);

    // 1. Test Gzip compression
    let mut ctx_gzip = Context::new(
        Method::GET,
        Uri::from_static("/data"),
        HeaderMap::new(),
        Bytes::new(),
    );
    ctx_gzip
        .headers
        .insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    ctx_gzip.set_response(StatusCode::OK, "This is uncompressed test data repeated repeated repeated repeated repeated repeated repeated!");

    handler.handle(&mut ctx_gzip).await.unwrap();

    assert_eq!(
        ctx_gzip.response_headers.get(CONTENT_ENCODING).unwrap(),
        "gzip"
    );
    let compressed_body = ctx_gzip.response_body.unwrap();

    // Verify decompression with GzDecoder
    let mut decoder = GzDecoder::new(&compressed_body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert_eq!(
        decompressed,
        "This is uncompressed test data repeated repeated repeated repeated repeated repeated repeated!"
    );

    // 2. Test Zstd compression
    let mut ctx_zstd = Context::new(
        Method::GET,
        Uri::from_static("/data"),
        HeaderMap::new(),
        Bytes::new(),
    );
    ctx_zstd
        .headers
        .insert(ACCEPT_ENCODING, HeaderValue::from_static("zstd"));
    ctx_zstd.set_response(
        StatusCode::OK,
        "Zstd uncompressed test payload for Raddy web server!",
    );

    handler.handle(&mut ctx_zstd).await.unwrap();

    assert_eq!(
        ctx_zstd.response_headers.get(CONTENT_ENCODING).unwrap(),
        "zstd"
    );
    let zstd_compressed = ctx_zstd.response_body.unwrap();

    let decompressed_zstd = zstd::decode_all(&zstd_compressed[..]).unwrap();
    assert_eq!(
        String::from_utf8(decompressed_zstd).unwrap(),
        "Zstd uncompressed test payload for Raddy web server!"
    );
}

#[tokio::test]
async fn test_templates_rendering() {
    let handler = TemplatesHandler::new();

    let mut ctx = Context::new(
        Method::POST,
        Uri::from_static("/user/dashboard?tab=overview"),
        HeaderMap::new(),
        Bytes::new(),
    );
    ctx.headers
        .insert("host", HeaderValue::from_static("example.com"));
    ctx.vars.insert("username".into(), "Alice".into());

    let template_body =
        "Hello {{ vars.username }}! You requested {{ req.method }} on {{ req.host }}{{ req.path }}";
    ctx.set_response(StatusCode::OK, template_body);

    handler.handle(&mut ctx).await.unwrap();

    let rendered = String::from_utf8(ctx.response_body.unwrap().to_vec()).unwrap();
    assert_eq!(
        rendered,
        "Hello Alice! You requested POST on example.com/user/dashboard"
    );
}

#[tokio::test]
async fn test_replace_handler() {
    let handler = ReplaceHandler::new(
        vec![
            ReplacementRule {
                search: "https://files.pythonhosted.org".into(),
                replace: "https://m.lqy.me/pypi-files".into(),
                regex: None,
            },
            ReplacementRule {
                search: r"action=/search/".into(),
                replace: r"action=/pypi/search/".into(),
                regex: None,
            },
            ReplacementRule {
                search: r"v\d+\.\d+".into(),
                replace: "v2.0".into(),
                regex: Some(regex::Regex::new(r"v\d+\.\d+").unwrap()),
            },
        ],
        vec![],
        false,
    );

    let mut ctx = Context::new(
        Method::GET,
        Uri::from_static("/simple/pkg/"),
        HeaderMap::new(),
        Bytes::new(),
    );
    let initial_body = r#"<a href="https://files.pythonhosted.org/packages/test.whl">download</a> <form action=/search/> version v1.2</form>"#;
    ctx.set_response(StatusCode::OK, initial_body);

    handler.handle(&mut ctx).await.unwrap();

    let rendered = String::from_utf8(ctx.response_body.unwrap().to_vec()).unwrap();
    assert_eq!(
        rendered,
        r#"<a href="https://m.lqy.me/pypi-files/packages/test.whl">download</a> <form action=/pypi/search/> version v2.0</form>"#
    );
    assert_eq!(
        ctx.response_headers
            .get(http::header::CONTENT_LENGTH)
            .unwrap(),
        &rendered.len().to_string()
    );
}

#[tokio::test]
async fn test_basic_auth_bcrypt_and_unauthorized() {
    let mut users = HashMap::new();
    // bcrypt hash of "secret123"
    let hash = bcrypt::hash("secret123", 4).unwrap();
    users.insert("admin".to_string(), hash);
    users.insert("guest".to_string(), "plainpass".to_string());

    let handler = BasicAuthHandler::new(users, Some("AdminArea".into()));

    // 1. Missing credentials
    let mut ctx_missing = Context::new(
        Method::GET,
        Uri::from_static("/admin"),
        HeaderMap::new(),
        Bytes::new(),
    );
    handler.handle(&mut ctx_missing).await.unwrap();
    assert_eq!(ctx_missing.status, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(
        ctx_missing
            .response_headers
            .get("www-authenticate")
            .unwrap(),
        "Basic realm=\"AdminArea\""
    );
    assert!(ctx_missing.response_written);

    // 2. Invalid password
    let mut ctx_bad = Context::new(
        Method::GET,
        Uri::from_static("/admin"),
        HeaderMap::new(),
        Bytes::new(),
    );
    // "admin:wrongpass" in base64 is "YWRtaW46d3JvbmdwYXNz"
    ctx_bad.headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic YWRtaW46d3JvbmdwYXNz"),
    );
    handler.handle(&mut ctx_bad).await.unwrap();
    assert_eq!(ctx_bad.status, Some(StatusCode::UNAUTHORIZED));

    // 3. Valid bcrypt password
    let mut ctx_good = Context::new(
        Method::GET,
        Uri::from_static("/admin"),
        HeaderMap::new(),
        Bytes::new(),
    );
    // "admin:secret123" in base64 is "YWRtaW46c2VjcmV0MTIz"
    ctx_good.headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic YWRtaW46c2VjcmV0MTIz"),
    );
    handler.handle(&mut ctx_good).await.unwrap();
    assert_eq!(
        ctx_good.status, None,
        "Authenticated request should proceed to downstream handlers"
    );
    assert!(!ctx_good.response_written);

    // 4. Valid plaintext password
    let mut ctx_guest = Context::new(
        Method::GET,
        Uri::from_static("/guest"),
        HeaderMap::new(),
        Bytes::new(),
    );
    // "guest:plainpass" in base64 is "Z3Vlc3Q6cGxhaW5wYXNz"
    ctx_guest.headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic Z3Vlc3Q6cGxhaW5wYXNz"),
    );
    handler.handle(&mut ctx_guest).await.unwrap();
    assert_eq!(ctx_guest.status, None);
    assert!(!ctx_guest.response_written);
}

#[tokio::test]
async fn test_request_body_limits() {
    let handler = RequestBodyLimitHandler::new(100); // 100 bytes max

    // 1. Within limit
    let mut ctx_ok = Context::new(
        Method::POST,
        Uri::from_static("/upload"),
        HeaderMap::new(),
        Bytes::from(vec![0u8; 50]),
    );
    handler.handle(&mut ctx_ok).await.unwrap();
    assert_eq!(ctx_ok.status, None);

    // 2. Exceeds limit
    let mut ctx_large = Context::new(
        Method::POST,
        Uri::from_static("/upload"),
        HeaderMap::new(),
        Bytes::from(vec![0u8; 150]),
    );
    handler.handle(&mut ctx_large).await.unwrap();
    assert_eq!(ctx_large.status, Some(StatusCode::PAYLOAD_TOO_LARGE));
    assert!(ctx_large.response_written);
}

#[tokio::test]
async fn test_map_directive_lookup() {
    let mappings = vec![
        ("api.*".to_string(), "api_backend".to_string()),
        ("static.*".to_string(), "cdn_backend".to_string()),
    ];
    let handler = MapHandler::new(
        "{host}",
        "backend",
        mappings,
        Some("default_backend".into()),
    );

    // 1. Matching api.*
    let mut ctx_api = Context::new(
        Method::GET,
        Uri::from_static("/"),
        HeaderMap::new(),
        Bytes::new(),
    );
    ctx_api
        .headers
        .insert("host", HeaderValue::from_static("api.example.com"));
    handler.handle(&mut ctx_api).await.unwrap();
    assert_eq!(ctx_api.vars.get("backend").unwrap(), "api_backend");

    // 2. Matching default fallback
    let mut ctx_other = Context::new(
        Method::GET,
        Uri::from_static("/"),
        HeaderMap::new(),
        Bytes::new(),
    );
    ctx_other
        .headers
        .insert("host", HeaderValue::from_static("blog.example.com"));
    handler.handle(&mut ctx_other).await.unwrap();
    assert_eq!(ctx_other.vars.get("backend").unwrap(), "default_backend");
}

#[tokio::test]
async fn test_abort_and_error_handlers() {
    // Abort handler
    let abort = AbortHandler;
    let mut ctx_abort = Context::new(
        Method::GET,
        Uri::from_static("/bad"),
        HeaderMap::new(),
        Bytes::new(),
    );
    abort.handle(&mut ctx_abort).await.unwrap();
    assert_eq!(ctx_abort.status, Some(StatusCode::BAD_REQUEST));
    assert!(ctx_abort.response_written);

    // Error handler
    let error = ErrorHandler::new(
        StatusCode::FORBIDDEN,
        "Access to this resource is prohibited",
    );
    let mut ctx_error = Context::new(
        Method::GET,
        Uri::from_static("/forbidden"),
        HeaderMap::new(),
        Bytes::new(),
    );
    error.handle(&mut ctx_error).await.unwrap();
    assert_eq!(ctx_error.status, Some(StatusCode::FORBIDDEN));
    assert_eq!(
        String::from_utf8(ctx_error.response_body.unwrap().to_vec()).unwrap(),
        "Access to this resource is prohibited\n"
    );
    assert!(ctx_error.response_written);
}

#[tokio::test]
async fn test_live_server_with_caddyfile_directives() {
    use raddy_caddyfile::Adapter;
    use raddy_caddyfile::parse_caddyfile;
    use raddy_core::module::ModuleRegistry;
    use raddy_http::router::compile_virtual_host_router;
    use raddy_http::server::HttpServerInstance;

    let caddyfile_text = r#"
    :0 {
        basic_auth {
            admin secret123
        }
        templates
        respond "Hello {{ req.method }}! Authorized user." 200
    }
    "#;

    let parsed = parse_caddyfile(caddyfile_text).expect("Failed to parse Caddyfile");
    let mut adapter = Adapter::new();
    let config = adapter.adapt(&parsed).expect("Failed to adapt Caddyfile");

    let http_app = config.http_app().expect("Missing HTTP app");
    let server_cfg = http_app.servers.values().next().expect("Missing server");

    let registry = ModuleRegistry::new();
    let vhost_router =
        compile_virtual_host_router(server_cfg, &registry).expect("Failed to compile router");

    let mut instance = HttpServerInstance::new("phase7_test", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind server");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move { instance.run(shutdown_rx).await });

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/test", bound_addr.port());

    // 1. Unauthenticated request -> 401
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 2. Authenticated request -> 200 with template rendering executed!
    let resp = client
        .get(&url)
        .basic_auth("admin", Some("secret123"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Hello GET! Authorized user.");

    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}
