use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use raddy_core::context::Context;
use raddy_core::handler::Handler;
use raddy_proxy::forward::acl::{default_acl_suffix_rules, new_acl_rule};
use raddy_proxy::forward::auth::{AuthConfig, AuthError};
use raddy_proxy::forward::handler::ForwardProxyHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_forward_proxy_auth_and_credentials() {
    let auth = AuthConfig::new(vec![AuthConfig::encode_credentials("user1", "secretpass")]);

    // 1. Missing auth
    assert_eq!(auth.check(None), Err(AuthError::Missing));

    // 2. Wrong scheme
    let wrong_scheme = HeaderValue::from_static("Bearer token123");
    assert_eq!(auth.check(Some(&wrong_scheme)), Err(AuthError::UnsupportedScheme));

    // 3. Wrong credentials
    let wrong_creds = HeaderValue::from_str(&format!(
        "Basic {}",
        AuthConfig::encode_credentials("user1", "wrongpass")
    ))
    .unwrap();
    assert!(matches!(auth.check(Some(&wrong_creds)), Err(AuthError::InvalidCredentials(_))));

    // 4. Correct credentials
    let correct = HeaderValue::from_str(&format!(
        "Basic {}",
        AuthConfig::encode_credentials("user1", "secretpass")
    ))
    .unwrap();
    assert_eq!(auth.check(Some(&correct)), Ok("user1".to_string()));
}

#[tokio::test]
async fn test_forward_proxy_acl_rules() {
    let deny_local = default_acl_suffix_rules();

    // Default ACL denies localhost
    let localhost_ip = "127.0.0.1".parse().unwrap();
    assert!(!raddy_proxy::forward::acl::is_host_allowed(&deny_local, "localhost", localhost_ip));

    let private_ip = "192.168.1.50".parse().unwrap();
    assert!(!raddy_proxy::forward::acl::is_host_allowed(&deny_local, "internal.lan", private_ip));

    // Public IP allowed by default `allow all` at the end
    let public_ip = "93.184.216.34".parse().unwrap();
    assert!(raddy_proxy::forward::acl::is_host_allowed(&deny_local, "example.com", public_ip));

    // Custom ACL: allow all first overrides default deny
    let mut custom_rules = vec![new_acl_rule("all", true).unwrap()];
    custom_rules.extend(default_acl_suffix_rules());
    assert!(raddy_proxy::forward::acl::is_host_allowed(&custom_rules, "localhost", localhost_ip));

    // Custom domain ACL
    let domain_rules = vec![
        new_acl_rule("*.trusted.com", true).unwrap(),
        new_acl_rule("deny.com", false).unwrap(),
        new_acl_rule("all", false).unwrap(),
    ];
    assert!(raddy_proxy::forward::acl::is_host_allowed(&domain_rules, "sub.trusted.com", public_ip));
    assert!(raddy_proxy::forward::acl::is_host_allowed(&domain_rules, "trusted.com", public_ip));
    assert!(!raddy_proxy::forward::acl::is_host_allowed(&domain_rules, "deny.com", public_ip));
    assert!(!raddy_proxy::forward::acl::is_host_allowed(&domain_rules, "untrusted.com", public_ip));
}

#[tokio::test]
async fn test_forward_proxy_pac_serving() {
    let mut config_map = std::collections::HashMap::new();
    config_map.insert("pac_path".to_string(), serde_json::json!("/my-proxy.pac"));

    let handler = ForwardProxyHandler::from_config(&config_map).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("proxy.example.com:8443"));

    let mut ctx = Context::new(
        Method::GET,
        Uri::from_static("https://proxy.example.com:8443/my-proxy.pac"),
        headers,
        Bytes::new(),
    );

    handler.handle(&mut ctx).await.unwrap();

    assert!(ctx.response_written);
    assert_eq!(ctx.status, Some(StatusCode::OK));
    let body = String::from_utf8(ctx.response_body.unwrap().to_vec()).unwrap();
    assert!(body.contains("FindProxyForURL"));
    assert!(body.contains("HTTPS proxy.example.com:8443"));
}

#[tokio::test]
async fn test_forward_proxy_probe_resistance() {
    let mut config_map = std::collections::HashMap::new();
    config_map.insert(
        "auth_credentials".to_string(),
        serde_json::json!([AuthConfig::encode_credentials("admin", "p@ssword")]),
    );
    config_map.insert(
        "probe_resistance".to_string(),
        serde_json::json!({ "domain": "secret-domain.test" }),
    );

    let handler = ForwardProxyHandler::from_config(&config_map).unwrap();

    // 1. Visit normal host with wrong credentials: acts as if proxy doesn't exist (transparent passthrough)
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("normal-host.com"));
    let mut ctx = Context::new(
        Method::GET,
        Uri::from_static("http://normal-host.com/"),
        headers,
        Bytes::new(),
    );
    handler.handle(&mut ctx).await.unwrap();
    assert!(!ctx.response_written, "Should pass through to next handler without writing response");

    // 2. Visit secret probe resistance link with wrong credentials: returns 407 hidden page
    let mut headers_secret = HeaderMap::new();
    headers_secret.insert(http::header::HOST, HeaderValue::from_static("secret-domain.test"));
    let mut ctx_secret = Context::new(
        Method::GET,
        Uri::from_static("http://secret-domain.test/"),
        headers_secret,
        Bytes::new(),
    );
    handler.handle(&mut ctx_secret).await.unwrap();
    assert!(ctx_secret.response_written);
    assert_eq!(ctx_secret.status, Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED));
    let body = String::from_utf8(ctx_secret.response_body.unwrap().to_vec()).unwrap();
    assert!(body.contains("Hidden Proxy Page"));
    assert!(body.contains("Please authenticate yourself to the proxy."));

    // 3. Visit secret probe resistance link with valid credentials: returns 200 hidden page
    let mut headers_auth = HeaderMap::new();
    headers_auth.insert(http::header::HOST, HeaderValue::from_static("secret-domain.test"));
    headers_auth.insert(
        "proxy-authorization",
        HeaderValue::from_str(&format!(
            "Basic {}",
            AuthConfig::encode_credentials("admin", "p@ssword")
        ))
        .unwrap(),
    );
    let mut ctx_auth = Context::new(
        Method::GET,
        Uri::from_static("http://secret-domain.test/"),
        headers_auth,
        Bytes::new(),
    );
    handler.handle(&mut ctx_auth).await.unwrap();
    assert!(ctx_auth.response_written);
    assert_eq!(ctx_auth.status, Some(StatusCode::OK));
    let body = String::from_utf8(ctx_auth.response_body.unwrap().to_vec()).unwrap();
    assert!(body.contains("Congratulations, you are successfully authenticated to the proxy!"));
}

#[tokio::test]
async fn test_forward_proxy_port_restrictions() {
    let mut config_map = std::collections::HashMap::new();
    config_map.insert("ports".to_string(), serde_json::json!([80, 443]));
    // Allow localhost for test
    config_map.insert(
        "acl".to_string(),
        serde_json::json!([{"allow": true, "subjects": ["all"]}]),
    );

    let handler = ForwardProxyHandler::from_config(&config_map).unwrap();

    // Port 8080 should be forbidden
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
    let mut ctx = Context::new(
        Method::CONNECT,
        Uri::from_static("127.0.0.1:8080"),
        headers,
        Bytes::new(),
    );

    handler.handle(&mut ctx).await.unwrap();
    assert!(ctx.response_written);
    assert_eq!(ctx.status, Some(StatusCode::FORBIDDEN));
    let body = String::from_utf8(ctx.response_body.unwrap().to_vec()).unwrap();
    assert!(body.contains("port 8080 is not allowed"));
}

#[tokio::test]
async fn test_forward_proxy_connect_tunneling_end_to_end() {
    // 1. Start a mock echo TCP server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Configure forward proxy with auth and allow all
    let mut config_map = std::collections::HashMap::new();
    config_map.insert(
        "auth_credentials".to_string(),
        serde_json::json!([AuthConfig::encode_credentials("testuser", "testpass")]),
    );
    config_map.insert(
        "acl".to_string(),
        serde_json::json!([{"allow": true, "subjects": ["all"]}]),
    );

    let handler = ForwardProxyHandler::from_config(&config_map).unwrap();

    // 3. Test unauthenticated CONNECT -> 407
    let mut headers_unauth = HeaderMap::new();
    headers_unauth.insert(
        http::header::HOST,
        HeaderValue::from_str(&echo_addr.to_string()).unwrap(),
    );
    let mut ctx_unauth = Context::new(
        Method::CONNECT,
        Uri::try_from(echo_addr.to_string()).unwrap(),
        headers_unauth,
        Bytes::new(),
    );
    handler.handle(&mut ctx_unauth).await.unwrap();
    assert_eq!(ctx_unauth.status, Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED));

    // 4. Test authenticated CONNECT
    let mut headers_auth = HeaderMap::new();
    headers_auth.insert(
        http::header::HOST,
        HeaderValue::from_str(&echo_addr.to_string()).unwrap(),
    );
    headers_auth.insert(
        "proxy-authorization",
        HeaderValue::from_str(&format!(
            "Basic {}",
            AuthConfig::encode_credentials("testuser", "testpass")
        ))
        .unwrap(),
    );

    let mut ctx_auth = Context::new(
        Method::CONNECT,
        Uri::try_from(echo_addr.to_string()).unwrap(),
        headers_auth,
        Bytes::new(),
    );

    handler.handle(&mut ctx_auth).await.unwrap();
    assert_eq!(ctx_auth.status, Some(StatusCode::OK));
    assert!(ctx_auth.response_written);
}
