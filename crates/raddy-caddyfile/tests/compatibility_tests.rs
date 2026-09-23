use raddy_caddyfile::{adapt_caddyfile, parse_caddyfile};

#[test]
fn test_complex_production_caddyfile() {
    let input = r#"
{
    email admin@example.com
    http_port 8080
    https_port 8443
    auto_https disable_redirects
}

(common_headers) {
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        -Server
    }
}

(proxy_backend) {
    reverse_proxy {args.0} {
        lb_policy round_robin
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }
}

api.example.com {
    import common_headers

    @post_requests {
        method POST PUT
        path /api/v1/*
    }

    import proxy_backend 10.0.0.1:8000

    handle /healthz {
        respond "OK" 200
    }

    tls internal
}

example.com, www.example.com {
    import common_headers
    root * /var/www/html

    encode gzip zstd

    redir /old-path /new-path 301

    file_server browse
}

:9090 {
    respond "Metrics placeholder" 200
}
"#;

    let cf_ast = parse_caddyfile(input).expect("Failed to parse AST");
    assert!(cf_ast.global_options.is_some());
    assert_eq!(cf_ast.snippets.len(), 2);
    assert_eq!(cf_ast.site_blocks.len(), 3);

    let config = adapt_caddyfile(input, ".").expect("Failed to adapt caddyfile");

    let http_app = config.http_app().expect("Missing http app");
    // We have servers for:
    // - srv_:8443 (for api.example.com and example.com)
    // - srv_:9090 (for :9090)
    assert!(http_app.servers.contains_key("srv_:8443"));
    assert!(http_app.servers.contains_key("srv_:9090"));

    let srv_https = http_app.servers.get("srv_:8443").unwrap();
    // Verify TLS policies exist
    assert!(srv_https.tls_connection_policies.is_some());

    // Verify automatic https settings were adapted from global options
    assert!(srv_https.automatic_https.is_some());
    assert_eq!(
        srv_https.automatic_https.as_ref().unwrap().disable_redirects,
        Some(true)
    );

    // Verify routes were created
    assert!(!srv_https.routes.is_empty());

    // Print JSON output for inspection
    let json_str = serde_json::to_string_pretty(&config).unwrap();
    assert!(json_str.contains("reverse_proxy"));
    assert!(json_str.contains("file_server"));
    assert!(json_str.contains("static_response"));
    assert!(json_str.contains("encode"));
}

#[test]
fn test_single_line_site_shorthand() {
    let input = "localhost:3000 respond \"Hello single line\" 200";
    let config = adapt_caddyfile(input, ".").expect("Failed to adapt single line");
    let http = config.http_app().expect("Missing http");
    let srv = http.servers.get("srv_:3000").expect("Missing srv_:3000");
    assert_eq!(srv.routes.len(), 1);
    assert_eq!(srv.routes[0].handle[0].handler, "static_response");
}
