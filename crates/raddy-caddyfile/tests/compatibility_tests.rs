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

#[test]
fn test_upstream_caddyfile_adapt_suite() {
    let test_dir = std::path::Path::new("/f/caddy/caddytest/integration/caddyfile_adapt");
    if !test_dir.exists() {
        eprintln!("Upstream Caddy test directory not found, skipping");
        return;
    }

    let entries = std::fs::read_dir(test_dir).expect("Failed to read test dir");
    let mut total = 0;
    let mut passed = 0;

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("caddyfiletest") {
            continue;
        }

        let content = std::fs::read_to_string(&path).expect("Failed to read test file");
        if !content.contains("----------") {
            continue;
        }

        let parts: Vec<&str> = content.split("----------").collect();
        let input = parts[0];
        let expected = parts[1].trim();

        // Only test valid JSON outputs in this test
        if serde_json::from_str::<serde_json::Value>(expected).is_err() {
            continue;
        }

        total += 1;
        match adapt_caddyfile(input, "/f/caddy/caddytest/integration") {
            Ok(_) => passed += 1,
            Err(e) => panic!(
                "Failed on test {}: {}\nInput:\n{}",
                path.file_name().unwrap().to_string_lossy(),
                e,
                input
            ),
        }
    }

    println!("Upstream Caddyfile adaptation test results: {} / {} passed", passed, total);
    assert!(total > 200, "Expected at least 200 tests");
    assert_eq!(passed, total, "All valid Caddy upstream tests should adapt successfully");
}

#[test]
fn test_caddyfile_global_servers_protocols() {
    let input = r#"
{
    servers {
        protocols h1 h2
    }
    http_port 81
}
(advertise_h3) {
    header Alt-Svc `h3=":443"; ma=2592000`
}
:443, laxccs.netlib.re {
    import advertise_h3
    file_server {
        root /var/www/html
    }
}
"#;

    let config = adapt_caddyfile(input, ".").expect("Failed to adapt caddyfile");
    let http = config.http_app().expect("Missing http app");
    assert!(http.servers.contains_key("srv_:443"));
    let srv443 = &http.servers["srv_:443"];
    assert_eq!(srv443.protocols, Some(vec!["h1".to_string(), "h2".to_string()]));
}

#[test]
fn test_user_caddyfile_handle_path_and_fileserver_adaptation() {
    let input = r#"
{
    servers {
        protocols h1 h2
    }
    http_port 81
}
(advertise_h3) {
    header Alt-Svc `h3=":443"; ma=2592000`
}
:443, laxccs.netlib.re {
    import advertise_h3
    reverse_proxy /dns-query https://1.1.1.1:443 {
        header_up Host "1.1.1.1"
    }
    file_server {
        root /var/www/html
    }
    redir /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/ 308
    handle_path /fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas/* {
        root /* /x/dl/
        file_server {
            browse
            hide .git
        }
    }
    log {
        output file /var/log/caddy/netlib
    }
}
"#;

    let config = adapt_caddyfile(input, ".").expect("Failed to adapt caddyfile");
    let http = config.http_app().expect("Missing http app");
    let srv443 = &http.servers["srv_:443"];

    // Find the routes
    // 1. Check handle_path route comes BEFORE file_server route
    let handle_path_idx = srv443.routes.iter().position(|r| {
        r.handle.iter().any(|h| h.handler == "subroute")
    }).expect("handle_path subroute should exist");

    let file_server_idx = srv443.routes.iter().position(|r| {
        r.handle.iter().any(|h| h.handler == "file_server")
    }).expect("file_server route should exist");

    assert!(handle_path_idx < file_server_idx, "handle_path (idx {}) must come before file_server (idx {})", handle_path_idx, file_server_idx);

    // 2. Check root was properly extracted for file_server { root /var/www/html }
    let fs_route = &srv443.routes[file_server_idx];
    let fs_handler = &fs_route.handle[0];
    assert_eq!(fs_handler.details.get("root").and_then(|v| v.as_str()), Some("/var/www/html"));

    // 3. Check handle_path subroute has strip_path_prefix and hide
    let hp_route = &srv443.routes[handle_path_idx];
    let hp_subroute = &hp_route.handle[0];
    let subroutes_val = hp_subroute.details.get("routes").unwrap();
    let subroutes: Vec<raddy_core::config::Route> = serde_json::from_value(subroutes_val.clone()).unwrap();
    
    // First route inside handle_path subroute is rewrite
    assert_eq!(subroutes[0].handle[0].handler, "rewrite");
    assert_eq!(
        subroutes[0].handle[0].details.get("strip_path_prefix").and_then(|v| v.as_str()),
        Some("/fasdddddddr3wfesdewfasdASFASde21qwfesdq3rd2qewklas")
    );

    // Second route inside handle_path subroute is vars (root)
    assert_eq!(subroutes[1].handle[0].handler, "vars");

    // Third route inside handle_path subroute is file_server with hide: [".git"]
    assert_eq!(subroutes[2].handle[0].handler, "file_server");
    assert_eq!(subroutes[2].handle[0].details.get("browse").and_then(|v| v.as_bool()), Some(true));
    let hide = subroutes[2].handle[0].details.get("hide").and_then(|v| v.as_array()).unwrap();
    assert_eq!(hide[0].as_str(), Some(".git"));
}


