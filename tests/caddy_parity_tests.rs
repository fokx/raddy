use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, header};
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::PlaceholderProvider;
use raddy_core::context::Context;
use raddy_core::module::ModuleRegistry;
use raddy_http::router::compile_virtual_host_router;
use std::path::Path;

#[test]
fn test_placeholders_extended() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "app.example.com".parse().unwrap());
    headers.insert(
        header::COOKIE,
        "session_id=abc123xyz; theme=dark".parse().unwrap(),
    );

    let mut ctx = Context::new(
        Method::GET,
        "/static/css/style.min.css?v=1".parse::<Uri>().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("192.168.1.100:12345".parse().unwrap());

    // File path placeholders
    assert_eq!(ctx.get_placeholder("dir").as_deref(), Some("/static/css"));
    assert_eq!(
        ctx.get_placeholder("file").as_deref(),
        Some("style.min.css")
    );
    assert_eq!(
        ctx.get_placeholder("file.base").as_deref(),
        Some("style.min")
    );
    assert_eq!(ctx.get_placeholder("file.ext").as_deref(), Some(".css"));

    // Host labels placeholders (reverse indexed 0=com, 1=example, 2=app)
    assert_eq!(ctx.get_placeholder("labels.0").as_deref(), Some("com"));
    assert_eq!(ctx.get_placeholder("labels.1").as_deref(), Some("example"));
    assert_eq!(ctx.get_placeholder("labels.2").as_deref(), Some("app"));

    // Cookie placeholders
    assert_eq!(
        ctx.get_placeholder("cookie.session_id").as_deref(),
        Some("abc123xyz")
    );
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
    let mut ctx_internal = Context::new(Method::GET, "/".parse().unwrap(), headers, Bytes::new());
    ctx_internal.remote_addr = Some("192.168.1.50:5000".parse().unwrap());
    router.route_request(&mut ctx_internal).await.unwrap();
    assert_eq!(ctx_internal.status, Some(StatusCode::OK));
    assert_eq!(
        ctx_internal.response_body,
        Some(Bytes::from("Internal access granted"))
    );

    // 8.8.8.8 is public range
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "localhost".parse().unwrap());
    let mut ctx_external = Context::new(Method::GET, "/".parse().unwrap(), headers, Bytes::new());
    ctx_external.remote_addr = Some("8.8.8.8:5000".parse().unwrap());
    router.route_request(&mut ctx_external).await.unwrap();
    assert_eq!(ctx_external.status, Some(StatusCode::FORBIDDEN));
    assert_eq!(
        ctx_external.response_body,
        Some(Bytes::from("External access"))
    );
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
    assert_eq!(
        ctx_ok.response_body,
        Some(Bytes::from("API Delete Authorized"))
    );

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
    let mut ctx = Context::new(Method::GET, "/".parse().unwrap(), headers, Bytes::new());
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(
        ctx.response_body,
        Some(Bytes::from("Method is PUT, mode is production"))
    );
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
    let mut ctx = Context::new(Method::GET, "/".parse().unwrap(), headers, Bytes::new());
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();
    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(
        ctx.response_headers.get("x-custom-fallback").unwrap(),
        "DefaultValue"
    );
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
    assert_eq!(
        ctx.response_body,
        Some(Bytes::from("Custom error: status 404 (Not Found)"))
    );
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
    assert_eq!(
        handlers[1].details.get("fastcgi"),
        Some(&serde_json::json!(true))
    );
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
    use axum::body::Body;
    use axum::http::Request;
    use raddy_admin::{AppState, build_admin_router};
    use std::sync::Arc;
    use tower::ServiceExt;

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
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
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
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
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
    assert_eq!(
        tls.challenges.as_ref().unwrap(),
        &vec!["tls-alpn-01".to_string()]
    );
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

    assert_eq!(
        tls.challenges.as_ref().unwrap(),
        &vec!["tls-alpn-01".to_string()]
    );
    assert_eq!(tls.disable_http_challenge, Some(true));
}

#[tokio::test]
async fn test_user_caddyfile_adaptation_and_compilation() {
    let caddyfile = r#"
{
        log {
                output file /var/log/caddy/caddy.log
                level INFO
        }
        servers {
                trusted_proxies static 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 127.0.0.1/32 178.128.90.43/32 178.128.15.131/32 24.199.124.51/32 167.172.200.153/32
                protocols h1 h2
        }
        order forward_proxy first
        order forward_proxy before file_server
        order forward_proxy before reverse_proxy
        order forward_proxy before rate_limit
        order forward_proxy before basicauth
        order rate_limit before reverse_proxy
        order rate_limit before basicauth
        http_port 81
}

:443, m.lqy.me:443 {
        header {
                Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        }

        forward_proxy {
                basic_auth cf0db2b43ff9f82630d76e1ddab28fd 1d5f3064af5d45b5645542c41aea087733
                hide_ip
                hide_via
                probe_resistance
        }
        @denycn {
                maxmind_geolocation {
                        db_path "/opt/mmdb/GeoLite2-Country.mmdb"
                        # deny_countries CN UNK
                }
        }
        reverse_proxy @denycn http://127.0.0.1:2480
        log {
                output file /var/log/caddy/lqy_mir.log {
                        roll_size 100mb
                        roll_keep 5
                        roll_keep_for 720h
                }
        }
}

:2480, http://localhost:2480, http://[::1]:2480, http://127.0.0.1:2480 {
        @kernel {
                path /arch/* /alpine/* /archlinux/* /centos/* /CPAN/* /debian/* /debian-cd/* /deepin/* /deepin-cd/* /fedora/* /fedora-epel/* /gentoo/* /gentoo-portage/* /gnu/* /linuxmint/* /linuxmint-packages/* /mageia/* /opensuse/* /oracle/* /qubes/* /sourceware/* /slackware/* /tails/* /ubuntu/* /ubuntu-releases/* /yocto/*
        }
        @ocf {
                path /qt/* /nongnu/* /ubuntu-ports/* /tdf/* /raspi/* /blender/* /archlinuxcn/* /rpmfusion/* /siduction/* /finnix-releases/* /trisquel-images/* /archlinuxarm/* /artix-iso/* /elpa/* /debian-security/* /freebsd/* /almalinux/* /linux-mint/* /ubuntu-ports-releases/* /trisquel/* /ipfire/* /puppetlabs/* /rocky/* /libreelec/* /debian-nonfree/* /centos-stream/* /parabola/* /pub/* /mx-linux/* /dragora/* /apache/* /parrot/* /osdn/* /freexian/* /gentoo-distfiles/* /openbsd/* /videolan-ftp/* /pikvm/* /kali-images/* /kali/* /devuan-cd/* /raspbian/* /melpa/* /openindiana/* /devuan/* /kde/* /gimp/* /blackarch/* /manjaro/* /theme/* /artix-linux/* /kde-applicationdata/* /centos-altarch/* /sage/* /opnsense/* /mx-packages/* /gnome/* /cran/* /openeuler/* /ocf-isos/*
        }
        rewrite /cpan /CPAN
        redir /CRAN /cran/
        redir /CRAN/ /cran/
        redir /arch /arch/
        uri replace /arch/ /archlinux/

        reverse_proxy @kernel https://mirrors.edge.kernel.org {
                header_up Host {upstream_hostport}
        }

        reverse_proxy @ocf https://mirrors.ocf.berkeley.edu {
                header_up Host {upstream_hostport}
        }

        handle / {
                root * /srv/mirror/
                file_server {
                        browse
                        hide .git
                }
        }

        redir /openwrt /openwrt/
        handle_path /openwrt/* {
                reverse_proxy https://mirror-03.infra.openwrt.org {
                        header_up Host {upstream_hostport}
                }
        }

        redir /archlinuxarm /archlinuxarm/
        handle_path /archlinuxarm/* {
                reverse_proxy https://ca.us.mirror.archlinuxarm.org {
                        header_up Host {upstream_hostport}
                }
        }
        redir /ctan /ctan/
        handle_path /ctan/* {
                reverse_proxy https://ctan.math.illinois.edu {
                        header_up Host {upstream_hostport}
                }
        }
        redir /lfs /lfs/
        handle_path /lfs/* {
                reverse_proxy https://mirror.koddos.net {
                        header_up Host {upstream_hostport}
                }
        }

        redir /blfs /blfs/
        handle_path /blfs/* {
                reverse_proxy https://mirror.koddos.net {
                        header_up Host {upstream_hostport}
                }
        }

        redir /crates.io-index /crates.io-index/
        handle /crates.io-index {
                root * /srv/crates.io-index/
                file_server {
                        browse
                }
        }
        redir /pypi /pypi/*
        handle_path /pypi/* {
                reverse_proxy https://pypi.org {
                        header_up Host pypi.org
                        header_up Accept-Encoding identity # disable gzip so replace can work
                        transport http {
                                tls
                                tls_server_name pypi.org
                        }
                }

                replace {
                        "https://files.pythonhosted.org" "https://m.lqy.me/pypi-files"
                        "action=\"/search/" "action=\"/pypi/search/"
                        "href=\"/simple/" "href=\"/pypi/simple/"
                        "href=\"/project/" "href=\"/pypi/project/"
                        "href=\"/user/" "href=\"/pypi/user/"
                        "href=\"/classifiers/" "href=\"/pypi/classifiers/"
                        "href=\"/search/" "href=\"/pypi/search/"
                }
        }

        handle_path /pypi-files/* {
                reverse_proxy https://files.pythonhosted.org {
                        header_up Host files.pythonhosted.org
                        transport http {
                                tls
                                tls_server_name files.pythonhosted.org
                        }
                }
        }

        redir /archrepo /archrepo/

        handle_path /archrepo/* {
                root * /srv/archaurpkgs
                file_server browse
                # Add proper MIME types for Arch packages
                header Content-Type "application/octet-stream" *.pkg.tar.zst
                header Content-Type "application/octet-stream" *.pkg.tar.xz
                header Content-Type "application/octet-stream" *.db
                header Content-Type "application/octet-stream" *.db.tar.gz
                header Content-Type "application/octet-stream" *.files
                header Content-Type "application/octet-stream" *.files.tar.gz
        }
        redir /xdlb01db3f09e230c736a1285b388e6695204d81100a5fb8e /xdlb01db3f09e230c736a1285b388e6695204d81100a5fb8e/ 308
        handle_path /xdlb01db3f09e230c736a1285b388e6695204d81100a5fb8e/* {
                root /* /x/dl
                #root /* /srv/bbcdl/
                file_server {
                        browse
                        hide .git
                }
        }
        redir /bbcdl0511bcc93a58fb9d41867f1db932014ecd08be /bbcdl0511bcc93a58fb9d41867f1db932014ecd08be/ 308
        handle_path /bbcdl0511bcc93a58fb9d41867f1db932014ecd08be/* {
                #root /* /x/dl
                root /* /srv/bbcdl/
                file_server {
                        browse
                        hide .git
                }
        }

        redir /tools /tools/ 308
        handle_path /tools/* {
                root /* /srv/tools/
                file_server {
                        browse
                        hide .git
                }
        }

        file_server {
                root /srv/mirror/404.html
        }
        handle_errors {
                @404 {
                        expression {http.error.status_code} == 404
                }
                rewrite @404 /srv/mirror/404.html
                file_server
        }
}
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let registry = ModuleRegistry::new();

    for (name, srv) in &http.servers {
        let vhost_router = compile_virtual_host_router(srv, &registry);
        assert!(
            vhost_router.is_ok(),
            "Failed to compile server router for '{}': {:?}",
            name,
            vhost_router.err()
        );
    }
}

#[tokio::test]
async fn test_caddyfile_handle_errors_with_named_expression_matcher() {
    let caddyfile = r#"
    localhost:8080 {
        handle_errors {
            @404 {
                expression {http.error.status_code} == 404
            }
            respond @404 "Custom 404 handler matched" 404
            respond "Other error" 500
        }
        error 404 "Not Found"
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
        "/anything".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    ctx.remote_addr = Some("127.0.0.1:5000".parse().unwrap());
    router.route_request(&mut ctx).await.unwrap();

    assert_eq!(ctx.status, Some(StatusCode::NOT_FOUND));
    assert_eq!(
        ctx.response_body,
        Some(Bytes::from("Custom 404 handler matched"))
    );
}

#[tokio::test]
async fn test_reverse_proxy_dial_address_schemes() {
    use raddy_proxy::transport::parse_upstream_target;

    let target1 = parse_upstream_target("http://127.0.0.1:2480", false);
    assert_eq!(target1.dial_addr, "127.0.0.1:2480");
    assert_eq!(target1.host, "127.0.0.1");
    assert_eq!(target1.port, 2480);
    assert!(!target1.is_tls);

    let target2 = parse_upstream_target("https://mirrors.edge.kernel.org", false);
    assert_eq!(target2.dial_addr, "mirrors.edge.kernel.org:443");
    assert_eq!(target2.host, "mirrors.edge.kernel.org");
    assert_eq!(target2.port, 443);
    assert!(target2.is_tls);

    let target3 = parse_upstream_target("https://pypi.org:8443", false);
    assert_eq!(target3.dial_addr, "pypi.org:8443");
    assert_eq!(target3.host, "pypi.org");
    assert_eq!(target3.port, 8443);
    assert!(target3.is_tls);

    let target4 = parse_upstream_target("http://[::1]:2480", false);
    assert_eq!(target4.dial_addr, "[::1]:2480");
    assert_eq!(target4.host, "::1");
    assert_eq!(target4.port, 2480);
    assert!(!target4.is_tls);

    let target5 = parse_upstream_target(":8080", false);
    assert_eq!(target5.dial_addr, "127.0.0.1:8080");
    assert_eq!(target5.port, 8080);
    assert!(!target5.is_tls);
}

#[tokio::test]
async fn test_reverse_proxy_caddyfile_adaptation_transport_and_upstream_hostport() {
    let caddyfile = r#"
    localhost:8080 {
        reverse_proxy @api https://pypi.org {
            header_up Host {upstream_hostport}
            transport http {
                tls
                tls_server_name pypi.org
            }
        }
    }
    "#;

    let config = adapt_caddyfile(caddyfile, Path::new(".")).unwrap();
    let http = config.http_app().unwrap();
    let server = http.servers.values().next().unwrap();
    let route = &server.routes[0];
    let proxy_handler = &route.handle[0];
    assert_eq!(proxy_handler.handler, "reverse_proxy");

    let upstreams = proxy_handler
        .details
        .get("upstreams")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        upstreams[0].get("dial").unwrap().as_str().unwrap(),
        "pypi.org:443"
    );

    let transport = proxy_handler
        .details
        .get("transport")
        .unwrap()
        .as_object()
        .unwrap();
    assert_eq!(transport.get("protocol").unwrap().as_str().unwrap(), "http");
    let tls = transport.get("tls").unwrap().as_object().unwrap();
    assert_eq!(
        tls.get("server_name").unwrap().as_str().unwrap(),
        "pypi.org"
    );
}

#[tokio::test]
async fn test_reverse_proxy_end_to_end_with_http_scheme_dial() {
    use raddy_core::Handler;
    use raddy_proxy::{First, HeaderMutator, ReverseProxyHandler, Upstream};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // 1. Start mock upstream backend
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp_body = format!("OK from backend: {}", req_str);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    // 2. Configure ReverseProxyHandler with "http://127.0.0.1:<port>" (explicit scheme)
    let upstream_url = format!("http://{}", addr);
    let upstream = Arc::new(Upstream::new(&upstream_url));
    let mut mutator = HeaderMutator::new();
    mutator
        .header_up_set
        .insert("Host".to_string(), "{upstream_hostport}".to_string());

    let handler = ReverseProxyHandler::new(vec![upstream], Box::new(First), mutator);

    // 3. Send test request
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "m.lqy.me".parse().unwrap());
    let mut ctx = Context::new(
        Method::GET,
        "/arch/packages".parse().unwrap(),
        headers,
        Bytes::new(),
    );

    handler.handle(&mut ctx).await.unwrap();

    assert_eq!(ctx.status, Some(StatusCode::OK));
    let body_bytes = ctx.response_body.unwrap();
    let body_text = String::from_utf8_lossy(&body_bytes);
    assert!(body_text.contains("GET /arch/packages"));
    assert!(body_text.contains(&format!("host: {}", addr)));
}
