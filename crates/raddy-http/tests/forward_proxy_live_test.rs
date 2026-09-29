use std::time::Duration;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use raddy_caddyfile::adapt_caddyfile;
use raddy_core::module::ModuleRegistry;
use raddy_http::router::compile_virtual_host_router;
use raddy_http::server::HttpServerInstance;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_live_forward_proxy_end_to_end() {
    // 1. Start a mock target backend HTTP server
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    let target_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = target_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                if req_str.contains("GET /hello") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\nHello from target backend!";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.flush().await;
                }
            });
        }
    });

    // 2. Configure Raddy with forward_proxy directive in Caddyfile
    let cred = BASE64.encode("proxyadmin:proxypass");
    let caddyfile_text = format!(
        r#"
        {{
            order forward_proxy first
        }}
        :0 {{
            forward_proxy {{
                basic_auth proxyadmin proxypass
                serve_pac /proxy.pac
                probe_resistance secret.proxy.local
                acl {{
                    allow all
                }}
            }}
            respond / "Welcome to host website" 200
        }}
        "#
    );

    let config = adapt_caddyfile(&caddyfile_text, ".").expect("Failed to adapt Caddyfile");

    let http_app = config.http_app().expect("Missing HTTP app");
    let server_cfg = http_app.servers.values().next().expect("Missing server");

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(server_cfg, &registry).expect("Failed to compile router");

    let mut instance = HttpServerInstance::new("fp_test_server", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind server");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    // Let server initialize
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Test PAC file serving
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let pac_req = format!("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", bound_addr.port());
    stream.write_all(pac_req.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    eprintln!("PAC resp_str: {}", resp_str);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("FindProxyForURL"));

    // 4. Test Probe Resistance:
    // a) Secret domain without auth -> 407 hidden page
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let secret_req = format!("GET / HTTP/1.1\r\nHost: secret.proxy.local\r\nConnection: close\r\n\r\n");
    stream.write_all(secret_req.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    eprintln!("Secret resp_str: {}", resp_str);
    assert!(resp_str.contains("407 Proxy Authentication Required"));
    assert!(resp_str.contains("Hidden Proxy Page"));

    // b) Regular site without auth -> 200 "Welcome to host website" (passthrough!)
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let site_req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", bound_addr.port());
    stream.write_all(site_req.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Welcome to host website"));

    // 5. Test Plain HTTP Forward Proxying:
    // a) Without auth credentials -> 407 Proxy Authentication Required
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let proxy_unauth = format!(
        "GET /hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        target_addr.port()
    );
    stream.write_all(proxy_unauth.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    eprintln!("Unauth proxy resp_str: {}", resp_str);
    assert!(resp_str.contains("404 Not Found"));

    // b) With auth credentials -> 200 OK from target backend!
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let proxy_auth = format!(
        "GET /hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
        target_addr.port(),
        cred
    );
    stream.write_all(proxy_auth.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    assert!(resp_str.contains("HTTP/1.1 200 OK"), "Got response: {}", resp_str);
    assert!(resp_str.contains("Hello from target backend!"));
    assert!(resp_str.contains("via: 1.1 caddy"));

    // 6. Test CONNECT Tunneling:
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        target_addr.port(),
        target_addr.port(),
        cred
    );
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    // Read 200 OK CONNECT response
    let mut resp_buf = [0u8; 1024];
    let n = stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(resp_str.contains("200 OK"), "Expected 200 OK for CONNECT, got: {}", resp_str);

    // Send HTTP GET through the upgraded tunnel
    let tunnel_req = format!("GET /hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", target_addr.port());
    stream.write_all(tunnel_req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut tunnel_resp = Vec::new();
    stream.read_to_end(&mut tunnel_resp).await.unwrap();
    let tunnel_resp_str = String::from_utf8_lossy(&tunnel_resp);
    assert!(tunnel_resp_str.contains("HTTP/1.1 200 OK"));
    assert!(tunnel_resp_str.contains("Hello from target backend!"));

    // Shutdown
    shutdown_tx.send(true).unwrap();
    let _ = server_task.await;
    target_task.abort();
}

#[tokio::test]
async fn test_live_forward_proxy_standard_auth_challenge() {
    let caddyfile_text = r#"
    {
        order forward_proxy first
    }
    :0 {
        forward_proxy {
            basic_auth user pass
            acl {
                allow all
            }
        }
    }
    "#;

    let config = adapt_caddyfile(caddyfile_text, ".").expect("Failed to adapt Caddyfile");
    let http_app = config.http_app().expect("Missing HTTP app");
    let server_cfg = http_app.servers.values().next().expect("Missing server");

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(server_cfg, &registry).expect("Failed to compile router");

    let mut instance = HttpServerInstance::new("fp_std_server", "127.0.0.1:0", vhost_router);
    instance.bind().await.expect("Failed to bind server");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Unauthenticated request to standard forward proxy -> 407 Proxy Authentication Required
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp_buf = [0u8; 1024];
    let n = stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(resp_str.contains("HTTP/1.1 407 Proxy Authentication Required"));
    assert!(resp_str.contains("proxy-authenticate: Basic realm=\"Caddy Secure Web Proxy\""));

    shutdown_tx.send(true).unwrap();
    let _ = server_task.await;
}

