use raddy_caddyfile::adapt_caddyfile;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[test]
fn test_caddyfile_layer4_adaptation_global_options() {
    let caddyfile = r#"
{
    layer4 {
        :993 {
            matching_timeout 5s
            idle_timeout 60s
            @imaps tls sni imap.example.com
            route @imaps {
                tls
                proxy 127.0.0.1:143 {
                    proxy_protocol v2
                }
            }
        }
        :2222 {
            route {
                proxy 127.0.0.1:22
            }
        }
    }
}
"#;

    let config = adapt_caddyfile(caddyfile, Path::new("")).expect("Failed to adapt Caddyfile");
    let l4 = config.layer4_app().expect("layer4 app must be present in config");
    assert_eq!(l4.servers.len(), 2);

    let srv0 = l4.servers.get("srv0").expect("srv0 must exist");
    assert_eq!(srv0.listen, vec![":993"]);
    assert_eq!(srv0.matching_timeout, Some("5s".to_string()));
    assert_eq!(srv0.idle_timeout, Some("60s".to_string()));
    assert_eq!(srv0.routes.len(), 1);

    let route0 = &srv0.routes[0];
    let matchers = route0.r#match.as_ref().expect("matchers must exist");
    assert_eq!(matchers.len(), 1);
    let tls_matcher = matchers[0].tls.as_ref().expect("tls matcher must exist");
    assert_eq!(tls_matcher.sni, vec!["imap.example.com"]);

    assert_eq!(route0.handle.len(), 2);
    assert_eq!(route0.handle[0].handler, "tls");
    assert_eq!(route0.handle[1].handler, "proxy");
    assert_eq!(
        route0.handle[1].details.get("proxy_protocol").and_then(|v| v.as_str()),
        Some("v2")
    );

    let srv1 = l4.servers.get("srv1").expect("srv1 must exist");
    assert_eq!(srv1.listen, vec![":2222"]);
    assert_eq!(srv1.routes.len(), 1);
    assert_eq!(srv1.routes[0].handle[0].handler, "proxy");
}

#[test]
fn test_caddyfile_layer4_adaptation_top_level_and_matchers() {
    let caddyfile = r#"
layer4 {
    :4443 {
        @ssh ssh
        @http http
        @internal remote_ip 10.0.0.0/8 127.0.0.1
        @external not remote_ip 10.0.0.0/8

        route @ssh {
            proxy 127.0.0.1:22
        }

        route @http {
            proxy {
                upstream 127.0.0.1:8081 127.0.0.1:8082
                lb_policy least_conn
            }
        }

        route {
            echo
        }
    }
}
"#;

    let config = adapt_caddyfile(caddyfile, Path::new("")).expect("Failed to adapt Caddyfile");
    let l4 = config.layer4_app().expect("layer4 app must be present in config");
    assert_eq!(l4.servers.len(), 1);

    let srv = l4.servers.get("srv0").expect("srv0 must exist");
    assert_eq!(srv.listen, vec![":4443"]);
    assert_eq!(srv.routes.len(), 3);

    // Route 1: @ssh
    assert!(srv.routes[0].r#match.as_ref().unwrap()[0].ssh.is_some());
    assert_eq!(srv.routes[0].handle[0].handler, "proxy");

    // Route 2: @http
    assert!(srv.routes[1].r#match.as_ref().unwrap()[0].http.is_some());
    assert_eq!(srv.routes[1].handle[0].handler, "proxy");
    assert_eq!(
        srv.routes[1].handle[0].details.get("lb_policy").and_then(|v| v.as_str()),
        Some("least_conn")
    );
    let upstreams = srv.routes[1].handle[0]
        .details
        .get("upstreams")
        .and_then(|v| v.as_array())
        .expect("upstreams array must exist");
    assert_eq!(upstreams.len(), 2);

    // Route 3: fallback echo
    assert!(srv.routes[2].r#match.is_none());
    assert_eq!(srv.routes[2].handle[0].handler, "echo");
}

#[tokio::test]
async fn test_live_layer4_tcp_echo() {
    let port = 29100;
    let caddyfile = format!(
        r#"
layer4 {{
    127.0.0.1:{port} {{
        route {{
            echo
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect to echo server");

    let payload = b"Hello Layer 4 Echo!";
    stream.write_all(payload).await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_layer4_tcp_proxy_and_load_balancing() {
    // 1. Start two backend echo servers returning identifier prefixes
    let b1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b1_addr = b1_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = b1_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                if let Ok(n) = conn.read(&mut buf).await {
                    let mut resp = b"B1:".to_vec();
                    resp.extend_from_slice(&buf[..n]);
                    let _ = conn.write_all(&resp).await;
                }
            });
        }
    });

    let b2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b2_addr = b2_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = b2_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                if let Ok(n) = conn.read(&mut buf).await {
                    let mut resp = b"B2:".to_vec();
                    resp.extend_from_slice(&buf[..n]);
                    let _ = conn.write_all(&resp).await;
                }
            });
        }
    });

    // 2. Start Layer 4 proxy with round_robin
    let proxy_port = 29101;
    let caddyfile = format!(
        r#"
layer4 {{
    127.0.0.1:{proxy_port} {{
        route {{
            proxy {{
                upstream {b1_addr} {b2_addr}
                lb_policy round_robin
            }}
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // First request -> B1
    let mut s1 = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();
    s1.write_all(b"ping1").await.unwrap();
    let mut resp1 = vec![0u8; 8];
    s1.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1, b"B1:ping1");

    // Second request -> B2
    let mut s2 = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();
    s2.write_all(b"ping2").await.unwrap();
    let mut resp2 = vec![0u8; 8];
    s2.read_exact(&mut resp2).await.unwrap();
    assert_eq!(&resp2, b"B2:ping2");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_layer4_port_multiplexing_ssh_and_http() {
    // 1. Upstream SSH mock backend
    let ssh_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_addr = ssh_backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = ssh_backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if let Ok(n) = conn.read(&mut buf).await {
                    if buf[..n].starts_with(b"SSH-") {
                        let _ = conn.write_all(b"SSH_OK").await;
                    }
                }
            });
        }
    });

    // 2. Upstream HTTP mock backend
    let http_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = http_backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if let Ok(n) = conn.read(&mut buf).await {
                    if buf[..n].starts_with(b"GET ") {
                        let _ = conn.write_all(b"HTTP_OK").await;
                    }
                }
            });
        }
    });

    // 3. Layer 4 Multiplexer on a single port
    let mux_port = 29102;
    let caddyfile = format!(
        r#"
layer4 {{
    127.0.0.1:{mux_port} {{
        @ssh ssh
        @web http

        route @ssh {{
            proxy {ssh_addr}
        }}

        route @web {{
            proxy {http_addr}
        }}

        route {{
            echo
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client 1: SSH client connecting to mux port
    let mut s_ssh = TcpStream::connect(format!("127.0.0.1:{mux_port}"))
        .await
        .unwrap();
    s_ssh.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await.unwrap();
    let mut res_ssh = [0u8; 6];
    s_ssh.read_exact(&mut res_ssh).await.unwrap();
    assert_eq!(&res_ssh, b"SSH_OK");

    // Client 2: HTTP client connecting to mux port
    let mut s_http = TcpStream::connect(format!("127.0.0.1:{mux_port}"))
        .await
        .unwrap();
    s_http.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut res_http = [0u8; 7];
    s_http.read_exact(&mut res_http).await.unwrap();
    assert_eq!(&res_http, b"HTTP_OK");

    // Client 3: Non-SSH, non-HTTP data -> routes to fallback echo
    let mut s_other = TcpStream::connect(format!("127.0.0.1:{mux_port}"))
        .await
        .unwrap();
    s_other.write_all(b"UNKNOWN_PROTOCOL_DATA").await.unwrap();
    let mut res_other = [0u8; 21];
    s_other.read_exact(&mut res_other).await.unwrap();
    assert_eq!(&res_other, b"UNKNOWN_PROTOCOL_DATA");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_layer4_proxy_protocol_v1_and_v2() {
    // Upstream server verifying PROXY v1 header
    let pp_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pp_addr = pp_backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = pp_backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if let Ok(n) = conn.read(&mut buf).await {
                    let header_str = String::from_utf8_lossy(&buf[..n]);
                    if header_str.starts_with("PROXY TCP4 127.0.0.1") {
                        let _ = conn.write_all(b"PP_VERIFIED").await;
                    }
                }
            });
        }
    });

    let proxy_port = 29103;
    let caddyfile = format!(
        r#"
layer4 {{
    127.0.0.1:{proxy_port} {{
        route {{
            proxy {pp_addr} {{
                proxy_protocol v1
            }}
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();
    stream.write_all(b"payload_data").await.unwrap();

    let mut resp = [0u8; 11];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"PP_VERIFIED");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_layer4_udp_echo() {
    let udp_port = 29104;
    let caddyfile = format!(
        r#"
layer4 {{
    udp/127.0.0.1:{udp_port} {{
        route {{
            echo
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock
        .send_to(b"UDP_PING", format!("127.0.0.1:{udp_port}"))
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"UDP_PING");

    let _ = shutdown_tx.send(true);
}

fn create_client_hello_with_sni(sni: &str) -> Vec<u8> {
    let mut ext_sni = Vec::new();
    let sni_bytes = sni.as_bytes();
    // server name list length
    ext_sni.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    // name type 0 (host_name)
    ext_sni.push(0x00);
    // host name length
    ext_sni.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    ext_sni.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    // extension type 0x0000 (SNI)
    extensions.extend_from_slice(&0u16.to_be_bytes());
    // extension length
    extensions.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ext_sni);

    let mut handshake = Vec::new();
    // client version 0x0303 (TLS 1.2)
    handshake.extend_from_slice(&[0x03, 0x03]);
    // random (32 bytes)
    handshake.extend_from_slice(&[0xaa; 32]);
    // session id length 0
    handshake.push(0x00);
    // cipher suites length 2, cipher suite 0x1301 (TLS_AES_128_GCM_SHA256)
    handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    // compression methods length 1, 0x00 (null)
    handshake.extend_from_slice(&[0x01, 0x00]);
    // extensions length
    handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&extensions);

    let mut record = Vec::new();
    // record type 0x16 (Handshake)
    record.push(0x16);
    // record version 0x0301 (TLS 1.0 record layer)
    record.extend_from_slice(&[0x03, 0x01]);
    // record length (handshake type 1 byte + 3 bytes length + handshake body)
    let hs_total = 4 + handshake.len();
    record.extend_from_slice(&(hs_total as u16).to_be_bytes());
    // handshake type 0x01 (ClientHello)
    record.push(0x01);
    // handshake length (3 bytes)
    record.push(0x00);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[tokio::test]
async fn test_live_layer4_tls_sni_routing() {
    // 1. Upstream Alpha backend
    let alpha_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alpha_addr = alpha_backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = alpha_backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                if let Ok(n) = conn.read(&mut buf).await {
                    if n > 0 {
                        let _ = conn.write_all(b"ALPHA_BACKEND_REPLY").await;
                    }
                }
            });
        }
    });

    // 2. Upstream Beta backend
    let beta_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let beta_addr = beta_backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = beta_backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                if let Ok(n) = conn.read(&mut buf).await {
                    if n > 0 {
                        let _ = conn.write_all(b"BETA_BACKEND_REPLY").await;
                    }
                }
            });
        }
    });

    // 3. Layer 4 SNI router
    let sni_port = 29105;
    let caddyfile = format!(
        r#"
layer4 {{
    127.0.0.1:{sni_port} {{
        @alpha tls sni alpha.example.com
        @beta tls sni beta.example.com

        route @alpha {{
            proxy {alpha_addr}
        }}

        route @beta {{
            proxy {beta_addr}
        }}
    }}
}}
"#
    );

    let config = adapt_caddyfile(&caddyfile, Path::new("")).unwrap();
    let mut manager = raddy_l4::Layer4Manager::from_config(&config, None)
        .await
        .unwrap();
    manager.bind_all().await.unwrap();
    let shutdown_tx = manager.spawn_all_detached();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client 1: connect with alpha.example.com SNI
    let mut s1 = TcpStream::connect(format!("127.0.0.1:{sni_port}"))
        .await
        .unwrap();
    let ch1 = create_client_hello_with_sni("alpha.example.com");
    s1.write_all(&ch1).await.unwrap();
    let mut resp1 = [0u8; 19];
    s1.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1, b"ALPHA_BACKEND_REPLY");

    // Client 2: connect with beta.example.com SNI
    let mut s2 = TcpStream::connect(format!("127.0.0.1:{sni_port}"))
        .await
        .unwrap();
    let ch2 = create_client_hello_with_sni("beta.example.com");
    s2.write_all(&ch2).await.unwrap();
    let mut resp2 = [0u8; 18];
    s2.read_exact(&mut resp2).await.unwrap();
    assert_eq!(&resp2, b"BETA_BACKEND_REPLY");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_admin_api_layer4_reload() {
    use raddy_admin::AppState;
    use raddy_core::module::ModuleRegistry;
    use std::sync::Arc;

    let port = 29106;

    // Config 1: port echo
    let c1 = format!(
        r#"
layer4 {{
    127.0.0.1:{port} {{
        route {{
            echo
        }}
    }}
}}
"#
    );
    let cfg1 = adapt_caddyfile(&c1, Path::new("")).unwrap();
    let registry = Arc::new(ModuleRegistry::new());
    let state = AppState::new(cfg1.clone(), registry, None);

    // Initial load
    state.reload(cfg1).await.expect("Initial load must succeed");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to echo
    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    conn.write_all(b"TEST_ECHO").await.unwrap();
    let mut buf = [0u8; 9];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"TEST_ECHO");

    // Config 2: upstream proxy
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = backend.accept().await {
            let _ = conn.write_all(b"PROXY_NEW").await;
        }
    });

    let c2 = format!(
        r#"
layer4 {{
    127.0.0.1:{port} {{
        route {{
            proxy {b_addr}
        }}
    }}
}}
"#
    );
    let cfg2 = adapt_caddyfile(&c2, Path::new("")).unwrap();

    // Hot reload via state
    state.reload(cfg2).await.expect("Reload must succeed");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut conn2 = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let mut buf2 = [0u8; 9];
    conn2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"PROXY_NEW");

    state.stop_all();
}
