use raddy_core::config::{HandlerConfig, HttpServer, Route};
use raddy_core::module::ModuleRegistry;
use raddy_http::router::compile_virtual_host_router;
use raddy_http::server::HttpServerInstance;
use raddy_tls::LocalCa;
use raddy_tls::sni::SniResolver;
use raddy_tls::storage::parse_certified_key;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn test_live_https_server_with_tls_handshake() {
    // 1. Generate Local CA and leaf certificate for localhost and 127.0.0.1
    let ca = LocalCa::new().expect("Failed to create LocalCa");
    let (cert_pem, key_pem) = ca
        .issue_certificate(&["localhost".into(), "127.0.0.1".into()])
        .expect("Failed to issue cert");

    let certified_key =
        parse_certified_key(&cert_pem, &key_pem).expect("Failed to parse certified key");

    let sni_resolver = Arc::new(SniResolver::new());
    sni_resolver.insert("localhost", certified_key.clone());
    sni_resolver.insert("127.0.0.1", certified_key.clone());
    sni_resolver.set_default(certified_key);

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // 2. Setup HttpServer configuration
    let mut server = HttpServer::default();
    server.listen = vec!["127.0.0.1:0".into()];
    server.routes.push(Route {
        r#match: None,
        handle: vec![
            HandlerConfig::new("static_response")
                .with_field("status_code", 200)
                .with_field("body", "Secure HTTPS response from Raddy!"),
        ],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    let mut instance = HttpServerInstance::new("https_test", "127.0.0.1:0", vhost_router)
        .with_tls_acceptor(tls_acceptor);
    instance
        .bind()
        .await
        .expect("Failed to bind HTTPS listener");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move { instance.run(shutdown_rx).await });

    // 3. Setup client trusting the Local CA cert
    let mut root_store = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::Cursor::new(ca.ca_cert_pem().as_bytes());
    let ca_certs = rustls_pemfile::certs(&mut ca_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    for c in ca_certs {
        root_store.add(c).unwrap();
    }

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    // 4. Connect over TCP and perform TLS Handshake
    let tcp_stream = TcpStream::connect(bound_addr)
        .await
        .expect("Failed to connect TCP");
    let server_name = ServerName::try_from("localhost".to_string()).expect("Invalid server name");
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake failed");

    // 5. Send HTTP request over TLS
    let req = b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(req)
        .await
        .expect("Failed to write to TLS stream");
    tls_stream
        .flush()
        .await
        .expect("Failed to flush TLS stream");

    // 6. Read response from TLS stream
    let mut resp_bytes = Vec::new();
    tls_stream
        .read_to_end(&mut resp_bytes)
        .await
        .expect("Failed to read from TLS stream");
    let resp_str = String::from_utf8_lossy(&resp_bytes);

    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Secure HTTPS response from Raddy!"));

    // 7. Graceful shutdown
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}
