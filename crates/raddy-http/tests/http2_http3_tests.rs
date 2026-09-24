use std::sync::Arc;
use bytes::Buf;
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use raddy_core::config::{HandlerConfig, HttpServer, Route};
use raddy_core::module::ModuleRegistry;
use raddy_http::http3::build_quic_server_config;
use raddy_http::router::compile_virtual_host_router;
use raddy_http::server::HttpServerInstance;
use raddy_tls::LocalCa;
use raddy_tls::sni::SniResolver;
use raddy_tls::storage::parse_certified_key;

fn setup_test_server_instance(route_body: &str) -> (HttpServerInstance, LocalCa) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = LocalCa::new().expect("Failed to create LocalCa");
    let (cert_pem, key_pem) = ca
        .issue_certificate(&["localhost".into(), "127.0.0.1".into()])
        .expect("Failed to issue cert");

    let certified_key = parse_certified_key(&cert_pem, &key_pem).expect("Failed to parse certified key");

    let sni_resolver = Arc::new(SniResolver::new());
    sni_resolver.insert("localhost", certified_key.clone());
    sni_resolver.insert("127.0.0.1", certified_key.clone());
    sni_resolver.set_default(certified_key);

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config.clone()));
    let quic_config = build_quic_server_config(&server_config).expect("Failed to build QUIC config");

    let mut server = HttpServer::default();
    server.listen = vec!["127.0.0.1:0".into()];
    server.routes.push(Route {
        r#match: None,
        handle: vec![
            HandlerConfig::new("static_response")
                .with_field("status_code", 200)
                .with_field("body", route_body),
        ],
        terminal: Some(true),
        group: None,
    });

    let registry = ModuleRegistry::new();
    let vhost_router = compile_virtual_host_router(&server, &registry).unwrap();

    let instance = HttpServerInstance::new("h2_h3_test", "127.0.0.1:0", vhost_router)
        .with_tls_acceptor(tls_acceptor)
        .with_quic_config(quic_config)
        .with_protocols(vec!["h1".into(), "h2".into(), "h3".into()]);

    (instance, ca)
}

#[tokio::test]
async fn test_http2_alpn_negotiation_and_alt_svc() {
    let (mut instance, ca) = setup_test_server_instance("HTTP/2 response from Raddy!");
    instance.bind().await.expect("Failed to bind server");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    // Setup reqwest client with root CA
    let cert = reqwest::Certificate::from_pem(ca.ca_cert_pem().as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .build()
        .unwrap();

    let url = format!("https://localhost:{}/test", bound_addr.port());

    // Send HTTP/2 request
    let resp = client.get(&url).send().await.expect("Failed to send request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2, "Expected HTTP/2 ALPN negotiation");

    // Check Alt-Svc header advertising HTTP/3
    let alt_svc = resp.headers().get("alt-svc").expect("Missing Alt-Svc header");
    let alt_svc_str = alt_svc.to_str().unwrap();
    assert!(
        alt_svc_str.contains(&format!("h3=\":{}\"", bound_addr.port())),
        "Alt-Svc should advertise port {}: {}",
        bound_addr.port(),
        alt_svc_str
    );

    let text = resp.text().await.expect("Failed to read body");
    assert_eq!(text, "HTTP/2 response from Raddy!");

    // Test multiple concurrent requests over multiplexed HTTP/2
    let mut tasks = Vec::new();
    for i in 0..5 {
        let client_clone = client.clone();
        let url_clone = url.clone();
        tasks.push(tokio::spawn(async move {
            let r = client_clone.get(&url_clone).send().await.unwrap();
            assert_eq!(r.version(), reqwest::Version::HTTP_2);
            i
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_http3_quic_end_to_end_and_graceful_shutdown() {
    let (mut instance, ca) = setup_test_server_instance("HTTP/3 response via QUIC!");
    instance.bind().await.expect("Failed to bind server");
    let bound_addr = instance.local_addr().expect("Missing bound addr");

    assert!(instance.quic_endpoint.is_some(), "QUIC endpoint should be active");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        instance.run(shutdown_rx).await
    });

    // Build client trusting the local CA for QUIC
    let mut root_store = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::Cursor::new(ca.ca_cert_pem().as_bytes());
    let ca_certs = rustls_pemfile::certs(&mut ca_reader).collect::<std::result::Result<Vec<_>, _>>().unwrap();
    for c in ca_certs {
        root_store.add(c).unwrap();
    }

    let mut client_tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_crypto = Arc::new(QuicClientConfig::try_from(client_tls_cfg).unwrap());
    let quinn_client_cfg = QuinnClientConfig::new(quic_client_crypto);

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_cfg);

    // 1. Establish QUIC connection to the same port as HTTPS
    let quic_conn = client_endpoint.connect(bound_addr, "localhost").unwrap().await.expect("QUIC connect failed");
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(quic_conn)).await.expect("H3 client handshake failed");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // 2. Send GET request over HTTP/3
    let get_req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost:{}/h3-get", bound_addr.port()))
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(get_req).await.expect("Failed to send H3 request");
    stream.finish().await.expect("Failed to finish request stream");

    let resp = stream.recv_response().await.expect("Failed to receive H3 response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body_bytes = Vec::new();
    while let Some(chunk) = stream.recv_data().await.expect("Error reading chunk") {
        let mut chunk = chunk;
        while chunk.has_remaining() {
            body_bytes.push(chunk.get_u8());
        }
    }
    assert_eq!(String::from_utf8(body_bytes).unwrap(), "HTTP/3 response via QUIC!");

    // 3. Send POST request with body on the same H3 connection
    let post_req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost:{}/h3-post", bound_addr.port()))
        .body(())
        .unwrap();

    let mut stream2 = send_request.send_request(post_req).await.expect("Failed to send second H3 request");
    stream2.send_data(bytes::Bytes::from("Streaming data over HTTP/3")).await.unwrap();
    stream2.finish().await.expect("Failed to finish post stream");

    let resp2 = stream2.recv_response().await.expect("Failed to receive H3 response 2");
    assert_eq!(resp2.status(), StatusCode::OK);

    // 4. Graceful shutdown
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}

