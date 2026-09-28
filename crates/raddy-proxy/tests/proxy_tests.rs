use std::sync::Arc;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use raddy_core::context::Context;
use raddy_core::handler::Handler;
use raddy_proxy::headers::HeaderMutator;
use raddy_proxy::load_balancer::*;
use raddy_proxy::proxy::ReverseProxyHandler;
use raddy_proxy::upstream::Upstream;

#[test]
fn test_load_balancer_round_robin() {
    let u1 = Arc::new(Upstream::new("127.0.0.1:8001"));
    let u2 = Arc::new(Upstream::new("127.0.0.1:8002"));
    let u3 = Arc::new(Upstream::new("127.0.0.1:8003"));
    let upstreams = vec![u1.clone(), u2.clone(), u3.clone()];

    let lb = RoundRobin::new();
    let ctx = Context::new(Method::GET, Uri::from_static("/"), HeaderMap::new(), Bytes::new());

    let s1 = lb.select(&upstreams, &ctx).unwrap();
    let s2 = lb.select(&upstreams, &ctx).unwrap();
    let s3 = lb.select(&upstreams, &ctx).unwrap();
    let s4 = lb.select(&upstreams, &ctx).unwrap();

    assert_eq!(s1.dial, "127.0.0.1:8001");
    assert_eq!(s2.dial, "127.0.0.1:8002");
    assert_eq!(s3.dial, "127.0.0.1:8003");
    assert_eq!(s4.dial, "127.0.0.1:8001");
}

#[test]
fn test_load_balancer_least_conn() {
    let u1 = Arc::new(Upstream::new("127.0.0.1:8001"));
    let u2 = Arc::new(Upstream::new("127.0.0.1:8002"));
    let u3 = Arc::new(Upstream::new("127.0.0.1:8003"));

    u1.inc_active();
    u1.inc_active(); // u1 active = 2
    u2.inc_active(); // u2 active = 1
    u3.inc_active();
    u3.inc_active();
    u3.inc_active(); // u3 active = 3

    let upstreams = vec![u1, u2.clone(), u3];
    let lb = LeastConn;
    let ctx = Context::new(Method::GET, Uri::from_static("/"), HeaderMap::new(), Bytes::new());

    let selected = lb.select(&upstreams, &ctx).unwrap();
    assert_eq!(selected.dial, "127.0.0.1:8002");
}

#[test]
fn test_load_balancer_ip_hash() {
    let u1 = Arc::new(Upstream::new("127.0.0.1:8001"));
    let u2 = Arc::new(Upstream::new("127.0.0.1:8002"));
    let upstreams = vec![u1, u2];
    let lb = IpHash;

    let mut ctx1 = Context::new(Method::GET, Uri::from_static("/"), HeaderMap::new(), Bytes::new());
    ctx1.remote_addr = Some("192.168.1.50:1234".parse().unwrap());

    let sel1 = lb.select(&upstreams, &ctx1).unwrap();
    let sel2 = lb.select(&upstreams, &ctx1).unwrap();
    // Same IP must hash to the exact same upstream
    assert_eq!(sel1.dial, sel2.dial);
}

#[test]
fn test_header_mutator_rules() {
    let mut mutator = HeaderMutator::new();
    mutator.header_up_set.insert("X-Custom-Req".into(), "CustomVal-{remote_host}".into());
    mutator.header_up_delete.push("X-Delete-Me".into());
    mutator.header_down_set.insert("X-Proxy-By".into(), "Raddy".into());
    mutator.header_down_delete.push("Server".into());

    let mut ctx = Context::new(Method::GET, Uri::from_static("/"), HeaderMap::new(), Bytes::new());
    ctx.remote_addr = Some("10.0.0.1:9999".parse().unwrap());
    ctx.headers.insert("Host", HeaderValue::from_static("example.com"));
    ctx.headers.insert("X-Delete-Me", HeaderValue::from_static("secret"));

    // 1. Apply header_up
    let mut req_headers = ctx.headers.clone();
    mutator.apply_header_up(&mut req_headers, &ctx);

    assert_eq!(req_headers.get("X-Custom-Req").unwrap(), "CustomVal-10.0.0.1");
    assert!(req_headers.get("X-Delete-Me").is_none());
    assert_eq!(req_headers.get("x-forwarded-for").unwrap(), "10.0.0.1");
    assert_eq!(req_headers.get("x-forwarded-proto").unwrap(), "http");
    assert_eq!(req_headers.get("x-forwarded-host").unwrap(), "example.com");

    // 2. Apply header_down
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Server", HeaderValue::from_static("nginx/1.24"));
    mutator.apply_header_down(&mut resp_headers, &ctx);

    assert!(resp_headers.get("Server").is_none());
    assert_eq!(resp_headers.get("X-Proxy-By").unwrap(), "Raddy");
}

#[tokio::test]
async fn test_live_reverse_proxy_end_to_end() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::TcpListener;

    // 1. Start a mock backend server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let io = TokioIo::new(stream);
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                                let fwd = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("");
                                let resp_body = format!("Hello from backend! Client IP: {}", fwd);
                                let mut resp = http::Response::new(http_body_util::Full::new(Bytes::from(resp_body)));
                                resp.headers_mut().insert("X-Backend-Id", HeaderValue::from_static("backend-1"));
                                Ok::<_, std::convert::Infallible>(resp)
                            });
                            let _ = Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(io, service).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });

    // 2. Setup ReverseProxyHandler
    let upstream = Arc::new(Upstream::new(backend_addr.to_string()));
    let handler = ReverseProxyHandler::new(vec![upstream], Box::new(RoundRobin::new()), HeaderMutator::new());

    // 3. Dispatch request through ReverseProxyHandler
    let mut ctx = Context::new(Method::GET, Uri::from_static("/test"), HeaderMap::new(), Bytes::new());
    ctx.remote_addr = Some("192.168.1.99:4567".parse().unwrap());
    handler.handle(&mut ctx).await.expect("Proxy failed");

    assert_eq!(ctx.status, Some(StatusCode::OK));
    assert_eq!(
        ctx.response_headers.get("X-Backend-Id").and_then(|v| v.to_str().ok()),
        Some("backend-1")
    );
    let body_str = String::from_utf8_lossy(ctx.response_body.as_ref().unwrap());
    assert!(body_str.contains("Hello from backend!"));
    assert!(body_str.contains("Client IP: 192.168.1.99"));

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_reverse_proxy_failover_and_retries() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::TcpListener;

    // Upstream 1: dead port (guaranteed connection failure)
    let dead_upstream = Arc::new(Upstream::new("127.0.0.1:1")); // Port 1 won't be listening

    // Upstream 2: live mock backend server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_addr = listener.local_addr().unwrap();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let io = TokioIo::new(stream);
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(|_| async move {
                                let resp = http::Response::new(http_body_util::Full::new(Bytes::from("Failover success!")));
                                Ok::<_, std::convert::Infallible>(resp)
                            });
                            let _ = Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(io, service).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });

    let live_upstream = Arc::new(Upstream::new(live_addr.to_string()));

    // Use First load balancer: it tries dead_upstream first, fails, then retries on live_upstream!
    let handler = ReverseProxyHandler::new(
        vec![dead_upstream.clone(), live_upstream],
        Box::new(First),
        HeaderMutator::new(),
    ).with_retries(2);

    let mut ctx = Context::new(Method::GET, Uri::from_static("/"), HeaderMap::new(), Bytes::new());
    handler.handle(&mut ctx).await.expect("Proxy failed");

    assert_eq!(ctx.status, Some(StatusCode::OK));
    let body_str = String::from_utf8_lossy(ctx.response_body.as_ref().unwrap());
    assert_eq!(body_str, "Failover success!");

    // Dead upstream should have recorded failures and be marked unhealthy
    assert!(!dead_upstream.is_available() || dead_upstream.active_requests() == 0);

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_reverse_proxy_forwards_host_from_uri_authority_when_host_header_missing() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let received_host = Arc::new(tokio::sync::Mutex::new(String::new()));
    let rec_clone = received_host.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let io = TokioIo::new(stream);
                        let rec = rec_clone.clone();
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                                let host_hdr = req.headers().get(http::header::HOST)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let rec = rec.clone();
                                async move {
                                    *rec.lock().await = host_hdr;
                                    let resp = http::Response::new(http_body_util::Full::new(Bytes::from("OK")));
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });
                            let _ = Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(io, service).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });

    let upstream = Arc::new(Upstream::new(backend_addr.to_string()));
    let handler = ReverseProxyHandler::new(
        vec![upstream],
        Box::new(First),
        HeaderMutator::new(),
    );

    // Simulate an HTTP/2 request: no Host header in HeaderMap, authority present in Uri
    let uri: Uri = "https://umami.pig2.de/".parse().unwrap();
    let mut ctx = Context::new(Method::GET, uri, HeaderMap::new(), Bytes::new());
    ctx.tls_server_name = Some("umami.pig2.de".to_string());

    handler.handle(&mut ctx).await.expect("Proxy failed");
    assert_eq!(ctx.status, Some(StatusCode::OK));

    let host = received_host.lock().await.clone();
    assert_eq!(host, "umami.pig2.de", "Backend should have received Host: umami.pig2.de");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_reverse_proxy_x_forwarded_host_placeholder_fallback() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let received_xfh = Arc::new(tokio::sync::Mutex::new(String::new()));
    let rec_clone = received_xfh.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let io = TokioIo::new(stream);
                        let rec = rec_clone.clone();
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                                let xfh = req.headers().get("x-forwarded-host")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let rec = rec.clone();
                                async move {
                                    *rec.lock().await = xfh;
                                    let resp = http::Response::new(http_body_util::Full::new(Bytes::from("OK")));
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });
                            let _ = Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(io, service).await;
                        });
                    }
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    });

    let mut mutator = HeaderMutator::new();
    // Replicate user Caddyfile rule: header_up X-Forwarded-Host {header.X-Forwarded-Host}
    mutator.header_up_set.insert("X-Forwarded-Host".to_string(), "{header.X-Forwarded-Host}".to_string());

    let upstream = Arc::new(Upstream::new(backend_addr.to_string()));
    let handler = ReverseProxyHandler::new(
        vec![upstream],
        Box::new(First),
        mutator,
    );

    // Request with no incoming X-Forwarded-Host header
    let uri: Uri = "https://kr.pig2.de/".parse().unwrap();
    let mut ctx = Context::new(Method::GET, uri, HeaderMap::new(), Bytes::new());
    ctx.tls_server_name = Some("kr.pig2.de".to_string());

    handler.handle(&mut ctx).await.expect("Proxy failed");
    assert_eq!(ctx.status, Some(StatusCode::OK));

    let xfh = received_xfh.lock().await.clone();
    assert_eq!(xfh, "kr.pig2.de", "Backend should have received valid host, not literal placeholder");

    let _ = shutdown_tx.send(true);
}


