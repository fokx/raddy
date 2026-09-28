use std::net::SocketAddr;
use std::sync::Arc;
use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::Request;
use raddy_core::context::Context;
use crate::logging::LogPipeline;
use crate::router::VirtualHostRouter;

/// Service handler for incoming Hyper HTTP requests.
pub async fn handle_request(
    req: Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    router: Arc<VirtualHostRouter>,
    alt_svc_port: Option<u16>,
    challenge_store: Option<raddy_tls::acme::Http01ChallengeStore>,
    log_pipeline: Option<Arc<LogPipeline>>,
    server_logs: Option<raddy_core::config::ServerLogConfig>,
    tls_server_name: Option<String>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let start_time = std::time::Instant::now();
    let (parts, incoming_body) = req.into_parts();

    // Intercept ACME HTTP-01 challenge if present
    if parts.uri.path().starts_with("/.well-known/acme-challenge/") {
        if let Some(ref store) = challenge_store {
            let token = parts.uri.path().trim_start_matches("/.well-known/acme-challenge/");
            if let Some(key_auth) = store.get(token) {
                tracing::info!("Responding to ACME HTTP-01 challenge for token '{}'", token);
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(Full::new(Bytes::from(key_auth)))
                    .unwrap();
                return Ok(resp);
            } else {
                tracing::warn!("ACME HTTP-01 challenge token '{}' not found in store", token);
            }
        }
    }

    // Read full incoming request body
    let body_bytes = match incoming_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!("Failed to read incoming request body: {}", e);
            Bytes::new()
        }
    };

    let mut ctx = Context::new(parts.method, parts.uri, parts.headers, body_bytes);
    ctx.remote_addr = remote_addr;
    ctx.tls_server_name = tls_server_name;
    if !ctx.headers.contains_key(http::header::HOST) {
        if let Some(ref sni) = ctx.tls_server_name {
            if let Ok(val) = HeaderValue::try_from(sni.as_str()) {
                ctx.headers.insert(http::header::HOST, val);
            }
        }
    }

    if let Err(e) = router.route_request(&mut ctx).await {
        tracing::error!("Internal error routing request: {}", e);
        ctx.set_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("500 Internal Server Error: {}\n", e),
        );
    }

    // Advertise HTTP/3 over QUIC via Alt-Svc if enabled
    if let Some(port) = alt_svc_port {
        if !ctx.response_headers.contains_key("alt-svc") {
            if let Ok(val) = http::header::HeaderValue::from_str(&format!("h3=\":{}\"; ma=2592000", port)) {
                ctx.response_headers.insert(http::header::HeaderName::from_static("alt-svc"), val);
            }
        }
    }

    let status = ctx.status.unwrap_or(StatusCode::OK);
    let mut resp_builder = Response::builder().status(status);

    for (k, v) in &ctx.response_headers {
        resp_builder = resp_builder.header(k, v);
    }

    let body = ctx.response_body.clone().unwrap_or_default();
    let body_len = body.len();
    let resp = resp_builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("500 Internal Error"))));

    let duration = start_time.elapsed();
    if let Some(ref pl) = log_pipeline {
        pl.log_request(&ctx, duration, status, body_len, server_logs.as_ref());
    }

    Ok(resp)
}
