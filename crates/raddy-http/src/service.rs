use crate::logging::LogPipeline;
use crate::router::VirtualHostRouter;
use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::Request;
use hyper::body::Frame;
use hyper::body::Incoming;
use raddy_core::context::Context;
use std::net::SocketAddr;
use std::sync::Arc;

pub type ResponseBoxBody = BoxBody<Bytes, std::io::Error>;

fn full_box_body(bytes: Bytes) -> ResponseBoxBody {
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| -> std::io::Error { match never {} })
        .boxed()
}

/// Service handler for incoming Hyper HTTP requests.
pub async fn handle_request(
    mut req: Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    router: Arc<VirtualHostRouter>,
    alt_svc_port: Option<u16>,
    challenge_store: Option<raddy_tls::acme::Http01ChallengeStore>,
    log_pipeline: Option<Arc<LogPipeline>>,
    server_logs: Option<raddy_core::config::ServerLogConfig>,
    tls_server_name: Option<String>,
) -> std::result::Result<Response<ResponseBoxBody>, std::convert::Infallible> {
    let start_time = std::time::Instant::now();
    let on_upgrade = hyper::upgrade::on(&mut req);
    let (mut parts, incoming_body) = req.into_parts();
    parts.extensions.insert(on_upgrade);

    // Intercept ACME HTTP-01 challenge if present
    if parts.uri.path().starts_with("/.well-known/acme-challenge/") {
        if let Some(ref store) = challenge_store {
            let token = parts
                .uri
                .path()
                .trim_start_matches("/.well-known/acme-challenge/");
            if let Some(key_auth) = store.get(token) {
                tracing::info!("Responding to ACME HTTP-01 challenge for token '{}'", token);
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(full_box_body(Bytes::from(key_auth)))
                    .unwrap();
                return Ok(resp);
            } else {
                tracing::warn!(
                    "ACME HTTP-01 challenge token '{}' not found in store",
                    token
                );
            }
        }
    }

    // Read full incoming request body (skip for CONNECT since tunnel is upgraded)
    let body_bytes = if parts.method == http::Method::CONNECT {
        Bytes::new()
    } else {
        match incoming_body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!("Failed to read incoming request body: {}", e);
                Bytes::new()
            }
        }
    };

    let mut ctx = Context::new(parts.method, parts.uri, parts.headers, body_bytes);
    ctx.extensions = std::sync::Arc::new(std::sync::Mutex::new(parts.extensions));
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
            if let Ok(val) =
                http::header::HeaderValue::from_str(&format!("h3=\":{}\"; ma=2592000", port))
            {
                ctx.response_headers
                    .insert(http::header::HeaderName::from_static("alt-svc"), val);
            }
        }
    }

    let status = ctx.status.unwrap_or(StatusCode::OK);
    let mut resp_builder = Response::builder().status(status);

    for (k, v) in &ctx.response_headers {
        resp_builder = resp_builder.header(k, v);
    }

    let body_len = ctx
        .response_headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| ctx.response_body.as_ref().map(|b| b.len()))
        .unwrap_or(0);

    let body: ResponseBoxBody = if let Some(stream) = ctx.response_stream.take() {
        use futures_util::StreamExt;
        let frame_stream = stream.map(|res| res.map(Frame::data));
        BodyExt::boxed(StreamBody::new(frame_stream))
    } else {
        full_box_body(ctx.response_body.take().unwrap_or_default())
    };

    let resp = resp_builder
        .body(body)
        .unwrap_or_else(|_| Response::new(full_box_body(Bytes::from("500 Internal Error"))));

    let duration = start_time.elapsed();
    if let Some(ref pl) = log_pipeline {
        pl.log_request(&ctx, duration, status, body_len, server_logs.as_ref());
    }

    Ok(resp)
}
