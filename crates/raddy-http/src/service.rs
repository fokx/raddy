use std::net::SocketAddr;
use std::sync::Arc;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::Request;
use raddy_core::context::Context;

use crate::router::VirtualHostRouter;

/// Service handler for incoming Hyper HTTP requests.
pub async fn handle_request(
    req: Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    router: Arc<VirtualHostRouter>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, incoming_body) = req.into_parts();

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

    if let Err(e) = router.route_request(&mut ctx).await {
        tracing::error!("Internal error routing request: {}", e);
        ctx.set_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("500 Internal Server Error: {}\n", e),
        );
    }

    let status = ctx.status.unwrap_or(StatusCode::OK);
    let mut resp_builder = Response::builder().status(status);

    for (k, v) in &ctx.response_headers {
        resp_builder = resp_builder.header(k, v);
    }

    let body = ctx.response_body.unwrap_or_default();
    let resp = resp_builder
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("500 Internal Error"))));

    Ok(resp)
}
