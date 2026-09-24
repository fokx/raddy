use std::net::SocketAddr;
use std::sync::Arc;
use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, ServerConfig as QuinnServerConfig};
use rustls::server::ServerConfig as RustlsServerConfig;
use raddy_core::context::Context;

use crate::error::{HttpServerError, Result};
use crate::router::VirtualHostRouter;

/// Builds a Quinn ServerConfig from a Rustls ServerConfig with ALPN set to "h3".
pub fn build_quic_server_config(rustls_config: &RustlsServerConfig) -> Result<QuinnServerConfig> {
    let mut quic_tls_cfg = rustls_config.clone();
    quic_tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = QuicServerConfig::try_from(quic_tls_cfg)
        .map_err(|e| HttpServerError::Http3(format!("Failed to build QUIC server crypto: {}", e)))?;

    Ok(QuinnServerConfig::with_crypto(Arc::new(quic_crypto)))
}

/// Serves HTTP/3 requests for an established QUIC connection.
pub async fn serve_h3_connection(
    conn: Connection,
    remote_addr: SocketAddr,
    router: Arc<VirtualHostRouter>,
) -> Result<()> {
    let mut h3_conn = match h3::server::builder()
        .build(h3_quinn::Connection::new(conn))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("H3 handshake failed with {}: {}", remote_addr, e);
            return Ok(());
        }
    };

    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let router_clone = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_h3_stream(resolver, remote_addr, router_clone).await {
                tracing::debug!("H3 stream error from {}: {}", remote_addr, e);
            }
        });
    }

    Ok(())
}

/// Handles a single bidirectional HTTP/3 stream (request + response).
async fn handle_h3_stream(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    remote_addr: SocketAddr,
    router: Arc<VirtualHostRouter>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (req, mut stream) = resolver.resolve_request().await?;
    let (parts, _) = req.into_parts();

    // Read full incoming request body
    let mut body_bytes = Vec::new();
    while let Ok(Some(chunk)) = stream.recv_data().await {
        let mut chunk = chunk;
        while chunk.has_remaining() {
            body_bytes.push(chunk.get_u8());
        }
    }

    let mut ctx = Context::new(parts.method, parts.uri, parts.headers, Bytes::from(body_bytes));
    ctx.remote_addr = Some(remote_addr);

    if let Err(e) = router.route_request(&mut ctx).await {
        tracing::error!("Internal error routing H3 request: {}", e);
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

    let resp = resp_builder.body(())?;
    stream.send_response(resp).await?;

    if let Some(body) = ctx.response_body {
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
    }

    stream.finish().await?;
    Ok(())
}
