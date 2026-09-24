use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::upstream::Upstream;

/// Passive health check configuration (circuit breaker).
#[derive(Debug, Clone)]
pub struct PassiveHealthConfig {
    pub max_fails: usize,
    pub fail_duration_secs: u64,
    pub unhealthy_status_codes: Vec<u16>,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            max_fails: 3,
            fail_duration_secs: 30,
            unhealthy_status_codes: vec![500, 502, 503, 504],
        }
    }
}

/// Active health check configuration with periodic probing.
#[derive(Debug, Clone)]
pub struct ActiveHealthConfig {
    pub uri: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub expected_status: u16,
}

impl Default for ActiveHealthConfig {
    fn default() -> Self {
        Self {
            uri: "/healthz".into(),
            interval_secs: 15,
            timeout_secs: 5,
            expected_status: 200,
        }
    }
}

/// Spawns a background worker for active health checking of upstreams.
pub fn spawn_active_health_checker(
    upstreams: Vec<Arc<Upstream>>,
    config: ActiveHealthConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(config.interval_secs.max(1));
        let timeout = Duration::from_secs(config.timeout_secs.max(1));

        loop {
            sleep(interval).await;

            for upstream in &upstreams {
                let dial = &upstream.dial;
                let target_url = if dial.starts_with("http://") || dial.starts_with("https://") {
                    format!("{}{}", dial.trim_end_matches('/'), config.uri)
                } else {
                    format!("http://{}{}", dial.trim_end_matches('/'), config.uri)
                };

                let is_ok = probe_url(&target_url, timeout, config.expected_status).await;
                upstream.set_healthy(is_ok);
                if !is_ok {
                    tracing::warn!("Active health check failed for upstream '{}'", dial);
                }
            }
        }
    })
}

async fn probe_url(url: &str, timeout: Duration, expected_status: u16) -> bool {
    match tokio::time::timeout(timeout, send_simple_get(url)).await {
        Ok(Ok(status)) => status == expected_status,
        _ => false,
    }
}

async fn send_simple_get(url: &str) -> Result<u16, ()> {
    use http_body_util::Empty;
    use bytes::Bytes;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let parsed_url: http::Uri = url.parse().map_err(|_| ())?;
    let host = parsed_url.host().ok_or(())?;
    let port = parsed_url.port_u16().unwrap_or(80);
    let path = parsed_url.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr).await.map_err(|_| ())?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|_| ())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(http::header::HOST, host)
        .header(http::header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| ())?;

    let resp = sender.send_request(req).await.map_err(|_| ())?;
    Ok(resp.status().as_u16())
}
