use crate::headers::HeaderMutator;
use crate::health::PassiveHealthConfig;
use crate::load_balancer::LoadBalancer;
use crate::transport::HttpTransport;
use crate::upstream::Upstream;
use async_trait::async_trait;
use http::StatusCode;
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use std::sync::Arc;

/// Reverse Proxy Handler implementing Caddy's `reverse_proxy` directive.
pub struct ReverseProxyHandler {
    upstreams: Vec<Arc<Upstream>>,
    load_balancer: Box<dyn LoadBalancer>,
    mutator: HeaderMutator,
    transport: HttpTransport,
    passive_health: PassiveHealthConfig,
    retries: usize,
}

impl ReverseProxyHandler {
    pub fn new(
        upstreams: Vec<Arc<Upstream>>,
        load_balancer: Box<dyn LoadBalancer>,
        mutator: HeaderMutator,
    ) -> Self {
        Self {
            upstreams,
            load_balancer,
            mutator,
            transport: HttpTransport::new(),
            passive_health: PassiveHealthConfig::default(),
            retries: 2,
        }
    }

    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_passive_health(mut self, config: PassiveHealthConfig) -> Self {
        self.passive_health = config;
        self
    }

    pub fn with_transport(mut self, transport: HttpTransport) -> Self {
        self.transport = transport;
        self
    }
}

struct ActiveGuard<'a>(&'a Upstream);
impl<'a> Drop for ActiveGuard<'a> {
    fn drop(&mut self) {
        self.0.dec_active();
    }
}

#[async_trait]
impl Handler for ReverseProxyHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let attempts = self.retries + 1;
        let mut last_err = None;
        let mut tried = std::collections::HashSet::new();

        for attempt in 0..attempts {
            // 1. Select available candidate not yet tried in this request
            let candidates: Vec<Arc<Upstream>> = self
                .upstreams
                .iter()
                .filter(|u| !tried.contains(&u.dial) && u.is_available())
                .cloned()
                .collect();

            let upstream = if !candidates.is_empty() {
                self.load_balancer.select(&candidates, ctx).cloned()
            } else {
                self.load_balancer.select(&self.upstreams, ctx).cloned()
            };

            let upstream = match upstream {
                Some(u) => u,
                None => {
                    tracing::warn!("No healthy upstreams available for reverse proxy");
                    ctx.set_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "503 Service Unavailable: No healthy upstreams\n",
                    );
                    return Ok(());
                }
            };

            tried.insert(upstream.dial.clone());

            // 2. Track concurrency
            upstream.inc_active();
            let _guard = ActiveGuard(upstream.as_ref());

            // Set upstream placeholders in context
            let host_header = if (upstream.is_tls && upstream.port == 443)
                || (!upstream.is_tls && upstream.port == 80)
            {
                upstream.host.clone()
            } else {
                upstream.dial.clone()
            };
            ctx.set_var("upstream_hostport", host_header.clone());
            ctx.set_var("http.reverse_proxy.upstream.hostport", host_header.clone());
            ctx.set_var("upstream_host", upstream.host.clone());
            ctx.set_var("http.reverse_proxy.upstream.host", upstream.host.clone());
            ctx.set_var("upstream_port", upstream.port.to_string());
            ctx.set_var(
                "http.reverse_proxy.upstream.port",
                upstream.port.to_string(),
            );

            // 3. Mutate request headers (header_up + X-Forwarded-*)
            let mut req_headers = ctx.headers.clone();
            self.mutator.apply_header_up(&mut req_headers, ctx);

            // 4. Send request to upstream
            let dial = upstream.dial.clone();
            let result = self
                .transport
                .round_trip_with_tls(
                    &dial,
                    upstream.is_tls || self.transport.tls,
                    ctx.method.clone(),
                    &ctx.uri,
                    req_headers,
                    ctx.body.clone(),
                )
                .await;

            match result {
                Ok((status, mut resp_headers, body_bytes)) => {
                    // Check if status is considered unhealthy
                    if self
                        .passive_health
                        .unhealthy_status_codes
                        .contains(&status.as_u16())
                    {
                        upstream.record_failure(
                            self.passive_health.max_fails,
                            self.passive_health.fail_duration_secs,
                        );

                        if attempt + 1 < attempts {
                            tracing::warn!(
                                "Upstream '{}' returned status {}, retrying on another upstream...",
                                dial,
                                status
                            );
                            continue;
                        }
                    } else {
                        upstream.record_success();
                    }

                    // 5. Mutate response headers (header_down)
                    self.mutator.apply_header_down(&mut resp_headers, ctx);

                    // 6. Write final response to context
                    ctx.status = Some(status);
                    ctx.response_headers = resp_headers;
                    ctx.response_body = Some(body_bytes);
                    ctx.response_written = true;
                    return Ok(());
                }

                Err(err) => {
                    tracing::warn!(
                        "Error proxying to upstream '{}' (attempt {}/{}): {}",
                        dial,
                        attempt + 1,
                        attempts,
                        err
                    );
                    upstream.record_failure(
                        self.passive_health.max_fails,
                        self.passive_health.fail_duration_secs,
                    );
                    last_err = Some(err);
                }
            }
        }

        // All attempts failed
        let err_msg = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Bad Gateway".into());

        ctx.set_response(
            StatusCode::BAD_GATEWAY,
            format!("502 Bad Gateway: {}\n", err_msg),
        );

        Ok(())
    }
}
