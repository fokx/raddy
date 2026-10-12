use crate::context::ConnectionContext;
use crate::error::{Layer4Error, Result};
use crate::handler::{CloseHandler, EchoHandler, ProxyHandler, VarsHandler};
use crate::matcher::{matches_matcher_set, requires_payload_data};
use raddy_core::config::{Layer4MatcherSet, Layer4Route};
use raddy_tls::TlsManager;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

/// Compiled Layer 4 Handler.
pub enum CompiledHandler {
    Proxy(Arc<ProxyHandler>),
    Echo(EchoHandler),
    Close(CloseHandler),
    Vars(VarsHandler),
    Tls,
}

/// A compiled Layer 4 Route with matchers and handlers.
pub struct CompiledRoute {
    pub matcher_sets: Vec<Layer4MatcherSet>,
    pub handlers: Vec<CompiledHandler>,
    pub tls_manager: Option<Arc<TlsManager>>,
}

impl CompiledRoute {
    pub fn compile(route: &Layer4Route, tls_manager: Option<Arc<TlsManager>>) -> Result<Self> {
        let matcher_sets = route.r#match.clone().unwrap_or_default();
        let mut handlers = Vec::new();

        for h_cfg in &route.handle {
            match h_cfg.handler.as_str() {
                "proxy" | "reverse_proxy" => {
                    let proxy = ProxyHandler::from_config(h_cfg)?;
                    handlers.push(CompiledHandler::Proxy(Arc::new(proxy)));
                }
                "echo" => {
                    handlers.push(CompiledHandler::Echo(EchoHandler));
                }
                "close" => {
                    handlers.push(CompiledHandler::Close(CloseHandler));
                }
                "vars" => {
                    handlers.push(CompiledHandler::Vars(VarsHandler::from_config(h_cfg)));
                }
                "tls" => {
                    handlers.push(CompiledHandler::Tls);
                }
                other => {
                    tracing::warn!("Unknown layer4 handler '{}', skipping", other);
                }
            }
        }

        // If no handler was specified, default to Echo
        if handlers.is_empty() {
            handlers.push(CompiledHandler::Echo(EchoHandler));
        }

        Ok(Self {
            matcher_sets,
            handlers,
            tls_manager,
        })
    }

    /// Evaluates if this route matches the connection.
    pub fn matches(&self, ctx: &mut ConnectionContext, buf: &[u8]) -> bool {
        if self.matcher_sets.is_empty() {
            return true;
        }

        // OR logic across matcher sets
        self.matcher_sets
            .iter()
            .any(|set| matches_matcher_set(set, ctx, buf))
    }

    /// Returns true if this route requires reading payload bytes to evaluate its matchers.
    pub fn requires_payload(&self) -> bool {
        if self.matcher_sets.is_empty() {
            return false;
        }
        self.matcher_sets.iter().any(requires_payload_data)
    }

    /// Executes the route's handlers on a TCP stream.
    pub async fn execute_tcp<S>(&self, stream: S, ctx: &mut ConnectionContext) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.execute_tcp_chain(Box::new(stream), 0, ctx).await
    }

    fn execute_tcp_chain<'a>(
        &'a self,
        stream: Box<dyn AsyncStream + Send + Unpin>,
        handler_idx: usize,
        ctx: &'a mut ConnectionContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if handler_idx >= self.handlers.len() {
                return Ok(());
            }

            match &self.handlers[handler_idx] {
                CompiledHandler::Vars(vars) => {
                    vars.apply(ctx);
                    self.execute_tcp_chain(stream, handler_idx + 1, ctx).await
                }
                CompiledHandler::Close(close) => close.handle_tcp(stream).await,
                CompiledHandler::Echo(echo) => echo.handle_tcp(stream).await,
                CompiledHandler::Proxy(proxy) => proxy.handle_tcp(stream, ctx).await,
                CompiledHandler::Tls => {
                    // TLS termination
                    let tls_acceptor = if let Some(ref tls) = self.tls_manager {
                        let acceptor = tls
                            .build_tls_acceptor()
                            .map_err(|e| Layer4Error::Tls(e.to_string()))?;
                        acceptor
                    } else {
                        return Err(Layer4Error::Tls("TLS manager not configured".into()));
                    };

                    let tls_stream = tls_acceptor
                        .accept(stream)
                        .await
                        .map_err(|e| Layer4Error::Tls(e.to_string()))?;

                    self.execute_tcp_chain(Box::new(tls_stream), handler_idx + 1, ctx)
                        .await
                }
            }
        })
    }

    /// Executes the route's handlers on a UDP packet.
    pub async fn execute_udp(
        &self,
        socket: &UdpSocket,
        packet: &[u8],
        client_addr: SocketAddr,
        ctx: &mut ConnectionContext,
    ) -> Result<()> {
        for handler in &self.handlers {
            match handler {
                CompiledHandler::Vars(vars) => {
                    vars.apply(ctx);
                }
                CompiledHandler::Echo(echo) => {
                    return echo.handle_udp(socket, packet, client_addr).await;
                }
                CompiledHandler::Close(close) => {
                    return close.handle_udp().await;
                }
                CompiledHandler::Proxy(proxy) => {
                    return proxy.handle_udp(socket, packet, client_addr, ctx).await;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncStream for T {}
