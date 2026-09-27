use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use async_trait::async_trait;
use http::StatusCode;
use raddy_core::config::{HandlerConfig, HttpServer, MatcherSet, Route};
use raddy_core::context::Context;
use raddy_core::error::{CoreError, Result};
use raddy_core::handler::*;
use raddy_core::matcher::*;
use raddy_core::module::ModuleRegistry;
use raddy_core::placeholder::PlaceholderProvider;

use crate::fileserver::FileServerHandler;

/// A compiled route containing matchers and a sequence of handlers.
pub struct CompiledRoute {
    pub matchers: Vec<Box<dyn Matcher>>,
    pub handlers: Vec<Arc<dyn Handler>>,
    pub terminal: bool,
    pub group: Option<String>,
}

impl CompiledRoute {
    pub fn matches(&self, ctx: &Context) -> bool {
        for m in &self.matchers {
            if !m.matches(ctx) {
                return false;
            }
        }
        true
    }

    pub fn is_response_transformer(&self) -> bool {
        self.handlers.iter().any(|h| h.is_response_transformer())
    }

    pub async fn execute(&self, ctx: &mut Context) -> Result<()> {
        let is_transformer = self.is_response_transformer();
        for h in &self.handlers {
            h.handle(ctx).await?;
            if !is_transformer && ctx.response_written {
                break;
            }
        }
        Ok(())
    }
}

/// Router for a single site/virtual host.
#[derive(Default)]
pub struct Router {
    pub routes: Vec<CompiledRoute>,
}

impl Router {
    pub fn new(routes: Vec<CompiledRoute>) -> Self {
        Self { routes }
    }

    pub async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let mut executed_groups: HashSet<String> = HashSet::new();

        for route in &self.routes {
            if let Some(ref grp) = route.group {
                if executed_groups.contains(grp) {
                    continue;
                }
            }

            if route.matches(ctx) {
                // If a response has already been written, only execute response transformers
                if ctx.response_written && !route.is_response_transformer() {
                    continue;
                }

                if let Some(ref grp) = route.group {
                    executed_groups.insert(grp.clone());
                }

                route.execute(ctx).await?;

                if route.terminal {
                    break;
                }
            }
        }

        Ok(())
    }
}


/// Subroute handler for nested routing (`route` and `handle` blocks).
pub struct SubrouteHandler {
    router: Router,
}

impl SubrouteHandler {
    pub fn new(router: Router) -> Self {
        Self { router }
    }
}

#[async_trait]
impl Handler for SubrouteHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        self.router.handle(ctx).await
    }
}

/// VirtualHostRouter routes requests according to Host (exact, wildcard, or default).
#[derive(Default)]
pub struct VirtualHostRouter {
    exact_hosts: HashMap<String, Router>,
    wildcard_hosts: Vec<(String, Router)>,
    default_router: Option<Router>,
}

impl VirtualHostRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_exact(&mut self, host: impl Into<String>, router: Router) {
        self.exact_hosts.insert(host.into().to_lowercase(), router);
    }

    pub fn insert_wildcard(&mut self, suffix: impl Into<String>, router: Router) {
        self.wildcard_hosts.push((suffix.into().to_lowercase(), router));
    }

    pub fn set_default(&mut self, router: Router) {
        self.default_router = Some(router);
    }

    pub async fn route_request(&self, ctx: &mut Context) -> Result<()> {
        let host = ctx.get_placeholder("host").unwrap_or_default().to_lowercase();

        // 1. Exact host match
        if let Some(router) = self.exact_hosts.get(&host) {
            router.handle(ctx).await?;
            if ctx.response_written {
                return Ok(());
            }
        }

        // 2. Wildcard host match (e.g. *.example.com)
        for (suffix, router) in &self.wildcard_hosts {
            if host.ends_with(suffix) {
                router.handle(ctx).await?;
                if ctx.response_written {
                    return Ok(());
                }
            }
        }

        // 3. Fallback to default router
        if let Some(ref router) = self.default_router {
            router.handle(ctx).await?;
            if ctx.response_written {
                return Ok(());
            }
        }

        // 4. Default 404 if no handler responded
        if !ctx.response_written {
            ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
        }

        Ok(())
    }
}

/// Compiles an `HttpServer` configuration into a `VirtualHostRouter`.
pub fn compile_virtual_host_router(
    server: &HttpServer,
    registry: &ModuleRegistry,
) -> Result<VirtualHostRouter> {
    let mut vhost_router = VirtualHostRouter::new();

    // Group routes by host
    let mut host_routes: HashMap<String, Vec<CompiledRoute>> = HashMap::new();
    let mut default_routes: Vec<CompiledRoute> = Vec::new();

    for route_cfg in &server.routes {
        let compiled = compile_route(route_cfg, registry)?;

        let mut hosts = Vec::new();
        if let Some(ref matcher_sets) = route_cfg.r#match {
            for set in matcher_sets {
                if let Some(ref h_list) = set.host {
                    hosts.extend(h_list.clone());
                }
            }
        }

        if hosts.is_empty() {
            default_routes.push(compiled);
        } else {
            for host in hosts {
                if host == "*" {
                    // Clone route for default
                    let c = compile_route(route_cfg, registry)?;
                    default_routes.push(c);
                } else {
                    let c = compile_route(route_cfg, registry)?;
                    host_routes.entry(host).or_default().push(c);
                }
            }
        }
    }

    for (host, routes) in host_routes {
        if let Some(suffix) = host.strip_prefix("*.") {
            vhost_router.insert_wildcard(suffix, Router::new(routes));
        } else {
            vhost_router.insert_exact(host, Router::new(routes));
        }
    }

    if !default_routes.is_empty() {
        vhost_router.set_default(Router::new(default_routes));
    }

    Ok(vhost_router)
}

fn compile_route(route_cfg: &Route, registry: &ModuleRegistry) -> Result<CompiledRoute> {
    let mut matchers: Vec<Box<dyn Matcher>> = Vec::new();

    if let Some(ref matcher_sets) = route_cfg.r#match {
        for set in matcher_sets {
            // Note: Host matching is handled primarily at the VirtualHostRouter level,
            // but we also keep path, method, header, remote_ip, etc.
            let mut set_no_host = set.clone();
            set_no_host.host = None; // Avoid duplicate host check inside the router
            if set_no_host != MatcherSet::default() {
                matchers.push(Box::new(CompiledMatcherSet::from_config(&set_no_host)));
            }
        }
    }

    let mut handlers: Vec<Arc<dyn Handler>> = Vec::new();
    for h_cfg in &route_cfg.handle {
        let handler = compile_handler(h_cfg, registry)?;
        handlers.push(handler);
    }

    Ok(CompiledRoute {
        matchers,
        handlers,
        terminal: route_cfg.terminal.unwrap_or(false),
        group: route_cfg.group.clone(),
    })
}

fn compile_handler(h_cfg: &HandlerConfig, registry: &ModuleRegistry) -> Result<Arc<dyn Handler>> {
    match h_cfg.handler.as_str() {
        "static_response" => {
            let status_code_u16 = h_cfg
                .details
                .get("status_code")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as u16;
            let status_code = StatusCode::from_u16(status_code_u16)
                .unwrap_or(StatusCode::OK);

            if let Some(loc) = h_cfg.details.get("location").and_then(|v| v.as_str()) {
                Ok(Arc::new(RedirectHandler {
                    location: loc.to_string(),
                    status_code,
                }))
            } else {
                let body = h_cfg
                    .details
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let close = h_cfg
                    .details
                    .get("close")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                Ok(Arc::new(StaticResponseHandler {
                    status_code,
                    body,
                    close,
                }))
            }
        }

        "rewrite" => {
            let uri_template = h_cfg
                .details
                .get("uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let strip_path_prefix = h_cfg
                .details
                .get("strip_path_prefix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let strip_path_suffix = h_cfg
                .details
                .get("strip_path_suffix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Ok(Arc::new(RewriteHandler {
                uri_template,
                strip_path_prefix,
                strip_path_suffix,
            }))
        }

        "headers" => {
            let mut set_response_headers = HashMap::new();
            if let Some(map) = h_cfg.details.get("set_response_headers").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        set_response_headers.insert(k.clone(), s.to_string());
                    }
                }
            }

            let mut delete_response_headers = Vec::new();
            if let Some(arr) = h_cfg.details.get("delete_response_headers").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        delete_response_headers.push(s.to_string());
                    }
                }
            }

            let mut set_request_headers = HashMap::new();
            if let Some(map) = h_cfg.details.get("set_request_headers").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        set_request_headers.insert(k.clone(), s.to_string());
                    }
                }
            }

            let mut delete_request_headers = Vec::new();
            if let Some(arr) = h_cfg.details.get("delete_request_headers").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        delete_request_headers.push(s.to_string());
                    }
                }
            }

            Ok(Arc::new(HeadersHandler {
                set_response_headers,
                delete_response_headers,
                set_request_headers,
                delete_request_headers,
            }))
        }

        "vars" => {
            let mut vars = HashMap::new();
            if let Some(map) = h_cfg.details.get("vars").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        vars.insert(k.clone(), s.to_string());
                    }
                }
            }
            Ok(Arc::new(VarsHandler { vars }))
        }

        "file_server" => {
            let root = h_cfg.details.get("root").and_then(|v| v.as_str()).map(|s| s.to_string());
            let browse = h_cfg.details.get("browse").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(Arc::new(FileServerHandler::new(root, browse)))
        }

        "reverse_proxy" => {
            let proxy_handler = raddy_proxy::build_reverse_proxy_from_config(&h_cfg.details)?;
            Ok(Arc::new(proxy_handler))
        }

        "subroute" => {
            let routes_val = h_cfg.details.get("routes").cloned().unwrap_or(serde_json::Value::Null);
            let sub_routes_cfg: Vec<Route> = serde_json::from_value(routes_val)
                .map_err(|e| CoreError::Config(format!("Invalid subroute config: {}", e)))?;

            let mut compiled_subroutes = Vec::new();
            for r in &sub_routes_cfg {
                compiled_subroutes.push(compile_route(r, registry)?);
            }
            Ok(Arc::new(SubrouteHandler::new(Router::new(compiled_subroutes))))
        }

        "encode" => {
            let encodings = h_cfg
                .details
                .get("encodings")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_else(|| vec!["zstd".into(), "gzip".into()]);
            Ok(Arc::new(crate::encode::EncodeHandler::from_format_names(&encodings)))
        }

        "templates" => {
            Ok(Arc::new(crate::templates::TemplatesHandler::new()))
        }

        "basic_auth" | "authentication" => {
            let mut users = HashMap::new();
            if let Some(map) = h_cfg.details.get("users").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        users.insert(k.clone(), s.to_string());
                    }
                }
            }
            let realm = h_cfg.details.get("realm").and_then(|v| v.as_str()).map(|s| s.to_string());
            Ok(Arc::new(crate::auth::BasicAuthHandler::new(users, realm)))
        }

        "forward_auth" => {
            let upstream = h_cfg.details.get("upstream").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let uri_override = h_cfg.details.get("uri").and_then(|v| v.as_str()).map(|s| s.to_string());
            let mut copy_headers = Vec::new();
            if let Some(arr) = h_cfg.details.get("copy_headers").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        copy_headers.push(s.to_string());
                    }
                }
            }
            Ok(Arc::new(crate::auth::ForwardAuthHandler::new(upstream, uri_override, copy_headers)))
        }

        "request_body" => {
            let max_size = h_cfg
                .details
                .get("max_size")
                .and_then(|v| v.as_u64())
                .map(|s| s as usize)
                .unwrap_or(10 * 1024 * 1024);
            Ok(Arc::new(crate::limits::RequestBodyLimitHandler::new(max_size)))
        }

        "map" => {
            let source = h_cfg.details.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let dest = h_cfg.details.get("dest").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let default_val = h_cfg.details.get("default").and_then(|v| v.as_str()).map(|s| s.to_string());
            let mut mappings = Vec::new();
            if let Some(arr) = h_cfg.details.get("mappings").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(obj) = item.as_object() {
                        if let (Some(k), Some(v)) = (
                            obj.get("pattern").and_then(|x| x.as_str()),
                            obj.get("value").and_then(|x| x.as_str()),
                        ) {
                            mappings.push((k.to_string(), v.to_string()));
                        }
                    }
                }
            }
            Ok(Arc::new(crate::map::MapHandler::new(source, dest, mappings, default_val)))
        }

        "abort" => {
            Ok(Arc::new(crate::flow::AbortHandler))
        }

        "error" => {
            let status_u16 = h_cfg.details.get("status_code").and_then(|v| v.as_u64()).unwrap_or(500) as u16;
            let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let message = h_cfg.details.get("error").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Ok(Arc::new(crate::flow::ErrorHandler::new(status, message)))
        }

        "log_skip" => {
            Ok(Arc::new(LogSkipHandler))
        }

        "log_append" => {
            let key = h_cfg.details.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let value = h_cfg.details.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Ok(Arc::new(LogAppendHandler { key, value }))
        }

        "log_name" => {
            let name = h_cfg.details.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Ok(Arc::new(LogNameHandler { name }))
        }

        other => {
            // Attempt to resolve through dynamic module registry
            registry.create_handler(other, serde_json::to_value(&h_cfg.details)?)
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogSkipHandler;

#[async_trait]
impl Handler for LogSkipHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        ctx.log_skip = true;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LogAppendHandler {
    pub key: String,
    pub value: String,
}

#[async_trait]
impl Handler for LogAppendHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let val_eval = raddy_core::eval_placeholders(&self.value, ctx);
        ctx.log_appends.insert(self.key.clone(), serde_json::Value::String(val_eval));
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LogNameHandler {
    pub name: String,
}

#[async_trait]
impl Handler for LogNameHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let name_eval = raddy_core::eval_placeholders(&self.name, ctx);
        ctx.log_name = Some(name_eval);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NoopHandler;

#[async_trait]
impl Handler for NoopHandler {
    async fn handle(&self, _ctx: &mut Context) -> Result<()> {
        Ok(())
    }
}

