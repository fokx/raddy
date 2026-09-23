use std::collections::HashMap;
use raddy_core::config::*;
use crate::ast::*;
use crate::error::{ParseError, ParseResult};

pub const DEFAULT_HTTP_PORT: u16 = 80;
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Official Caddy directive execution order.
/// Lower index means the directive runs earlier in the middleware pipeline.
pub const DIRECTIVE_ORDER: &[&str] = &[
    "tracing",
    "map",
    "vars",
    "fs",
    "root",
    "log",
    "log_append",
    "log_skip",
    "request_id",
    "header",
    "request_header",
    "encode",
    "push",
    "templates",
    "invoke",
    "redir",
    "respond",
    "abort",
    "error",
    "rewrite",
    "uri",
    "try_files",
    "basic_auth",
    "forward_auth",
    "request_body",
    "php_fastcgi",
    "file_server",
    "acme_server",
    "reverse_proxy",
];

pub struct Adapter {
    http_port: u16,
    https_port: u16,
    auto_https: Option<AutoHttpsConfig>,
    admin: Option<AdminConfig>,
    logging: Option<LoggingConfig>,
    custom_order: HashMap<String, usize>,
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter {
    pub fn new() -> Self {
        let mut custom_order = HashMap::new();
        for (i, &name) in DIRECTIVE_ORDER.iter().enumerate() {
            custom_order.insert(name.to_string(), i * 10);
        }

        Self {
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
            auto_https: None,
            admin: None,
            logging: None,
            custom_order,
        }
    }

    /// Adapts a Caddyfile AST into Raddy's internal JSON Config model.
    pub fn adapt(&mut self, caddyfile: &Caddyfile) -> ParseResult<Config> {
        // 1. Process global options
        if let Some(ref opts) = caddyfile.global_options {
            self.process_global_options(opts)?;
        }

        let mut config = Config::new();
        config.admin = self.admin.clone();
        config.logging = self.logging.clone();

        let mut servers: HashMap<String, HttpServer> = HashMap::new();

        // 2. Process each site block
        for site in &caddyfile.site_blocks {
            self.adapt_site_block(site, &mut servers)?;
        }

        let http_app = HttpApp { servers };
        config.set_http_app(http_app).map_err(|e| ParseError::Adaptation {
            line: 1,
            message: format!("Failed to serialize HTTP app: {}", e),
        })?;

        Ok(config)
    }

    fn process_global_options(&mut self, opts: &GlobalOptionsNode) -> ParseResult<()> {
        for opt in &opts.options {
            match opt.name.as_str() {
                "http_port" => {
                    if let Some(arg) = opt.args.first() {
                        self.http_port = arg.parse().map_err(|_| ParseError::Adaptation {
                            line: opt.span.line,
                            message: format!("Invalid http_port '{}'", arg),
                        })?;
                    }
                }
                "https_port" => {
                    if let Some(arg) = opt.args.first() {
                        self.https_port = arg.parse().map_err(|_| ParseError::Adaptation {
                            line: opt.span.line,
                            message: format!("Invalid https_port '{}'", arg),
                        })?;
                    }
                }
                "auto_https" => {
                    let mut auto = self.auto_https.take().unwrap_or_default();
                    if let Some(arg) = opt.args.first() {
                        match arg.as_str() {
                            "off" => auto.disabled = Some(true),
                            "disable_redirects" => auto.disable_redirects = Some(true),
                            "disable_certs" => auto.disable_certificates = Some(true),
                            _ => {}
                        }
                    }
                    self.auto_https = Some(auto);
                }
                "admin" => {
                    let mut admin = self.admin.take().unwrap_or_default();
                    if let Some(arg) = opt.args.first() {
                        if arg == "off" {
                            admin.disabled = Some(true);
                        } else {
                            admin.listen = Some(arg.clone());
                        }
                    }
                    self.admin = Some(admin);
                }
                "order" => {
                    // order <dir1> first | last | before <dir2> | after <dir2>
                    if opt.args.len() >= 2 {
                        let dir = &opt.args[0];
                        let pos = &opt.args[1];
                        if pos == "first" {
                            self.custom_order.insert(dir.clone(), 0);
                        } else if pos == "last" {
                            self.custom_order.insert(dir.clone(), 9999);
                        } else if pos == "before" && opt.args.len() >= 3 {
                            let target = &opt.args[2];
                            let target_prio = self.custom_order.get(target).copied().unwrap_or(500);
                            self.custom_order.insert(dir.clone(), target_prio.saturating_sub(1));
                        } else if pos == "after" && opt.args.len() >= 3 {
                            let target = &opt.args[2];
                            let target_prio = self.custom_order.get(target).copied().unwrap_or(500);
                            self.custom_order.insert(dir.clone(), target_prio + 1);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn adapt_site_block(
        &self,
        site: &SiteBlockNode,
        servers: &mut HashMap<String, HttpServer>,
    ) -> ParseResult<()> {
        // Collect named matchers defined in this site block: `@name { ... }`
        let mut named_matchers: HashMap<String, MatcherSet> = HashMap::new();
        let mut regular_directives: Vec<DirectiveNode> = Vec::new();
        let mut site_tls_policy: Option<TlsConnectionPolicy> = None;

        for dir in &site.directives {
            if dir.name.starts_with('@') {
                let name = dir.name.clone();
                let matcher_set = parse_named_matcher_block(dir)?;
                named_matchers.insert(name, matcher_set);
            } else if dir.name == "tls" {
                site_tls_policy = Some(parse_tls_directive(dir)?);
            } else {
                regular_directives.push(dir.clone());
            }
        }

        // Sort directives by priority table
        regular_directives.sort_by_key(|dir| {
            self.custom_order.get(&dir.name).copied().unwrap_or(500)
        });

        // Each address in site.addresses maps to a parsed address
        for addr_str in &site.addresses {
            let parsed_addr = parse_site_address(addr_str, self.http_port, self.https_port);
            let server_key = format!("srv_{}", parsed_addr.listen);

            let server = servers.entry(server_key).or_insert_with(|| HttpServer {
                listen: vec![parsed_addr.listen.clone()],
                routes: Vec::new(),
                tls_connection_policies: None,
                automatic_https: self.auto_https.clone(),
                protocols: None,
                logs: None,
            });

            if let Some(ref tls_pol) = site_tls_policy {
                let mut pol_clone = tls_pol.clone();
                if pol_clone.r#match.is_none() && parsed_addr.host != "*" {
                    pol_clone.r#match = Some(TlsConnectionMatch {
                        sni: Some(vec![parsed_addr.host.clone()]),
                    });
                }
                let policies = server.tls_connection_policies.get_or_insert_with(Vec::new);
                policies.push(pol_clone);
            }

            // Build route matchers for host and path prefix
            let mut host_matchers = Vec::new();
            if parsed_addr.host != "*" {
                host_matchers.push(parsed_addr.host.clone());
            }

            let path_matcher = parsed_addr.path_prefix.clone();

            // Translate directives into Route handlers
            for dir in &regular_directives {
                let route = self.adapt_directive(dir, &host_matchers, path_matcher.as_deref(), &named_matchers)?;
                server.routes.push(route);
            }
        }

        Ok(())
    }

    fn adapt_directive(
        &self,
        dir: &DirectiveNode,
        host_matchers: &[String],
        site_path_prefix: Option<&str>,
        named_matchers: &HashMap<String, MatcherSet>,
    ) -> ParseResult<Route> {
        let mut matcher_set = MatcherSet::default();
        if !host_matchers.is_empty() {
            matcher_set.host = Some(host_matchers.to_vec());
        }

        // Attach path matcher from site address if present
        if let Some(p) = site_path_prefix {
            matcher_set.path = Some(vec![format!("{}*", p)]);
        }

        // Attach directive matcher if specified
        if let Some(ref m) = dir.matcher {
            if m.starts_with('@') {
                if let Some(named) = named_matchers.get(m) {
                    merge_matcher_set(&mut matcher_set, named);
                }
            } else if m.starts_with('/') {
                let mut paths = matcher_set.path.unwrap_or_default();
                paths.push(m.clone());
                matcher_set.path = Some(paths);
            }
        }

        let mut route = Route::default();
        if matcher_set != MatcherSet::default() {
            route.r#match = Some(vec![matcher_set]);
        }

        let handlers = self.build_handler_config(dir)?;
        route.handle = handlers;
        Ok(route)
    }

    fn build_handler_config(&self, dir: &DirectiveNode) -> ParseResult<Vec<HandlerConfig>> {
        let mut configs = Vec::new();

        match dir.name.as_str() {
            "respond" => {
                let mut status = 200;
                let mut body = String::new();
                let mut close = false;

                if let Some(first_arg) = dir.args.first() {
                    if let Ok(st) = first_arg.parse::<u16>() {
                        status = st;
                        if dir.args.len() > 1 {
                            body = dir.args[1..].join(" ");
                        }
                    } else {
                        body = first_arg.clone();
                        if let Some(second_arg) = dir.args.get(1) {
                            if let Ok(st) = second_arg.parse::<u16>() {
                                status = st;
                            }
                        }
                    }
                }

                if let Some(ref block) = dir.block {
                    for sub in block {
                        if sub.name == "body" {
                            body = sub.args.join(" ");
                        } else if sub.name == "close" {
                            close = true;
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("static_response")
                    .with_field("status_code", status)
                    .with_field("body", body);
                if close {
                    cfg = cfg.with_field("close", true);
                }
                configs.push(cfg);
            }

            "redir" => {
                let mut status = 302;
                let mut to = String::new();

                if let Some(first) = dir.args.first() {
                    if let Ok(st) = first.parse::<u16>() {
                        status = st;
                        if let Some(sec) = dir.args.get(1) {
                            to = sec.clone();
                        }
                    } else {
                        to = first.clone();
                        if let Some(sec) = dir.args.get(1) {
                            if let Ok(st) = sec.parse::<u16>() {
                                status = st;
                            }
                        }
                    }
                }

                let cfg = HandlerConfig::new("static_response")
                    .with_field("status_code", status)
                    .with_field("location", to);
                configs.push(cfg);
            }

            "rewrite" => {
                let uri = dir.args.first().cloned().unwrap_or_default();
                let cfg = HandlerConfig::new("rewrite").with_field("uri", uri);
                configs.push(cfg);
            }

            "uri" => {
                let mut cfg = HandlerConfig::new("rewrite");
                if let Some(subcmd) = dir.args.first() {
                    match subcmd.as_str() {
                        "strip_prefix" => {
                            if let Some(prefix) = dir.args.get(1) {
                                cfg = cfg.with_field("strip_path_prefix", prefix);
                            }
                        }
                        "strip_suffix" => {
                            if let Some(suffix) = dir.args.get(1) {
                                cfg = cfg.with_field("strip_path_suffix", suffix);
                            }
                        }
                        "replace" => {
                            if dir.args.len() >= 3 {
                                cfg = cfg.with_field("search", &dir.args[1])
                                         .with_field("replace", &dir.args[2]);
                            }
                        }
                        _ => {}
                    }
                }
                configs.push(cfg);
            }

            "root" => {
                let path = dir.args.first().cloned().unwrap_or_default();
                let mut vars = HashMap::new();
                vars.insert("root".to_string(), path);
                let cfg = HandlerConfig::new("vars").with_field("vars", vars);
                configs.push(cfg);
            }

            "header" | "request_header" => {
                let is_request = dir.name == "request_header";
                let mut set_headers = HashMap::new();
                let mut delete_headers = Vec::new();

                if let Some(name) = dir.args.first() {
                    if let Some(stripped) = name.strip_prefix('-') {
                        delete_headers.push(stripped.to_string());
                    } else if dir.args.len() > 1 {
                        let clean_name = name.strip_prefix('+').unwrap_or(name);
                        set_headers.insert(clean_name.to_string(), dir.args[1..].join(" "));
                    }
                }

                if let Some(ref block) = dir.block {
                    for sub in block {
                        if let Some(stripped) = sub.name.strip_prefix('-') {
                            delete_headers.push(stripped.to_string());
                        } else if !sub.args.is_empty() {
                            let clean_name = sub.name.strip_prefix('+').unwrap_or(&sub.name);
                            set_headers.insert(clean_name.to_string(), sub.args.join(" "));
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("headers");
                if is_request {
                    cfg = cfg.with_field("set_request_headers", set_headers)
                             .with_field("delete_request_headers", delete_headers);
                } else {
                    cfg = cfg.with_field("set_response_headers", set_headers)
                             .with_field("delete_response_headers", delete_headers);
                }
                configs.push(cfg);
            }

            "reverse_proxy" => {
                let mut upstreams = Vec::new();
                for arg in &dir.args {
                    upstreams.push(json_upstream(arg));
                }

                let mut lb_policy = "random".to_string();
                let mut header_up = HashMap::new();
                let mut header_down = HashMap::new();

                if let Some(ref block) = dir.block {
                    for sub in block {
                        match sub.name.as_str() {
                            "to" => {
                                for arg in &sub.args {
                                    upstreams.push(json_upstream(arg));
                                }
                            }
                            "lb_policy" => {
                                if let Some(pol) = sub.args.first() {
                                    lb_policy = pol.clone();
                                }
                            }
                            "header_up" => {
                                if sub.args.len() >= 2 {
                                    header_up.insert(sub.args[0].clone(), sub.args[1..].join(" "));
                                }
                            }
                            "header_down" => {
                                if sub.args.len() >= 2 {
                                    header_down.insert(sub.args[0].clone(), sub.args[1..].join(" "));
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let cfg = HandlerConfig::new("reverse_proxy")
                    .with_field("upstreams", upstreams)
                    .with_field("lb_policy", lb_policy)
                    .with_field("headers", serde_json::json!({
                        "request": { "set": header_up },
                        "response": { "set": header_down }
                    }));
                configs.push(cfg);
            }

            "file_server" => {
                let mut browse = false;
                let mut root = None;

                for arg in &dir.args {
                    if arg == "browse" {
                        browse = true;
                    }
                }

                if let Some(ref block) = dir.block {
                    for sub in block {
                        if sub.name == "browse" {
                            browse = true;
                        } else if sub.name == "root" {
                            root = sub.args.first().cloned();
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("file_server").with_field("browse", browse);
                if let Some(r) = root {
                    cfg = cfg.with_field("root", r);
                }
                configs.push(cfg);
            }

            "encode" => {
                let mut encodings = Vec::new();
                if dir.args.is_empty() {
                    encodings.push("gzip".to_string());
                    encodings.push("zstd".to_string());
                } else {
                    for arg in &dir.args {
                        encodings.push(arg.clone());
                    }
                }
                let cfg = HandlerConfig::new("encode").with_field("encodings", encodings);
                configs.push(cfg);
            }

            "route" => {
                // Route block preserves exact sequence of subdirectives
                if let Some(ref block) = dir.block {
                    let mut sub_routes = Vec::new();
                    for sub in block {
                        let r = self.adapt_directive(sub, &[], None, &HashMap::new())?;
                        sub_routes.push(r);
                    }
                    let cfg = HandlerConfig::new("subroute").with_field("routes", sub_routes);
                    configs.push(cfg);
                }
            }

            "handle" => {
                if let Some(ref block) = dir.block {
                    let mut sub_routes = Vec::new();
                    for sub in block {
                        let r = self.adapt_directive(sub, &[], None, &HashMap::new())?;
                        sub_routes.push(r);
                    }
                    let cfg = HandlerConfig::new("subroute").with_field("routes", sub_routes);
                    configs.push(cfg);
                }
            }

            "abort" => {
                let cfg = HandlerConfig::new("abort");
                configs.push(cfg);
            }

            "error" => {
                let code = dir.args.first().and_then(|c| c.parse::<u16>().ok()).unwrap_or(500);
                let message = if dir.args.len() > 1 {
                    dir.args[1..].join(" ")
                } else {
                    "Internal Server Error".to_string()
                };
                let cfg = HandlerConfig::new("error")
                    .with_field("error", message)
                    .with_field("status_code", code);
                configs.push(cfg);
            }

            other => {
                // Generic handler passthrough
                let mut cfg = HandlerConfig::new(other);
                if !dir.args.is_empty() {
                    cfg = cfg.with_field("args", &dir.args);
                }
                configs.push(cfg);
            }
        }

        Ok(configs)
    }
}

fn json_upstream(addr: &str) -> serde_json::Value {
    let dial = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:80", addr)
    };
    serde_json::json!({ "dial": dial })
}

#[derive(Debug, Clone)]
struct ParsedAddress {
    host: String,
    #[allow(dead_code)]
    port: u16,
    listen: String,
    path_prefix: Option<String>,
}

fn parse_site_address(addr: &str, default_http_port: u16, default_https_port: u16) -> ParsedAddress {
    let mut s = addr;
    let mut scheme = None;

    if let Some(stripped) = s.strip_prefix("http://") {
        scheme = Some("http");
        s = stripped;
    } else if let Some(stripped) = s.strip_prefix("https://") {
        scheme = Some("https");
        s = stripped;
    }

    let mut path_prefix = None;
    if let Some(slash_idx) = s.find('/') {
        path_prefix = Some(s[slash_idx..].to_string());
        s = &s[..slash_idx];
    }

    let (host, port) = if let Some(colon_idx) = s.rfind(':') {
        let h = &s[..colon_idx];
        let p = s[colon_idx + 1..].parse::<u16>().unwrap_or(80);
        let host_val = if h.is_empty() { "*" } else { h };
        (host_val.to_string(), p)
    } else if s.is_empty() || s == "*" {
        ("*".to_string(), if scheme == Some("http") { default_http_port } else { default_https_port })
    } else {
        let p = if scheme == Some("http") {
            default_http_port
        } else {
            default_https_port
        };
        (s.to_string(), p)
    };

    let listen = format!(":{}", port);
    ParsedAddress {
        host,
        port,
        listen,
        path_prefix,
    }
}

fn parse_named_matcher_block(dir: &DirectiveNode) -> ParseResult<MatcherSet> {
    let mut set = MatcherSet::default();
    if let Some(ref block) = dir.block {
        for sub in block {
            match sub.name.as_str() {
                "host" => {
                    set.host = Some(sub.args.clone());
                }
                "path" => {
                    set.path = Some(sub.args.clone());
                }
                "method" => {
                    set.method = Some(sub.args.clone());
                }
                "header" => {
                    if sub.args.len() >= 2 {
                        let mut hdr = set.header.unwrap_or_default();
                        hdr.insert(sub.args[0].clone(), vec![sub.args[1].clone()]);
                        set.header = Some(hdr);
                    }
                }
                "remote_ip" => {
                    set.remote_ip = Some(RemoteIpMatcher {
                        ranges: sub.args.clone(),
                    });
                }
                "expression" => {
                    set.expression = Some(sub.args.join(" "));
                }
                _ => {}
            }
        }
    }
    Ok(set)
}

fn parse_tls_directive(dir: &DirectiveNode) -> ParseResult<TlsConnectionPolicy> {
    let mut policy = TlsConnectionPolicy::default();

    if let Some(first) = dir.args.first() {
        if first == "internal" {
            // Self-signed local CA
            policy.certificate_selection = Some(CertificateSelection {
                any_tag: Some(vec!["internal".to_string()]),
                all_tags: None,
                serial_number: None,
            });
        }
    }

    if let Some(ref block) = dir.block {
        for sub in block {
            match sub.name.as_str() {
                "protocols" => {
                    if let Some(pmin) = sub.args.first() {
                        policy.protocol_min = Some(pmin.clone());
                    }
                    if let Some(pmax) = sub.args.get(1) {
                        policy.protocol_max = Some(pmax.clone());
                    }
                }
                "ciphers" => {
                    policy.cipher_suites = Some(sub.args.clone());
                }
                "curves" => {
                    policy.curves = Some(sub.args.clone());
                }
                _ => {}
            }
        }
    }

    Ok(policy)
}

fn merge_matcher_set(dst: &mut MatcherSet, src: &MatcherSet) {
    if let Some(ref h) = src.host {
        let mut existing = dst.host.take().unwrap_or_default();
        existing.extend(h.clone());
        dst.host = Some(existing);
    }
    if let Some(ref p) = src.path {
        let mut existing = dst.path.take().unwrap_or_default();
        existing.extend(p.clone());
        dst.path = Some(existing);
    }
    if let Some(ref m) = src.method {
        dst.method = Some(m.clone());
    }
    if let Some(ref hdr) = src.header {
        let mut existing = dst.header.take().unwrap_or_default();
        existing.extend(hdr.clone());
        dst.header = Some(existing);
    }
    if let Some(ref ip) = src.remote_ip {
        dst.remote_ip = Some(ip.clone());
    }
    if let Some(ref expr) = src.expression {
        dst.expression = Some(expr.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    #[test]
    fn test_adapt_respond() {
        let input = "localhost:8080 {\n  respond \"Hello Raddy!\" 200\n}";
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        let http = config.http_app().unwrap();
        assert_eq!(http.servers.len(), 1);
        let srv = http.servers.get("srv_:8080").unwrap();
        assert_eq!(srv.routes.len(), 1);
        let route = &srv.routes[0];
        assert_eq!(route.handle.len(), 1);
        assert_eq!(route.handle[0].handler, "static_response");
        assert_eq!(route.handle[0].details.get("status_code"), Some(&serde_json::json!(200)));
        assert_eq!(route.handle[0].details.get("body"), Some(&serde_json::json!("Hello Raddy!")));
    }

    #[test]
    fn test_adapt_reverse_proxy_with_matcher() {
        let input = r#"
example.com {
    @api {
        path /api/*
        method POST
    }
    reverse_proxy @api 127.0.0.1:5000 {
        lb_policy round_robin
        header_up X-Real-IP {remote_host}
    }
    file_server
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        let http = config.http_app().unwrap();
        let srv = http.servers.get("srv_:443").unwrap();
        // file_server has higher priority (runs earlier or later depending on order)
        assert_eq!(srv.routes.len(), 2);
    }
}
