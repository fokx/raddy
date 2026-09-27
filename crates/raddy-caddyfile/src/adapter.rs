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
    "request_body",
    "basic_auth",
    "forward_auth",
    "rewrite",
    "uri",
    "try_files",
    "push",
    "invoke",
    "redir",
    "respond",
    "abort",
    "error",
    "php_fastcgi",
    "file_server",
    "acme_server",
    "reverse_proxy",
    "templates",
    "encode",
];



pub struct Adapter {
    http_port: u16,
    https_port: u16,
    auto_https: Option<AutoHttpsConfig>,
    admin: Option<AdminConfig>,
    logging: Option<LoggingConfig>,
    email: Option<String>,
    acme_ca: Option<String>,
    staging: Option<bool>,
    custom_order: HashMap<String, usize>,
    site_log_counter: usize,
    named_routes: HashMap<String, NamedRouteNode>,
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
            email: None,
            acme_ca: None,
            staging: None,
            custom_order,
            site_log_counter: 0,
            named_routes: HashMap::new(),
        }
    }

    /// Adapts a Caddyfile AST into Raddy's internal JSON Config model.
    pub fn adapt(&mut self, caddyfile: &Caddyfile) -> ParseResult<Config> {
        self.named_routes = caddyfile.named_routes.clone();

        // 1. Process global options
        if let Some(ref opts) = caddyfile.global_options {
            self.process_global_options(opts)?;
        }

        let mut config = Config::new();
        config.admin = self.admin.clone();

        let mut servers: HashMap<String, HttpServer> = HashMap::new();

        // 2. Process each site block
        for site in &caddyfile.site_blocks {
            self.adapt_site_block(site, &mut servers)?;
        }

        config.logging = self.logging.clone();

        // 3. Automatic HTTPS: generate port 80 server for HTTP->HTTPS redirects and ACME HTTP-01 challenges
        let auto_https_disabled = self.auto_https.as_ref().and_then(|a| a.disabled).unwrap_or(false);
        if !auto_https_disabled {
            self.setup_automatic_https(&mut servers);
        }

        let http_app = HttpApp { servers };
        config.set_http_app(http_app).map_err(|e| ParseError::Adaptation {
            line: 1,
            message: format!("Failed to serialize HTTP app: {}", e),
        })?;

        if self.email.is_some() || self.acme_ca.is_some() || self.staging.is_some() {
            let tls_app = TlsApp {
                email: self.email.clone(),
                acme_ca: self.acme_ca.clone(),
                staging: self.staging,
                extra: HashMap::new(),
            };
            let _ = config.set_tls_app(tls_app);
        }

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
                "email" => {
                    self.email = opt.args.first().cloned();
                }
                "acme_ca" => {
                    self.acme_ca = opt.args.first().cloned();
                }
                "local_certs" => {
                    self.staging = Some(false);
                }
                "debug" => {
                    let logging = self.logging.get_or_insert_with(LoggingConfig::default);
                    let default_log = logging.logs.entry("default".to_string()).or_default();
                    default_log.level = Some("DEBUG".to_string());
                }
                "log" => {
                    let log_name = opt.args.first().cloned().unwrap_or_else(|| "default".to_string());
                    let log_cfg = parse_log_directive(opt, &log_name)?;
                    let logging = self.logging.get_or_insert_with(LoggingConfig::default);
                    logging.logs.insert(log_name, log_cfg);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn adapt_site_block(
        &mut self,
        site: &SiteBlockNode,
        servers: &mut HashMap<String, HttpServer>,
    ) -> ParseResult<()> {
        // Collect named matchers defined in this site block: `@name { ... }`
        let mut named_matchers: HashMap<String, MatcherSet> = HashMap::new();
        let mut regular_directives: Vec<DirectiveNode> = Vec::new();
        let mut site_tls_policy: Option<TlsConnectionPolicy> = None;
        let mut site_log_dir: Option<DirectiveNode> = None;

        for dir in &site.directives {
            if dir.name.starts_with('@') {
                let name = dir.name.clone();
                let matcher_set = parse_named_matcher_block(dir)?;
                named_matchers.insert(name, matcher_set);
            } else if dir.name == "tls" {
                site_tls_policy = Some(parse_tls_directive(dir)?);
            } else if dir.name == "log" {
                site_log_dir = Some(dir.clone());
            } else {
                regular_directives.push(dir.clone());
            }
        }

        // Process site log directive if present
        let site_logger_name = if let Some(ref log_node) = site_log_dir {
            let name = if let Some(first) = log_node.args.first() {
                first.clone()
            } else {
                let generated = format!("log{}", self.site_log_counter);
                self.site_log_counter += 1;
                generated
            };
            let log_cfg = parse_log_directive(log_node, &name)?;
            let logging = self.logging.get_or_insert_with(LoggingConfig::default);
            logging.logs.insert(name.clone(), log_cfg);
            Some(name)
        } else {
            None
        };

        // Sort directives by priority table
        regular_directives.sort_by_key(|dir| {
            self.custom_order.get(&dir.name).copied().unwrap_or(500)
        });

        // Each address in site.addresses maps to a parsed address
        for addr_str in &site.addresses {
            let parsed_addr = parse_site_address(addr_str, self.http_port, self.https_port)?;
            let server_key = format!("srv_{}", parsed_addr.listen);

            let server = servers.entry(server_key).or_insert_with(|| HttpServer {
                listen: vec![parsed_addr.listen.clone()],
                routes: Vec::new(),
                tls_connection_policies: None,
                automatic_https: self.auto_https.clone(),
                protocols: None,
                logs: None,
            });

            if let Some(ref log_name) = site_logger_name {
                let srv_logs = server.logs.get_or_insert_with(ServerLogConfig::default);
                if srv_logs.default_logger_name.is_none() {
                    srv_logs.default_logger_name = Some(log_name.clone());
                }
                let names = srv_logs.logger_names.get_or_insert_with(HashMap::new);
                names.insert(parsed_addr.host.clone(), log_name.clone());
            }

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

            "handle_path" => {
                let prefix = dir.matcher.as_deref().or_else(|| dir.args.first().map(|s| s.as_str())).unwrap_or("");
                let clean_prefix = prefix.trim_end_matches('*');
                let mut sub_routes = Vec::new();
                if !clean_prefix.is_empty() {
                    let rewrite_cfg = HandlerConfig::new("rewrite").with_field("strip_path_prefix", clean_prefix);
                    let mut r = Route::default();
                    r.handle = vec![rewrite_cfg];
                    sub_routes.push(r);
                }
                if let Some(ref block) = dir.block {
                    for sub in block {
                        let r = self.adapt_directive(sub, &[], None, &HashMap::new())?;
                        sub_routes.push(r);
                    }
                }
                let cfg = HandlerConfig::new("subroute").with_field("routes", sub_routes);
                configs.push(cfg);
            }

            "invoke" => {
                let name = dir.args.first().ok_or_else(|| ParseError::Adaptation {
                    line: dir.span.line,
                    message: "invoke directive requires a named route name".into(),
                })?;

                if !self.named_routes.contains_key(name) {
                    return Err(ParseError::Adaptation {
                        line: dir.span.line,
                        message: format!("cannot invoke named route '{}', which was not defined", name),
                    });
                }

                let cfg = HandlerConfig::new("invoke").with_field("name", name);
                configs.push(cfg);
            }

            "log_skip" | "log_append" => {
                let cfg = HandlerConfig::new(dir.name.as_str());
                configs.push(cfg);
            }

            "templates" => {
                let cfg = HandlerConfig::new("templates");
                configs.push(cfg);
            }

            "basic_auth" => {
                let mut users = HashMap::new();
                let mut realm = None;

                if dir.args.len() == 1 {
                    realm = Some(dir.args[0].clone());
                } else if dir.args.len() == 2 {
                    users.insert(dir.args[0].clone(), dir.args[1].clone());
                } else if dir.args.len() >= 3 {
                    realm = Some(dir.args[0].clone());
                    users.insert(dir.args[1].clone(), dir.args[2].clone());
                }

                if let Some(ref block) = dir.block {
                    for sub in block {
                        if let Some(pass) = sub.args.first() {
                            users.insert(sub.name.clone(), pass.clone());
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("basic_auth").with_field("users", users);
                if let Some(r) = realm {
                    cfg = cfg.with_field("realm", r);
                }
                configs.push(cfg);
            }

            "forward_auth" => {
                let upstream = dir.args.first().cloned().unwrap_or_default();
                let mut uri = None;
                let mut copy_headers = Vec::new();

                if let Some(ref block) = dir.block {
                    for sub in block {
                        match sub.name.as_str() {
                            "uri" => {
                                uri = sub.args.first().cloned();
                            }
                            "copy_headers" => {
                                copy_headers.extend(sub.args.clone());
                            }
                            _ => {}
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("forward_auth")
                    .with_field("upstream", upstream)
                    .with_field("copy_headers", copy_headers);
                if let Some(u) = uri {
                    cfg = cfg.with_field("uri", u);
                }
                configs.push(cfg);
            }

            "request_body" => {
                let mut max_size_str = dir.args.first().cloned();
                if let Some(ref block) = dir.block {
                    for sub in block {
                        if sub.name == "max_size" {
                            max_size_str = sub.args.first().cloned();
                        }
                    }
                }
                let size_bytes = max_size_str.as_deref().map(parse_size_bytes).unwrap_or(10 * 1024 * 1024);
                let cfg = HandlerConfig::new("request_body").with_field("max_size", size_bytes);
                configs.push(cfg);
            }

            "map" => {
                let source = dir.args.first().cloned().unwrap_or_default();
                let dest = dir.args.get(1).cloned().unwrap_or_default();
                let mut default_val = None;
                let mut mappings = Vec::new();

                if let Some(ref block) = dir.block {
                    for sub in block {
                        if sub.name == "default" {
                            default_val = sub.args.first().cloned();
                        } else if let Some(val) = sub.args.first() {
                            mappings.push(serde_json::json!({
                                "pattern": sub.name,
                                "value": val,
                            }));
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("map")
                    .with_field("source", source)
                    .with_field("dest", dest)
                    .with_field("mappings", mappings);
                if let Some(def) = default_val {
                    cfg = cfg.with_field("default", def);
                }
                configs.push(cfg);
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

    fn setup_automatic_https(&self, servers: &mut HashMap<String, HttpServer>) {
        let https_port_str = format!(":{}", self.https_port);
        let http_port_str = format!(":{}", self.http_port);
        let http_server_key = format!("srv_{}", http_port_str);

        // Find hosts served on HTTPS
        let mut https_hosts = Vec::new();
        for srv in servers.values() {
            let is_https = srv.listen.iter().any(|l| l.ends_with(&https_port_str))
                || srv.tls_connection_policies.is_some();
            if is_https {
                for route in &srv.routes {
                    if let Some(ref matchers) = route.r#match {
                        for m in matchers {
                            if let Some(ref hosts) = m.host {
                                for h in hosts {
                                    if h != "*" && !https_hosts.contains(h) {
                                        https_hosts.push(h.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if https_hosts.is_empty() {
            return;
        }

        let disable_redirects = self
            .auto_https
            .as_ref()
            .and_then(|a| a.disable_redirects)
            .unwrap_or(false);

        let http_server = servers.entry(http_server_key).or_insert_with(|| HttpServer {
            listen: vec![http_port_str],
            routes: Vec::new(),
            tls_connection_policies: None,
            automatic_https: self.auto_https.clone(),
            protocols: None,
            logs: None,
        });

        if !disable_redirects {
            for host in https_hosts {
                let host_already_has_route = http_server.routes.iter().any(|r| {
                    r.r#match
                        .as_ref()
                        .map(|ms| {
                            ms.iter().any(|m| {
                                m.host
                                    .as_ref()
                                    .map(|hs| hs.contains(&host))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                });

                if !host_already_has_route {
                    let mut redir_route = Route::default();
                    redir_route.r#match = Some(vec![MatcherSet {
                        host: Some(vec![host.clone()]),
                        ..Default::default()
                    }]);
                    let redir_cfg = HandlerConfig::new("static_response")
                        .with_field("status_code", 308)
                        .with_field("location", "https://{host}{uri}");
                    redir_route.handle = vec![redir_cfg];
                    http_server.routes.push(redir_route);
                }
            }
        }
    }
}

fn parse_log_directive(dir: &DirectiveNode, logger_name: &str) -> ParseResult<LogConfig> {
    let mut writer = None;
    let mut encoder = None;
    let mut level = Some("INFO".to_string());
    let mut include = vec![format!("http.log.access.{}", logger_name)];
    let mut exclude = Vec::new();

    if let Some(ref block) = dir.block {
        for sub in block {
            match sub.name.as_str() {
                "output" => {
                    if let Some(wtype) = sub.args.first() {
                        match wtype.as_str() {
                            "file" => {
                                let filename = sub.args.get(1).cloned().unwrap_or_else(|| "access.log".into());
                                let mut obj = serde_json::json!({
                                    "output": "file",
                                    "filename": filename,
                                });
                                if let Some(ref file_block) = sub.block {
                                    for opt in file_block {
                                        if let Some(val) = opt.args.first() {
                                            obj[opt.name.clone()] = serde_json::json!(val);
                                        }
                                    }
                                }
                                writer = Some(obj);
                            }
                            "stdout" => {
                                writer = Some(serde_json::json!({ "output": "stdout" }));
                            }
                            "stderr" => {
                                writer = Some(serde_json::json!({ "output": "stderr" }));
                            }
                            "discard" => {
                                writer = Some(serde_json::json!({ "output": "discard" }));
                            }
                            "net" => {
                                let addr = sub.args.get(1).cloned().unwrap_or_default();
                                writer = Some(serde_json::json!({ "output": "net", "address": addr }));
                            }
                            _ => {
                                writer = Some(serde_json::json!({ "output": wtype }));
                            }
                        }
                    }
                }
                "format" => {
                    if let Some(ftype) = sub.args.first() {
                        match ftype.as_str() {
                            "json" => {
                                encoder = Some(serde_json::json!({ "format": "json" }));
                            }
                            "console" => {
                                encoder = Some(serde_json::json!({ "format": "console" }));
                            }
                            other => {
                                encoder = Some(serde_json::json!({ "format": other }));
                            }
                        }
                    }
                }
                "level" => {
                    if let Some(lvl) = sub.args.first() {
                        level = Some(lvl.to_uppercase());
                    }
                }
                "include" => {
                    include = sub.args.clone();
                }
                "exclude" => {
                    exclude = sub.args.clone();
                }
                _ => {}
            }
        }
    }

    if writer.is_none() {
        writer = Some(serde_json::json!({ "output": "stdout" }));
    }
    if encoder.is_none() {
        encoder = Some(serde_json::json!({ "format": "console" }));
    }

    Ok(LogConfig {
        writer,
        encoder,
        level,
        include,
        exclude,
    })
}

fn json_upstream(addr: &str) -> serde_json::Value {
    let dial = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:80", addr)
    };
    serde_json::json!({ "dial": dial })
}

fn parse_size_bytes(s: &str) -> usize {
    let s = s.trim().to_lowercase();
    if let Some(stripped) = s.strip_suffix("gb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if let Some(stripped) = s.strip_suffix("mb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024
    } else if let Some(stripped) = s.strip_suffix("kb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024
    } else if let Some(stripped) = s.strip_suffix('b') {
        stripped.trim().parse::<usize>().unwrap_or(0)
    } else {
        s.parse::<usize>().unwrap_or(0)
    }
}


#[derive(Debug, Clone)]
struct ParsedAddress {
    host: String,
    #[allow(dead_code)]
    port: u16,
    listen: String,
    path_prefix: Option<String>,
}

fn parse_site_address(addr: &str, default_http_port: u16, default_https_port: u16) -> ParseResult<ParsedAddress> {
    if addr.starts_with("wss://") {
        return Err(ParseError::Syntax {
            line: 0,
            col: 0,
            message: "the scheme wss:// is only supported in browsers; use https:// instead".into(),
        });
    }

    if let Some(idx) = addr.find("://") {
        let scheme = &addr[..idx];
        if scheme != "http" && scheme != "https" {
            return Err(ParseError::Syntax {
                line: 0,
                col: 0,
                message: format!("unsupported URL scheme {}://", scheme),
            });
        }
    }

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
        let port_str = &s[colon_idx + 1..];
        let p = match port_str.parse::<i64>() {
            Ok(val) if (0..=65535).contains(&val) => val as u16,
            _ => {
                return Err(ParseError::Syntax {
                    line: 0,
                    col: 0,
                    message: format!("port {} is out of range", port_str),
                });
            }
        };
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
    Ok(ParsedAddress {
        host,
        port,
        listen,
        path_prefix,
    })
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
        } else if dir.args.len() >= 2 {
            let cert_file = first.clone();
            let key_file = dir.args[1].clone();
            policy.certificate_selection = Some(CertificateSelection {
                any_tag: Some(vec![format!("custom:{}:{}", cert_file, key_file)]),
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

    #[test]
    fn test_adapt_site_with_log_and_auto_https() {
        let input = r#"
hkg.eeeu.de {
    respond "OK" 200
    log {
        output file /var/log/caddy/hkghhh
    }
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        // 1. Verify logging configuration
        let logging = config.logging.as_ref().unwrap();
        let log0 = logging.logs.get("log0").unwrap();
        assert_eq!(
            log0.writer,
            Some(serde_json::json!({ "output": "file", "filename": "/var/log/caddy/hkghhh" }))
        );

        // 2. Verify HTTPS server and ServerLogConfig
        let http = config.http_app().unwrap();
        let srv_https = http.servers.get("srv_:443").unwrap();
        assert_eq!(srv_https.routes.len(), 1);
        assert_eq!(srv_https.routes[0].handle[0].handler, "static_response");
        let srv_logs = srv_https.logs.as_ref().unwrap();
        assert_eq!(srv_logs.default_logger_name.as_deref(), Some("log0"));
        assert_eq!(srv_logs.logger_names.as_ref().unwrap().get("hkg.eeeu.de"), Some(&"log0".to_string()));

        // 3. Verify automatic HTTP server on port 80 with redirect
        let srv_http = http.servers.get("srv_:80").unwrap();
        assert_eq!(srv_http.routes.len(), 1);
        assert_eq!(srv_http.routes[0].handle[0].handler, "static_response");
        assert_eq!(srv_http.routes[0].handle[0].details.get("status_code"), Some(&serde_json::json!(308)));
        assert_eq!(srv_http.routes[0].handle[0].details.get("location"), Some(&serde_json::json!("https://{host}{uri}")));
    }
}
