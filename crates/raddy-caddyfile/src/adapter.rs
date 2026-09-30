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
    "log_name",
    "log_append",
    "log_skip",
    "skip_log",
    "request_id",
    "header",
    "copy_response_headers",
    "request_body",
    "timeouts",
    "redir",
    "method",
    "rewrite",
    "uri",
    "try_files",
    "basicauth",
    "basic_auth",
    "forward_auth",
    "request_header",
    "push",
    "intercept",
    "invoke",
    "handle",
    "handle_path",
    "route",
    "abort",
    "error",
    "copy_response",
    "respond",
    "metrics",
    "reverse_proxy",
    "php_fastcgi",
    "file_server",
    "forward_proxy",
    "acme_server",
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
    log_credentials: Option<bool>,
    custom_order: HashMap<String, usize>,
    site_log_counter: usize,
    handle_group_counter: usize,
    named_routes: HashMap<String, NamedRouteNode>,
    server_options: Vec<ServerGlobalOptions>,
    default_bind: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
struct ServerGlobalOptions {
    listener_address: Option<String>,
    protocols: Option<Vec<String>>,
    strict_sni_host: Option<bool>,
    name: Option<String>,
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter {
    pub fn new() -> Self {
        let mut custom_order = HashMap::new();
        let mut handle_prio = 0;
        for (i, &name) in DIRECTIVE_ORDER.iter().enumerate() {
            let prio = i * 10;
            if name == "handle" {
                handle_prio = prio;
            }
            custom_order.insert(name.to_string(), prio);
        }
        custom_order.insert("handle_path".to_string(), handle_prio);

        Self {
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
            auto_https: None,
            admin: None,
            logging: None,
            email: None,
            acme_ca: None,
            staging: None,
            log_credentials: None,
            custom_order,
            site_log_counter: 0,
            handle_group_counter: 0,
            named_routes: HashMap::new(),
            server_options: Vec::new(),
            default_bind: None,
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

        // 4. Apply server global options overrides
        self.apply_server_options(&mut servers)?;

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
                    if let Some(arg) = opt.args.first() {
                        let resolved = raddy_core::config::resolve_acme_ca(arg);
                        if resolved.contains("staging") {
                            self.staging = Some(true);
                        }
                        self.acme_ca = Some(resolved);
                    }
                }
                "acme_staging" | "acme_dev" => {
                    self.acme_ca = Some(raddy_core::config::LETS_ENCRYPT_STAGING.to_string());
                    self.staging = Some(true);
                }
                "local_certs" => {
                    self.staging = Some(false);
                }
                "log_credentials" => {
                    self.log_credentials = Some(true);
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
                "default_bind" => {
                    self.default_bind = Some(opt.args.clone());
                }
                "servers" => {
                    let mut srv_opt = ServerGlobalOptions::default();
                    if let Some(arg) = opt.args.first() {
                        srv_opt.listener_address = Some(arg.clone());
                    }
                    if let Some(ref block) = opt.block {
                        for sub in block {
                            match sub.name.as_str() {
                                "protocols" => {
                                    srv_opt.protocols = Some(sub.args.clone());
                                }
                                "name" => {
                                    if let Some(n) = sub.args.first() {
                                        srv_opt.name = Some(n.clone());
                                    }
                                }
                                "strict_sni_host" => {
                                    let val = sub.args.first().map(|s| s.as_str() != "insecure_off").unwrap_or(true);
                                    srv_opt.strict_sni_host = Some(val);
                                }
                                _ => {}
                            }
                        }
                    }
                    self.server_options.push(srv_opt);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_server_options(&self, servers: &mut HashMap<String, HttpServer>) -> ParseResult<()> {
        if self.server_options.is_empty() {
            return Ok(());
        }

        // Apply generic server options (without listener_address) first,
        // then specific server options (with listener_address) so specific options take precedence.
        let mut sorted_opts = self.server_options.clone();
        sorted_opts.sort_by_key(|o| if o.listener_address.is_some() { 1 } else { 0 });

        let mut name_replacements = Vec::new();

        for (srv_name, server) in servers.iter_mut() {
            for opt in &sorted_opts {
                let matches = match &opt.listener_address {
                    Some(addr) => {
                        server.listen.iter().any(|l| l == addr || l.ends_with(addr) || addr.ends_with(l))
                    }
                    None => true,
                };

                if matches {
                    if let Some(ref protos) = opt.protocols {
                        server.protocols = Some(protos.clone());
                    }
                    if let Some(ref new_name) = opt.name {
                        name_replacements.push((srv_name.clone(), new_name.clone()));
                    }
                }
            }
        }

        for (old_name, new_name) in name_replacements {
            if let Some(srv) = servers.remove(&old_name) {
                servers.insert(new_name, srv);
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
        let mut site_log_dirs: Vec<DirectiveNode> = Vec::new();
        let mut site_bind_hosts: Vec<String> = Vec::new();
        let mut handle_errors_dirs: Vec<DirectiveNode> = Vec::new();

        for dir in &site.directives {
            if dir.name.starts_with('@') {
                let name = dir.name.clone();
                let matcher_set = parse_named_matcher_block(dir)?;
                named_matchers.insert(name, matcher_set);
            } else if dir.name == "tls" {
                let pol = parse_tls_directive(dir)?;
                if let Some(ref cs) = pol.certificate_selection {
                    if let Some(ref tags) = cs.any_tag {
                        for t in tags {
                            if let Some(ca) = t.strip_prefix("ca:") {
                                if self.acme_ca.is_none() {
                                    self.acme_ca = Some(ca.to_string());
                                }
                                if ca.contains("staging") {
                                    self.staging = Some(true);
                                }
                            } else if let Some(em) = t.strip_prefix("email:") {
                                if self.email.is_none() {
                                    self.email = Some(em.to_string());
                                }
                            }
                        }
                    }
                }
                site_tls_policy = Some(pol);
            } else if dir.name == "log" {
                site_log_dirs.push(dir.clone());
            } else if dir.name == "bind" {
                site_bind_hosts.extend(dir.args.clone());
            } else if dir.name == "handle_errors" {
                handle_errors_dirs.push(dir.clone());
            } else {
                regular_directives.push(dir.clone());
            }
        }

        if site_bind_hosts.is_empty() {
            if let Some(ref db) = self.default_bind {
                site_bind_hosts.extend(db.clone());
            }
        }

        // Process site log directives
        struct ParsedSiteLogger {
            name: String,
            hostnames: Vec<String>,
            no_hostname: bool,
        }

        let mut site_loggers = Vec::new();

        for log_node in &site_log_dirs {
            let name = if let Some(first) = log_node.args.first() {
                first.clone()
            } else {
                let generated = format!("log{}", self.site_log_counter);
                self.site_log_counter += 1;
                generated
            };

            let mut hostnames = Vec::new();
            let mut no_hostname = false;

            if let Some(ref block) = log_node.block {
                for sub in block {
                    if sub.name == "no_hostname" {
                        no_hostname = true;
                    } else if sub.name == "hostnames" {
                        hostnames.extend(sub.args.clone());
                    }
                }
            }

            let log_cfg = parse_log_directive(log_node, &name)?;
            let logging = self.logging.get_or_insert_with(LoggingConfig::default);
            logging.logs.insert(name.clone(), log_cfg);

            site_loggers.push(ParsedSiteLogger {
                name,
                hostnames,
                no_hostname,
            });
        }

        let handle_group_id = format!("group_{}", self.handle_group_counter);
        self.handle_group_counter += 1;

        // Sort directives by priority table.
        // Directives with matchers sort before fallback handle directives without matchers.
        regular_directives.sort_by_key(|dir| {
            let prio = self.custom_order.get(&dir.name).copied().unwrap_or(500);
            let is_fallback_handle = if dir.name == "handle" && dir.matcher.is_none() && dir.args.is_empty() {
                1
            } else {
                0
            };
            (prio, is_fallback_handle)
        });

        // Each address in site.addresses maps to a parsed address
        for addr_str in &site.addresses {
            let parsed_addr = parse_site_address(addr_str, self.http_port, self.https_port)?;
            let listens = if !site_bind_hosts.is_empty() {
                let port_str = if let Some(idx) = parsed_addr.listen.rfind(':') {
                    &parsed_addr.listen[idx..]
                } else {
                    ":80"
                };
                site_bind_hosts.iter().map(|h| format!("{}{}", h, port_str)).collect::<Vec<_>>()
            } else {
                vec![parsed_addr.listen.clone()]
            };

            let server_key = format!("srv_{}", listens.join(","));

            let server = servers.entry(server_key).or_insert_with(|| HttpServer {
                listen: listens,
                routes: Vec::new(),
                tls_connection_policies: None,
                automatic_https: self.auto_https.clone(),
                protocols: None,
                logs: None,
                errors: None,
            });

            for sl in &site_loggers {
                if !sl.no_hostname {
                    let srv_logs = server.logs.get_or_insert_with(ServerLogConfig::default);
                    if self.log_credentials.is_some() {
                        srv_logs.log_credentials = self.log_credentials;
                    }
                    if !sl.hostnames.is_empty() {
                        let names = srv_logs.logger_names.get_or_insert_with(HashMap::new);
                        for h in &sl.hostnames {
                            names.insert(h.clone(), sl.name.clone());
                        }
                    } else {
                        if srv_logs.default_logger_name.is_none() {
                            srv_logs.default_logger_name = Some(sl.name.clone());
                        }
                        let names = srv_logs.logger_names.get_or_insert_with(HashMap::new);
                        names.insert(parsed_addr.host.clone(), sl.name.clone());
                    }
                }
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
                let mut route = self.adapt_directive(dir, &host_matchers, path_matcher.as_deref(), &named_matchers)?;
                if dir.name == "handle" || dir.name == "handle_path" {
                    route.group = Some(handle_group_id.clone());
                }
                server.routes.push(route);
            }

            // Attach handle_errors routes if present
            if !handle_errors_dirs.is_empty() {
                let errors_cfg = server.errors.get_or_insert_with(HttpErrorsConfig::default);
                for dir in &handle_errors_dirs {
                    let mut matchers = None;
                    if !dir.args.is_empty() {
                        let mut vars_map = HashMap::new();
                        vars_map.insert("err.status_code".to_string(), dir.args.join(" "));
                        matchers = Some(vec![MatcherSet {
                            vars: Some(vars_map),
                            ..Default::default()
                        }]);
                    }
                    if let Some(ref block) = dir.block {
                        for sub in block {
                            let mut sub_route = self.adapt_directive(sub, &host_matchers, None, &named_matchers)?;
                            if matchers.is_some() {
                                sub_route.r#match = matchers.clone();
                            }
                            errors_cfg.routes.push(sub_route);
                        }
                    }
                }
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
        let effective_matcher = dir.matcher.as_ref().or_else(|| {
            if dir.name == "handle_path" {
                dir.args.first()
            } else {
                None
            }
        });
        if let Some(m) = effective_matcher {
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
                let path = if !dir.args.is_empty() {
                    dir.args[0].clone()
                } else if let Some(ref m) = dir.matcher {
                    m.clone()
                } else {
                    String::new()
                };
                let mut vars = HashMap::new();
                vars.insert("root".to_string(), path);
                let cfg = HandlerConfig::new("vars").with_field("vars", vars);
                configs.push(cfg);
            }

            "method" => {
                let method = dir.args.first().cloned().unwrap_or_default();
                let cfg = HandlerConfig::new("method").with_field("method", method);
                configs.push(cfg);
            }

            "vars" => {
                let mut vars = HashMap::new();
                if dir.args.len() >= 2 {
                    vars.insert(dir.args[0].clone(), dir.args[1..].join(" "));
                }
                if let Some(ref block) = dir.block {
                    for sub in block {
                        vars.insert(sub.name.clone(), sub.args.join(" "));
                    }
                }
                let cfg = HandlerConfig::new("vars").with_field("vars", vars);
                configs.push(cfg);
            }

            "try_files" => {
                let files = dir.args.clone();
                let cfg = HandlerConfig::new("try_files").with_field("try_files", files);
                configs.push(cfg);
            }

            "php_fastcgi" => {
                let try_files = vec!["{path}".to_string(), "{path}/index.php".to_string(), "index.php".to_string()];
                configs.push(HandlerConfig::new("try_files").with_field("try_files", try_files));

                let mut upstreams = Vec::new();
                for arg in &dir.args {
                    upstreams.push(json_upstream(arg));
                }
                if let Some(ref block) = dir.block {
                    for sub in block {
                        if sub.name == "to" {
                            for arg in &sub.args {
                                upstreams.push(json_upstream(arg));
                            }
                        }
                    }
                }
                let cfg = HandlerConfig::new("reverse_proxy")
                    .with_field("upstreams", upstreams)
                    .with_field("fastcgi", true);
                configs.push(cfg);
            }

            "header" | "request_header" => {
                let is_request = dir.name == "request_header";
                let mut set_headers = HashMap::new();
                let mut default_headers = HashMap::new();
                let mut delete_headers = Vec::new();

                let process_header_item = |name: &str, args: &[String], set_map: &mut HashMap<String, String>, def_map: &mut HashMap<String, String>, del_list: &mut Vec<String>| {
                    if let Some(stripped) = name.strip_prefix('-') {
                        del_list.push(stripped.to_string());
                    } else if let Some(stripped) = name.strip_prefix('?') {
                        if !args.is_empty() {
                            def_map.insert(stripped.to_string(), args.join(" "));
                        }
                    } else if !args.is_empty() {
                        let clean_name = name.strip_prefix('+').unwrap_or(name);
                        set_map.insert(clean_name.to_string(), args.join(" "));
                    }
                };

                if let Some(name) = dir.args.first() {
                    process_header_item(name, &dir.args[1..], &mut set_headers, &mut default_headers, &mut delete_headers);
                }

                if let Some(ref block) = dir.block {
                    for sub in block {
                        process_header_item(&sub.name, &sub.args, &mut set_headers, &mut default_headers, &mut delete_headers);
                    }
                }

                let mut cfg = HandlerConfig::new("headers");
                if is_request {
                    cfg = cfg.with_field("set_request_headers", set_headers)
                             .with_field("default_request_headers", default_headers)
                             .with_field("delete_request_headers", delete_headers);
                } else {
                    cfg = cfg.with_field("set_response_headers", set_headers)
                             .with_field("default_response_headers", default_headers)
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
                let mut hide = Vec::new();

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
                            root = sub.args.first().cloned().or_else(|| sub.matcher.clone());
                        } else if sub.name == "hide" {
                            hide.extend(sub.args.clone());
                            if let Some(ref m) = sub.matcher {
                                hide.push(m.clone());
                            }
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("file_server").with_field("browse", browse);
                if let Some(r) = root {
                    cfg = cfg.with_field("root", r);
                }
                if !hide.is_empty() {
                    cfg = cfg.with_field("hide", hide);
                }
                configs.push(cfg);
            }

            "forward_proxy" => {
                let mut basic_auth = Vec::new();
                let mut hosts = Vec::new();
                let mut ports = Vec::new();
                let mut hide_ip = false;
                let mut hide_via = false;
                let mut disable_insecure_upstreams_check = false;
                let mut probe_resistance = None;
                let mut serve_pac = None;
                let mut dial_timeout = None;
                let mut max_idle_conns = None;
                let mut max_idle_conns_per_host = None;
                let mut upstream = None;
                let mut acl = Vec::new();

                if let Some(ref block) = dir.block {
                    for sub in block {
                        match sub.name.as_str() {
                            "basic_auth" => {
                                if sub.args.len() == 2 {
                                    let user = &sub.args[0];
                                    let pass = &sub.args[1];
                                    use base64::engine::general_purpose::STANDARD as BASE64;
                                    use base64::Engine;
                                    let cred = BASE64.encode(format!("{}:{}", user, pass));
                                    basic_auth.push(cred);
                                }
                            }
                            "hosts" => {
                                hosts.extend(sub.args.clone());
                            }
                            "ports" => {
                                for p in &sub.args {
                                    if let Ok(port_num) = p.parse::<u16>() {
                                        ports.push(port_num);
                                    }
                                }
                            }
                            "hide_ip" => {
                                hide_ip = true;
                            }
                            "hide_via" => {
                                hide_via = true;
                            }
                            "disable_insecure_upstreams_check" => {
                                disable_insecure_upstreams_check = true;
                            }
                            "probe_resistance" => {
                                let domain = sub.args.first().cloned();
                                probe_resistance = Some(serde_json::json!({
                                    "domain": domain
                                }));
                            }
                            "serve_pac" => {
                                let pac = sub.matcher.clone()
                                    .or_else(|| sub.args.first().cloned())
                                    .unwrap_or_else(|| "/proxy.pac".to_string());
                                serve_pac = Some(pac);
                            }
                            "dial_timeout" => {
                                if let Some(arg) = sub.args.first() {
                                    dial_timeout = Some(arg.clone());
                                }
                            }
                            "max_idle_conns" => {
                                if let Some(arg) = sub.args.first() {
                                    if let Ok(v) = arg.parse::<i64>() {
                                        max_idle_conns = Some(v);
                                    }
                                }
                            }
                            "max_idle_conns_per_host" => {
                                if let Some(arg) = sub.args.first() {
                                    if let Ok(v) = arg.parse::<i64>() {
                                        max_idle_conns_per_host = Some(v);
                                    }
                                }
                            }
                            "upstream" => {
                                if let Some(arg) = sub.args.first() {
                                    upstream = Some(arg.clone());
                                }
                            }
                            "acl" => {
                                if let Some(ref acl_block) = sub.block {
                                    for acl_dir in acl_block {
                                        match acl_dir.name.as_str() {
                                            "allow" => {
                                                acl.push(serde_json::json!({
                                                    "allow": true,
                                                    "subjects": acl_dir.args.clone()
                                                }));
                                            }
                                            "deny" => {
                                                acl.push(serde_json::json!({
                                                    "allow": false,
                                                    "subjects": acl_dir.args.clone()
                                                }));
                                            }
                                            "allow_file" => {
                                                let file_path = acl_dir.matcher.clone().or_else(|| acl_dir.args.first().cloned());
                                                if let Some(path) = file_path {
                                                    if let Ok(lines) = read_file_lines(&path) {
                                                        acl.push(serde_json::json!({
                                                            "allow": true,
                                                            "subjects": lines
                                                        }));
                                                    }
                                                }
                                            }
                                            "deny_file" => {
                                                let file_path = acl_dir.matcher.clone().or_else(|| acl_dir.args.first().cloned());
                                                if let Some(path) = file_path {
                                                    if let Ok(lines) = read_file_lines(&path) {
                                                        acl.push(serde_json::json!({
                                                            "allow": false,
                                                            "subjects": lines
                                                        }));
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let mut cfg = HandlerConfig::new("forward_proxy");
                if !basic_auth.is_empty() {
                    cfg = cfg.with_field("auth_credentials", basic_auth);
                }
                if !hosts.is_empty() {
                    cfg = cfg.with_field("hosts", hosts);
                }
                if !ports.is_empty() {
                    cfg = cfg.with_field("ports", ports);
                }
                if hide_ip {
                    cfg = cfg.with_field("hide_ip", true);
                }
                if hide_via {
                    cfg = cfg.with_field("hide_via", true);
                }
                if disable_insecure_upstreams_check {
                    cfg = cfg.with_field("disable_insecure_upstreams_check", true);
                }
                if let Some(pr) = probe_resistance {
                    cfg = cfg.with_field("probe_resistance", pr);
                }
                if let Some(pac) = serve_pac {
                    cfg = cfg.with_field("pac_path", pac);
                }
                if let Some(dt) = dial_timeout {
                    cfg = cfg.with_field("dial_timeout", dt);
                }
                if let Some(mic) = max_idle_conns {
                    cfg = cfg.with_field("max_idle_conns", mic);
                }
                if let Some(micph) = max_idle_conns_per_host {
                    cfg = cfg.with_field("max_idle_conns_per_host", micph);
                }
                if let Some(u) = upstream {
                    cfg = cfg.with_field("upstream", u);
                }
                if !acl.is_empty() {
                    cfg = cfg.with_field("acl", acl);
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
                    let mut sorted_block = block.clone();
                    sorted_block.sort_by_key(|sub| {
                        self.custom_order.get(&sub.name).copied().unwrap_or(500)
                    });
                    let mut sub_routes = Vec::new();
                    for sub in &sorted_block {
                        let r = self.adapt_directive(sub, &[], None, &HashMap::new())?;
                        sub_routes.push(r);
                    }
                    let cfg = HandlerConfig::new("subroute").with_field("routes", sub_routes);
                    configs.push(cfg);
                }
            }

            "handle_path" => {
                let prefix = dir.matcher.as_deref().or_else(|| dir.args.first().map(|s| s.as_str())).unwrap_or("");
                let clean_prefix = if prefix.ends_with("/*") {
                    &prefix[..prefix.len() - 2]
                } else if prefix.ends_with('*') {
                    &prefix[..prefix.len() - 1]
                } else {
                    prefix
                };
                let mut sub_routes = Vec::new();
                if !clean_prefix.is_empty() {
                    let rewrite_cfg = HandlerConfig::new("rewrite").with_field("strip_path_prefix", clean_prefix);
                    let mut r = Route::default();
                    r.handle = vec![rewrite_cfg];
                    sub_routes.push(r);
                }
                if let Some(ref block) = dir.block {
                    let mut sorted_block = block.clone();
                    sorted_block.sort_by_key(|sub| {
                        self.custom_order.get(&sub.name).copied().unwrap_or(500)
                    });
                    for sub in &sorted_block {
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

            "log_skip" => {
                let cfg = HandlerConfig::new("log_skip");
                configs.push(cfg);
            }

            "log_append" => {
                let key = dir.args.first().cloned().unwrap_or_default();
                let value = dir.args.get(1).cloned().unwrap_or_default();
                let cfg = HandlerConfig::new("log_append")
                    .with_field("key", key)
                    .with_field("value", value);
                configs.push(cfg);
            }

            "log_name" => {
                let name = dir.args.first().cloned().unwrap_or_default();
                let cfg = HandlerConfig::new("log_name")
                    .with_field("name", name);
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
            errors: None,
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
    let mut sampling = None;

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
                                        if opt.args.is_empty() {
                                            obj[opt.name.clone()] = serde_json::json!(true);
                                        } else if opt.args.len() == 1 {
                                            obj[opt.name.clone()] = serde_json::json!(opt.args[0]);
                                        } else {
                                            obj[opt.name.clone()] = serde_json::json!(opt.args);
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
                                let mut obj = serde_json::json!({ "output": "net", "address": addr });
                                if let Some(ref net_block) = sub.block {
                                    for opt in net_block {
                                        if opt.args.is_empty() {
                                            obj[opt.name.clone()] = serde_json::json!(true);
                                        } else if let Some(val) = opt.args.first() {
                                            obj[opt.name.clone()] = serde_json::json!(val);
                                        }
                                    }
                                }
                                writer = Some(obj);
                            }
                            _ => {
                                writer = Some(serde_json::json!({ "output": wtype }));
                            }
                        }
                    }
                }
                "format" => {
                    encoder = Some(parse_format_directive(sub)?);
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
                "sampling" => {
                    let mut s_cfg = LogSamplingConfig::default();
                    if let Some(ref s_block) = sub.block {
                        for item in s_block {
                            match item.name.as_str() {
                                "interval" => s_cfg.interval = item.args.first().cloned(),
                                "first" => s_cfg.first = item.args.first().and_then(|s| s.parse().ok()),
                                "thereafter" => s_cfg.thereafter = item.args.first().and_then(|s| s.parse().ok()),
                                _ => {}
                            }
                        }
                    }
                    sampling = Some(s_cfg);
                }
                _ => {}
            }
        }
    }

    if writer.is_none() {
        writer = Some(serde_json::json!({ "output": "stderr" }));
    }
    if encoder.is_none() {
        encoder = Some(serde_json::json!({ "format": "json" }));
    }

    Ok(LogConfig {
        writer,
        encoder,
        level,
        include,
        exclude,
        sampling,
    })
}

fn parse_format_directive(sub: &DirectiveNode) -> ParseResult<serde_json::Value> {
    let ftype = sub.args.first().map(|s| s.as_str()).unwrap_or("json");
    let mut obj = serde_json::json!({ "format": ftype });

    if let Some(ref block) = sub.block {
        match ftype {
            "filter" => {
                let mut filters = Vec::new();
                for node in block {
                    if node.name == "wrap" {
                        let wrap_type = node.args.first().cloned().unwrap_or_else(|| "json".into());
                        obj["wrap"] = serde_json::json!({ "format": wrap_type });
                    } else if node.name == "fields" {
                        if let Some(ref inner_block) = node.block {
                            for inner in inner_block {
                                if let Some(rule) = parse_filter_node(inner) {
                                    filters.push(rule);
                                }
                            }
                        }
                    } else if is_common_format_option(&node.name) {
                        apply_common_format_option(&mut obj, node);
                    } else if let Some(rule) = parse_filter_node(node) {
                        filters.push(rule);
                    }
                }
                obj["filters"] = serde_json::json!(filters);
            }
            "append" => {
                let mut fields = serde_json::Map::new();
                for node in block {
                    if node.name == "wrap" {
                        let wrap_type = node.args.first().cloned().unwrap_or_else(|| "json".into());
                        obj["wrap"] = serde_json::json!({ "format": wrap_type });
                    } else if node.name == "fields" {
                        if let Some(ref inner_block) = node.block {
                            for inner in inner_block {
                                if let Some(val) = inner.args.first() {
                                    fields.insert(inner.name.clone(), serde_json::json!(val));
                                }
                            }
                        }
                    } else if is_common_format_option(&node.name) {
                        apply_common_format_option(&mut obj, node);
                    } else if let Some(val) = node.args.first() {
                        fields.insert(node.name.clone(), serde_json::json!(val));
                    }
                }
                obj["fields"] = serde_json::Value::Object(fields);
            }
            _ => {
                // json, console, or custom
                for node in block {
                    if is_common_format_option(&node.name) {
                        apply_common_format_option(&mut obj, node);
                    }
                }
            }
        }
    }

    Ok(obj)
}

fn is_common_format_option(name: &str) -> bool {
    matches!(
        name,
        "message_key"
            | "level_key"
            | "time_key"
            | "name_key"
            | "caller_key"
            | "stacktrace_key"
            | "line_ending"
            | "time_format"
            | "time_local"
            | "duration_format"
            | "level_format"
    )
}

fn apply_common_format_option(obj: &mut serde_json::Value, node: &DirectiveNode) {
    if node.name == "time_local" {
        obj["time_local"] = serde_json::json!(true);
    } else if let Some(val) = node.args.first() {
        obj[node.name.clone()] = serde_json::json!(val);
    }
}

fn parse_filter_node(node: &DirectiveNode) -> Option<serde_json::Value> {
    let field = &node.name;
    let act_type = node.args.first()?.as_str();

    let mut rule = serde_json::json!({
        "field": field,
        "type": act_type,
    });

    match act_type {
        "delete" => {}
        "rename" => {
            if let Some(new_key) = node.args.get(1) {
                rule["key"] = serde_json::json!(new_key);
            }
        }
        "replace" => {
            if let Some(rep) = node.args.get(1) {
                rule["replacement"] = serde_json::json!(rep);
            }
        }
        "hash" => {}
        "regexp" => {
            if let Some(pat) = node.args.get(1) {
                rule["pattern"] = serde_json::json!(pat);
            }
            if let Some(rep) = node.args.get(2) {
                rule["replacement"] = serde_json::json!(rep);
            }
        }
        "ip_mask" => {
            let mut ipv4 = node.args.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(16);
            let mut ipv6 = node.args.get(2).and_then(|s| s.parse::<u8>().ok()).unwrap_or(32);
            if let Some(ref block) = node.block {
                for item in block {
                    if item.name == "ipv4" {
                        if let Some(v) = item.args.first().and_then(|s| s.parse::<u8>().ok()) {
                            ipv4 = v;
                        }
                    } else if item.name == "ipv6" {
                        if let Some(v) = item.args.first().and_then(|s| s.parse::<u8>().ok()) {
                            ipv6 = v;
                        }
                    }
                }
            }
            rule["ipv4"] = serde_json::json!(ipv4);
            rule["ipv6"] = serde_json::json!(ipv6);
        }
        "query" | "cookie" => {
            let mut actions = Vec::new();
            if let Some(ref block) = node.block {
                for act in block {
                    let atype = act.name.as_str();
                    let key = act.args.first().cloned().unwrap_or_default();
                    let val = act.args.get(1).cloned().unwrap_or_default();
                    actions.push(serde_json::json!({
                        "type": atype,
                        "key": key,
                        "name": key,
                        "value": val,
                    }));
                }
            }
            rule["actions"] = serde_json::json!(actions);
        }
        _ => return None,
    }

    Some(rule)
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

fn read_file_lines(path: &str) -> std::io::Result<Vec<String>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed.to_string());
        }
    }
    Ok(lines)
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

fn populate_named_matcher_item(set: &mut MatcherSet, name: &str, args: &[String]) {
    match name {
        "host" => {
            set.host = Some(args.to_vec());
        }
        "path" => {
            set.path = Some(args.to_vec());
        }
        "path_regexp" => {
            let item = if args.len() == 1 {
                RegexpMatcher {
                    name: None,
                    pattern: args[0].clone(),
                }
            } else if args.len() >= 2 {
                RegexpMatcher {
                    name: Some(args[0].clone()),
                    pattern: args[1].clone(),
                }
            } else {
                return;
            };
            let mut existing = set.path_regexp.take().unwrap_or_default();
            existing.push(item);
            set.path_regexp = Some(existing);
        }
        "method" => {
            let methods = args.iter().map(|m| m.to_uppercase()).collect();
            set.method = Some(methods);
        }
        "header" => {
            if args.len() >= 2 {
                let mut hdr = set.header.clone().unwrap_or_default();
                hdr.insert(args[0].clone(), vec![args[1].clone()]);
                set.header = Some(hdr);
            }
        }
        "header_regexp" => {
            if args.len() == 2 {
                let mut re_map = set.header_regexp.clone().unwrap_or_default();
                re_map.insert(args[0].clone(), RegexpMatcher {
                    name: None,
                    pattern: args[1].clone(),
                });
                set.header_regexp = Some(re_map);
            } else if args.len() >= 3 {
                let mut re_map = set.header_regexp.clone().unwrap_or_default();
                re_map.insert(args[1].clone(), RegexpMatcher {
                    name: Some(args[0].clone()),
                    pattern: args[2].clone(),
                });
                set.header_regexp = Some(re_map);
            }
        }
        "query" => {
            let mut q_map = set.query.clone().unwrap_or_default();
            for arg in args {
                if let Some((k, v)) = arg.split_once('=') {
                    q_map.entry(k.to_string()).or_default().push(v.to_string());
                } else if args.len() == 2 && q_map.is_empty() {
                    q_map.entry(args[0].clone()).or_default().push(args[1].clone());
                    break;
                }
            }
            set.query = Some(q_map);
        }
        "remote_ip" => {
            set.remote_ip = Some(RemoteIpMatcher {
                ranges: args.to_vec(),
            });
        }
        "client_ip" => {
            set.client_ip = Some(RemoteIpMatcher {
                ranges: args.to_vec(),
            });
        }
        "protocol" => {
            set.protocol = args.first().cloned();
        }
        "vars" => {
            if args.len() >= 2 {
                let mut vars = set.vars.clone().unwrap_or_default();
                vars.insert(args[0].clone(), args[1..].join(" "));
                set.vars = Some(vars);
            }
        }
        "vars_regexp" => {
            if args.len() == 2 {
                let mut vars_re = set.vars_regexp.clone().unwrap_or_default();
                vars_re.insert(args[0].clone(), args[1].clone());
                set.vars_regexp = Some(vars_re);
            } else if args.len() >= 3 {
                let mut vars_re = set.vars_regexp.clone().unwrap_or_default();
                vars_re.insert(args[1].clone(), args[2].clone());
                set.vars_regexp = Some(vars_re);
            }
        }
        "file" => {
            let mut file_cfg = set.file.clone().unwrap_or_default();
            if !args.is_empty() {
                file_cfg.try_files = args.to_vec();
            }
            set.file = Some(file_cfg);
        }
        "expression" => {
            set.expression = Some(args.join(" "));
        }
        _ => {}
    }
}

fn parse_named_matcher_block(dir: &DirectiveNode) -> ParseResult<MatcherSet> {
    let mut set = MatcherSet::default();
    if let Some(ref block) = dir.block {
        for sub in block {
            if sub.name == "not" {
                let inner = if let Some(ref not_block) = sub.block {
                    let mut inner_set = MatcherSet::default();
                    for inner_sub in not_block {
                        populate_named_matcher_item(&mut inner_set, inner_sub.name.as_str(), &inner_sub.args);
                    }
                    inner_set
                } else if !sub.args.is_empty() {
                    let mut inner_set = MatcherSet::default();
                    populate_named_matcher_item(&mut inner_set, sub.args[0].as_str(), &sub.args[1..]);
                    inner_set
                } else {
                    MatcherSet::default()
                };
                let mut existing_not = set.not.take().unwrap_or_default();
                existing_not.push(inner);
                set.not = Some(existing_not);
            } else if sub.name == "file" && sub.block.is_some() {
                let mut file_cfg = FileMatcherConfig::default();
                if let Some(ref fblock) = sub.block {
                    for fsub in fblock {
                        match fsub.name.as_str() {
                            "root" => file_cfg.root = fsub.args.first().cloned(),
                            "try_files" => file_cfg.try_files = fsub.args.clone(),
                            "split_path" => file_cfg.split_path = fsub.args.clone(),
                            _ => {}
                        }
                    }
                }
                set.file = Some(file_cfg);
            } else {
                populate_named_matcher_item(&mut set, sub.name.as_str(), &sub.args);
            }
        }
    } else if !dir.args.is_empty() {
        if dir.args[0].starts_with('/') {
            // Shorthand path matcher: @name /path1 /path2
            set.path = Some(dir.args.clone());
        } else if dir.args[0] == "not" {
            let mut inner_set = MatcherSet::default();
            if dir.args.len() > 1 {
                if dir.args[1].starts_with('/') {
                    inner_set.path = Some(dir.args[1..].to_vec());
                } else {
                    populate_named_matcher_item(&mut inner_set, dir.args[1].as_str(), &dir.args[2..]);
                }
            }
            set.not = Some(vec![inner_set]);
        } else {
            // Standard single-line matcher: @name matcher_type [args...]
            populate_named_matcher_item(&mut set, dir.args[0].as_str(), &dir.args[1..]);
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
        } else if first == "staging" || first == "dev" {
            policy.certificate_selection = Some(CertificateSelection {
                any_tag: Some(vec![format!("ca:{}", raddy_core::config::LETS_ENCRYPT_STAGING)]),
                all_tags: None,
                serial_number: None,
            });
        } else if first.contains('@') {
            policy.certificate_selection = Some(CertificateSelection {
                any_tag: Some(vec![format!("email:{}", first)]),
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
                "ca" => {
                    if let Some(ca_arg) = sub.args.first() {
                        let resolved = raddy_core::config::resolve_acme_ca(ca_arg);
                        let tags = policy.certificate_selection.get_or_insert_with(CertificateSelection::default);
                        let any_tag = tags.any_tag.get_or_insert_with(Vec::new);
                        any_tag.push(format!("ca:{}", resolved));
                    }
                }
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
    if let Some(ref pr) = src.path_regexp {
        let mut existing = dst.path_regexp.take().unwrap_or_default();
        existing.extend(pr.clone());
        dst.path_regexp = Some(existing);
    }
    if let Some(ref m) = src.method {
        dst.method = Some(m.clone());
    }
    if let Some(ref hdr) = src.header {
        let mut existing = dst.header.take().unwrap_or_default();
        existing.extend(hdr.clone());
        dst.header = Some(existing);
    }
    if let Some(ref hdr_re) = src.header_regexp {
        let mut existing = dst.header_regexp.take().unwrap_or_default();
        existing.extend(hdr_re.clone());
        dst.header_regexp = Some(existing);
    }
    if let Some(ref q) = src.query {
        let mut existing = dst.query.take().unwrap_or_default();
        existing.extend(q.clone());
        dst.query = Some(existing);
    }
    if let Some(ref ip) = src.remote_ip {
        dst.remote_ip = Some(ip.clone());
    }
    if let Some(ref ip) = src.client_ip {
        dst.client_ip = Some(ip.clone());
    }
    if let Some(ref proto) = src.protocol {
        dst.protocol = Some(proto.clone());
    }
    if let Some(ref v) = src.vars {
        let mut existing = dst.vars.take().unwrap_or_default();
        existing.extend(v.clone());
        dst.vars = Some(existing);
    }
    if let Some(ref vr) = src.vars_regexp {
        let mut existing = dst.vars_regexp.take().unwrap_or_default();
        existing.extend(vr.clone());
        dst.vars_regexp = Some(existing);
    }
    if let Some(ref f) = src.file {
        dst.file = Some(f.clone());
    }
    if let Some(ref n) = src.not {
        let mut existing = dst.not.take().unwrap_or_default();
        existing.extend(n.clone());
        dst.not = Some(existing);
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

    #[test]
    fn test_adapt_log_with_rolling_and_sampling() {
        let input = r#"
example.com {
    log {
        output file /var/log/access.log {
            roll_size 50mb
            roll_keep 5
            roll_keep_for 720h
            roll_uncompressed
            roll_local_time
            mode 0640
        }
        format json {
            time_format rfc3339
            time_local
            duration_format ms
        }
        sampling {
            interval 2s
            first 10
            thereafter 5
        }
    }
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        let logging = config.logging.as_ref().unwrap();
        let log0 = logging.logs.get("log0").unwrap();

        let writer = log0.writer.as_ref().unwrap();
        assert_eq!(writer.get("output"), Some(&serde_json::json!("file")));
        assert_eq!(writer.get("filename"), Some(&serde_json::json!("/var/log/access.log")));
        assert_eq!(writer.get("roll_size"), Some(&serde_json::json!("50mb")));
        assert_eq!(writer.get("roll_keep"), Some(&serde_json::json!("5")));
        assert_eq!(writer.get("roll_keep_for"), Some(&serde_json::json!("720h")));
        assert_eq!(writer.get("roll_uncompressed"), Some(&serde_json::json!(true)));
        assert_eq!(writer.get("roll_local_time"), Some(&serde_json::json!(true)));
        assert_eq!(writer.get("mode"), Some(&serde_json::json!("0640")));

        let encoder = log0.encoder.as_ref().unwrap();
        assert_eq!(encoder.get("format"), Some(&serde_json::json!("json")));
        assert_eq!(encoder.get("time_format"), Some(&serde_json::json!("rfc3339")));
        assert_eq!(encoder.get("time_local"), Some(&serde_json::json!(true)));
        assert_eq!(encoder.get("duration_format"), Some(&serde_json::json!("ms")));

        let sampling = log0.sampling.as_ref().unwrap();
        assert_eq!(sampling.interval.as_deref(), Some("2s"));
        assert_eq!(sampling.first, Some(10));
        assert_eq!(sampling.thereafter, Some(5));
    }

    #[test]
    fn test_adapt_log_filter_and_append() {
        let input = r#"
example.com {
    log {
        format filter {
            request>headers>User-Agent delete
            request>remote_ip ip_mask 16 32
            request>uri query {
                delete secret
                replace token REDACTED
            }
            request>headers>Cookie cookie {
                replace session SESS_REDACTED
            }
            wrap json
        }
    }
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        let logging = config.logging.as_ref().unwrap();
        let log0 = logging.logs.get("log0").unwrap();

        let encoder = log0.encoder.as_ref().unwrap();
        assert_eq!(encoder.get("format"), Some(&serde_json::json!("filter")));
        assert_eq!(encoder.get("wrap"), Some(&serde_json::json!({ "format": "json" })));

        let filters = encoder.get("filters").and_then(|v| v.as_array()).unwrap();
        assert_eq!(filters.len(), 4);
        assert_eq!(filters[0].get("field"), Some(&serde_json::json!("request>headers>User-Agent")));
        assert_eq!(filters[0].get("type"), Some(&serde_json::json!("delete")));

        assert_eq!(filters[1].get("field"), Some(&serde_json::json!("request>remote_ip")));
        assert_eq!(filters[1].get("type"), Some(&serde_json::json!("ip_mask")));
        assert_eq!(filters[1].get("ipv4"), Some(&serde_json::json!(16)));
        assert_eq!(filters[1].get("ipv6"), Some(&serde_json::json!(32)));

        assert_eq!(filters[2].get("field"), Some(&serde_json::json!("request>uri")));
        assert_eq!(filters[2].get("type"), Some(&serde_json::json!("query")));

        assert_eq!(filters[3].get("field"), Some(&serde_json::json!("request>headers>Cookie")));
        assert_eq!(filters[3].get("type"), Some(&serde_json::json!("cookie")));
    }

    #[test]
    fn test_adapt_multiple_logs_hostnames_and_no_hostname() {
        let input = r#"
{
    log_credentials
}

*.example.com {
    log {
        hostnames foo.example.com
        output file /var/log/foo.log
    }
    log {
        hostnames bar.example.com
        output file /var/log/bar.log
    }
    log custom_logger {
        no_hostname
        output file /var/log/custom.log
    }
    log_skip /health
    log_append cluster us-east-1
    log_name @api custom_logger
}
"#;
        let tokens = Lexer::new(input).tokenize().unwrap();
        let caddyfile = Parser::new(tokens).parse().unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&caddyfile).unwrap();

        let logging = config.logging.as_ref().unwrap();
        assert!(logging.logs.contains_key("log0"));
        assert!(logging.logs.contains_key("log1"));
        assert!(logging.logs.contains_key("custom_logger"));

        let http = config.http_app().unwrap();
        let srv = http.servers.get("srv_:443").unwrap();
        let srv_logs = srv.logs.as_ref().unwrap();

        assert_eq!(srv_logs.log_credentials, Some(true));
        let logger_names = srv_logs.logger_names.as_ref().unwrap();
        assert_eq!(logger_names.get("foo.example.com"), Some(&"log0".to_string()));
        assert_eq!(logger_names.get("bar.example.com"), Some(&"log1".to_string()));
        // custom_logger had no_hostname, so it shouldn't be mapped directly
        assert_ne!(logger_names.get("*.example.com"), Some(&"custom_logger".to_string()));

        // Check routes have log_skip, log_append, log_name handlers
        let handlers: Vec<&str> = srv.routes.iter().flat_map(|r| r.handle.iter()).map(|h| h.handler.as_str()).collect();
        assert!(handlers.contains(&"log_skip"));
        assert!(handlers.contains(&"log_append"));
        assert!(handlers.contains(&"log_name"));
    }
}
