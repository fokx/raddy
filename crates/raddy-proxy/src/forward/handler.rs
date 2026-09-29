use std::collections::HashMap;
use std::time::Duration;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use raddy_core::context::Context;
use raddy_core::error::{CoreError, Result as CoreResult};
use raddy_core::handler::Handler;
use serde::{Deserialize, Serialize};

use super::acl::{default_acl_suffix_rules, new_acl_rule, AclRule, AclRuleConfig};
use super::auth::{AuthConfig, AuthError};
use super::upstream::{dial_target, UpstreamProxy};

const HIDDEN_PAGE: &str = "<html>\n<head>\n  <title>Hidden Proxy Page</title>\n</head>\n<body>\n<h1>Hidden Proxy Page!</h1>\n{}<br/>\n</body>\n</html>";
const AUTH_FAIL: &str = "Please authenticate yourself to the proxy.";
const AUTH_OK: &str = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!";

const PAC_TEMPLATE: &str = "\nfunction FindProxyForURL(url, host) {\n\tif (host === \"127.0.0.1\" || host === \"::1\" || host === \"localhost\")\n\t\treturn \"DIRECT\";\n\treturn \"HTTPS {}\";\n}\n";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForwardProxyConfig {
    pub pac_path: Option<String>,
    #[serde(default)]
    pub hide_ip: bool,
    #[serde(default)]
    pub hide_via: bool,
    #[serde(default)]
    pub disable_insecure_upstreams_check: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub probe_resistance: Option<ProbeResistanceConfig>,
    pub dial_timeout: Option<String>,
    pub max_idle_conns: Option<i64>,
    pub max_idle_conns_per_host: Option<i64>,
    pub upstream: Option<String>,
    pub acl: Option<Vec<AclRuleConfig>>,
    pub allowed_ports: Option<Vec<u16>>,
    pub auth_credentials: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbeResistanceConfig {
    pub domain: Option<String>,
}

pub struct ForwardProxyHandler {
    pub pac_path: Option<String>,
    pub hide_ip: bool,
    pub hide_via: bool,
    pub disable_insecure_upstreams_check: bool,
    pub hosts: Vec<String>,
    pub probe_resistance_domain: Option<String>,
    pub has_probe_resistance: bool,
    pub dial_timeout: Duration,
    pub max_idle_conns: usize,
    pub max_idle_conns_per_host: usize,
    pub upstream: Option<UpstreamProxy>,
    pub allowed_ports: Vec<u16>,
    pub acl_rules: Vec<AclRule>,
    pub auth: Option<AuthConfig>,
}

impl ForwardProxyHandler {
    pub fn from_config(details: &HashMap<String, serde_json::Value>) -> CoreResult<Self> {
        let pac_path = details
            .get("pac_path")
            .and_then(|v| v.as_str())
            .map(|s| if s.starts_with('/') { s.to_string() } else { format!("/{}", s) });

        let hide_ip = details.get("hide_ip").and_then(|v| v.as_bool()).unwrap_or(false);
        let hide_via = details.get("hide_via").and_then(|v| v.as_bool()).unwrap_or(false);
        let disable_insecure_upstreams_check = details
            .get("disable_insecure_upstreams_check")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let hosts = details
            .get("hosts")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let mut has_probe_resistance = false;
        let mut probe_resistance_domain = None;
        if let Some(val) = details.get("probe_resistance") {
            has_probe_resistance = true;
            if let Some(obj) = val.as_object() {
                probe_resistance_domain = obj
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            } else if let Some(s) = val.as_str() {
                probe_resistance_domain = Some(s.to_string());
            }
        }

        let dial_timeout = if let Some(val) = details.get("dial_timeout").and_then(|v| v.as_str()) {
            parse_duration(val).unwrap_or(Duration::from_secs(30))
        } else {
            Duration::from_secs(30)
        };

        let max_idle_conns = details
            .get("max_idle_conns")
            .and_then(|v| v.as_i64())
            .map(|v| if v <= 0 { 0 } else { v as usize })
            .unwrap_or(50);

        let max_idle_conns_per_host = details
            .get("max_idle_conns_per_host")
            .and_then(|v| v.as_i64())
            .map(|v| if v <= 0 { 0 } else { v as usize })
            .unwrap_or(2);

        let upstream = if let Some(u_str) = details.get("upstream").and_then(|v| v.as_str()) {
            Some(UpstreamProxy::parse(u_str, disable_insecure_upstreams_check).map_err(|e| {
                CoreError::Config(format!("Failed to parse upstream proxy URL: {}", e))
            })?)
        } else {
            None
        };

        let allowed_ports = details
            .get("ports")
            .or_else(|| details.get("allowed_ports"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|p| p as u16))
                    .collect()
            })
            .unwrap_or_default();

        let mut auth = None;
        if let Some(creds) = details.get("auth_credentials").and_then(|v| v.as_array()) {
            let cred_list: Vec<String> = creds
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if !cred_list.is_empty() {
                auth = Some(AuthConfig::new(cred_list));
            }
        }

        if has_probe_resistance && auth.is_none() {
            return Err(CoreError::Config("probe resistance requires authentication".into()));
        }

        let mut acl_rules = Vec::new();
        if let Some(arr) = details.get("acl").and_then(|v| v.as_array()) {
            for item in arr {
                let allow = item.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
                if let Some(subjects) = item.get("subjects").and_then(|v| v.as_array()) {
                    for subj in subjects {
                        if let Some(s) = subj.as_str() {
                            let rule = new_acl_rule(s, allow).map_err(|e| {
                                CoreError::Config(format!("Invalid ACL rule subject '{}': {}", s, e))
                            })?;
                            acl_rules.push(rule);
                        }
                    }
                }
            }
        }
        acl_rules.extend(default_acl_suffix_rules());

        Ok(Self {
            pac_path,
            hide_ip,
            hide_via,
            disable_insecure_upstreams_check,
            hosts,
            probe_resistance_domain,
            has_probe_resistance,
            dial_timeout,
            max_idle_conns,
            max_idle_conns_per_host,
            upstream,
            allowed_ports,
            acl_rules,
            auth,
        })
    }

    fn should_serve_pac(&self, ctx: &Context) -> bool {
        if let Some(ref pac) = self.pac_path {
            let path = ctx.uri.path();
            path == pac || (pac == "/proxy.pac" && path == "/proxy.pac")
        } else {
            false
        }
    }

    fn serve_pac(&self, ctx: &mut Context) {
        let host_port = ctx
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost")
            .to_string();

        let body = PAC_TEMPLATE.replace("{}", &host_port);
        ctx.response_headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
        );
        ctx.set_response(StatusCode::OK, body);
    }
}

#[async_trait]
impl Handler for ForwardProxyHandler {
    async fn handle(&self, ctx: &mut Context) -> CoreResult<()> {
        let req_host = ctx
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(':').next().unwrap_or(s).to_string())
            .or_else(|| ctx.uri.host().map(|h| h.to_string()))
            .unwrap_or_default();

        // 1. Check Authentication if configured
        let mut auth_err = None;
        if let Some(ref auth) = self.auth {
            let auth_res = auth.check(ctx.headers.get("proxy-authorization"));
            match auth_res {
                Ok(ref username) => {
                    ctx.set_var("http.auth.user.id", username.clone());
                }
                Err(e) => {
                    match e {
                        AuthError::InvalidCredentials(Some(ref u)) => {
                            ctx.set_var("http.auth.user.id", format!("invalid:{}", u));
                        }
                        AuthError::InvalidBase64 => {
                            ctx.set_var("http.auth.user.id", "invalidbase64");
                        }
                        _ => {
                            ctx.set_var("http.auth.user.id", "invalid::");
                        }
                    }
                    auth_err = Some(e);
                }
            }
        }

        // 2. PAC file check
        if self.should_serve_pac(ctx) {
            self.serve_pac(ctx);
            return Ok(());
        }

        // 3. Probe Resistance check
        if self.has_probe_resistance {
            if let Some(ref secret_domain) = self.probe_resistance_domain {
                if req_host.eq_ignore_ascii_case(secret_domain) {
                    ctx.response_headers.insert(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/html"),
                    );
                    if auth_err.is_some() {
                        ctx.response_headers.insert(
                            http::header::HeaderName::from_static("proxy-authenticate"),
                            HeaderValue::from_static("Basic realm=\"Caddy Secure Web Proxy\""),
                        );
                        ctx.set_response(
                            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                            HIDDEN_PAGE.replace("{}", AUTH_FAIL),
                        );
                    } else {
                        ctx.set_response(StatusCode::OK, HIDDEN_PAGE.replace("{}", AUTH_OK));
                    }
                    return Ok(());
                }
            }

            // Probe resistance is enabled and requested host does NOT match secret domain:
            // If auth failed, pass through to next handler (act as if proxy does not exist)!
            if auth_err.is_some() {
                return Ok(());
            }
        }

        // 4. Origin host request check (pass through non-proxy requests destined for site itself)
        let is_matching_host = !self.hosts.is_empty()
            && self.hosts.iter().any(|h| h.eq_ignore_ascii_case(&req_host));

        let is_origin_request = is_matching_host
            || (self.hosts.is_empty()
                && ctx.method != Method::CONNECT
                && ctx.uri.scheme().is_none()
                && !ctx.headers.contains_key("proxy-authorization")
                && ctx.uri.host().is_none());

        if is_origin_request && (ctx.method != Method::CONNECT || auth_err.is_some()) {
            return Ok(());
        }

        // 5. Reject with 407 if authentication failed and not probe-resistant passthrough
        if auth_err.is_some() {
            ctx.response_headers.insert(
                http::header::HeaderName::from_static("proxy-authenticate"),
                HeaderValue::from_static("Basic realm=\"Caddy Secure Web Proxy\""),
            );
            ctx.set_response(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "407 Proxy Authentication Required\n",
            );
            return Ok(());
        }

        // 6. Handle CONNECT method
        if ctx.method == Method::CONNECT {
            let host_port_str = if let Some(auth) = ctx.uri.authority() {
                auth.as_str().to_string()
            } else if let Some(h) = ctx.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()) {
                h.to_string()
            } else {
                ctx.uri.to_string()
            };

            let (target_host, target_port) = match host_port_str.split_once(':') {
                Some((h, p)) => {
                    let port_num = p.parse::<u16>().unwrap_or(443);
                    (h.to_string(), port_num)
                }
                None => (host_port_str, 443),
            };

            // Dial target or upstream proxy
            let mut target_stream = match dial_target(
                &target_host,
                target_port,
                self.dial_timeout,
                &self.allowed_ports,
                &self.acl_rules,
                self.upstream.as_ref(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("not allowed") || err_str.contains("disallowed") {
                        ctx.set_response(StatusCode::FORBIDDEN, format!("403 Forbidden: {}\n", e));
                    } else {
                        ctx.set_response(StatusCode::BAD_GATEWAY, format!("502 Bad Gateway: {}\n", e));
                    }
                    return Ok(());
                }
            };

            // Retrieve upgrade receiver
            let on_upgrade = ctx.remove_extension::<hyper::upgrade::OnUpgrade>();

            // Respond 200 OK to complete CONNECT handshake
            ctx.set_response(StatusCode::OK, Bytes::new());
            ctx.response_headers.remove(http::header::CONTENT_LENGTH);

            if let Some(upgrade) = on_upgrade {
                tokio::spawn(async move {
                    match upgrade.await {
                        Ok(upgraded) => {
                            let mut client_io = TokioIo::new(upgraded);
                            let _ = tokio::io::copy_bidirectional(&mut client_io, &mut target_stream).await;
                        }
                        Err(e) => {
                            tracing::debug!("CONNECT upgrade failed: {}", e);
                        }
                    }
                });
            }

            return Ok(());
        }

        // 7. Handle standard HTTP request forwarding (GET, POST, etc.)
        let target_host = ctx
            .uri
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                ctx.headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(':').next().unwrap_or(s).to_string())
            })
            .unwrap_or_else(|| req_host.clone());

        let target_port = ctx
            .uri
            .port_u16()
            .or_else(|| {
                ctx.headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(':').nth(1))
                    .and_then(|p| p.parse().ok())
            })
            .unwrap_or(80);

        let target_stream = match dial_target(
            &target_host,
            target_port,
            self.dial_timeout,
            &self.allowed_ports,
            &self.acl_rules,
            self.upstream.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("not allowed") || err_str.contains("disallowed") {
                    ctx.set_response(StatusCode::FORBIDDEN, format!("403 Forbidden: {}\n", e));
                } else {
                    ctx.set_response(StatusCode::BAD_GATEWAY, format!("502 Bad Gateway: {}\n", e));
                }
                return Ok(());
            }
        };

        // Prepare request headers (remove hop-by-hop, add Forwarded and Via)
        let mut req_headers = ctx.headers.clone();
        remove_hop_by_hop(&mut req_headers);

        if !self.hide_ip {
            if let Some(remote) = ctx.remote_addr {
                let fwd_val = format!("for=\"{}\"", remote.ip());
                if let Ok(v) = HeaderValue::try_from(fwd_val) {
                    req_headers.insert("forwarded", v);
                }
            }
        }

        if !self.hide_via {
            req_headers.insert("via", HeaderValue::from_static("1.1 caddy"));
        }

        if let Some(ref ups) = self.upstream {
            if let Some(ref auth) = ups.auth_header {
                if let Ok(v) = HeaderValue::try_from(auth.as_str()) {
                    req_headers.insert("proxy-authorization", v);
                }
            }
        }

        // Send HTTP request to target or upstream
        let io = TokioIo::new(target_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| CoreError::Handler(format!("Upstream HTTP handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("Upstream connection closed: {}", e);
            }
        });

        // Determine path and query to send
        let uri_path = ctx.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let mut req_builder = http::Request::builder()
            .method(ctx.method.clone())
            .uri(uri_path);

        let mut has_host = false;
        for (k, v) in req_headers {
            if let Some(name) = k {
                if name == http::header::HOST {
                    has_host = true;
                }
                req_builder = req_builder.header(name, v);
            }
        }
        if !has_host {
            let host_header = if target_port == 80 {
                target_host.clone()
            } else {
                format!("{}:{}", target_host, target_port)
            };
            req_builder = req_builder.header(http::header::HOST, host_header);
        }

        let upstream_req = req_builder
            .body(Full::new(ctx.body.clone()))
            .map_err(|e| CoreError::Handler(e.to_string()))?;

        let resp = sender
            .send_request(upstream_req)
            .await
            .map_err(|e| CoreError::Handler(format!("Upstream request failed: {}", e)))?;

        let (resp_parts, resp_body) = resp.into_parts();
        let body_bytes = resp_body
            .collect()
            .await
            .map_err(|e| CoreError::Handler(format!("Failed to read response body: {}", e)))?
            .to_bytes();

        let mut resp_headers = resp_parts.headers;
        remove_hop_by_hop(&mut resp_headers);
        resp_headers.remove(http::header::SERVER);

        if !self.hide_via {
            resp_headers.insert("via", HeaderValue::from_static("1.1 caddy"));
        }

        ctx.status = Some(resp_parts.status);
        ctx.response_headers = resp_headers;
        ctx.response_body = Some(body_bytes);
        ctx.response_written = true;

        Ok(())
    }
}

pub fn remove_hop_by_hop(headers: &mut HeaderMap) {
    if let Some(conn_val) = headers.get(http::header::CONNECTION) {
        if let Ok(s) = conn_val.to_str() {
            let to_remove: Vec<String> = s.split(',').map(|x| x.trim().to_lowercase()).collect();
            for h in to_remove {
                headers.remove(&h);
            }
        }
    }

    let hop_headers = [
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "upgrade",
        "connection",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
    ];

    for h in hop_headers {
        headers.remove(h);
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        num.parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(num) = s.strip_suffix('s') {
        num.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(num) = s.strip_suffix('h') {
        num.parse::<u64>().ok().map(|h| Duration::from_secs(h * 3600))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}
