use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root configuration model, matching Caddy's native JSON configuration layout.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingConfig>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub apps: HashMap<String, serde_json::Value>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn http_app(&self) -> Option<HttpApp> {
        self.apps
            .get("http")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn set_http_app(&mut self, app: HttpApp) -> Result<(), serde_json::Error> {
        let val = serde_json::to_value(app)?;
        self.apps.insert("http".to_string(), val);
        Ok(())
    }
}

/// Admin API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AdminConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_origin: Option<bool>,
}

/// Global logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LoggingConfig {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub logs: HashMap<String, LogConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LogConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoder: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

/// HTTP App configuration containing servers.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HttpApp {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub servers: HashMap<String, HttpServer>,
}

/// HTTP Server definition.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HttpServer {
    #[serde(default)]
    pub listen: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_connection_policies: Option<Vec<TlsConnectionPolicy>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatic_https: Option<AutoHttpsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<ServerLogConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ServerLogConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_logger_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger_names: Option<HashMap<String, String>>,
}

/// A Route maps request matchers to a sequence of handlers.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Route {
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub r#match: Option<Vec<MatcherSet>>,

    #[serde(default)]
    pub handle: Vec<HandlerConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// MatcherSet contains one or more matchers evaluated in conjunction (AND).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MatcherSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_regexp: Option<Vec<RegexpMatcher>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<HashMap<String, Vec<String>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_regexp: Option<HashMap<String, RegexpMatcher>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, Vec<String>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<RemoteIpMatcher>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub not: Option<Vec<MatcherSet>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RegexpMatcher {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RemoteIpMatcher {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<String>,
}

/// Configuration for an HTTP handler inside a route.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HandlerConfig {
    pub handler: String,

    #[serde(flatten)]
    pub details: HashMap<String, serde_json::Value>,
}

impl HandlerConfig {
    pub fn new(handler: impl Into<String>) -> Self {
        Self {
            handler: handler.into(),
            details: HashMap::new(),
        }
    }

    pub fn with_field(mut self, key: impl Into<String>, val: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(val) {
            self.details.insert(key.into(), v);
        }
        self
    }
}

/// TLS Connection Policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TlsConnectionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#match: Option<TlsConnectionMatch>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_selection: Option<CertificateSelection>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub curves: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_min: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_max: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TlsConnectionMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CertificateSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_tag: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
}

/// Automatic HTTPS configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AutoHttpsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_certificates: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_redirects: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_certificates: Option<Vec<String>>,
}
