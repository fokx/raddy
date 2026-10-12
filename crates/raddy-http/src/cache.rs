use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, SystemTime};

/// Default cache TTL (120 seconds matching caddyserver/cache-handler & Souin).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(120);

/// Global shared cache pools across reloads.
static GLOBAL_CACHE_POOLS: LazyLock<Mutex<HashMap<String, Arc<CacheStoragePool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Returns or initializes a named cache storage pool.
pub fn get_or_create_cache_pool(
    name: &str,
    storage_config: &CacheStorageConfig,
    default_ttl: Duration,
) -> Arc<CacheStoragePool> {
    let mut pools = GLOBAL_CACHE_POOLS.lock().unwrap();
    if let Some(pool) = pools.get(name) {
        pool.clone()
    } else {
        let pool = Arc::new(CacheStoragePool::new(name, storage_config, default_ttl));
        pools.insert(name.to_string(), pool.clone());
        pool
    }
}

/// Cache key options configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CacheKeyConfig {
    #[serde(default)]
    pub disable_body: bool,
    #[serde(default)]
    pub disable_host: bool,
    #[serde(default)]
    pub disable_method: bool,
    #[serde(default)]
    pub disable_query: bool,
    #[serde(default)]
    pub disable_scheme: bool,
    #[serde(default)]
    pub sort_query: bool,
    #[serde(default)]
    pub hash: bool,
    #[serde(default)]
    pub hide: bool,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub template: Option<String>,
}

/// Cache storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CacheStorageConfig {
    /// In-memory storage (default)
    #[serde(default)]
    pub in_memory: bool,
    /// Badger / Nuts / SimpleFS / filesystem path
    pub path: Option<String>,
    /// Redis url
    pub redis_url: Option<String>,
}

/// Route-level or pattern-level cache override rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CacheKeyRule {
    pub pattern: String,
    pub key: CacheKeyConfig,
}

/// Comprehensive Cache Handler configuration matching caddyserver/cache-handler & Souin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheConfig {
    /// Cache name identifier (used in Cache-Status header, defaults to "Souin" or "raddy-cache")
    #[serde(default = "default_cache_name")]
    pub cache_name: String,

    /// Default TTL for cached entries
    #[serde(default = "default_ttl_duration")]
    pub ttl: Duration,

    /// Stale-while-revalidate duration
    #[serde(default)]
    pub stale: Duration,

    /// Allowed HTTP verbs (defaults to GET, HEAD)
    #[serde(default = "default_allowed_methods")]
    pub allowed_http_verbs: Vec<String>,

    /// Additional allowed HTTP status codes to cache
    #[serde(default)]
    pub allowed_additional_status_codes: Vec<u16>,

    /// Default Cache-Control header to assume if upstream provides none
    pub default_cache_control: Option<String>,

    /// Maximum body size in bytes eligible for caching (0 = unlimited)
    #[serde(default)]
    pub max_cacheable_body_bytes: usize,

    /// Mode: "strict", "bypass", etc.
    #[serde(default)]
    pub mode: Option<String>,

    /// Regex exclude pattern
    pub regex_exclude: Option<String>,

    /// Global / default cache key generation rules
    #[serde(default)]
    pub key: CacheKeyConfig,

    /// Path / URL specific cache key rules
    #[serde(default)]
    pub cache_keys: Vec<CacheKeyRule>,

    /// Storage provider configuration
    #[serde(default)]
    pub storage: CacheStorageConfig,

    /// Request headers always included in cache key
    #[serde(default)]
    pub headers: Vec<String>,
}

fn default_cache_name() -> String {
    "Souin".to_string()
}

fn default_ttl_duration() -> Duration {
    DEFAULT_CACHE_TTL
}

fn default_allowed_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_name: default_cache_name(),
            ttl: default_ttl_duration(),
            stale: Duration::ZERO,
            allowed_http_verbs: default_allowed_methods(),
            allowed_additional_status_codes: Vec::new(),
            default_cache_control: None,
            max_cacheable_body_bytes: 0,
            mode: None,
            regex_exclude: None,
            key: CacheKeyConfig::default(),
            cache_keys: Vec::new(),
            storage: CacheStorageConfig::default(),
            headers: Vec::new(),
        }
    }
}

/// Cached HTTP response entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stored_at: u64, // Unix timestamp in seconds
    pub ttl_secs: u64,
    pub stale_secs: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl CachedResponse {
    pub fn is_fresh(&self, now: u64) -> bool {
        now <= self.stored_at + self.ttl_secs
    }

    pub fn is_stale_allowed(&self, now: u64) -> bool {
        now <= self.stored_at + self.ttl_secs + self.stale_secs
    }

    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.stored_at)
    }
}

/// Backing storage pool for cached responses.
pub struct CacheStoragePool {
    pub name: String,
    pub storage_config: CacheStorageConfig,
    pub memory_store: RwLock<HashMap<String, CachedResponse>>,
    pub disk_path: Option<PathBuf>,
}

impl CacheStoragePool {
    pub fn new(name: &str, storage_config: &CacheStorageConfig, _default_ttl: Duration) -> Self {
        let disk_path = storage_config.path.as_ref().map(|p| {
            let pb = PathBuf::from(p);
            if let Err(e) = fs::create_dir_all(&pb) {
                tracing::warn!("Failed to create cache storage directory {:?}: {}", pb, e);
            }
            pb
        });

        Self {
            name: name.to_string(),
            storage_config: storage_config.clone(),
            memory_store: RwLock::new(HashMap::new()),
            disk_path,
        }
    }

    pub fn get(&self, key: &str) -> Option<CachedResponse> {
        // 1. Check in-memory store
        if let Some(entry) = self.memory_store.read().unwrap().get(key).cloned() {
            return Some(entry);
        }

        // 2. Check disk store if configured
        if let Some(ref dir) = self.disk_path {
            let file_name = sanitize_key_for_filename(key);
            let file_path = dir.join(&file_name);
            if file_path.exists() {
                if let Ok(data) = fs::read(&file_path) {
                    if let Ok(entry) = serde_json::from_slice::<CachedResponse>(&data) {
                        // Populate memory cache
                        self.memory_store
                            .write()
                            .unwrap()
                            .insert(key.to_string(), entry.clone());
                        return Some(entry);
                    }
                }
            }
        }

        None
    }

    pub fn set(&self, key: &str, entry: CachedResponse) {
        if let Some(ref dir) = self.disk_path {
            let file_name = sanitize_key_for_filename(key);
            let file_path = dir.join(&file_name);
            if let Ok(data) = serde_json::to_vec(&entry) {
                let _ = fs::write(file_path, data);
            }
        }

        self.memory_store
            .write()
            .unwrap()
            .insert(key.to_string(), entry);
    }

    pub fn delete(&self, key: &str) -> bool {
        let mem_removed = self.memory_store.write().unwrap().remove(key).is_some();
        let mut disk_removed = false;
        if let Some(ref dir) = self.disk_path {
            let file_name = sanitize_key_for_filename(key);
            let file_path = dir.join(file_name);
            if file_path.exists() {
                disk_removed = fs::remove_file(file_path).is_ok();
            }
        }
        mem_removed || disk_removed
    }

    pub fn clear(&self) {
        self.memory_store.write().unwrap().clear();
        if let Some(ref dir) = self.disk_path {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    pub fn keys(&self) -> Vec<String> {
        self.memory_store.read().unwrap().keys().cloned().collect()
    }
}

fn sanitize_key_for_filename(key: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash = hasher.finish();
    let sanitized: String = key
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(32)
        .collect();
    format!("{}_{:x}.cache", sanitized, hash)
}

/// Compiled rule for route regex matching.
#[derive(Clone)]
struct CompiledCacheKeyRule {
    regex: Regex,
    key: CacheKeyConfig,
}

/// Cache Middleware Handler implementing caddyserver/cache-handler parity.
#[derive(Clone)]
pub struct CacheHandler {
    pub config: CacheConfig,
    pub pool: Arc<CacheStoragePool>,
    compiled_exclude: Option<Regex>,
    compiled_cache_keys: Vec<CompiledCacheKeyRule>,
}

impl CacheHandler {
    pub fn new(config: CacheConfig) -> Self {
        let pool =
            get_or_create_cache_pool(&config.cache_name, &config.storage, config.ttl);

        let compiled_exclude = config
            .regex_exclude
            .as_ref()
            .and_then(|pat| Regex::new(pat).ok());

        let mut compiled_cache_keys = Vec::new();
        for rule in &config.cache_keys {
            if let Ok(re) = Regex::new(&rule.pattern) {
                compiled_cache_keys.push(CompiledCacheKeyRule {
                    regex: re,
                    key: rule.key.clone(),
                });
            }
        }

        Self {
            config,
            pool,
            compiled_exclude,
            compiled_cache_keys,
        }
    }

    /// Generates a cache key based on the request Context and matching CacheKeyConfig.
    pub fn generate_cache_key(&self, ctx: &Context) -> String {
        let uri_path = ctx.uri.path();

        // Check if path matches any specific cache_keys rules
        let key_cfg = self
            .compiled_cache_keys
            .iter()
            .find(|r| r.regex.is_match(uri_path))
            .map(|r| &r.key)
            .unwrap_or(&self.config.key);

        // 1. Method (HEAD shares cache entry with GET per RFC 7234/9111)
        let method = if key_cfg.disable_method {
            String::new()
        } else if ctx.method == Method::HEAD {
            "GET".to_string()
        } else {
            ctx.method.as_str().to_string()
        };

        // 2. Scheme
        let scheme = if key_cfg.disable_scheme {
            String::new()
        } else {
            ctx.uri
                .scheme_str()
                .unwrap_or_else(|| {
                    if ctx.tls_server_name.is_some() {
                        "https"
                    } else {
                        "http"
                    }
                })
                .to_string()
        };

        // 3. Host
        let host = if key_cfg.disable_host {
            String::new()
        } else {
            ctx.headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| ctx.uri.host())
                .unwrap_or("")
                .to_string()
        };

        // 4. Path & Query
        let path = ctx.uri.path();
        let query = if key_cfg.disable_query {
            String::new()
        } else if let Some(q) = ctx.uri.query() {
            if key_cfg.sort_query {
                let mut params: Vec<&str> = q.split('&').collect();
                params.sort();
                format!("?{}", params.join("&"))
            } else {
                format!("?{}", q)
            }
        } else {
            String::new()
        };

        // 5. Headers to vary on
        let mut header_parts = Vec::new();
        let mut check_headers = self.config.headers.clone();
        check_headers.extend(key_cfg.headers.clone());
        check_headers.sort();
        check_headers.dedup();

        for h in check_headers {
            if let Some(val) = ctx.headers.get(&h).and_then(|v| v.to_str().ok()) {
                header_parts.push(format!("{}:{}", h.to_lowercase(), val));
            }
        }

        // 6. Body hash if not disabled and not empty
        let body_part = if key_cfg.disable_body || ctx.body.is_empty() {
            String::new()
        } else {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            ctx.body.hash(&mut hasher);
            format!("body:{:x}", hasher.finish())
        };

        let raw_key = format!(
            "{}|{}|{}|{}{}|{}|{}",
            method,
            scheme,
            host,
            path,
            query,
            header_parts.join(";"),
            body_part
        );

        if key_cfg.hash {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            raw_key.hash(&mut hasher);
            format!("{:x}", hasher.finish())
        } else {
            raw_key
        }
    }

    /// Determines if the incoming request is eligible to be looked up in or cached.
    pub fn is_request_cacheable(&self, ctx: &Context) -> bool {
        // Mode bypass
        if let Some(ref m) = self.config.mode {
            if m.eq_ignore_ascii_case("bypass") {
                return false;
            }
        }

        // Method check (default GET, HEAD)
        let method = ctx.method.as_str();
        if !self
            .config
            .allowed_http_verbs
            .iter()
            .any(|v| v.eq_ignore_ascii_case(method))
        {
            return false;
        }

        // Regex exclude check
        if let Some(ref re) = self.compiled_exclude {
            if re.is_match(ctx.uri.path()) {
                return false;
            }
        }

        // RFC 7234: If client sends "Cache-Control: no-store", do not read from or store into cache
        if let Some(cc) = ctx.headers.get(http::header::CACHE_CONTROL) {
            if let Ok(cc_str) = cc.to_str() {
                if cc_str.contains("no-store") {
                    return false;
                }
            }
        }

        // RFC 7234 & Souin security: Requests with Authorization header are NOT served from shared cache
        // unless explicitly handled by custom key configuration
        if ctx.headers.contains_key(http::header::AUTHORIZATION) {
            let key_cfg = self
                .compiled_cache_keys
                .iter()
                .find(|r| r.regex.is_match(ctx.uri.path()))
                .map(|r| &r.key)
                .unwrap_or(&self.config.key);
            if !key_cfg.headers.iter().any(|h| h.eq_ignore_ascii_case("authorization")) {
                return false;
            }
        }

        true
    }

    /// Evaluates if an upstream response is eligible to be cached and computes TTL.
    pub fn parse_response_cacheability(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        body_len: usize,
    ) -> Option<(Duration, Duration)> {
        // Max body bytes check
        if self.config.max_cacheable_body_bytes > 0
            && body_len > self.config.max_cacheable_body_bytes
        {
            return None;
        }

        // Status code check: 200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501
        // plus allowed_additional_status_codes
        let status_code = status.as_u16();
        let standard_cacheable = matches!(status_code, 200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501);
        let additional = self
            .config
            .allowed_additional_status_codes
            .contains(&status_code);
        if !standard_cacheable && !additional {
            return None;
        }

        // Cache-Control headers inspection
        let cc_header = headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .or(self.config.default_cache_control.as_deref());

        let mut ttl = self.config.ttl;
        let mut stale = self.config.stale;

        if let Some(cc) = cc_header {
            let directives = parse_cache_control(cc);
            if directives.no_store || directives.private {
                return None;
            }

            if let Some(s_maxage) = directives.s_maxage {
                ttl = Duration::from_secs(s_maxage);
            } else if let Some(max_age) = directives.max_age {
                ttl = Duration::from_secs(max_age);
            }

            if let Some(swr) = directives.stale_while_revalidate {
                stale = Duration::from_secs(swr);
            }
        }

        Some((ttl, stale))
    }
    /// Intercepts and records the upstream response into the cache pool if eligible.
    pub fn record_response(&self, ctx: &mut Context) {
        let now_sec = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if this was a cache hit that we already served in the first pass
        if ctx.response_headers.contains_key("cache-status") {
            return;
        }

        // Upstream response just finished! Check if eligible to cache
        if self.is_request_cacheable(ctx) {
            let status = ctx.status.unwrap_or(StatusCode::OK);
            let body_len = ctx.response_body.as_ref().map(|b| b.len()).unwrap_or(0);

            if let Some((ttl, stale)) =
                self.parse_response_cacheability(status, &ctx.response_headers, body_len)
            {
                if let Some(ref body) = ctx.response_body {
                    let cache_key = self.generate_cache_key(ctx);
                    let mut stored_headers = Vec::new();
                    for (k, v) in &ctx.response_headers {
                        if let Ok(v_str) = v.to_str() {
                            stored_headers.push((k.as_str().to_string(), v_str.to_string()));
                        }
                    }

                    let etag = ctx
                        .response_headers
                        .get(http::header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let last_modified = ctx
                        .response_headers
                        .get(http::header::LAST_MODIFIED)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let entry = CachedResponse {
                        status: status.as_u16(),
                        headers: stored_headers,
                        body: body.to_vec(),
                        stored_at: now_sec,
                        ttl_secs: ttl.as_secs(),
                        stale_secs: stale.as_secs(),
                        etag,
                        last_modified,
                    };

                    self.pool.set(&cache_key, entry);

                    // Set Cache-Status: <name>; fwd=uri-miss; ttl=<ttl>
                    let cs = format!(
                        "{}; fwd=uri-miss; ttl={}",
                        self.config.cache_name,
                        ttl.as_secs()
                    );
                    if let Ok(val) = HeaderValue::from_str(&cs) {
                        ctx.response_headers
                            .insert(http::HeaderName::from_static("cache-status"), val);
                    }
                } else {
                    let cs = format!("{}; fwd=bypass", self.config.cache_name);
                    if let Ok(val) = HeaderValue::from_str(&cs) {
                        ctx.response_headers
                            .insert(http::HeaderName::from_static("cache-status"), val);
                    }
                }
            } else {
                // Uncacheable upstream response
                let cs = format!("{}; fwd=bypass", self.config.cache_name);
                if let Ok(val) = HeaderValue::from_str(&cs) {
                    ctx.response_headers
                        .insert(http::HeaderName::from_static("cache-status"), val);
                }
            }
        }
    }
}

/// Context extension holding a pending cache handler waiting for upstream response completion.
#[derive(Clone)]
pub struct PendingCacheHandler(pub Arc<CacheHandler>);

/// Helper struct for parsed Cache-Control directives.
#[derive(Debug, Default)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    stale_while_revalidate: Option<u64>,
}

fn parse_cache_control(val: &str) -> CacheControlDirectives {
    let mut res = CacheControlDirectives::default();
    for part in val.split(',') {
        let item = part.trim();
        if item.eq_ignore_ascii_case("no-store") {
            res.no_store = true;
        } else if item.eq_ignore_ascii_case("no-cache") {
            res.no_cache = true;
        } else if item.eq_ignore_ascii_case("private") {
            res.private = true;
        } else if item.eq_ignore_ascii_case("public") {
            res.public = true;
        } else if let Some(arg) = item.strip_prefix("s-maxage=") {
            if let Ok(secs) = arg.trim().parse::<u64>() {
                res.s_maxage = Some(secs);
            }
        } else if let Some(arg) = item.strip_prefix("max-age=") {
            if let Ok(secs) = arg.trim().parse::<u64>() {
                res.max_age = Some(secs);
            }
        } else if let Some(arg) = item.strip_prefix("stale-while-revalidate=") {
            if let Ok(secs) = arg.trim().parse::<u64>() {
                res.stale_while_revalidate = Some(secs);
            }
        }
    }
    res
}

#[async_trait]
impl Handler for CacheHandler {
    fn is_response_transformer(&self) -> bool {
        false
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let now_sec = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. If response is already written
        if ctx.response_written {
            self.record_response(ctx);
            return Ok(());
        }

        // 2. Request arrival pass: Evaluate if we have a fresh or stale cache entry!
        if !self.is_request_cacheable(ctx) {
            let cs = format!("{}; fwd=bypass", self.config.cache_name);
            if let Ok(val) = HeaderValue::from_str(&cs) {
                ctx.response_headers
                    .insert(http::HeaderName::from_static("cache-status"), val);
            }
            return Ok(());
        }

        let cache_key = self.generate_cache_key(ctx);
        if let Some(entry) = self.pool.get(&cache_key) {
            let is_fresh = entry.is_fresh(now_sec);
            let is_stale_allowed = entry.is_stale_allowed(now_sec);

            if is_fresh || is_stale_allowed {
                let age = entry.age(now_sec);

                // Check conditional requests (If-None-Match / If-Modified-Since) -> 304 Not Modified
                let mut not_modified = false;
                if let Some(ref etag) = entry.etag {
                    if let Some(inm) = ctx.headers.get(http::header::IF_NONE_MATCH) {
                        if let Ok(inm_str) = inm.to_str() {
                            if inm_str == etag.as_str() || inm_str == "*" {
                                not_modified = true;
                            }
                        }
                    }
                }
                if !not_modified {
                    if let Some(ref lm) = entry.last_modified {
                        if let Some(ims) = ctx.headers.get(http::header::IF_MODIFIED_SINCE) {
                            if let Ok(ims_str) = ims.to_str() {
                                if ims_str == lm.as_str() {
                                    not_modified = true;
                                }
                            }
                        }
                    }
                }

                // Restore response headers
                for (k, v) in &entry.headers {
                    if let (Ok(h_name), Ok(h_val)) = (
                        http::HeaderName::try_from(k.as_str()),
                        http::HeaderValue::try_from(v.as_str()),
                    ) {
                        ctx.response_headers.insert(h_name, h_val);
                    }
                }

                // Add Age header
                if let Ok(age_val) = HeaderValue::from_str(&age.to_string()) {
                    ctx.response_headers.insert(http::header::AGE, age_val);
                }

                let status_code = if not_modified {
                    StatusCode::NOT_MODIFIED
                } else {
                    StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK)
                };

                let cs = if is_fresh {
                    format!("{}; hit; ttl={}", self.config.cache_name, entry.ttl_secs.saturating_sub(age))
                } else {
                    format!("{}; stale", self.config.cache_name)
                };
                if let Ok(val) = HeaderValue::from_str(&cs) {
                    ctx.response_headers
                        .insert(http::HeaderName::from_static("cache-status"), val);
                }

                let body_bytes = if not_modified || ctx.method == Method::HEAD {
                    Bytes::new()
                } else {
                    Bytes::from(entry.body)
                };

                ctx.set_response(status_code, body_bytes);
                return Ok(());
            }
        }

        // Cache miss: register pending cache handler so that when the downstream response
        // is written, it will be captured and saved.
        ctx.insert_extension(PendingCacheHandler(Arc::new(self.clone())));

        Ok(())
    }
}
