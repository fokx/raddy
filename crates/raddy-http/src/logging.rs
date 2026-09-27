use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use http::StatusCode;
use regex::Regex;
use ring::digest::{digest, SHA256};
use raddy_core::config::{Config, LogConfig, LogSamplingConfig, ServerLogConfig};
use raddy_core::context::Context;
use raddy_core::PlaceholderProvider;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Central logging pipeline coordinating configured loggers.
#[derive(Clone, Default)]
pub struct LogPipeline {
    loggers: Arc<HashMap<String, LoggerInstance>>,
}

impl LogPipeline {
    /// Builds the logging pipeline from the global configuration.
    pub fn from_config(config: &Config) -> Self {
        let mut loggers = HashMap::new();

        if let Some(ref logging) = config.logging {
            for (name, log_cfg) in &logging.logs {
                loggers.insert(name.clone(), LoggerInstance::new(name, log_cfg));
            }
        }

        Self {
            loggers: Arc::new(loggers),
        }
    }

    /// Evaluates and writes an access log for a handled request.
    pub fn log_request(
        &self,
        ctx: &Context,
        duration: Duration,
        status: StatusCode,
        body_len: usize,
        server_logs: Option<&ServerLogConfig>,
    ) {
        if ctx.log_skip {
            return;
        }

        let matching_loggers = self.resolve_loggers(ctx, server_logs);
        if matching_loggers.is_empty() {
            return;
        }

        let log_credentials = server_logs.and_then(|s| s.log_credentials).unwrap_or(false);

        for logger in matching_loggers {
            logger.log(ctx, duration, status, body_len, log_credentials);
        }
    }

    fn resolve_loggers(
        &self,
        ctx: &Context,
        server_logs: Option<&ServerLogConfig>,
    ) -> Vec<&LoggerInstance> {
        let mut result = Vec::new();

        // 1. Explicit logger override via `log_name` directive
        if let Some(ref name) = ctx.log_name {
            if let Some(logger) = self.loggers.get(name) {
                result.push(logger);
                return result;
            }
        }

        // 2. Server log configuration lookup
        if let Some(srv_logs) = server_logs {
            let host = ctx.get_placeholder("host").unwrap_or_default().to_lowercase();
            let host_clean = host.split(':').next().unwrap_or(&host);

            if let Some(ref names) = srv_logs.logger_names {
                // Exact host match
                if let Some(logger_name) = names.get(host_clean) {
                    if let Some(logger) = self.loggers.get(logger_name) {
                        result.push(logger);
                        return result;
                    }
                }

                // Wildcard match (e.g. *.example.com)
                for (pattern, logger_name) in names {
                    if pattern.starts_with("*.") {
                        let suffix = &pattern[1..];
                        if host_clean.ends_with(suffix) {
                            if let Some(logger) = self.loggers.get(logger_name) {
                                result.push(logger);
                                return result;
                            }
                        }
                    }
                }
            }

            // Default logger on this server
            if let Some(ref def_name) = srv_logs.default_logger_name {
                if let Some(logger) = self.loggers.get(def_name) {
                    result.push(logger);
                    return result;
                }
            }
        }

        // 3. Fallback: match any logger including "http.log.access" or named "default"
        for (name, logger) in self.loggers.as_ref() {
            if logger.matches_include("http.log.access") || name == "default" {
                result.push(logger);
            }
        }

        result
    }
}

/// An individual active logger instance.
pub struct LoggerInstance {
    pub name: String,
    writer: Arc<dyn LogWriter>,
    encoder: Arc<LogEncoder>,
    level: LogLevel,
    include: Vec<String>,
    exclude: Vec<String>,
    sampler: Option<Arc<Mutex<LogSampler>>>,
}

impl LoggerInstance {
    pub fn new(name: &str, cfg: &LogConfig) -> Self {
        let writer = build_writer(cfg.writer.as_ref());
        let encoder = Arc::new(LogEncoder::from_config(cfg.encoder.as_ref()));
        let level = parse_level(cfg.level.as_deref().unwrap_or("INFO"));

        let sampler = cfg.sampling.as_ref().map(|s| {
            Arc::new(Mutex::new(LogSampler::new(s)))
        });

        Self {
            name: name.to_string(),
            writer,
            encoder,
            level,
            include: cfg.include.clone(),
            exclude: cfg.exclude.clone(),
            sampler,
        }
    }

    pub fn matches_include(&self, topic: &str) -> bool {
        if self.include.is_empty() {
            return false;
        }
        if self.exclude.iter().any(|exc| exc == topic || topic.starts_with(exc)) {
            return false;
        }
        self.include.iter().any(|inc| {
            inc == topic || topic.starts_with(inc) || inc == "*"
        })
    }

    pub fn log(
        &self,
        ctx: &Context,
        duration: Duration,
        status: StatusCode,
        body_len: usize,
        log_credentials: bool,
    ) {
        let record_level = if status.is_server_error() {
            LogLevel::Error
        } else {
            LogLevel::Info
        };

        if record_level < self.level {
            return;
        }

        if let Some(ref sampler) = self.sampler {
            if !sampler.lock().unwrap().should_sample() {
                return;
            }
        }

        let raw_entry = self.build_access_entry(ctx, duration, status, body_len, log_credentials, record_level);
        let encoded_line = self.encoder.encode(&raw_entry, &self.name, record_level);

        if let Err(e) = self.writer.write_line(&encoded_line) {
            tracing::warn!("Failed to write access log to logger '{}': {}", self.name, e);
        }
    }

    fn build_access_entry(
        &self,
        ctx: &Context,
        duration: Duration,
        status: StatusCode,
        body_len: usize,
        log_credentials: bool,
        record_level: LogLevel,
    ) -> serde_json::Value {
        let now = SystemTime::now();
        let ts_float = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let remote_ip = ctx.remote_addr.map(|a| a.ip().to_string()).unwrap_or_default();
        let remote_port = ctx.remote_addr.map(|a| a.port().to_string()).unwrap_or_default();
        let client_ip = ctx
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| remote_ip.clone());

        let proto = if ctx.tls_server_name.is_some() {
            "HTTP/2.0"
        } else {
            "HTTP/1.1"
        };

        let host = ctx.get_placeholder("host").unwrap_or_default();
        let uri = ctx.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();

        let mut req_headers = serde_json::Map::new();
        for (name, val) in &ctx.headers {
            let name_str = name.as_str();
            let is_sensitive = matches!(
                name_str.to_ascii_lowercase().as_str(),
                "cookie" | "set-cookie" | "authorization" | "proxy-authorization"
            );

            let value_str = if is_sensitive && !log_credentials {
                "REDACTED".to_string()
            } else {
                val.to_str().unwrap_or("").to_string()
            };

            let canonical_name = canonicalize_header_name(name_str);
            let entry = req_headers
                .entry(canonical_name)
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let serde_json::Value::Array(arr) = entry {
                arr.push(serde_json::Value::String(value_str));
            }
        }

        let mut resp_headers = serde_json::Map::new();
        for (name, val) in &ctx.response_headers {
            let name_str = name.as_str();
            let is_sensitive = matches!(
                name_str.to_ascii_lowercase().as_str(),
                "cookie" | "set-cookie" | "authorization" | "proxy-authorization"
            );

            let value_str = if is_sensitive && !log_credentials {
                "REDACTED".to_string()
            } else {
                val.to_str().unwrap_or("").to_string()
            };

            let canonical_name = canonicalize_header_name(name_str);
            let entry = resp_headers
                .entry(canonical_name)
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let serde_json::Value::Array(arr) = entry {
                arr.push(serde_json::Value::String(value_str));
            }
        }

        let user_id = ctx.get_var("user_id").unwrap_or("").to_string();

        let mut root = serde_json::json!({
            "level": record_level.as_str(),
            "ts": ts_float,
            "logger": format!("http.log.access.{}", self.name),
            "msg": "handled request",
            "request": {
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "client_ip": client_ip,
                "proto": proto,
                "method": ctx.method.as_str(),
                "host": host,
                "uri": uri,
                "headers": req_headers,
            },
            "user_id": user_id,
            "duration": duration.as_secs_f64(),
            "size": body_len,
            "status": status.as_u16(),
            "resp_headers": resp_headers,
        });

        // Attach custom appends from `log_append` directive
        if let serde_json::Value::Object(map) = &mut root {
            for (k, v) in &ctx.log_appends {
                map.insert(k.clone(), v.clone());
            }
        }

        root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

fn parse_level(s: &str) -> LogLevel {
    match s.trim().to_uppercase().as_str() {
        "DEBUG" => LogLevel::Debug,
        "WARN" | "WARNING" => LogLevel::Warn,
        "ERROR" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

// -------------------------------------------------------------------------------------------------
// Writers
// -------------------------------------------------------------------------------------------------

pub trait LogWriter: Send + Sync {
    fn write_line(&self, line: &str) -> std::io::Result<()>;
}

struct StdoutWriter;
impl LogWriter for StdoutWriter {
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", line)?;
        out.flush()
    }
}

struct StderrWriter;
impl LogWriter for StderrWriter {
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut err = std::io::stderr().lock();
        writeln!(err, "{}", line)?;
        err.flush()
    }
}

struct DiscardWriter;
impl LogWriter for DiscardWriter {
    fn write_line(&self, _line: &str) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct FileRollOptions {
    pub roll_disabled: bool,
    pub roll_size: u64,
    pub roll_interval: Option<Duration>,
    pub roll_uncompressed: bool,
    pub roll_local_time: bool,
    pub roll_keep: usize,
    pub roll_keep_for: Option<Duration>,
    pub backup_time_format: String,
    pub mode: Option<u32>,
}

impl Default for FileRollOptions {
    fn default() -> Self {
        Self {
            roll_disabled: false,
            roll_size: 100 * 1024 * 1024, // 100 MiB
            roll_interval: None,
            roll_uncompressed: false, // Default to gzip compression
            roll_local_time: false,
            roll_keep: 10,
            roll_keep_for: Some(Duration::from_secs(90 * 24 * 3600)), // 90 days
            backup_time_format: "%Y-%m-%dT%H-%M-%S".to_string(),
            mode: None,
        }
    }
}

struct FileWriterInner {
    file_path: PathBuf,
    file: Option<File>,
    current_size: u64,
    last_rotated: Instant,
    options: FileRollOptions,
}

impl FileWriterInner {
    fn open_current_file(&mut self) -> std::io::Result<()> {
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        let metadata = file.metadata()?;
        self.current_size = metadata.len();

        #[cfg(unix)]
        if let Some(mode) = self.options.mode {
            let _ = std::fs::set_permissions(&self.file_path, std::fs::Permissions::from_mode(mode));
        }

        self.file = Some(file);
        self.last_rotated = Instant::now();
        Ok(())
    }

    fn check_and_roll(&mut self, incoming_len: usize) -> std::io::Result<()> {
        if self.options.roll_disabled {
            return Ok(());
        }

        let mut reason = None;

        if self.current_size + incoming_len as u64 > self.options.roll_size {
            reason = Some("size");
        } else if let Some(interval) = self.options.roll_interval {
            if self.last_rotated.elapsed() >= interval {
                reason = Some("time");
            }
        }

        if let Some(r) = reason {
            self.execute_roll(r)?;
        }

        Ok(())
    }

    fn execute_roll(&mut self, reason: &str) -> std::io::Result<()> {
        // Close current file
        if let Some(mut f) = self.file.take() {
            let _ = f.flush();
        }

        let timestamp_str = if self.options.roll_local_time {
            chrono::Local::now().format(&self.options.backup_time_format).to_string()
        } else {
            chrono::Utc::now().format(&self.options.backup_time_format).to_string()
        };

        let file_stem = self.file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("log");
        let file_ext = self.file_path.extension().and_then(|s| s.to_str()).unwrap_or("log");
        let parent_dir = self.file_path.parent().unwrap_or_else(|| Path::new("."));

        let rolled_name = format!("{}-{}-{}.{}", file_stem, timestamp_str, reason, file_ext);
        let rolled_path = parent_dir.join(&rolled_name);

        if self.file_path.exists() {
            let _ = std::fs::rename(&self.file_path, &rolled_path);

            if !self.options.roll_uncompressed {
                // Compress via gzip with flate2
                let gz_path = parent_dir.join(format!("{}.gz", rolled_name));
                if let Ok(src_file) = File::open(&rolled_path) {
                    if let Ok(dst_file) = File::create(&gz_path) {
                        let mut encoder = flate2::write::GzEncoder::new(dst_file, flate2::Compression::default());
                        let mut reader = std::io::BufReader::new(src_file);
                        if std::io::copy(&mut reader, &mut encoder).is_ok() && encoder.finish().is_ok() {
                            let _ = std::fs::remove_file(&rolled_path);
                        }
                    }
                }
            }
        }

        // Apply retention cleanup
        self.cleanup_old_logs(parent_dir, file_stem, file_ext);

        // Open fresh file
        self.open_current_file()
    }

    fn cleanup_old_logs(&self, dir: &Path, file_stem: &str, file_ext: &str) {
        let prefix = format!("{}-", file_stem);
        let Ok(entries) = std::fs::read_dir(dir) else { return };

        let mut matching_files: Vec<(PathBuf, SystemTime)> = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                if fname.starts_with(&prefix) && (fname.contains(file_ext) || fname.ends_with(".gz")) {
                    let mtime = entry.metadata().and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                    matching_files.push((path, mtime));
                }
            }
        }

        // Sort descending by mtime (newest first)
        matching_files.sort_by(|a, b| b.1.cmp(&a.1));

        let now = SystemTime::now();

        // 1. Keep at most roll_keep files
        if self.options.roll_keep > 0 && matching_files.len() > self.options.roll_keep {
            for (excess_path, _) in &matching_files[self.options.roll_keep..] {
                let _ = std::fs::remove_file(excess_path);
            }
        }

        // 2. Remove files older than roll_keep_for
        if let Some(keep_for) = self.options.roll_keep_for {
            for (path, mtime) in &matching_files {
                if let Ok(age) = now.duration_since(*mtime) {
                    if age > keep_for {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
        }
    }
}

pub struct FileWriter {
    inner: Mutex<FileWriterInner>,
}

impl FileWriter {
    pub fn new(path: impl Into<PathBuf>, options: FileRollOptions) -> std::io::Result<Self> {
        let mut inner = FileWriterInner {
            file_path: path.into(),
            file: None,
            current_size: 0,
            last_rotated: Instant::now(),
            options,
        };
        inner.open_current_file()?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }
}

impl LogWriter for FileWriter {
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let bytes = line.as_bytes();
        inner.check_and_roll(bytes.len() + 1)?;

        if let Some(ref mut f) = inner.file {
            f.write_all(bytes)?;
            f.write_all(b"\n")?;
            f.flush()?;
            inner.current_size += bytes.len() as u64 + 1;
        }
        Ok(())
    }
}

struct NetWriter {
    address: String,
    soft_start: bool,
    stream: Mutex<Option<std::net::TcpStream>>,
}

impl NetWriter {
    pub fn new(address: String, soft_start: bool) -> Self {
        let stream = match std::net::TcpStream::connect(&address) {
            Ok(s) => Some(s),
            Err(e) => {
                if !soft_start {
                    tracing::warn!("Failed to connect to net log target {}: {}", address, e);
                }
                None
            }
        };

        Self {
            address,
            soft_start,
            stream: Mutex::new(stream),
        }
    }
}

impl LogWriter for NetWriter {
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut stream_guard = self.stream.lock().unwrap();
        if stream_guard.is_none() {
            if let Ok(s) = std::net::TcpStream::connect(&self.address) {
                *stream_guard = Some(s);
            }
        }

        if let Some(ref mut s) = *stream_guard {
            if s.write_all(line.as_bytes()).is_ok() && s.write_all(b"\n").is_ok() {
                return Ok(());
            }
            *stream_guard = None; // Connection broken
        }

        if self.soft_start {
            // Fallback to stderr
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "{}", line);
        }
        Ok(())
    }
}

fn build_writer(val: Option<&serde_json::Value>) -> Arc<dyn LogWriter> {
    let Some(val) = val else {
        return Arc::new(StdoutWriter);
    };

    let output_type = val.get("output").and_then(|v| v.as_str()).unwrap_or("stdout");

    match output_type {
        "stderr" => Arc::new(StderrWriter),
        "discard" => Arc::new(DiscardWriter),
        "file" => {
            let filename = val.get("filename").and_then(|v| v.as_str()).unwrap_or("access.log");
            let mut options = FileRollOptions::default();

            if let Some(disabled) = val.get("roll_disabled").and_then(|v| v.as_bool()) {
                options.roll_disabled = disabled;
            }
            if let Some(size_str) = val.get("roll_size").and_then(|v| v.as_str()) {
                options.roll_size = parse_size_bytes(size_str) as u64;
            }
            if let Some(size_num) = val.get("roll_size").and_then(|v| v.as_u64()) {
                options.roll_size = size_num;
            }
            if let Some(int_str) = val.get("roll_interval").and_then(|v| v.as_str()) {
                options.roll_interval = parse_duration_str(int_str);
            }
            if let Some(uncomp) = val.get("roll_uncompressed").and_then(|v| v.as_bool()) {
                options.roll_uncompressed = uncomp;
            }
            if let Some(local) = val.get("roll_local_time").and_then(|v| v.as_bool()) {
                options.roll_local_time = local;
            }
            if let Some(keep) = val.get("roll_keep").and_then(|v| v.as_u64()) {
                options.roll_keep = keep as usize;
            }
            if let Some(keep_for_str) = val.get("roll_keep_for").and_then(|v| v.as_str()) {
                options.roll_keep_for = parse_duration_str(keep_for_str);
            }
            if let Some(fmt) = val.get("backup_time_format").and_then(|v| v.as_str()) {
                options.backup_time_format = convert_time_format(fmt);
            }
            if let Some(mode_str) = val.get("mode").and_then(|v| v.as_str()) {
                if let Ok(m) = u32::from_str_radix(mode_str.trim_start_matches('0'), 8) {
                    options.mode = Some(m);
                }
            }

            match FileWriter::new(filename, options) {
                Ok(w) => Arc::new(w),
                Err(e) => {
                    tracing::error!("Failed to open log file '{}': {}. Defaulting to stderr.", filename, e);
                    Arc::new(StderrWriter)
                }
            }
        }
        "net" => {
            let addr = val.get("address").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:9000");
            let soft = val.get("soft_start").and_then(|v| v.as_bool()).unwrap_or(false);
            Arc::new(NetWriter::new(addr.to_string(), soft))
        }
        _ => Arc::new(StdoutWriter),
    }
}

// -------------------------------------------------------------------------------------------------
// Encoders and Filtering
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EncoderType {
    Json,
    Console,
}

#[derive(Debug, Clone)]
pub enum FilterAction {
    Delete,
    Rename(String),
    Replace(String),
    Hash,
    Regexp(Regex, String),
    IpMask { ipv4: u8, ipv6: u8 },
    Query {
        delete: Vec<String>,
        replace: HashMap<String, String>,
        hash: Vec<String>,
    },
    Cookie {
        delete: Vec<String>,
        replace: HashMap<String, String>,
        hash: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct FilterRule {
    pub field_path: Vec<String>,
    pub action: FilterAction,
}

pub struct LogEncoder {
    pub encoder_type: EncoderType,
    pub time_format: String,
    pub time_local: bool,
    pub duration_format: String,
    pub level_format: String,
    pub message_key: String,
    pub level_key: String,
    pub time_key: String,
    pub name_key: String,
    pub filters: Vec<FilterRule>,
    pub append_fields: HashMap<String, String>,
}

impl LogEncoder {
    pub fn from_config(val: Option<&serde_json::Value>) -> Self {
        let mut encoder_type = EncoderType::Json;
        let mut time_format = "unix_seconds_float".to_string();
        let mut time_local = false;
        let mut duration_format = "seconds".to_string();
        let mut level_format = "lower".to_string();
        let mut message_key = "msg".to_string();
        let mut level_key = "level".to_string();
        let mut time_key = "ts".to_string();
        let mut name_key = "logger".to_string();
        let mut filters = Vec::new();
        let mut append_fields = HashMap::new();

        if let Some(val) = val {
            let format_str = val.get("format").and_then(|v| v.as_str()).unwrap_or("json");
            match format_str {
                "console" => {
                    encoder_type = EncoderType::Console;
                    time_format = "wall_milli".to_string();
                    level_format = "color".to_string();
                }
                "filter" => {
                    if let Some(wrap) = val.get("wrap").and_then(|v| v.get("format")).and_then(|v| v.as_str()) {
                        if wrap == "console" {
                            encoder_type = EncoderType::Console;
                        }
                    }
                    if let Some(rules) = val.get("filters").and_then(|v| v.as_array()) {
                        for r in rules {
                            if let Some(rule) = parse_filter_rule(r) {
                                filters.push(rule);
                            }
                        }
                    }
                }
                "append" => {
                    if let Some(wrap) = val.get("wrap").and_then(|v| v.get("format")).and_then(|v| v.as_str()) {
                        if wrap == "console" {
                            encoder_type = EncoderType::Console;
                        }
                    }
                    if let Some(fields) = val.get("fields").and_then(|v| v.as_object()) {
                        for (k, v) in fields {
                            if let Some(s) = v.as_str() {
                                append_fields.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }

            if let Some(tf) = val.get("time_format").and_then(|v| v.as_str()) {
                time_format = tf.to_string();
            }
            if let Some(tl) = val.get("time_local").and_then(|v| v.as_bool()) {
                time_local = tl;
            }
            if let Some(df) = val.get("duration_format").and_then(|v| v.as_str()) {
                duration_format = df.to_string();
            }
            if let Some(lf) = val.get("level_format").and_then(|v| v.as_str()) {
                level_format = lf.to_string();
            }
            if let Some(mk) = val.get("message_key").and_then(|v| v.as_str()) {
                message_key = mk.to_string();
            }
            if let Some(lk) = val.get("level_key").and_then(|v| v.as_str()) {
                level_key = lk.to_string();
            }
            if let Some(tk) = val.get("time_key").and_then(|v| v.as_str()) {
                time_key = tk.to_string();
            }
            if let Some(nk) = val.get("name_key").and_then(|v| v.as_str()) {
                name_key = nk.to_string();
            }
        }

        Self {
            encoder_type,
            time_format,
            time_local,
            duration_format,
            level_format,
            message_key,
            level_key,
            time_key,
            name_key,
            filters,
            append_fields,
        }
    }

    pub fn encode(&self, raw: &serde_json::Value, logger_name: &str, level: LogLevel) -> String {
        let mut entry = raw.clone();

        // 1. Apply filter rules
        for rule in &self.filters {
            apply_filter(&mut entry, &rule.field_path, &rule.action);
        }

        // 2. Apply append fields with environment placeholder evaluation
        if !self.append_fields.is_empty() {
            if let serde_json::Value::Object(map) = &mut entry {
                for (k, v) in &self.append_fields {
                    let evaluated = eval_env_placeholders(v);
                    map.insert(k.clone(), serde_json::Value::String(evaluated));
                }
            }
        }

        // 3. Apply timestamp formatting
        let raw_ts = entry.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let formatted_ts = format_timestamp(raw_ts, &self.time_format, self.time_local);

        // 4. Apply duration formatting
        let raw_dur = entry.get("duration").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let formatted_dur = format_duration(raw_dur, &self.duration_format);

        // 5. Apply level formatting
        let formatted_level = format_level(level, &self.level_format);

        match self.encoder_type {
            EncoderType::Json => {
                if let serde_json::Value::Object(map) = &mut entry {
                    // Update key names if customized
                    if self.time_key != "ts" {
                        map.remove("ts");
                    }
                    map.insert(self.time_key.clone(), formatted_ts);

                    if self.duration_format == "string" {
                        map.insert("duration".to_string(), serde_json::Value::String(formatted_dur));
                    } else if let Ok(num) = formatted_dur.parse::<f64>() {
                        map.insert("duration".to_string(), serde_json::json!(num));
                    }

                    if self.level_key != "level" {
                        map.remove("level");
                    }
                    map.insert(self.level_key.clone(), serde_json::Value::String(formatted_level));

                    if self.message_key != "msg" {
                        if let Some(msg) = map.remove("msg") {
                            map.insert(self.message_key.clone(), msg);
                        }
                    }

                    if self.name_key != "logger" {
                        if let Some(name) = map.remove("logger") {
                            map.insert(self.name_key.clone(), name);
                        }
                    }
                }
                serde_json::to_string(&entry).unwrap_or_default()
            }
            EncoderType::Console => {
                let ts = match formatted_ts {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                let status = entry.get("status").and_then(|v| v.as_u64()).unwrap_or(200);
                let method = entry.get("request").and_then(|r| r.get("method")).and_then(|v| v.as_str()).unwrap_or("");
                let uri = entry.get("request").and_then(|r| r.get("uri")).and_then(|v| v.as_str()).unwrap_or("");
                let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

                format!(
                    "{}  {}\t{}\t{}\t{} {} -> {} ({}B, {})",
                    ts, formatted_level, logger_name, "handled request", method, uri, status, size, formatted_dur
                )
            }
        }
    }
}

fn parse_filter_rule(val: &serde_json::Value) -> Option<FilterRule> {
    let field = val.get("field").and_then(|v| v.as_str())?;
    let ftype = val.get("type").and_then(|v| v.as_str())?;
    let field_path: Vec<String> = field.split('>').map(|s| s.to_string()).collect();

    let action = match ftype {
        "delete" => FilterAction::Delete,
        "rename" => {
            let key = val.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
            FilterAction::Rename(key)
        }
        "replace" => {
            let rep = val.get("replacement").and_then(|v| v.as_str()).unwrap_or("").to_string();
            FilterAction::Replace(rep)
        }
        "hash" => FilterAction::Hash,
        "regexp" => {
            let pat = val.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let rep = val.get("replacement").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let regex = Regex::new(pat).ok()?;
            FilterAction::Regexp(regex, rep)
        }
        "ip_mask" => {
            let ipv4 = val.get("ipv4").and_then(|v| v.as_u64()).unwrap_or(16) as u8;
            let ipv6 = val.get("ipv6").and_then(|v| v.as_u64()).unwrap_or(32) as u8;
            FilterAction::IpMask { ipv4, ipv6 }
        }
        "query" => {
            let mut delete = Vec::new();
            let mut replace = HashMap::new();
            let mut hash = Vec::new();

            if let Some(actions) = val.get("actions").and_then(|v| v.as_array()) {
                for a in actions {
                    let act_type = a.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let key = a.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    match act_type {
                        "delete" => delete.push(key),
                        "replace" => {
                            let val_str = a.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            replace.insert(key, val_str);
                        }
                        "hash" => hash.push(key),
                        _ => {}
                    }
                }
            }
            FilterAction::Query { delete, replace, hash }
        }
        "cookie" => {
            let mut delete = Vec::new();
            let mut replace = HashMap::new();
            let mut hash = Vec::new();

            if let Some(actions) = val.get("actions").and_then(|v| v.as_array()) {
                for a in actions {
                    let act_type = a.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    match act_type {
                        "delete" => delete.push(name),
                        "replace" => {
                            let val_str = a.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            replace.insert(name, val_str);
                        }
                        "hash" => hash.push(name),
                        _ => {}
                    }
                }
            }
            FilterAction::Cookie { delete, replace, hash }
        }
        _ => return None,
    };

    Some(FilterRule { field_path, action })
}

fn apply_filter(target: &mut serde_json::Value, path: &[String], action: &FilterAction) {
    if path.is_empty() {
        return;
    }

    if path.len() == 1 {
        let key = &path[0];
        match action {
            FilterAction::Delete => {
                if let serde_json::Value::Object(map) = target {
                    map.remove(key);
                }
            }
            FilterAction::Rename(new_key) => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.remove(key) {
                        map.insert(new_key.clone(), val);
                    }
                }
            }
            FilterAction::Replace(replacement) => {
                if let serde_json::Value::Object(map) = target {
                    if map.contains_key(key) {
                        map.insert(key.clone(), serde_json::Value::String(replacement.clone()));
                    }
                }
            }
            FilterAction::Hash => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.get_mut(key) {
                        transform_value_hash(val);
                    }
                }
            }
            FilterAction::Regexp(re, rep) => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.get_mut(key) {
                        transform_value_regexp(val, re, rep);
                    }
                }
            }
            FilterAction::IpMask { ipv4, ipv6 } => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.get_mut(key) {
                        transform_value_ipmask(val, *ipv4, *ipv6);
                    }
                }
            }
            FilterAction::Query { delete, replace, hash } => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.get_mut(key) {
                        transform_value_query(val, delete, replace, hash);
                    }
                }
            }
            FilterAction::Cookie { delete, replace, hash } => {
                if let serde_json::Value::Object(map) = target {
                    if let Some(val) = map.get_mut(key) {
                        transform_value_cookie(val, delete, replace, hash);
                    }
                }
            }
        }
    } else {
        let head = &path[0];
        let tail = &path[1..];
        if let serde_json::Value::Object(map) = target {
            if let Some(next_obj) = map.get_mut(head) {
                apply_filter(next_obj, tail, action);
            }
        }
    }
}

fn sha256_short_hex(input: &str) -> String {
    let d = digest(&SHA256, input.as_bytes());
    // first 4 bytes = 8 hex chars
    hex::encode(&d.as_ref()[..4])
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

fn transform_value_hash(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::String(s) => {
            *s = sha256_short_hex(s);
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let serde_json::Value::String(s) = item {
                    *s = sha256_short_hex(s);
                }
            }
        }
        _ => {}
    }
}

fn transform_value_regexp(val: &mut serde_json::Value, re: &Regex, rep: &str) {
    match val {
        serde_json::Value::String(s) => {
            *s = re.replace_all(s, rep).to_string();
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let serde_json::Value::String(s) = item {
                    *s = re.replace_all(s, rep).to_string();
                }
            }
        }
        _ => {}
    }
}

fn transform_value_ipmask(val: &mut serde_json::Value, ipv4_cidr: u8, ipv6_cidr: u8) {
    match val {
        serde_json::Value::String(s) => {
            *s = mask_ip_string(s, ipv4_cidr, ipv6_cidr);
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let serde_json::Value::String(s) = item {
                    *s = mask_ip_string(s, ipv4_cidr, ipv6_cidr);
                }
            }
        }
        _ => {}
    }
}

fn mask_ip_string(s: &str, ipv4_cidr: u8, ipv6_cidr: u8) -> String {
    let mut parts = Vec::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    let bits = u32::from(v4);
                    let mask = if ipv4_cidr == 0 {
                        0
                    } else if ipv4_cidr >= 32 {
                        u32::MAX
                    } else {
                        !((1u32 << (32 - ipv4_cidr)) - 1)
                    };
                    let masked = std::net::Ipv4Addr::from(bits & mask);
                    parts.push(masked.to_string());
                }
                IpAddr::V6(v6) => {
                    let bits = u128::from(v6);
                    let mask = if ipv6_cidr == 0 {
                        0
                    } else if ipv6_cidr >= 128 {
                        u128::MAX
                    } else {
                        !((1u128 << (128 - ipv6_cidr)) - 1)
                    };
                    let masked = std::net::Ipv6Addr::from(bits & mask);
                    parts.push(masked.to_string());
                }
            }
        } else {
            parts.push(trimmed.to_string());
        }
    }
    parts.join(", ")
}

fn transform_value_query(
    val: &mut serde_json::Value,
    delete: &[String],
    replace: &HashMap<String, String>,
    hash: &[String],
) {
    let serde_json::Value::String(uri_str) = val else { return };
    let Some((path, query)) = uri_str.split_once('?') else { return };

    let mut new_pairs = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if delete.iter().any(|d| d == k) {
            continue;
        }
        if let Some(replacement) = replace.get(k) {
            new_pairs.push(format!("{}={}", k, replacement));
        } else if hash.iter().any(|h| h == k) {
            new_pairs.push(format!("{}={}", k, sha256_short_hex(v)));
        } else {
            new_pairs.push(pair.to_string());
        }
    }

    if new_pairs.is_empty() {
        *uri_str = path.to_string();
    } else {
        *uri_str = format!("{}?{}", path, new_pairs.join("&"));
    }
}

fn transform_value_cookie(
    val: &mut serde_json::Value,
    delete: &[String],
    replace: &HashMap<String, String>,
    hash: &[String],
) {
    match val {
        serde_json::Value::String(s) => {
            *s = transform_cookie_header_str(s, delete, replace, hash);
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let serde_json::Value::String(s) = item {
                    *s = transform_cookie_header_str(s, delete, replace, hash);
                }
            }
        }
        _ => {}
    }
}

fn transform_cookie_header_str(
    header: &str,
    delete: &[String],
    replace: &HashMap<String, String>,
    hash: &[String],
) -> String {
    let mut parts = Vec::new();
    for item in header.split(';') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k, v) = trimmed.split_once('=').unwrap_or((trimmed, ""));
        let k_trim = k.trim();
        let v_trim = v.trim();

        if delete.iter().any(|d| d == k_trim) {
            continue;
        }

        if let Some(replacement) = replace.get(k_trim) {
            parts.push(format!("{}={}", k_trim, replacement));
        } else if hash.iter().any(|h| h == k_trim) {
            parts.push(format!("{}={}", k_trim, sha256_short_hex(v_trim)));
        } else {
            parts.push(trimmed.to_string());
        }
    }
    parts.join("; ")
}

fn eval_env_placeholders(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(start) = out.find("{env.") {
        if let Some(end) = out[start..].find('}') {
            let key = &out[start + 5..start + end];
            let val = std::env::var(key).unwrap_or_default();
            out.replace_range(start..start + end + 1, &val);
        } else {
            break;
        }
    }
    out
}

fn format_timestamp(ts_float: f64, format_str: &str, local: bool) -> serde_json::Value {
    let secs = ts_float.trunc() as i64;
    let nanos = (ts_float.fract() * 1_000_000_000.0) as u32;

    match format_str {
        "unix_seconds_float" => serde_json::json!(ts_float),
        "unix_milli_float" => serde_json::json!(ts_float * 1000.0),
        "unix_nano" => serde_json::json!((secs as i128) * 1_000_000_000 + (nanos as i128)),
        _ => {
            let dt = chrono::DateTime::from_timestamp(secs, nanos).unwrap_or_default();
            let formatted = if local {
                let local_dt: chrono::DateTime<chrono::Local> = chrono::DateTime::from(dt);
                match format_str {
                    "iso8601" | "rfc3339" => local_dt.to_rfc3339(),
                    "rfc3339_nano" => local_dt.format("%Y-%m-%dT%H:%M:%S%.9f%z").to_string(),
                    "wall" => local_dt.format("%Y/%m/%d %H:%M:%S").to_string(),
                    "wall_milli" => local_dt.format("%Y/%m/%d %H:%M:%S%.3f").to_string(),
                    "wall_nano" => local_dt.format("%Y/%m/%d %H:%M:%S%.9f").to_string(),
                    "common_log" => local_dt.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
                    other => local_dt.format(&convert_time_format(other)).to_string(),
                }
            } else {
                match format_str {
                    "iso8601" | "rfc3339" => dt.to_rfc3339(),
                    "rfc3339_nano" => dt.format("%Y-%m-%dT%H:%M:%S%.9f%z").to_string(),
                    "wall" => dt.format("%Y/%m/%d %H:%M:%S").to_string(),
                    "wall_milli" => dt.format("%Y/%m/%d %H:%M:%S%.3f").to_string(),
                    "wall_nano" => dt.format("%Y/%m/%d %H:%M:%S%.9f").to_string(),
                    "common_log" => dt.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
                    other => dt.format(&convert_time_format(other)).to_string(),
                }
            };
            serde_json::Value::String(formatted)
        }
    }
}

fn format_duration(dur_secs: f64, format_str: &str) -> String {
    match format_str {
        "ms" | "milli" | "millis" => format!("{:.3}", dur_secs * 1000.0),
        "ns" | "nano" | "nanos" => format!("{}", (dur_secs * 1_000_000_000.0) as u64),
        "string" => {
            if dur_secs < 0.001 {
                format!("{:.2}µs", dur_secs * 1_000_000.0)
            } else if dur_secs < 1.0 {
                format!("{:.2}ms", dur_secs * 1000.0)
            } else {
                format!("{:.2}s", dur_secs)
            }
        }
        _ => format!("{:.6}", dur_secs),
    }
}

fn format_level(level: LogLevel, format_str: &str) -> String {
    match format_str {
        "upper" => level.as_str().to_uppercase(),
        "color" => match level {
            LogLevel::Debug => "\x1b[35mDEBUG\x1b[0m".to_string(),
            LogLevel::Info => "\x1b[32mINFO\x1b[0m".to_string(),
            LogLevel::Warn => "\x1b[33mWARN\x1b[0m".to_string(),
            LogLevel::Error => "\x1b[31mERROR\x1b[0m".to_string(),
        },
        _ => level.as_str().to_lowercase(),
    }
}

fn convert_time_format(fmt: &str) -> String {
    fmt.replace("2006", "%Y")
        .replace("01", "%m")
        .replace("02", "%d")
        .replace("15", "%H")
        .replace("04", "%M")
        .replace("05", "%S")
        .replace("Jan", "%b")
        .replace("January", "%B")
        .replace("Mon", "%a")
        .replace("Monday", "%A")
        .replace("-07:00", "%:z")
        .replace("-0700", "%z")
}

fn parse_size_bytes(s: &str) -> usize {
    let s = s.trim().to_lowercase();
    if let Some(stripped) = s.strip_suffix("gib") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if let Some(stripped) = s.strip_suffix("gb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1000 * 1000 * 1000
    } else if let Some(stripped) = s.strip_suffix("mib") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024 * 1024
    } else if let Some(stripped) = s.strip_suffix("mb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1000 * 1000
    } else if let Some(stripped) = s.strip_suffix("kib") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1024
    } else if let Some(stripped) = s.strip_suffix("kb") {
        stripped.trim().parse::<usize>().unwrap_or(0) * 1000
    } else if let Some(stripped) = s.strip_suffix('b') {
        stripped.trim().parse::<usize>().unwrap_or(0)
    } else {
        s.parse::<usize>().unwrap_or(0)
    }
}

fn parse_duration_str(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();
    if let Some(stripped) = s.strip_suffix('d') {
        let days: u64 = stripped.trim().parse().ok()?;
        Some(Duration::from_secs(days * 24 * 3600))
    } else if let Some(stripped) = s.strip_suffix('h') {
        let hours: u64 = stripped.trim().parse().ok()?;
        Some(Duration::from_secs(hours * 3600))
    } else if let Some(stripped) = s.strip_suffix('m') {
        let mins: u64 = stripped.trim().parse().ok()?;
        Some(Duration::from_secs(mins * 60))
    } else if let Some(stripped) = s.strip_suffix('s') {
        let secs: u64 = stripped.trim().parse().ok()?;
        Some(Duration::from_secs(secs))
    } else {
        None
    }
}

// -------------------------------------------------------------------------------------------------
// Sampling
// -------------------------------------------------------------------------------------------------

pub struct LogSampler {
    interval: Duration,
    first: usize,
    thereafter: usize,
    window_start: Instant,
    count_in_window: usize,
}

impl LogSampler {
    pub fn new(cfg: &LogSamplingConfig) -> Self {
        let interval = cfg
            .interval
            .as_deref()
            .and_then(parse_duration_str)
            .unwrap_or_else(|| Duration::from_secs(1));
        let first = cfg.first.unwrap_or(100);
        let thereafter = cfg.thereafter.unwrap_or(100);

        Self {
            interval,
            first,
            thereafter,
            window_start: Instant::now(),
            count_in_window: 0,
        }
    }

    pub fn should_sample(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.interval {
            self.window_start = now;
            self.count_in_window = 0;
        }

        self.count_in_window += 1;

        if self.count_in_window <= self.first {
            true
        } else if self.thereafter > 0 {
            (self.count_in_window - self.first) % self.thereafter == 0
        } else {
            false
        }
    }
}

fn canonicalize_header_name(s: &str) -> String {
    s.split('-')
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let mut out = first.to_uppercase().to_string();
                    out.extend(chars.map(|c| c.to_ascii_lowercase()));
                    out
                }
            }
        })
        .collect::<Vec<String>>()
        .join("-")
}
