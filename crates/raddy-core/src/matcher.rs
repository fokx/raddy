use crate::config::{FileMatcherConfig, MatcherSet};
use crate::context::Context;
use crate::placeholder::{PlaceholderProvider, Replacer, eval_placeholders};
use ipnet::IpNet;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const PRIVATE_RANGES: &[&str] = &[
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "127.0.0.1/8",
    "fd00::/8",
    "::1",
];

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &Context) -> bool;
}

/// Matches request paths. Supports exact match, prefix match (`/path*`), suffix match (`*.php`),
/// substring match (`*substring*`), or globular match (`/foo/*/baz`). Case-insensitive matching.
#[derive(Debug, Clone)]
pub struct PathMatcher {
    pub patterns: Vec<String>,
}

impl PathMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }
}

impl Matcher for PathMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let req_path = ctx.uri.path().to_lowercase();
        let repl = Replacer::new();

        for pattern in &self.patterns {
            let pat = repl.replace_all(pattern, "").to_lowercase();
            if pat == "*" || pat == "/*" {
                return true;
            }

            // Substring: *substring*
            if pat.len() >= 2 && pat.starts_with('*') && pat.ends_with('*') {
                let sub = &pat[1..pat.len() - 1];
                if req_path.contains(sub) {
                    return true;
                }
                continue;
            }

            // Suffix: *.ext
            if pat.starts_with('*') && pat.chars().filter(|&c| c == '*').count() == 1 {
                let suffix = &pat[1..];
                if req_path.ends_with(suffix) {
                    return true;
                }
                continue;
            }

            // Prefix: /prefix*
            if pat.ends_with('*') && pat.chars().filter(|&c| c == '*').count() == 1 {
                let prefix = &pat[..pat.len() - 1];
                if req_path.starts_with(prefix) {
                    return true;
                }
                continue;
            }

            // Glob with wildcard in the middle: /foo/*/baz
            if pat.contains('*') {
                if glob_match(&pat, &req_path) {
                    return true;
                }
                continue;
            }

            // Exact match
            if req_path == pat {
                return true;
            }
        }
        false
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    if pat_parts.len() != path_parts.len() {
        return false;
    }
    for (p, s) in pat_parts.iter().zip(path_parts.iter()) {
        if *p == "*" {
            continue;
        }
        if *p != *s {
            return false;
        }
    }
    true
}

/// Matches request hosts. Supports exact host, port stripping, and label wildcards.
#[derive(Debug, Clone)]
pub struct HostMatcher {
    pub hosts: Vec<String>,
}

impl HostMatcher {
    pub fn new(hosts: Vec<String>) -> Self {
        Self { hosts }
    }
}

impl Matcher for HostMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let host_raw = match ctx.get_placeholder("host") {
            Some(h) => h,
            None => return false,
        };

        // Strip port and IPv6 brackets
        let req_host = if let Some(stripped) = host_raw.strip_prefix('[') {
            if let Some(close_bracket) = stripped.find(']') {
                &stripped[..close_bracket]
            } else {
                host_raw.as_str()
            }
        } else if let Some((h, _)) = host_raw.split_once(':') {
            h
        } else {
            host_raw.as_str()
        };

        let repl = Replacer::new();

        for pattern in &self.hosts {
            let pat = repl.replace_all(pattern, "");
            if pat.is_empty() {
                continue;
            }
            if pat == "*" {
                return true;
            }
            if pat.contains('*') {
                let pattern_parts: Vec<&str> = pat.split('.').collect();
                let incoming_parts: Vec<&str> = req_host.split('.').collect();
                if pattern_parts.len() != incoming_parts.len() {
                    continue;
                }
                let mut matched = true;
                for (p_part, in_part) in pattern_parts.iter().zip(incoming_parts.iter()) {
                    if *p_part == "*" {
                        continue;
                    }
                    if !p_part.eq_ignore_ascii_case(in_part) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return true;
                }
            } else if req_host.eq_ignore_ascii_case(&pat) {
                return true;
            }
        }
        false
    }
}

/// Matches HTTP methods (GET, POST, etc.) - case-insensitive.
#[derive(Debug, Clone)]
pub struct MethodMatcher {
    pub methods: HashSet<String>,
}

impl MethodMatcher {
    pub fn new(methods: Vec<String>) -> Self {
        Self {
            methods: methods.into_iter().map(|m| m.to_uppercase()).collect(),
        }
    }
}

impl Matcher for MethodMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let method = ctx.method.as_str().to_uppercase();
        self.methods.contains(&method)
    }
}

/// Matches headers. Supports exact value, presence, and wildcard `*`.
#[derive(Debug, Clone)]
pub struct HeaderMatcher {
    pub headers: HashMap<String, Vec<String>>,
}

impl HeaderMatcher {
    pub fn new(headers: HashMap<String, Vec<String>>) -> Self {
        Self { headers }
    }
}

impl Matcher for HeaderMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        for (name, allowed_values) in &self.headers {
            let actual = match ctx.headers.get(name).and_then(|v| v.to_str().ok()) {
                Some(val) => val,
                None => return false,
            };

            if allowed_values.is_empty() {
                continue; // presence check
            }

            let mut matched = false;
            for val in allowed_values {
                if val == "*" || actual == val {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }
        true
    }
}

/// Matches header values with regular expressions.
#[derive(Debug, Clone)]
pub struct HeaderRegexpMatcher {
    pub patterns: HashMap<String, Regex>,
}

impl HeaderRegexpMatcher {
    pub fn new(patterns: HashMap<String, String>) -> Result<Self, regex::Error> {
        let mut compiled = HashMap::new();
        for (k, v) in patterns {
            let re = Regex::new(&v)?;
            compiled.insert(k, re);
        }
        Ok(Self { patterns: compiled })
    }
}

impl Matcher for HeaderRegexpMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        for (name, re) in &self.patterns {
            let actual = match ctx.headers.get(name).and_then(|v| v.to_str().ok()) {
                Some(val) => val,
                None => return false,
            };
            if !re.is_match(actual) {
                return false;
            }
        }
        true
    }
}

/// Matches request path with a regular expression.
#[derive(Debug, Clone)]
pub struct PathRegexpMatcher {
    pub regex: Regex,
}

impl PathRegexpMatcher {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        let re = Regex::new(pattern)?;
        Ok(Self { regex: re })
    }
}

impl Matcher for PathRegexpMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        self.regex.is_match(ctx.uri.path())
    }
}

/// Matches query string parameters.
#[derive(Debug, Clone)]
pub struct QueryMatcher {
    pub params: HashMap<String, Vec<String>>,
}

impl QueryMatcher {
    pub fn new(params: HashMap<String, Vec<String>>) -> Self {
        Self { params }
    }
}

impl Matcher for QueryMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let query_str = match ctx.uri.query() {
            Some(q) => q,
            None => return false,
        };

        // Parse query string into map
        let mut actual_params: HashMap<String, Vec<String>> = HashMap::new();
        for pair in query_str.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                actual_params
                    .entry(k.to_string())
                    .or_default()
                    .push(v.to_string());
            } else if !pair.is_empty() {
                actual_params
                    .entry(pair.to_string())
                    .or_default()
                    .push(String::new());
            }
        }

        for (name, allowed_vals) in &self.params {
            let values = match actual_params.get(name) {
                Some(v) => v,
                None => return false,
            };

            if allowed_vals.is_empty() {
                continue;
            }

            let mut found = false;
            for val in allowed_vals {
                if val == "*" || values.contains(val) {
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }
}

/// Matches remote client IP address against CIDRs or exact IPs.
#[derive(Debug, Clone)]
pub struct RemoteIpMatcher {
    pub networks: Vec<IpNet>,
    pub exact_ips: Vec<IpAddr>,
}

impl RemoteIpMatcher {
    pub fn parse(ranges: &[String]) -> Self {
        let mut networks = Vec::new();
        let mut exact_ips = Vec::new();

        for r in ranges {
            if let Ok(net) = r.parse::<IpNet>() {
                networks.push(net);
            } else if let Ok(ip) = r.parse::<IpAddr>() {
                exact_ips.push(ip);
            }
        }

        Self {
            networks,
            exact_ips,
        }
    }
}

impl Matcher for RemoteIpMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let client_ip = match ctx.remote_addr {
            Some(addr) => addr.ip(),
            None => return false,
        };

        if self.exact_ips.contains(&client_ip) {
            return true;
        }

        for net in &self.networks {
            if net.contains(&client_ip) {
                return true;
            }
        }

        false
    }
}

/// Matches request protocol (http, https, grpc).
#[derive(Debug, Clone)]
pub struct ProtocolMatcher {
    pub protocol: String,
}

impl ProtocolMatcher {
    pub fn new(protocol: String) -> Self {
        Self {
            protocol: protocol.to_lowercase(),
        }
    }
}

impl Matcher for ProtocolMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let scheme = ctx
            .get_placeholder("scheme")
            .unwrap_or_else(|| "http".to_string())
            .to_lowercase();
        if self.protocol == "http" {
            scheme == "http"
        } else if self.protocol == "https" {
            scheme == "https" || ctx.tls_server_name.is_some()
        } else if self.protocol == "grpc" {
            let content_type = ctx
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            content_type.starts_with("application/grpc")
        } else {
            scheme == self.protocol
        }
    }
}

/// Matches arbitrary request variables.
#[derive(Debug, Clone)]
pub struct VarsMatcher {
    pub vars: HashMap<String, String>,
}

impl VarsMatcher {
    pub fn new(vars: HashMap<String, String>) -> Self {
        Self { vars }
    }
}

impl Matcher for VarsMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        for (k, expected) in &self.vars {
            let clean_k = k
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(k);
            let actual = ctx
                .get_placeholder(clean_k)
                .or_else(|| ctx.vars.get(clean_k).cloned());
            match actual {
                Some(ref val) => {
                    let exp = eval_placeholders(expected, ctx);
                    if val != &exp {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// Matches arbitrary request variables using regular expressions.
#[derive(Debug, Clone)]
pub struct VarsRegexpMatcher {
    pub patterns: HashMap<String, Regex>,
}

impl VarsRegexpMatcher {
    pub fn new(patterns: HashMap<String, String>) -> std::result::Result<Self, regex::Error> {
        let mut compiled = HashMap::new();
        for (k, v) in patterns {
            compiled.insert(k, Regex::new(&v)?);
        }
        Ok(Self { patterns: compiled })
    }
}

impl Matcher for VarsRegexpMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        for (k, re) in &self.patterns {
            let clean_k = k
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(k);
            let actual = ctx
                .get_placeholder(clean_k)
                .or_else(|| ctx.vars.get(clean_k).cloned())
                .unwrap_or_default();
            if !re.is_match(&actual) {
                return false;
            }
        }
        true
    }
}

/// Matches file existence on the local filesystem.
#[derive(Debug, Clone)]
pub struct FileMatcher {
    pub config: FileMatcherConfig,
}

impl FileMatcher {
    pub fn new(config: FileMatcherConfig) -> Self {
        Self { config }
    }
}

impl Matcher for FileMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let root = self
            .config
            .root
            .as_deref()
            .or_else(|| ctx.get_var("root"))
            .unwrap_or(".");
        let root_path = std::path::Path::new(root);

        for pat in &self.config.try_files {
            let evaluated = eval_placeholders(pat, ctx);
            let clean_pat = evaluated.trim_start_matches('/');
            let target_path = root_path.join(clean_pat);

            let matched = if evaluated.ends_with('/') {
                target_path.is_dir()
            } else {
                target_path.is_file() || target_path.exists()
            };

            if matched {
                return true;
            }
        }
        false
    }
}

/// Matches CEL-like expressions, e.g. `{http.error.status_code} == 404` or `int({http.error.status_code}) in [404, 410]`.
#[derive(Debug, Clone)]
pub struct ExpressionMatcher {
    pub expression: String,
}

impl ExpressionMatcher {
    pub fn new(expression: String) -> Self {
        Self { expression }
    }
}

impl Matcher for ExpressionMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        let evaluated = eval_placeholders(&self.expression, ctx);
        eval_expression(&evaluated, ctx)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ExprToken {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Ident(String),
    Eq,
    Ne,
    Le,
    Ge,
    Lt,
    Gt,
    And,
    Or,
    Not,
    In,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize_expr(input: &str) -> Vec<ExprToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if i + 1 < n {
            match (c, chars[i + 1]) {
                ('&', '&') => {
                    tokens.push(ExprToken::And);
                    i += 2;
                    continue;
                }
                ('|', '|') => {
                    tokens.push(ExprToken::Or);
                    i += 2;
                    continue;
                }
                ('=', '=') => {
                    tokens.push(ExprToken::Eq);
                    i += 2;
                    continue;
                }
                ('!', '=') => {
                    tokens.push(ExprToken::Ne);
                    i += 2;
                    continue;
                }
                ('<', '=') => {
                    tokens.push(ExprToken::Le);
                    i += 2;
                    continue;
                }
                ('>', '=') => {
                    tokens.push(ExprToken::Ge);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }

        match c {
            '<' => {
                tokens.push(ExprToken::Lt);
                i += 1;
                continue;
            }
            '>' => {
                tokens.push(ExprToken::Gt);
                i += 1;
                continue;
            }
            '!' => {
                tokens.push(ExprToken::Not);
                i += 1;
                continue;
            }
            '(' => {
                tokens.push(ExprToken::LParen);
                i += 1;
                continue;
            }
            ')' => {
                tokens.push(ExprToken::RParen);
                i += 1;
                continue;
            }
            '[' => {
                tokens.push(ExprToken::LBracket);
                i += 1;
                continue;
            }
            ']' => {
                tokens.push(ExprToken::RBracket);
                i += 1;
                continue;
            }
            ',' => {
                tokens.push(ExprToken::Comma);
                i += 1;
                continue;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                let mut escaped = false;
                while i < n {
                    let ch = chars[i];
                    if escaped {
                        s.push(ch);
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == quote {
                        i += 1;
                        break;
                    } else {
                        s.push(ch);
                    }
                    i += 1;
                }
                tokens.push(ExprToken::Str(s));
                continue;
            }
            _ => {}
        }

        if c.is_ascii_digit() {
            let mut num_str = String::new();
            let mut is_float = false;
            while i < n && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' {
                    if is_float {
                        break;
                    }
                    is_float = true;
                }
                num_str.push(chars[i]);
                i += 1;
            }
            if is_float {
                if let Ok(f) = num_str.parse::<f64>() {
                    tokens.push(ExprToken::Float(f));
                }
            } else if let Ok(int_val) = num_str.parse::<i64>() {
                tokens.push(ExprToken::Int(int_val));
            }
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            let mut id = String::new();
            while i < n
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || chars[i] == '.'
                    || chars[i] == '-')
            {
                id.push(chars[i]);
                i += 1;
            }
            match id.as_str() {
                "true" => tokens.push(ExprToken::Bool(true)),
                "false" => tokens.push(ExprToken::Bool(false)),
                "in" => tokens.push(ExprToken::In),
                _ => tokens.push(ExprToken::Ident(id)),
            }
            continue;
        }

        i += 1;
    }

    tokens
}

#[derive(Debug, Clone, PartialEq)]
enum ExprVal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<ExprVal>),
}

impl ExprVal {
    fn is_truthy(&self) -> bool {
        match self {
            ExprVal::Bool(b) => *b,
            ExprVal::Int(n) => *n != 0,
            ExprVal::Float(f) => *f != 0.0,
            ExprVal::Str(s) => !s.is_empty() && s != "false" && s != "0",
            ExprVal::List(l) => !l.is_empty(),
            ExprVal::Null => false,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            ExprVal::Int(n) => Some(*n as f64),
            ExprVal::Float(f) => Some(*f),
            ExprVal::Str(s) => s.trim().parse::<f64>().ok(),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            ExprVal::Int(n) => Some(*n),
            ExprVal::Float(f) => Some(*f as i64),
            ExprVal::Str(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    fn as_str(&self) -> String {
        match self {
            ExprVal::Str(s) => s.clone(),
            ExprVal::Int(n) => n.to_string(),
            ExprVal::Float(f) => f.to_string(),
            ExprVal::Bool(b) => b.to_string(),
            ExprVal::List(_) => "[...]".to_string(),
            ExprVal::Null => "".to_string(),
        }
    }

    fn eq_val(&self, other: &Self) -> bool {
        if let (Some(a), Some(b)) = (self.as_i64(), other.as_i64()) {
            return a == b;
        }
        if let (Some(a), Some(b)) = (self.as_f64(), other.as_f64()) {
            return (a - b).abs() < f64::EPSILON;
        }
        match (self, other) {
            (ExprVal::Bool(a), ExprVal::Bool(b)) => a == b,
            (ExprVal::Null, ExprVal::Null) => true,
            _ => self.as_str() == other.as_str(),
        }
    }

    fn cmp_val(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if let (Some(a), Some(b)) = (self.as_i64(), other.as_i64()) {
            return Some(a.cmp(&b));
        }
        if let (Some(a), Some(b)) = (self.as_f64(), other.as_f64()) {
            return a.partial_cmp(&b);
        }
        Some(self.as_str().cmp(&other.as_str()))
    }
}

struct ExprParser<'a> {
    tokens: &'a [ExprToken],
    pos: usize,
    ctx: &'a Context,
}

impl<'a> ExprParser<'a> {
    fn peek(&self) -> Option<&ExprToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<ExprToken> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn parse_or(&mut self) -> ExprVal {
        let mut left = self.parse_and();
        while let Some(ExprToken::Or) = self.peek() {
            self.next();
            let right = self.parse_and();
            left = ExprVal::Bool(left.is_truthy() || right.is_truthy());
        }
        left
    }

    fn parse_and(&mut self) -> ExprVal {
        let mut left = self.parse_not();
        while let Some(ExprToken::And) = self.peek() {
            self.next();
            let right = self.parse_not();
            left = ExprVal::Bool(left.is_truthy() && right.is_truthy());
        }
        left
    }

    fn parse_not(&mut self) -> ExprVal {
        if let Some(ExprToken::Not) = self.peek() {
            self.next();
            let val = self.parse_not();
            return ExprVal::Bool(!val.is_truthy());
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> ExprVal {
        let left = self.parse_primary();
        match self.peek() {
            Some(ExprToken::Eq) => {
                self.next();
                let right = self.parse_primary();
                ExprVal::Bool(left.eq_val(&right))
            }
            Some(ExprToken::Ne) => {
                self.next();
                let right = self.parse_primary();
                ExprVal::Bool(!left.eq_val(&right))
            }
            Some(ExprToken::Lt) => {
                self.next();
                let right = self.parse_primary();
                let res = left.cmp_val(&right).map(|o| o.is_lt()).unwrap_or(false);
                ExprVal::Bool(res)
            }
            Some(ExprToken::Le) => {
                self.next();
                let right = self.parse_primary();
                let res = left.cmp_val(&right).map(|o| o.is_le()).unwrap_or(false);
                ExprVal::Bool(res)
            }
            Some(ExprToken::Gt) => {
                self.next();
                let right = self.parse_primary();
                let res = left.cmp_val(&right).map(|o| o.is_gt()).unwrap_or(false);
                ExprVal::Bool(res)
            }
            Some(ExprToken::Ge) => {
                self.next();
                let right = self.parse_primary();
                let res = left.cmp_val(&right).map(|o| o.is_ge()).unwrap_or(false);
                ExprVal::Bool(res)
            }
            Some(ExprToken::In) => {
                self.next();
                let right = self.parse_primary();
                match right {
                    ExprVal::List(items) => {
                        let contains = items.iter().any(|item| item.eq_val(&left));
                        ExprVal::Bool(contains)
                    }
                    ExprVal::Str(s) => ExprVal::Bool(s.contains(&left.as_str())),
                    _ => ExprVal::Bool(false),
                }
            }
            _ => left,
        }
    }

    fn parse_primary(&mut self) -> ExprVal {
        match self.next() {
            Some(ExprToken::Int(n)) => ExprVal::Int(n),
            Some(ExprToken::Float(f)) => ExprVal::Float(f),
            Some(ExprToken::Str(s)) => ExprVal::Str(s),
            Some(ExprToken::Bool(b)) => ExprVal::Bool(b),
            Some(ExprToken::LParen) => {
                let inner = self.parse_or();
                if let Some(ExprToken::RParen) = self.peek() {
                    self.next();
                }
                inner
            }
            Some(ExprToken::LBracket) => {
                let mut items = Vec::new();
                while let Some(tok) = self.peek() {
                    if let ExprToken::RBracket = tok {
                        self.next();
                        break;
                    }
                    let item = self.parse_or();
                    items.push(item);
                    if let Some(ExprToken::Comma) = self.peek() {
                        self.next();
                    }
                }
                ExprVal::List(items)
            }
            Some(ExprToken::Ident(id)) => {
                if id == "int" && matches!(self.peek(), Some(ExprToken::LParen)) {
                    self.next();
                    let inner = self.parse_or();
                    if let Some(ExprToken::RParen) = self.peek() {
                        self.next();
                    }
                    return ExprVal::Int(inner.as_i64().unwrap_or(0));
                }
                let placeholder_val = self.ctx.get_placeholder(&id);
                let val_opt = if placeholder_val.is_some() {
                    placeholder_val
                } else {
                    self.ctx.vars.get(&id).cloned()
                };
                if let Some(val) = val_opt {
                    if let Ok(i) = val.parse::<i64>() {
                        ExprVal::Int(i)
                    } else if let Ok(f) = val.parse::<f64>() {
                        ExprVal::Float(f)
                    } else if val == "true" {
                        ExprVal::Bool(true)
                    } else if val == "false" {
                        ExprVal::Bool(false)
                    } else {
                        ExprVal::Str(val)
                    }
                } else {
                    ExprVal::Str(id)
                }
            }
            _ => ExprVal::Null,
        }
    }
}

fn eval_expression(expr: &str, ctx: &Context) -> bool {
    let tokens = tokenize_expr(expr);
    if tokens.is_empty() {
        return false;
    }
    let mut parser = ExprParser {
        tokens: &tokens,
        pos: 0,
        ctx,
    };
    parser.parse_or().is_truthy()
}

/// Inverted matcher (NOT).
pub struct NotMatcher {
    pub inner: Box<dyn Matcher>,
}

impl Matcher for NotMatcher {
    fn matches(&self, ctx: &Context) -> bool {
        !self.inner.matches(ctx)
    }
}

/// Evaluates a `MatcherSet` from config.
pub struct CompiledMatcherSet {
    matchers: Vec<Box<dyn Matcher>>,
}

impl CompiledMatcherSet {
    pub fn from_config(config: &MatcherSet) -> Self {
        let mut matchers: Vec<Box<dyn Matcher>> = Vec::new();

        if let Some(ref hosts) = config.host {
            matchers.push(Box::new(HostMatcher::new(hosts.clone())));
        }

        if let Some(ref paths) = config.path {
            matchers.push(Box::new(PathMatcher::new(paths.clone())));
        }

        if let Some(ref re_list) = config.path_regexp {
            for re_m in re_list {
                if let Ok(m) = PathRegexpMatcher::new(&re_m.pattern) {
                    matchers.push(Box::new(m));
                }
            }
        }

        if let Some(ref methods) = config.method {
            matchers.push(Box::new(MethodMatcher::new(methods.clone())));
        }

        if let Some(ref headers) = config.header {
            matchers.push(Box::new(HeaderMatcher {
                headers: headers.clone(),
            }));
        }

        if let Some(ref re_map) = config.header_regexp {
            let mut patterns = HashMap::new();
            for (k, v) in re_map {
                patterns.insert(k.clone(), v.pattern.clone());
            }
            if let Ok(m) = HeaderRegexpMatcher::new(patterns) {
                matchers.push(Box::new(m));
            }
        }

        if let Some(ref query_map) = config.query {
            matchers.push(Box::new(QueryMatcher::new(query_map.clone())));
        }

        if let Some(ref proto) = config.protocol {
            matchers.push(Box::new(ProtocolMatcher::new(proto.clone())));
        }

        if let Some(ref remote_ip) = config.remote_ip {
            matchers.push(Box::new(RemoteIpMatcher::parse(&remote_ip.ranges)));
        }

        if let Some(ref client_ip) = config.client_ip {
            let mut expanded = Vec::new();
            for r in &client_ip.ranges {
                if r == "private_ranges" {
                    expanded.extend(PRIVATE_RANGES.iter().map(|s| s.to_string()));
                } else {
                    expanded.push(r.clone());
                }
            }
            matchers.push(Box::new(RemoteIpMatcher::parse(&expanded)));
        }

        if let Some(ref vars_map) = config.vars {
            matchers.push(Box::new(VarsMatcher::new(vars_map.clone())));
        }

        if let Some(ref vars_re) = config.vars_regexp {
            if let Ok(m) = VarsRegexpMatcher::new(vars_re.clone()) {
                matchers.push(Box::new(m));
            }
        }

        if let Some(ref file_cfg) = config.file {
            matchers.push(Box::new(FileMatcher::new(file_cfg.clone())));
        }

        if let Some(ref expr) = config.expression {
            matchers.push(Box::new(ExpressionMatcher::new(expr.clone())));
        }

        if let Some(ref not_sets) = config.not {
            for not_set in not_sets {
                let inner = CompiledMatcherSet::from_config(not_set);
                matchers.push(Box::new(NotMatcher {
                    inner: Box::new(inner),
                }));
            }
        }

        Self { matchers }
    }
}

impl Matcher for CompiledMatcherSet {
    fn matches(&self, ctx: &Context) -> bool {
        for m in &self.matchers {
            if !m.matches(ctx) {
                return false;
            }
        }
        true
    }
}
