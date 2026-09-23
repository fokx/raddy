use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use ipnet::IpNet;
use crate::context::Context;
use crate::config::MatcherSet;
use crate::placeholder::PlaceholderProvider;

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &Context) -> bool;
}

/// Matches request paths. Supports exact match, prefix match (`/path*`), or wildcards.
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
        let path = ctx.uri.path();
        for pattern in &self.patterns {
            if pattern == "*" || pattern == "/*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix('*') {
                if path.starts_with(prefix) {
                    return true;
                }
            } else if path == pattern {
                return true;
            }
        }
        false
    }
}

/// Matches request hosts. Supports exact host and leading wildcard `*.example.com`.
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
        let host = match ctx.get_placeholder("host") {
            Some(h) => h,
            None => return false,
        };

        for pattern in &self.hosts {
            if pattern == "*" {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if host.ends_with(suffix) && host.len() > suffix.len() {
                    return true;
                }
            } else if host.eq_ignore_ascii_case(pattern) {
                return true;
            }
        }
        false
    }
}

/// Matches HTTP methods (GET, POST, etc.)
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
        self.methods.contains(ctx.method.as_str())
    }
}

/// Matches headers.
#[derive(Debug, Clone)]
pub struct HeaderMatcher {
    pub headers: HashMap<String, Vec<String>>,
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

        Self { networks, exact_ips }
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

        if let Some(ref methods) = config.method {
            matchers.push(Box::new(MethodMatcher::new(methods.clone())));
        }

        if let Some(ref headers) = config.header {
            matchers.push(Box::new(HeaderMatcher {
                headers: headers.clone(),
            }));
        }

        if let Some(ref remote_ip) = config.remote_ip {
            matchers.push(Box::new(RemoteIpMatcher::parse(&remote_ip.ranges)));
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
        // Conjunction (AND): all specified matchers in a set must match
        for m in &self.matchers {
            if !m.matches(ctx) {
                return false;
            }
        }
        true
    }
}
