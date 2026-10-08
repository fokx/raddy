use ipnet::IpNet;
use regex::Regex;
use std::net::{IpAddr, SocketAddr};

/// Matches client TLS SNI server name against a list of names or wildcards.
#[derive(Debug, Clone)]
pub struct ServerNameMatcher {
    pub names: Vec<String>,
}

impl ServerNameMatcher {
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    pub fn matches(&self, server_name: &str) -> bool {
        if server_name.is_empty() {
            return false;
        }

        let sni_norm = server_name.to_lowercase();

        for name in &self.names {
            let pat = name.to_lowercase();
            if pat == "*" {
                return true;
            }
            if let Some(suffix) = pat.strip_prefix("*.") {
                // Must have at least one label preceding suffix, e.g. "sub.example.com" matches "*.example.com"
                if sni_norm.ends_with(suffix)
                    && sni_norm.len() > suffix.len()
                    && !sni_norm[..sni_norm.len() - suffix.len()].contains('.')
                {
                    return true;
                }
                // Also support multi-level wildcard like "*.sub.example.com"
                if sni_norm.ends_with(suffix) && sni_norm.len() > suffix.len() {
                    return true;
                }
            } else if sni_norm == pat {
                return true;
            }
        }

        false
    }
}

/// Matches TLS SNI server name with a regex.
#[derive(Debug, Clone)]
pub struct ServerNameREMatcher {
    pub regex: Option<Regex>,
}

impl ServerNameREMatcher {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        if pattern.is_empty() {
            return Ok(Self { regex: None });
        }
        let re = Regex::new(pattern)?;
        Ok(Self { regex: Some(re) })
    }

    pub fn matches(&self, server_name: &str) -> bool {
        match &self.regex {
            Some(re) => re.is_match(server_name),
            None => server_name.is_empty(),
        }
    }
}

/// Matches connection remote IP against ranges.
#[derive(Debug, Clone)]
pub struct RemoteIpMatcher {
    pub ranges: Vec<IpNet>,
    pub exact_ips: Vec<IpAddr>,
    pub not_ranges: Vec<IpNet>,
    pub not_exact_ips: Vec<IpAddr>,
}

impl RemoteIpMatcher {
    pub fn new(ranges: &[String], not_ranges: &[String]) -> Self {
        let mut r_nets = Vec::new();
        let mut r_ips = Vec::new();
        for r in ranges {
            if let Ok(net) = r.parse::<IpNet>() {
                r_nets.push(net);
            } else if let Ok(ip) = r.parse::<IpAddr>() {
                r_ips.push(ip);
            }
        }

        let mut nr_nets = Vec::new();
        let mut nr_ips = Vec::new();
        for r in not_ranges {
            if let Ok(net) = r.parse::<IpNet>() {
                nr_nets.push(net);
            } else if let Ok(ip) = r.parse::<IpAddr>() {
                nr_ips.push(ip);
            }
        }

        Self {
            ranges: r_nets,
            exact_ips: r_ips,
            not_ranges: nr_nets,
            not_exact_ips: nr_ips,
        }
    }

    pub fn matches(&self, addr: &str) -> bool {
        let ip: IpAddr = if let Ok(sock) = addr.parse::<SocketAddr>() {
            sock.ip()
        } else if let Ok(ip) = addr.parse::<IpAddr>() {
            ip
        } else {
            return false;
        };

        // Check not_ranges first
        if self.not_exact_ips.contains(&ip) {
            return false;
        }
        for net in &self.not_ranges {
            if net.contains(&ip) {
                return false;
            }
        }

        if self.ranges.is_empty() && self.exact_ips.is_empty() {
            return true;
        }

        if self.exact_ips.contains(&ip) {
            return true;
        }

        for net in &self.ranges {
            if net.contains(&ip) {
                return true;
            }
        }

        false
    }
}
