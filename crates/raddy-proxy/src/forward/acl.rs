use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use crate::error::{ProxyError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
    NoMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclRuleConfig {
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub allow: bool,
}

#[derive(Debug, Clone)]
pub enum AclRule {
    Ip {
        net: IpNet,
        allow: bool,
    },
    Domain {
        domain: String,
        subdomains_allowed: bool,
        allow: bool,
    },
    All {
        allow: bool,
    },
}

impl AclRule {
    pub fn try_match(&self, ip: Option<IpAddr>, host: &str) -> AclDecision {
        match self {
            AclRule::All { allow } => {
                if *allow {
                    AclDecision::Allow
                } else {
                    AclDecision::Deny
                }
            }
            AclRule::Ip { net, allow } => {
                if let Some(ip_addr) = ip {
                    if net.contains(&ip_addr) {
                        return if *allow {
                            AclDecision::Allow
                        } else {
                            AclDecision::Deny
                        };
                    }
                }
                AclDecision::NoMatch
            }
            AclRule::Domain {
                domain,
                subdomains_allowed,
                allow,
            } => {
                let trimmed_host = host.trim_start_matches('.').to_lowercase();
                if trimmed_host == *domain
                    || (*subdomains_allowed && trimmed_host.ends_with(&format!(".{}", domain)))
                {
                    if *allow {
                        AclDecision::Allow
                    } else {
                        AclDecision::Deny
                    }
                } else {
                    AclDecision::NoMatch
                }
            }
        }
    }
}

pub fn new_acl_rule(subject: &str, allow: bool) -> Result<AclRule> {
    let subject = subject.trim();
    if subject.eq_ignore_ascii_case("all") {
        return Ok(AclRule::All { allow });
    }

    // Try parsing as CIDR
    if let Ok(net) = IpNet::from_str(subject) {
        return Ok(AclRule::Ip { net, allow });
    }

    // Try parsing as single IP
    if let Ok(ip) = IpAddr::from_str(subject) {
        let net = match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).map_err(|e| {
                ProxyError::Core(raddy_core::CoreError::Config(e.to_string()))
            })?),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).map_err(|e| {
                ProxyError::Core(raddy_core::CoreError::Config(e.to_string()))
            })?),
        };
        return Ok(AclRule::Ip { net, allow });
    }

    // Domain rule
    let mut domain = subject;
    let mut subdomains_allowed = false;
    if let Some(rest) = domain.strip_prefix("*.") {
        subdomains_allowed = true;
        domain = rest;
    }

    validate_domain_lite(domain)?;

    Ok(AclRule::Domain {
        domain: domain.to_lowercase(),
        subdomains_allowed,
        allow,
    })
}

fn validate_domain_lite(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(ProxyError::Core(raddy_core::CoreError::Config(
            "Empty domain name".into(),
        )));
    }

    for b in domain.bytes() {
        let is_valid = (b'a'..=b'z').contains(&b)
            || (b'A'..=b'Z').contains(&b)
            || (b'0'..=b'9').contains(&b)
            || b == b'_'
            || b == b'-'
            || b == b'.';
        if !is_valid {
            return Err(ProxyError::Core(raddy_core::CoreError::Config(format!(
                "Character '{}' is not allowed in domain '{}'",
                b as char, domain
            ))));
        }
    }

    for section in domain.split('.') {
        if section.is_empty() {
            return Err(ProxyError::Core(raddy_core::CoreError::Config(format!(
                "Empty section between dots in domain '{}'",
                domain
            ))));
        }
        if section.len() > 63 {
            return Err(ProxyError::Core(raddy_core::CoreError::Config(format!(
                "Domain section too long in domain '{}'",
                domain
            ))));
        }
    }

    Ok(())
}

pub fn read_lines_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(&path).map_err(|e| {
        ProxyError::Core(raddy_core::CoreError::Config(format!(
            "Failed to open ACL file '{}': {}",
            path.as_ref().display(),
            e
        )))
    })?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed.to_string());
        }
    }
    Ok(lines)
}

/// Builds the default ACL rules:
/// - deny private/local subnets:
///   10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fe80::/10
/// - allow all
pub fn default_acl_suffix_rules() -> Vec<AclRule> {
    let deny_nets = [
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fe80::/10",
    ];

    let mut rules = Vec::new();
    for net_str in deny_nets {
        if let Ok(rule) = new_acl_rule(net_str, false) {
            rules.push(rule);
        }
    }
    rules.push(AclRule::All { allow: true });
    rules
}

/// Evaluates if a given host & resolved IP is allowed.
pub fn is_host_allowed(rules: &[AclRule], host: &str, ip: IpAddr) -> bool {
    for rule in rules {
        match rule.try_match(Some(ip), host) {
            AclDecision::Deny => return false,
            AclDecision::Allow => return true,
            AclDecision::NoMatch => {}
        }
    }
    false
}

/// Checks early domain rules before DNS resolution.
/// Returns Some(true) if allowed early, Some(false) if denied early, or None if DNS check is required.
pub fn check_early_domain_rules(rules: &[AclRule], host: &str) -> Option<bool> {
    for rule in rules {
        if let AclRule::Domain { .. } = rule {
            match rule.try_match(None, host) {
                AclDecision::Deny => return Some(false),
                AclDecision::Allow => return Some(true),
                AclDecision::NoMatch => {}
            }
        }
    }
    None
}
