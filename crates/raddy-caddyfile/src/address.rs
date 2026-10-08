use crate::error::{ParseError, ParseResult};
use std::net::Ipv6Addr;
use std::str::FromStr;

/// Represents a parsed site address matching Caddy's `httpcaddyfile.Address`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Address {
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub path: String,
}

impl Address {
    /// Formats the address into a human-readable URL string.
    pub fn to_string_repr(&self) -> String {
        if self.host.is_empty() && self.port.is_empty() {
            return String::new();
        }

        let mut scheme = self.scheme.clone();
        if scheme.is_empty() {
            if self.port == "443" {
                scheme = "https".to_string();
            } else {
                scheme = "http".to_string();
            }
        }

        let mut s = String::new();
        if !scheme.is_empty() {
            s.push_str(&scheme);
            s.push_str("://");
        }

        if !self.port.is_empty()
            && ((scheme == "https" && self.port != "443")
                || (scheme == "http" && self.port != "80"))
        {
            s.push_str(&join_host_port(&self.host, &self.port));
        } else {
            s.push_str(&self.host);
        }

        if !self.path.is_empty() {
            s.push_str(&self.path);
        }

        s
    }

    /// Normalizes the address: lowercases scheme and host outside `{placeholder}` spans,
    /// and canonicalizes IPv6 host addresses.
    pub fn normalize(&self) -> Address {
        let mut host = self.host.trim().to_string();

        // Check if host is IPv6 and canonicalize (if not IPv4-mapped, matching Go's !ip.Is4In6())
        if let Ok(ip6) = Ipv6Addr::from_str(&host) {
            let segs = ip6.segments();
            let is_ipv4_mapped = segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0xffff;
            if !is_ipv4_mapped {
                host = ip6.to_string();
            }
        }

        Address {
            original: self.original.clone(),
            scheme: lower_except_placeholders(&self.scheme),
            host: lower_except_placeholders(&host),
            port: self.port.clone(),
            path: self.path.clone(),
        }
    }
}

/// Helper function to join host and port matching Go's `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Helper function to split host and port matching Go's `net.SplitHostPort`.
pub fn split_host_port(val: &str) -> Result<(String, String), String> {
    if let Some(stripped) = val.strip_prefix('[') {
        if let Some(close_bracket) = stripped.find(']') {
            let host = &stripped[..close_bracket];
            let rest = &stripped[close_bracket + 1..];
            if let Some(colon_port) = rest.strip_prefix(':') {
                return Ok((host.to_string(), colon_port.to_string()));
            } else {
                return Err("missing port in address".into());
            }
        } else {
            return Err("missing ']' in address".into());
        }
    }

    if let Some(colon_idx) = val.rfind(':') {
        // Make sure there are no other colons (which would be an IPv6 address without brackets)
        let host = &val[..colon_idx];
        let port = &val[colon_idx + 1..];
        if host.contains(':') {
            return Err("too many colons in address".into());
        }
        return Ok((host.to_string(), port.to_string()));
    }

    Err("missing port in address".into())
}

/// Parses an address string into structured `Address` components.
pub fn parse_address(str_val: &str) -> ParseResult<Address> {
    let mut str_val = str_val;
    if str_val.len() > 4096 {
        str_val = &str_val[..4096];
    }
    let remaining = str_val.trim();
    let mut a = Address {
        original: remaining.to_string(),
        ..Default::default()
    };

    let mut remaining_str = remaining;

    // extract scheme
    if let Some(idx) = remaining_str.find("://") {
        a.scheme = remaining_str[..idx].to_string();
        remaining_str = &remaining_str[idx + 3..];
    }

    // extract host and port vs path
    let (host_port_part, path_part) = if let Some(slash_idx) = remaining_str.find('/') {
        (
            &remaining_str[..slash_idx],
            Some(&remaining_str[slash_idx..]),
        )
    } else {
        (remaining_str, None)
    };

    if !host_port_part.is_empty() {
        if let Ok((h, p)) = split_host_port(host_port_part) {
            a.host = h;
            a.port = p;
        } else if let Ok((h, p)) = split_host_port(&format!("{}:", host_port_part)) {
            a.host = h;
            a.port = p;
        } else {
            a.host = host_port_part.to_string();
        }
    }

    if let Some(p) = path_part {
        a.path = p.to_string();
    }

    // Validate port if present
    if !a.port.is_empty() {
        match a.port.parse::<i64>() {
            Ok(p) if (0..=65535).contains(&p) => {}
            Ok(p) => {
                return Err(ParseError::Syntax {
                    line: 0,
                    col: 0,
                    message: format!("port {} is out of range", p),
                });
            }
            Err(_) => {
                return Err(ParseError::Syntax {
                    line: 0,
                    col: 0,
                    message: format!("invalid port '{}'", a.port),
                });
            }
        }
    }

    Ok(a)
}

/// Lowercases s except within placeholders (substrings in non-escaped '{ }' spans).
pub fn lower_except_placeholders(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut escaped = false;
    let mut in_placeholder = false;

    for ch in s.chars() {
        if ch == '\\' && !escaped {
            escaped = true;
            result.push(ch);
            continue;
        }
        if ch == '{' && !escaped {
            in_placeholder = true;
        }
        if ch == '}' && in_placeholder && !escaped {
            in_placeholder = false;
        }
        if in_placeholder {
            result.push(ch);
        } else {
            for lower_ch in ch.to_lowercase() {
                result.push(lower_ch);
            }
        }
        escaped = false;
    }

    result
}
