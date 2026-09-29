use std::fmt;

pub const MAX_PORT_SPAN: u64 = 65535;

/// NetworkAddress represents a parsed network address matching Caddy's `NetworkAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkAddress {
    pub network: String,
    pub host: String,
    pub start_port: u16,
    pub end_port: u16,
}

impl NetworkAddress {
    pub fn port(&self) -> String {
        if self.start_port == self.end_port {
            self.start_port.to_string()
        } else {
            format!("{}-{}", self.start_port, self.end_port)
        }
    }

    pub fn to_string_repr(&self) -> String {
        let mut netw = self.network.clone();
        if netw == "tcp" && (!self.host.is_empty() || self.port() != "0") {
            netw.clear();
        }
        join_network_address(&netw, &self.host, &self.port())
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

pub fn is_unix_network(netw: &str) -> bool {
    netw.starts_with("unix")
}

pub fn is_fd_network(netw: &str) -> bool {
    netw.starts_with("fd")
}

/// Splits a network address into network, host, and port components.
pub fn split_network_address(a: &str) -> Result<(String, String, String), String> {
    let mut network = String::new();
    let mut a = a;

    if let Some((before, after)) = a.split_once('/') {
        network = before.trim().to_lowercase();
        a = after;
        if is_unix_network(&network) || is_fd_network(&network) {
            let host = a.to_string();
            return Ok((network, host, String::new()));
        }
    }

    // Try splitting host:port
    let (host, port) = match split_host_port_relaxed(a) {
        Ok((h, p)) => (h, p),
        Err(_) => {
            // Missing port: try stripping brackets around IPv6 host
            let stripped = a.trim_matches(|c| c == '[' || c == ']');
            (stripped.to_string(), String::new())
        }
    };

    Ok((network, host, port))
}

fn split_host_port_relaxed(val: &str) -> Result<(String, String), String> {
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
        let host = &val[..colon_idx];
        let port = &val[colon_idx + 1..];
        if host.contains(':') {
            return Err("too many colons in address".into());
        }
        return Ok((host.to_string(), port.to_string()));
    }

    Err("missing port in address".into())
}

/// Combines network, host, and port into a single address string.
pub fn join_network_address(network: &str, host: &str, port: &str) -> String {
    let mut a = String::new();
    if !network.is_empty() {
        a.push_str(network);
        a.push('/');
    }

    if (!host.is_empty() && port.is_empty()) || is_unix_network(network) || is_fd_network(network) {
        a.push_str(host);
    } else if !port.is_empty() {
        if host.contains(':') && !host.starts_with('[') {
            a.push_str(&format!("[{}]:{}", host, port));
        } else {
            a.push_str(&format!("{}:{}", host, port));
        }
    }

    a
}

/// Parses addr into a NetworkAddress struct.
pub fn parse_network_address(addr: &str) -> Result<NetworkAddress, String> {
    parse_network_address_with_defaults(addr, "tcp", 0)
}

/// Parses addr into a NetworkAddress struct with default network and port.
pub fn parse_network_address_with_defaults(
    addr: &str,
    default_network: &str,
    default_port: u16,
) -> Result<NetworkAddress, String> {
    if addr.is_empty() {
        return Ok(NetworkAddress::default());
    }

    let (mut network, host, port) = split_network_address(addr)?;

    if network.is_empty() {
        network = default_network.to_string();
    }

    if is_unix_network(&network) || is_fd_network(&network) {
        return Ok(NetworkAddress {
            network,
            host,
            start_port: 0,
            end_port: 0,
        });
    }

    let (start, end) = if port.is_empty() {
        (default_port, default_port)
    } else {
        let (before, after) = if let Some((b, a)) = port.split_once('-') {
            (b, a)
        } else {
            (port.as_str(), port.as_str())
        };

        let start_val: u64 = before
            .parse()
            .map_err(|e| format!("invalid start port: {}", e))?;
        let end_val: u64 = after
            .parse()
            .map_err(|e| format!("invalid end port: {}", e))?;

        if start_val > 65535 || end_val > 65535 {
            return Err("port out of range 0-65535".into());
        }

        if end_val < start_val {
            return Err("end port must not be less than start port".into());
        }

        if (end_val - start_val) + 1 > MAX_PORT_SPAN {
            return Err(format!("port range exceeds {} ports", MAX_PORT_SPAN));
        }

        (start_val as u16, end_val as u16)
    };

    Ok(NetworkAddress {
        network,
        host,
        start_port: start,
        end_port: end,
    })
}
