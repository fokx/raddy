use std::path::PathBuf;

use crate::error::{AdminError, Result};

/// Parsed representation of an Admin API listening address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAdminAddr {
    /// TCP socket address (e.g. `127.0.0.1:2019` or `localhost:2019`).
    Tcp(String),
    /// Unix domain socket path with an optional permission mode (e.g. `0660`).
    Unix {
        path: PathBuf,
        mode: Option<u32>,
    },
}

impl ParsedAdminAddr {
    /// Returns true if this address is a Unix domain socket.
    pub fn is_unix(&self) -> bool {
        matches!(self, ParsedAdminAddr::Unix { .. })
    }
}

/// Parses an Admin API address string into either a TCP address or a Unix domain socket path.
///
/// Supported formats:
/// - Unix domain sockets:
///   - `unix//run/raddy/raddy-admin.sock`
///   - `unix//run/raddy/raddy-admin.sock|0660`
///   - `unix:///run/raddy/raddy-admin.sock`
///   - `unix:/run/raddy/raddy-admin.sock`
///   - `unix/path/to/socket`
///   - `/run/raddy/raddy-admin.sock`
/// - TCP network addresses:
///   - `127.0.0.1:2019`
///   - `localhost:2019`
///   - `:2019` (normalized to `127.0.0.1:2019`)
///   - `http://127.0.0.1:2019`
///   - `tcp/127.0.0.1:2019`
///   - `tcp/:2019`
pub fn parse_admin_addr(raw: &str) -> Result<ParsedAdminAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(ParsedAdminAddr::Tcp("127.0.0.1:2019".into()));
    }

    // Check for file mode suffix separated by '|': e.g. unix//path.sock|0660
    let (addr_str, mode) = if let Some((addr_part, mode_part)) = raw.split_once('|') {
        let trimmed_mode = mode_part.trim();
        let mode_num = u32::from_str_radix(trimmed_mode, 8).map_err(|e| {
            AdminError::BadRequest(format!(
                "Invalid socket file mode '{}': must be octal (e.g. 0660): {}",
                trimmed_mode, e
            ))
        })?;
        (addr_part.trim(), Some(mode_num))
    } else {
        (raw, None)
    };

    // Determine network type
    if addr_str.starts_with("unix:") || addr_str.starts_with("unix/") || addr_str.starts_with('/') {
        let path_str = if let Some(rest) = addr_str.strip_prefix("unix://") {
            rest
        } else if let Some(rest) = addr_str.strip_prefix("unix:") {
            rest
        } else if let Some(rest) = addr_str.strip_prefix("unix/") {
            rest
        } else {
            addr_str
        };

        Ok(ParsedAdminAddr::Unix {
            path: PathBuf::from(path_str),
            mode,
        })
    } else {
        // TCP address
        let mut tcp_addr = addr_str;
        if let Some(rest) = tcp_addr.strip_prefix("http://") {
            tcp_addr = rest;
        }
        if let Some(rest) = tcp_addr.strip_prefix("tcp://") {
            tcp_addr = rest;
        } else if let Some(rest) = tcp_addr.strip_prefix("tcp/") {
            tcp_addr = rest;
        } else if let Some(rest) = tcp_addr.strip_prefix("tcp4/") {
            tcp_addr = rest;
        } else if let Some(rest) = tcp_addr.strip_prefix("tcp6/") {
            tcp_addr = rest;
        }

        let tcp_str = if tcp_addr.starts_with(':') {
            format!("127.0.0.1{}", tcp_addr)
        } else {
            tcp_addr.to_string()
        };

        Ok(ParsedAdminAddr::Tcp(tcp_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unix_socket_addresses() {
        assert_eq!(
            parse_admin_addr("unix//run/raddy/raddy-admin.sock").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: None,
            }
        );

        assert_eq!(
            parse_admin_addr("unix//run/raddy/raddy-admin.sock|0660").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: Some(0o660),
            }
        );

        assert_eq!(
            parse_admin_addr("unix//run/raddy/raddy-admin.sock|0600").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: Some(0o600),
            }
        );

        assert_eq!(
            parse_admin_addr("unix:///run/raddy/raddy-admin.sock").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: None,
            }
        );

        assert_eq!(
            parse_admin_addr("unix:/run/raddy/raddy-admin.sock").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: None,
            }
        );

        assert_eq!(
            parse_admin_addr("/run/raddy/raddy-admin.sock").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("/run/raddy/raddy-admin.sock"),
                mode: None,
            }
        );

        assert_eq!(
            parse_admin_addr("unix/tmp/raddy-admin.sock").unwrap(),
            ParsedAdminAddr::Unix {
                path: PathBuf::from("tmp/raddy-admin.sock"),
                mode: None,
            }
        );
    }

    #[test]
    fn test_parse_tcp_addresses() {
        assert_eq!(
            parse_admin_addr("127.0.0.1:2019").unwrap(),
            ParsedAdminAddr::Tcp("127.0.0.1:2019".into())
        );

        assert_eq!(
            parse_admin_addr(":2019").unwrap(),
            ParsedAdminAddr::Tcp("127.0.0.1:2019".into())
        );

        assert_eq!(
            parse_admin_addr("http://127.0.0.1:2019").unwrap(),
            ParsedAdminAddr::Tcp("127.0.0.1:2019".into())
        );

        assert_eq!(
            parse_admin_addr("tcp/localhost:2019").unwrap(),
            ParsedAdminAddr::Tcp("localhost:2019".into())
        );

        assert_eq!(
            parse_admin_addr("").unwrap(),
            ParsedAdminAddr::Tcp("127.0.0.1:2019".into())
        );
    }

    #[test]
    fn test_invalid_mode() {
        assert!(parse_admin_addr("unix//path.sock|999").is_err());
        assert!(parse_admin_addr("unix//path.sock|invalid").is_err());
    }
}
