use std::collections::HashMap;
use std::net::SocketAddr;

/// Context containing metadata and extracted variables for a Layer 4 connection.
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub vars: HashMap<String, String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

impl ConnectionContext {
    pub fn new(remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        let mut vars = HashMap::new();
        vars.insert("remote_ip".to_string(), remote_addr.ip().to_string());
        vars.insert("remote_port".to_string(), remote_addr.port().to_string());
        vars.insert("local_ip".to_string(), local_addr.ip().to_string());
        vars.insert("local_port".to_string(), local_addr.port().to_string());

        Self {
            remote_addr,
            local_addr,
            vars,
            sni: None,
            alpn: None,
        }
    }

    pub fn set_var(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(key.into(), value.into());
    }

    pub fn get_var(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }
}
