use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// SNI-based certificate resolver implementing `rustls::server::ResolvesServerCert`.
#[derive(Clone, Default)]
pub struct SniResolver {
    exact_certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    wildcard_certs: Arc<RwLock<Vec<(String, Arc<CertifiedKey>)>>>,
    default_cert: Arc<RwLock<Option<Arc<CertifiedKey>>>>,
}

impl SniResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, name: impl Into<String>, key: Arc<CertifiedKey>) {
        let name_str = name.into().to_lowercase();
        if let Some(suffix) = name_str.strip_prefix("*.") {
            self.wildcard_certs.write().push((suffix.to_string(), key));
        } else {
            self.exact_certs.write().insert(name_str, key);
        }
    }

    pub fn set_default(&self, key: Arc<CertifiedKey>) {
        *self.default_cert.write() = Some(key);
    }

    pub fn cert_count(&self) -> usize {
        self.exact_certs.read().len() + self.wildcard_certs.read().len()
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("exact_count", &self.exact_certs.read().len())
            .field("wildcard_count", &self.wildcard_certs.read().len())
            .finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let sni_lower = sni.to_lowercase();

            // 1. Exact match
            if let Some(cert) = self.exact_certs.read().get(&sni_lower) {
                return Some(cert.clone());
            }

            // 2. Wildcard match (*.example.com)
            for (suffix, cert) in self.wildcard_certs.read().iter() {
                if sni_lower.ends_with(suffix) && sni_lower.len() > suffix.len() {
                    return Some(cert.clone());
                }
            }
        }

        // 3. Fallback default certificate
        self.default_cert.read().clone()
    }
}
