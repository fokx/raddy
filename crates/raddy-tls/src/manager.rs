use std::net::IpAddr;
use std::sync::Arc;
use ipnet::IpNet;
use rustls::server::ServerConfig;
use tokio_rustls::TlsAcceptor;
use crate::acme::{AcmeClient, Http01ChallengeStore, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING};
use crate::error::Result;
use crate::local_ca::LocalCa;
use crate::sni::SniResolver;
use crate::storage::{parse_certified_key, CertStorage, FileCertStorage};

pub struct TlsManager {
    local_ca: Arc<LocalCa>,
    storage: Arc<dyn CertStorage>,
    acme: Arc<AcmeClient>,
    sni_resolver: Arc<SniResolver>,
}

impl TlsManager {
    pub fn new(email: Option<String>, staging: bool) -> Result<Self> {
        let local_ca = Arc::new(LocalCa::new()?);
        let storage = Arc::new(FileCertStorage::new(FileCertStorage::default_dir()));
        let challenge_store = Http01ChallengeStore::new();

        let acme_url = if staging {
            LETS_ENCRYPT_STAGING
        } else {
            LETS_ENCRYPT_PRODUCTION
        };

        let acme = Arc::new(AcmeClient::new(acme_url, email, challenge_store));
        let sni_resolver = Arc::new(SniResolver::new());

        Ok(Self {
            local_ca,
            storage,
            acme,
            sni_resolver,
        })
    }

    pub fn with_storage(mut self, storage: Arc<dyn CertStorage>) -> Self {
        self.storage = storage;
        self
    }

    pub fn sni_resolver(&self) -> Arc<SniResolver> {
        self.sni_resolver.clone()
    }

    pub fn challenge_store(&self) -> Http01ChallengeStore {
        self.acme.challenge_store().clone()
    }

    /// Automatically provisions and installs a certificate for the given identifier.
    /// Checks if internal/local (Local CA) or public (ACME, supporting both domain names and public IPs).
    pub async fn provision_identifier(&self, identifier: &str, force_internal: bool) -> Result<()> {
        let is_internal = force_internal || is_local_or_private(identifier);

        if is_internal {
            // Check storage first
            if let Some((cert_pem, key_pem)) = self.storage.load(identifier).await? {
                let certified_key = parse_certified_key(&cert_pem, &key_pem)?;
                self.sni_resolver.insert(identifier, certified_key.clone());
                if self.sni_resolver.cert_count() == 1 {
                    self.sni_resolver.set_default(certified_key);
                }
                return Ok(());
            }

            // Generate via Local CA
            let (cert_pem, key_pem) = self.local_ca.issue_certificate(&[identifier.to_string()])?;
            self.storage.store(identifier, &cert_pem, &key_pem).await?;

            let certified_key = parse_certified_key(&cert_pem, &key_pem)?;
            self.sni_resolver.insert(identifier, certified_key.clone());
            if self.sni_resolver.cert_count() == 1 {
                self.sni_resolver.set_default(certified_key);
            }
            tracing::info!("Issued local development certificate for '{}'", identifier);
        } else {
            // Check storage first
            if let Some((cert_pem, key_pem)) = self.storage.load(identifier).await? {
                let certified_key = parse_certified_key(&cert_pem, &key_pem)?;
                self.sni_resolver.insert(identifier, certified_key.clone());
                if self.sni_resolver.cert_count() == 1 {
                    self.sni_resolver.set_default(certified_key);
                }
                return Ok(());
            }

            // Public domain or public IP certificate via ACME (instant-acme)
            tracing::info!("Requesting ACME certificate for '{}'...", identifier);
            let (cert_pem, key_pem) = self.acme.issue_certificate(&[identifier.to_string()]).await?;
            self.storage.store(identifier, &cert_pem, &key_pem).await?;

            let certified_key = parse_certified_key(&cert_pem, &key_pem)?;
            self.sni_resolver.insert(identifier, certified_key.clone());
            if self.sni_resolver.cert_count() == 1 {
                self.sni_resolver.set_default(certified_key);
            }
            tracing::info!("Successfully obtained and installed ACME certificate for '{}'", identifier);
        }

        Ok(())
    }

    /// Builds a rustls ServerConfig configured with the SniResolver and ALPN (h2, http/1.1).
    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.sni_resolver.clone());

        // Enable ALPN for HTTP/2 and HTTP/1.1
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Arc::new(config))
    }

    /// Creates a tokio-rustls TlsAcceptor.
    pub fn build_tls_acceptor(&self) -> Result<TlsAcceptor> {
        let cfg = self.build_server_config()?;
        Ok(TlsAcceptor::from(cfg))
    }
}

/// Determines if an identifier is local/internal or private IP.
pub fn is_local_or_private(identifier: &str) -> bool {
    let lower = identifier.to_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".test")
    {
        return true;
    }

    if let Ok(ip) = lower.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let loopback = "127.0.0.0/8".parse::<IpNet>().unwrap();
                let private_10 = "10.0.0.0/8".parse::<IpNet>().unwrap();
                let private_172 = "172.16.0.0/12".parse::<IpNet>().unwrap();
                let private_192 = "192.168.0.0/16".parse::<IpNet>().unwrap();
                let link_local = "169.254.0.0/16".parse::<IpNet>().unwrap();

                let ip_net = IpNet::from(IpAddr::V4(v4));
                loopback.contains(&ip_net)
                    || private_10.contains(&ip_net)
                    || private_172.contains(&ip_net)
                    || private_192.contains(&ip_net)
                    || link_local.contains(&ip_net)
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        false
    }
}
