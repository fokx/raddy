use std::path::{Path, PathBuf};
use std::sync::Arc;
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use crate::error::{Result, TlsError};

/// Abstract certificate storage backend interface.
#[async_trait]
pub trait CertStorage: Send + Sync {
    async fn store(&self, identifier: &str, cert_pem: &str, key_pem: &str) -> Result<()>;
    async fn load(&self, identifier: &str) -> Result<Option<(String, String)>>;
    async fn exists(&self, identifier: &str) -> bool;
}

/// Filesystem certificate cache.
#[derive(Debug, Clone)]
pub struct FileCertStorage {
    base_dir: PathBuf,
}

impl FileCertStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    pub fn default_dir() -> PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("raddy")
            .join("certificates")
    }

    fn item_dir(&self, identifier: &str) -> PathBuf {
        let sanitized = identifier.replace(['/', '\\', ':', '*'], "_");
        self.base_dir.join(sanitized)
    }
}

#[async_trait]
impl CertStorage for FileCertStorage {
    async fn store(&self, identifier: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        let dir = self.item_dir(identifier);
        tokio::fs::create_dir_all(&dir).await?;

        tokio::fs::write(dir.join("cert.pem"), cert_pem).await?;
        tokio::fs::write(dir.join("key.pem"), key_pem).await?;
        Ok(())
    }

    async fn load(&self, identifier: &str) -> Result<Option<(String, String)>> {
        let dir = self.item_dir(identifier);
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert = tokio::fs::read_to_string(cert_path).await?;
        let key = tokio::fs::read_to_string(key_path).await?;
        Ok(Some((cert, key)))
    }

    async fn exists(&self, identifier: &str) -> bool {
        let dir = self.item_dir(identifier);
        dir.join("cert.pem").exists() && dir.join("key.pem").exists()
    }
}

/// Parses certificate and private key PEM strings into a Rustls CertifiedKey.
pub fn parse_certified_key(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    // 1. Parse certificate chain
    let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

    if certs.is_empty() {
        return Err(TlsError::Certificate("No certificates found in PEM".into()));
    }

    // 2. Parse private key
    let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::Certificate(format!("Failed to parse private key PEM: {}", e)))?
        .ok_or_else(|| TlsError::Certificate("No private key found in PEM".into()))?;

    // 3. Create signing key using rustls default crypto provider
    let signing_key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| TlsError::Certificate(format!("Failed to load signing key: {}", e)))?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    Ok(Arc::new(certified_key))
}
