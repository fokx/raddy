use crate::error::{Result, TlsError};
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Converts an ACME directory URL to a sanitized directory key name matching Caddy/certmagic.
/// E.g.:
/// - https://acme-v02.api.letsencrypt.org/directory -> acme-v02.api.letsencrypt.org-directory
/// - https://acme-staging-v02.api.letsencrypt.org/directory -> acme-staging-v02.api.letsencrypt.org-directory
/// - https://acme.zerossl.com/v2/DV90 -> acme.zerossl.com-v2-dv90
pub fn ca_dir_key(ca_url: &str) -> String {
    let s = ca_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    sanitized.trim_matches('-').to_lowercase()
}

/// Abstract certificate storage backend interface.
#[async_trait]
pub trait CertStorage: Send + Sync {
    async fn store(&self, identifier: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        self.store_with_ca(identifier, cert_pem, key_pem, None)
            .await
    }
    async fn store_with_ca(
        &self,
        identifier: &str,
        cert_pem: &str,
        key_pem: &str,
        ca_url: Option<&str>,
    ) -> Result<()>;
    async fn load(&self, identifier: &str) -> Result<Option<(String, String)>>;
    async fn exists(&self, identifier: &str) -> bool;

    async fn store_account(
        &self,
        ca_url: &str,
        email: Option<&str>,
        account_json: &str,
        key_pem: Option<&str>,
    ) -> Result<()>;
    async fn load_account(&self, ca_url: &str, email: Option<&str>) -> Result<Option<String>>;
}

/// Filesystem certificate cache, compatible with Caddy's directory layout:
/// - certificates/<ca-key>/<domain>/<domain>.crt, <domain>.key, <domain>.json
/// - acme/<ca-key>/users/<account>/<account>.json, <account>.key
#[derive(Debug, Clone)]
pub struct FileCertStorage {
    base_dir: PathBuf,
    certs_dir: PathBuf,
    acme_dir: PathBuf,
}

impl FileCertStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        let p = base_dir.as_ref().to_path_buf();
        let (root_dir, certs_dir) = if p.ends_with("certificates") {
            let root = p.parent().unwrap_or(&p).to_path_buf();
            (root, p)
        } else {
            let certs = p.join("certificates");
            (p, certs)
        };
        let acme_dir = root_dir.join("acme");

        Self {
            base_dir: root_dir,
            certs_dir,
            acme_dir,
        }
    }

    pub fn default_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("RADDY_DATA_DIR") {
            return PathBuf::from(dir);
        }
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("raddy");
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("raddy")
    }

    pub fn caddy_data_dir() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("CADDY_DATA_DIR") {
            let p = PathBuf::from(dir);
            if p.exists() {
                return Some(p);
            }
        }
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg).join("caddy");
            if p.exists() {
                return Some(p);
            }
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        let p = PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("caddy");
        if p.exists() { Some(p) } else { None }
    }

    fn sanitize(identifier: &str) -> String {
        identifier.replace(['/', '\\', ':', '*'], "_")
    }
}

#[async_trait]
impl CertStorage for FileCertStorage {
    async fn store_with_ca(
        &self,
        identifier: &str,
        cert_pem: &str,
        key_pem: &str,
        ca_url: Option<&str>,
    ) -> Result<()> {
        let sanitized = Self::sanitize(identifier);
        let ca_key = match ca_url {
            Some(url) => ca_dir_key(url),
            None => "local".to_string(),
        };

        // 1. Caddy-style directory: certificates/<ca-key>/<domain>/
        let ca_cert_dir = self.certs_dir.join(&ca_key).join(&sanitized);
        tokio::fs::create_dir_all(&ca_cert_dir).await?;

        tokio::fs::write(ca_cert_dir.join(format!("{}.crt", sanitized)), cert_pem).await?;
        tokio::fs::write(ca_cert_dir.join(format!("{}.key", sanitized)), key_pem).await?;

        let meta = serde_json::json!({
            "sans": [identifier],
            "issuer_data": {
                "ca": ca_url.unwrap_or("local")
            }
        });
        let _ = tokio::fs::write(
            ca_cert_dir.join(format!("{}.json", sanitized)),
            serde_json::to_string_pretty(&meta).unwrap_or_default(),
        )
        .await;

        // Also write cert.pem and key.pem inside the ca directory
        let _ = tokio::fs::write(ca_cert_dir.join("cert.pem"), cert_pem).await;
        let _ = tokio::fs::write(ca_cert_dir.join("key.pem"), key_pem).await;

        // 2. Backward compatibility: also ensure certificates/<domain>/ has cert.pem and key.pem
        let direct_dir = self.certs_dir.join(&sanitized);
        if direct_dir != ca_cert_dir {
            tokio::fs::create_dir_all(&direct_dir).await?;
            let _ = tokio::fs::write(direct_dir.join("cert.pem"), cert_pem).await;
            let _ = tokio::fs::write(direct_dir.join("key.pem"), key_pem).await;
            let _ = tokio::fs::write(direct_dir.join(format!("{}.crt", sanitized)), cert_pem).await;
            let _ = tokio::fs::write(direct_dir.join(format!("{}.key", sanitized)), key_pem).await;
        }

        tracing::info!(
            "Saved certificate for '{}' under {}",
            identifier,
            ca_cert_dir.display()
        );
        Ok(())
    }

    async fn load(&self, identifier: &str) -> Result<Option<(String, String)>> {
        let sanitized = Self::sanitize(identifier);

        // 1. Check all CA folders under self.certs_dir/*/<sanitized>/
        if self.certs_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&self.certs_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let sub_dir = entry.path().join(&sanitized);
                    if sub_dir.is_dir() {
                        let crt = sub_dir.join(format!("{}.crt", sanitized));
                        let key = sub_dir.join(format!("{}.key", sanitized));
                        if crt.exists() && key.exists() {
                            let c = tokio::fs::read_to_string(crt).await?;
                            let k = tokio::fs::read_to_string(key).await?;
                            return Ok(Some((c, k)));
                        }
                        let crt_pem = sub_dir.join("cert.pem");
                        let key_pem = sub_dir.join("key.pem");
                        if crt_pem.exists() && key_pem.exists() {
                            let c = tokio::fs::read_to_string(crt_pem).await?;
                            let k = tokio::fs::read_to_string(key_pem).await?;
                            return Ok(Some((c, k)));
                        }
                    }
                }
            }

            // 2. Direct folder under certs_dir/<sanitized>/
            let direct = self.certs_dir.join(&sanitized);
            if direct.is_dir() {
                let crt = direct.join(format!("{}.crt", sanitized));
                let key = direct.join(format!("{}.key", sanitized));
                if crt.exists() && key.exists() {
                    let c = tokio::fs::read_to_string(crt).await?;
                    let k = tokio::fs::read_to_string(key).await?;
                    return Ok(Some((c, k)));
                }
                let crt_pem = direct.join("cert.pem");
                let key_pem = direct.join("key.pem");
                if crt_pem.exists() && key_pem.exists() {
                    let c = tokio::fs::read_to_string(crt_pem).await?;
                    let k = tokio::fs::read_to_string(key_pem).await?;
                    return Ok(Some((c, k)));
                }
            }
        }

        // 3. Direct folder under base_dir/<sanitized>/ (if different)
        if self.base_dir != self.certs_dir && self.base_dir.exists() {
            let direct = self.base_dir.join(&sanitized);
            if direct.is_dir() {
                let crt_pem = direct.join("cert.pem");
                let key_pem = direct.join("key.pem");
                if crt_pem.exists() && key_pem.exists() {
                    let c = tokio::fs::read_to_string(crt_pem).await?;
                    let k = tokio::fs::read_to_string(key_pem).await?;
                    return Ok(Some((c, k)));
                }
            }
        }

        // 4. Fallback search inside Caddy storage
        if let Some(caddy_root) = Self::caddy_data_dir() {
            let caddy_certs = caddy_root.join("certificates");
            if caddy_certs.exists() {
                if let Ok(mut entries) = tokio::fs::read_dir(&caddy_certs).await {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let sub_dir = entry.path().join(&sanitized);
                        if sub_dir.is_dir() {
                            let crt = sub_dir.join(format!("{}.crt", sanitized));
                            let key = sub_dir.join(format!("{}.key", sanitized));
                            if crt.exists() && key.exists() {
                                let c = tokio::fs::read_to_string(crt).await?;
                                let k = tokio::fs::read_to_string(key).await?;
                                tracing::info!(
                                    "Loaded existing certificate for '{}' from Caddy storage at {}",
                                    identifier,
                                    sub_dir.display()
                                );
                                return Ok(Some((c, k)));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    async fn exists(&self, identifier: &str) -> bool {
        let sanitized = Self::sanitize(identifier);

        // 1. Check CA subdirectories under certs_dir
        if self.certs_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&self.certs_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let sub_dir = entry.path().join(&sanitized);
                    if sub_dir.is_dir() {
                        let crt = sub_dir.join(format!("{}.crt", sanitized));
                        let key = sub_dir.join(format!("{}.key", sanitized));
                        if crt.exists() && key.exists() {
                            return true;
                        }
                        if sub_dir.join("cert.pem").exists() && sub_dir.join("key.pem").exists() {
                            return true;
                        }
                    }
                }
            }

            // 2. Direct folder under certs_dir
            let direct = self.certs_dir.join(&sanitized);
            if direct.is_dir() {
                if direct.join(format!("{}.crt", sanitized)).exists()
                    && direct.join(format!("{}.key", sanitized)).exists()
                {
                    return true;
                }
                if direct.join("cert.pem").exists() && direct.join("key.pem").exists() {
                    return true;
                }
            }
        }

        // 3. Direct folder under base_dir
        if self.base_dir != self.certs_dir && self.base_dir.exists() {
            let direct = self.base_dir.join(&sanitized);
            if direct.join("cert.pem").exists() && direct.join("key.pem").exists() {
                return true;
            }
        }

        // 4. Fallback search inside Caddy storage
        if let Some(caddy_root) = Self::caddy_data_dir() {
            let caddy_certs = caddy_root.join("certificates");
            if caddy_certs.exists() {
                if let Ok(mut entries) = tokio::fs::read_dir(&caddy_certs).await {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let sub_dir = entry.path().join(&sanitized);
                        if sub_dir.is_dir()
                            && sub_dir.join(format!("{}.crt", sanitized)).exists()
                            && sub_dir.join(format!("{}.key", sanitized)).exists()
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    async fn store_account(
        &self,
        ca_url: &str,
        email: Option<&str>,
        account_json: &str,
        key_pem: Option<&str>,
    ) -> Result<()> {
        let ca_key = ca_dir_key(ca_url);
        let account_id = email.unwrap_or("default");
        let dir = self.acme_dir.join(&ca_key).join("users").join(account_id);
        tokio::fs::create_dir_all(&dir).await?;

        let json_path = dir.join(format!("{}.json", account_id));
        tokio::fs::write(&json_path, account_json).await?;

        if let Some(key) = key_pem {
            let key_path = dir.join(format!("{}.key", account_id));
            let _ = tokio::fs::write(key_path, key).await;
        }

        tracing::info!(
            "Saved ACME account credentials for '{}' in {}",
            account_id,
            dir.display()
        );
        Ok(())
    }

    async fn load_account(&self, ca_url: &str, email: Option<&str>) -> Result<Option<String>> {
        let ca_key = ca_dir_key(ca_url);
        let account_id = email.unwrap_or("default");
        let json_path = self
            .acme_dir
            .join(&ca_key)
            .join("users")
            .join(account_id)
            .join(format!("{}.json", account_id));

        if json_path.exists() {
            let content = tokio::fs::read_to_string(&json_path).await?;
            return Ok(Some(content));
        }

        // Also check if Caddy has an account
        if let Some(caddy_root) = Self::caddy_data_dir() {
            let caddy_json = caddy_root
                .join("acme")
                .join(&ca_key)
                .join("users")
                .join(account_id)
                .join(format!("{}.json", account_id));
            if caddy_json.exists() {
                let content = tokio::fs::read_to_string(&caddy_json).await?;
                return Ok(Some(content));
            }
        }

        Ok(None)
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
