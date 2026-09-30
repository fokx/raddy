use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use parking_lot::RwLock;
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use ring::digest::{digest, SHA256};
use crate::error::{Result, TlsError};
use crate::sni::SniResolver;
use crate::storage::CertStorage;

pub use raddy_core::config::{
    resolve_acme_ca, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING, ZEROSSL_PRODUCTION,
};

/// In-memory storage for active HTTP-01 challenge authorizations.
/// Maps token -> key_authorization.
#[derive(Clone, Default)]
pub struct Http01ChallengeStore {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl Http01ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: impl Into<String>, key_auth: impl Into<String>) {
        self.challenges.write().insert(token.into(), key_auth.into());
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().get(token).cloned()
    }

    pub fn remove(&self, token: &str) {
        self.challenges.write().remove(token);
    }
}

/// ACME Client using `instant-acme` supporting both Domain Names and Public IP Addresses (RFC 8738).
pub struct AcmeClient {
    directory_url: String,
    email: Option<String>,
    challenge_store: Http01ChallengeStore,
    sni_resolver: Arc<SniResolver>,
    cert_storage: Arc<dyn CertStorage>,
}

impl AcmeClient {
    pub fn new(
        directory_url: impl Into<String>,
        email: Option<String>,
        challenge_store: Http01ChallengeStore,
        sni_resolver: Arc<SniResolver>,
        cert_storage: Arc<dyn CertStorage>,
    ) -> Self {
        Self {
            directory_url: directory_url.into(),
            email,
            challenge_store,
            sni_resolver,
            cert_storage,
        }
    }

    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    pub fn challenge_store(&self) -> &Http01ChallengeStore {
        &self.challenge_store
    }

    /// Orders and issues a certificate from ACME CA for given domain names and/or IP addresses.
    /// Supports short-lived public IP certificates (RFC 8738) via Identifier::Ip!
    pub async fn issue_certificate(
        &self,
        identifiers_str: &[String],
    ) -> Result<(String, String)> {
        if identifiers_str.is_empty() {
            return Err(TlsError::Acme("No identifiers provided for ACME order".into()));
        }

        // 1. Build ACME Identifiers: distinguish DNS names from IP addresses (RFC 8738)
        let mut identifiers = Vec::new();
        for item in identifiers_str {
            if let Ok(ip) = item.parse::<IpAddr>() {
                // Public IP Address identifier (RFC 8738) supported by Let's Encrypt!
                identifiers.push(Identifier::Ip(ip));
            } else {
                // Standard DNS domain identifier
                identifiers.push(Identifier::Dns(item.clone()));
            }
        }

        // 2. Load or Create Persistent ACME Account
        let account_id = self.email.as_deref().unwrap_or("default");
        tracing::debug!(
            "Resolving ACME account for '{}' using directory '{}'...",
            account_id,
            self.directory_url
        );

        let mut account_opt = None;
        if let Ok(Some(cached_json)) = self
            .cert_storage
            .load_account(&self.directory_url, self.email.as_deref())
            .await
        {
            match serde_json::from_str::<AccountCredentials>(&cached_json) {
                Ok(creds) => {
                    tracing::debug!("Found cached ACME credentials, restoring account session...");
                    if let Ok(builder) = Account::builder() {
                        match builder.from_credentials(creds).await {
                            Ok(acc) => {
                                tracing::info!(
                                    "Successfully restored cached ACME account for '{}' (CA: {})",
                                    account_id,
                                    self.directory_url
                                );
                                account_opt = Some(acc);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to restore ACME account from credentials: {}. Registering new account...",
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse cached ACME credentials JSON: {}. Registering new account...",
                        e
                    );
                }
            }
        }

        let account = match account_opt {
            Some(acc) => acc,
            None => {
                let contact = self
                    .email
                    .as_ref()
                    .map(|e| vec![format!("mailto:{}", e)])
                    .unwrap_or_default();
                let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

                tracing::info!(
                    "Registering new ACME account with CA '{}' (contact: {:?})...",
                    self.directory_url,
                    contact_refs
                );

                let (account, credentials) = Account::builder()
                    .map_err(|e| TlsError::Acme(format!("Account builder error: {}", e)))?
                    .create(
                        &NewAccount {
                            contact: &contact_refs,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.directory_url.clone(),
                        None,
                    )
                    .await
                    .map_err(|e| TlsError::Acme(format!("Failed to create ACME account: {}", e)))?;

                // Persist credentials
                match serde_json::to_string_pretty(&credentials) {
                    Ok(json_str) => {
                        let priv_key_pem = pem::encode(&pem::Pem::new(
                            "PRIVATE KEY",
                            credentials.private_key().secret_pkcs8_der(),
                        ));
                        if let Err(e) = self
                            .cert_storage
                            .store_account(
                                &self.directory_url,
                                self.email.as_deref(),
                                &json_str,
                                Some(&priv_key_pem),
                            )
                            .await
                        {
                            tracing::warn!("Failed to persist ACME account credentials: {}", e);
                        } else {
                            tracing::info!("Persisted ACME account credentials for '{}'", account_id);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to serialize ACME account credentials: {}", e);
                    }
                }

                account
            }
        };

        // 3. Create New Order
        tracing::info!("Submitting ACME order for identifiers: {:?}...", identifiers_str);
        let mut order = account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to create ACME order: {}", e)))?;
        tracing::debug!("ACME order created: {}", order.url());

        // 4. Handle HTTP-01 or TLS-ALPN-01 Challenges
        let mut active_tokens = Vec::new();
        let mut active_alpn_ids = Vec::new();
        let mut authorizations = order.authorizations();

        while let Some(res) = authorizations.next().await {
            let mut authz = res.map_err(|e| TlsError::Acme(format!("Authorization error: {}", e)))?;
            let id_str = authz.identifier().to_string();

            let has_http01 = authz.challenges.iter().any(|c| c.r#type == ChallengeType::Http01);
            let has_tls_alpn = authz.challenges.iter().any(|c| c.r#type == ChallengeType::TlsAlpn01);

            tracing::debug!(
                "Authorization challenges offered for '{}': {:?}",
                id_str,
                authz.challenges.iter().map(|c| c.r#type.clone()).collect::<Vec<_>>()
            );

            // Prefer HTTP-01 challenge if offered (standard across CDNs, proxies, and port 80).
            // Fall back to TLS-ALPN-01 if HTTP-01 is not offered.
            if has_http01 {
                let mut http_challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| TlsError::Acme("HTTP-01 challenge not found".into()))?;

                let token = http_challenge.token.to_string();
                let key_auth = http_challenge.key_authorization().as_str().to_string();

                tracing::info!(
                    "Solving ACME challenge for '{}' using HTTP-01 (token: '{}')...",
                    id_str,
                    token
                );

                self.challenge_store.insert(token.clone(), key_auth);
                active_tokens.push(token);

                http_challenge
                    .set_ready()
                    .await
                    .map_err(|e| TlsError::Acme(format!("Failed to set HTTP-01 challenge ready: {}", e)))?;
            } else if has_tls_alpn {
                let mut alpn_challenge = authz
                    .challenge(ChallengeType::TlsAlpn01)
                    .ok_or_else(|| TlsError::Acme("TLS-ALPN-01 challenge not found".into()))?;

                let key_auth = alpn_challenge.key_authorization().as_str().to_string();

                // Compute SHA-256 digest of key authorization (RFC 8737 §3)
                let key_digest = digest(&SHA256, key_auth.as_bytes());

                // Generate self-signed certificate with acmeValidation extension
                let mut params = CertificateParams::default();
                let mut ext = CustomExtension::new_acme_identifier(key_digest.as_ref());
                ext.set_criticality(true);
                params.custom_extensions.push(ext);

                if let Ok(ip) = id_str.parse::<IpAddr>() {
                    params.subject_alt_names.push(SanType::IpAddress(ip));
                } else {
                    let dns_name: rcgen::Ia5String = id_str.clone().try_into().map_err(|e| {
                        TlsError::Certificate(format!("Invalid DNS name '{}' for TLS-ALPN-01: {:?}", id_str, e))
                    })?;
                    params.subject_alt_names.push(SanType::DnsName(dns_name));
                }

                let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                let leaf_cert = params.self_signed(&leaf_key)?;
                let certified_key = crate::storage::parse_certified_key(&leaf_cert.pem(), &leaf_key.serialize_pem())?;

                self.sni_resolver.insert_alpn_challenge(&id_str, certified_key);
                active_alpn_ids.push(id_str.clone());

                tracing::info!("Solving ACME challenge for '{}' using TLS-ALPN-01...", id_str);

                alpn_challenge
                    .set_ready()
                    .await
                    .map_err(|e| TlsError::Acme(format!("Failed to set TLS-ALPN-01 challenge ready: {}", e)))?;
            } else {
                return Err(TlsError::Acme(format!(
                    "Neither HTTP-01 nor TLS-ALPN-01 challenge found in authorization for '{}'. Offered: {:?}",
                    id_str,
                    authz.challenges.iter().map(|c| c.r#type.clone()).collect::<Vec<_>>()
                )));
            }
        }

        // 5. Exponentially poll until order is ready or failed
        tracing::debug!("Polling ACME order status until validation completes...");
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| TlsError::Acme(format!("Failed waiting for order to become ready: {}", e)))?;

        // Clean up challenge tokens and ALPN challenge certificates
        for token in &active_tokens {
            self.challenge_store.remove(token);
        }
        for id in &active_alpn_ids {
            self.sni_resolver.remove_alpn_challenge(id);
        }

        if status != OrderStatus::Ready && status != OrderStatus::Valid {
            // Collect detailed failure diagnostics from all authorization challenges
            let mut failure_reasons = Vec::new();
            let mut authzs = order.authorizations();
            while let Some(res) = authzs.next().await {
                if let Ok(authz) = res {
                    let id_val = authz.identifier().to_string();
                    for ch in &authz.challenges {
                        if let Some(ref problem) = ch.error {
                            let detail = problem.detail.as_deref().unwrap_or("no detail provided");
                            let prob_type = problem.r#type.as_deref().unwrap_or("unknown");
                            failure_reasons.push(format!(
                                "Identifier '{}' challenge {:?}: {} (error type: {}, status: {:?})",
                                id_val, ch.r#type, detail, prob_type, problem.status
                            ));
                        }
                    }
                }
            }

            let detailed_msg = if failure_reasons.is_empty() {
                format!("Unexpected ACME order status: {:?}", status)
            } else {
                format!(
                    "Unexpected ACME order status: {:?}. Diagnostics: {}",
                    status,
                    failure_reasons.join("; ")
                )
            };
            tracing::error!("ACME order validation failed: {}", detailed_msg);
            return Err(TlsError::Acme(detailed_msg));
        }

        // 6. Finalize order (generates CSR and submits to CA)
        tracing::debug!("Finalizing ACME order (generating and submitting CSR)...");
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to finalize ACME order: {}", e)))?;

        // 7. Download Certificate Chain
        tracing::debug!("Downloading certificate chain from ACME CA...");
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to download certificate: {}", e)))?;

        tracing::info!(
            "Successfully obtained certificate chain for {:?} from ACME CA ({})",
            identifiers_str,
            self.directory_url
        );
        Ok((cert_chain_pem, private_key_pem))
    }
}
