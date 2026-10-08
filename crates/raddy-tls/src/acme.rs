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

/// Challenge type preference for ACME certificate issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChallengeTypePreference {
    /// Attempt TLS-ALPN-01 first directly over port 443 (RFC 8737).
    /// If TLS-ALPN-01 fails (e.g. behind a CDN or reverse proxy terminating TLS),
    /// automatically fall back to HTTP-01 challenge.
    #[default]
    TlsAlpnFirst,
    /// Attempt HTTP-01 first over port 80. If it fails, fall back to TLS-ALPN-01.
    Http01First,
    /// Only use TLS-ALPN-01 challenge (e.g. when port 80 is unavailable or disable_http_challenge is set).
    TlsAlpnOnly,
    /// Only use HTTP-01 challenge (e.g. when disable_tls_alpn_challenge is set).
    Http01Only,
}

/// ACME Client using `instant-acme` supporting both Domain Names and Public IP Addresses (RFC 8738).
#[derive(Clone)]
pub struct AcmeClient {
    directory_url: String,
    email: Option<String>,
    challenge_store: Http01ChallengeStore,
    sni_resolver: Arc<SniResolver>,
    cert_storage: Arc<dyn CertStorage>,
    challenge_preference: ChallengeTypePreference,
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
            challenge_preference: ChallengeTypePreference::default(),
        }
    }

    pub fn with_challenge_preference(mut self, pref: ChallengeTypePreference) -> Self {
        self.challenge_preference = pref;
        self
    }

    pub fn challenge_preference(&self) -> ChallengeTypePreference {
        self.challenge_preference
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

        // 3. Determine ACME challenge strategy sequence
        let methods_to_try = match self.challenge_preference {
            ChallengeTypePreference::TlsAlpnFirst => vec![ChallengeType::TlsAlpn01, ChallengeType::Http01],
            ChallengeTypePreference::Http01First => vec![ChallengeType::Http01, ChallengeType::TlsAlpn01],
            ChallengeTypePreference::TlsAlpnOnly => vec![ChallengeType::TlsAlpn01],
            ChallengeTypePreference::Http01Only => vec![ChallengeType::Http01],
        };

        let num_methods = methods_to_try.len();
        let mut last_error = None;

        for (attempt_idx, preferred_challenge) in methods_to_try.into_iter().enumerate() {
            let is_last_attempt = attempt_idx + 1 == num_methods;
            tracing::info!(
                "Submitting ACME order for identifiers: {:?} (challenge strategy: {:?}, attempt {}/{})",
                identifiers_str,
                preferred_challenge,
                attempt_idx + 1,
                num_methods
            );

            let mut order = match account.new_order(&NewOrder::new(identifiers.as_slice())).await {
                Ok(ord) => ord,
                Err(e) => {
                    let err_msg = format!("Failed to create ACME order: {}", e);
                    tracing::error!("{}", err_msg);
                    return Err(TlsError::Acme(err_msg));
                }
            };
            tracing::debug!("ACME order created: {}", order.url());

            // 4. Handle TLS-ALPN-01 or HTTP-01 Challenges
            let mut active_tokens = Vec::new();
            let mut active_alpn_ids = Vec::new();
            let mut authorizations = order.authorizations();
            let mut auth_error = None;

            while let Some(res) = authorizations.next().await {
                let mut authz = match res {
                    Ok(a) => a,
                    Err(e) => {
                        auth_error = Some(format!("Authorization error: {}", e));
                        break;
                    }
                };

                let id_str = authz.identifier().to_string();

                if authz.status == instant_acme::AuthorizationStatus::Valid {
                    tracing::debug!("Authorization for '{}' is already valid", id_str);
                    continue;
                }

                let has_tls_alpn = authz.challenges.iter().any(|c| c.r#type == ChallengeType::TlsAlpn01);
                let has_http01 = authz.challenges.iter().any(|c| c.r#type == ChallengeType::Http01);

                tracing::debug!(
                    "Authorization challenges offered for '{}': {:?}",
                    id_str,
                    authz.challenges.iter().map(|c| c.r#type.clone()).collect::<Vec<_>>()
                );

                // Determine which challenge solver to use for this authorization
                let chosen_type = if preferred_challenge == ChallengeType::TlsAlpn01 {
                    if has_tls_alpn {
                        ChallengeType::TlsAlpn01
                    } else if has_http01 {
                        ChallengeType::Http01
                    } else {
                        auth_error = Some(format!(
                            "Neither TLS-ALPN-01 nor HTTP-01 challenge offered for '{}'",
                            id_str
                        ));
                        break;
                    }
                } else {
                    if has_http01 {
                        ChallengeType::Http01
                    } else if has_tls_alpn {
                        ChallengeType::TlsAlpn01
                    } else {
                        auth_error = Some(format!(
                            "Neither HTTP-01 nor TLS-ALPN-01 challenge offered for '{}'",
                            id_str
                        ));
                        break;
                    }
                };

                if chosen_type == ChallengeType::TlsAlpn01 {
                    let mut alpn_challenge = match authz.challenge(ChallengeType::TlsAlpn01) {
                        Some(c) => c,
                        None => {
                            auth_error = Some(format!("TLS-ALPN-01 challenge handle missing for '{}'", id_str));
                            break;
                        }
                    };

                    let key_auth = alpn_challenge.key_authorization().as_str().to_string();

                    // Compute SHA-256 digest of key authorization (RFC 8737 §3)
                    let key_digest = digest(&SHA256, key_auth.as_bytes());

                    // Generate self-signed certificate with acmeValidation extension
                    let mut params = CertificateParams::default();
                    let mut ext = CustomExtension::new_acme_identifier(key_digest.as_ref());
                    ext.set_criticality(true);
                    params.custom_extensions.push(ext);

                    params.distinguished_name = rcgen::DistinguishedName::new();
                    params.distinguished_name.push(rcgen::DnType::CommonName, id_str.as_str());

                    if let Ok(ip) = id_str.parse::<IpAddr>() {
                        params.subject_alt_names.push(SanType::IpAddress(ip));
                    } else {
                        let dns_name = match rcgen::Ia5String::try_from(id_str.clone()) {
                            Ok(n) => n,
                            Err(e) => {
                                auth_error = Some(format!("Invalid DNS name '{}' for TLS-ALPN-01: {:?}", id_str, e));
                                break;
                            }
                        };
                        params.subject_alt_names.push(SanType::DnsName(dns_name));
                    }

                    let leaf_key = match KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
                        Ok(k) => k,
                        Err(e) => {
                            auth_error = Some(format!("Failed to generate ECDSA key for TLS-ALPN-01: {}", e));
                            break;
                        }
                    };
                    let leaf_cert = match params.self_signed(&leaf_key) {
                        Ok(c) => c,
                        Err(e) => {
                            auth_error = Some(format!("Failed to generate self-signed cert for TLS-ALPN-01: {}", e));
                            break;
                        }
                    };
                    let certified_key = match crate::storage::parse_certified_key(&leaf_cert.pem(), &leaf_key.serialize_pem()) {
                        Ok(k) => k,
                        Err(e) => {
                            auth_error = Some(format!("Failed to parse certified key for TLS-ALPN-01: {}", e));
                            break;
                        }
                    };

                    self.sni_resolver.insert_alpn_challenge(&id_str, certified_key);
                    active_alpn_ids.push(id_str.clone());

                    tracing::info!("Solving ACME challenge for '{}' using TLS-ALPN-01 (direct over port 443)...", id_str);

                    if let Err(e) = alpn_challenge.set_ready().await {
                        auth_error = Some(format!("Failed to set TLS-ALPN-01 challenge ready: {}", e));
                        break;
                    }
                } else {
                    let mut http_challenge = match authz.challenge(ChallengeType::Http01) {
                        Some(c) => c,
                        None => {
                            auth_error = Some(format!("HTTP-01 challenge handle missing for '{}'", id_str));
                            break;
                        }
                    };

                    let token = http_challenge.token.to_string();
                    let key_auth = http_challenge.key_authorization().as_str().to_string();

                    tracing::info!(
                        "Solving ACME challenge for '{}' using HTTP-01 (token: '{}')...",
                        id_str,
                        token
                    );

                    self.challenge_store.insert(token.clone(), key_auth);
                    active_tokens.push(token);

                    if let Err(e) = http_challenge.set_ready().await {
                        auth_error = Some(format!("Failed to set HTTP-01 challenge ready: {}", e));
                        break;
                    }
                }
            }

            if let Some(err) = auth_error {
                for token in &active_tokens {
                    self.challenge_store.remove(token);
                }
                for id in &active_alpn_ids {
                    self.sni_resolver.remove_alpn_challenge(id);
                }

                if !is_last_attempt {
                    tracing::warn!("ACME authorization setup error: {}. Retrying with fallback challenge...", err);
                    last_error = Some(err);
                    continue;
                } else {
                    return Err(TlsError::Acme(err));
                }
            }

            // 5. Exponentially poll until order is ready or failed
            tracing::debug!("Polling ACME order status until validation completes...");
            let poll_res = order.poll_ready(&RetryPolicy::default()).await;

            // Clean up challenge tokens and ALPN challenge certificates immediately
            for token in &active_tokens {
                self.challenge_store.remove(token);
            }
            for id in &active_alpn_ids {
                self.sni_resolver.remove_alpn_challenge(id);
            }

            let status = match poll_res {
                Ok(st) => st,
                Err(e) => {
                    let msg = format!("Failed waiting for order to become ready: {}", e);
                    if !is_last_attempt {
                        tracing::warn!("{}. Retrying with fallback challenge strategy...", msg);
                        last_error = Some(msg);
                        continue;
                    } else {
                        return Err(TlsError::Acme(msg));
                    }
                }
            };

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

                if !is_last_attempt {
                    tracing::warn!(
                        "ACME {:?} challenge validation failed: {}. Retrying with fallback challenge strategy...",
                        preferred_challenge,
                        detailed_msg
                    );
                    last_error = Some(detailed_msg);
                    continue;
                } else {
                    tracing::error!("ACME order validation failed: {}", detailed_msg);
                    return Err(TlsError::Acme(detailed_msg));
                }
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
                "Successfully obtained certificate chain for {:?} from ACME CA ({}) via {:?}",
                identifiers_str,
                self.directory_url,
                preferred_challenge
            );
            return Ok((cert_chain_pem, private_key_pem));
        }

        Err(TlsError::Acme(
            last_error.unwrap_or_else(|| "All ACME challenge attempts failed".to_string()),
        ))
    }
}
