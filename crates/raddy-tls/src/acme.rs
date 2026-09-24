use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::RwLock;
use crate::error::{Result, TlsError};

pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const ZEROSSL_PRODUCTION: &str = "https://acme.zerossl.com/v2/DV90";

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
}

impl AcmeClient {
    pub fn new(directory_url: impl Into<String>, email: Option<String>, challenge_store: Http01ChallengeStore) -> Self {
        Self {
            directory_url: directory_url.into(),
            email,
            challenge_store,
        }
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

        // 2. Create ACME Account
        let contact = self.email.as_ref().map(|e| vec![format!("mailto:{}", e)]).unwrap_or_default();
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        let (account, _credentials) = Account::builder()
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

        // 3. Create New Order
        let mut order = account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to create ACME order: {}", e)))?;

        // 4. Handle HTTP-01 Challenges
        let mut active_tokens = Vec::new();
        let mut authorizations = order.authorizations();

        while let Some(res) = authorizations.next().await {
            let mut authz = res.map_err(|e| TlsError::Acme(format!("Authorization error: {}", e)))?;

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| TlsError::Acme("No HTTP-01 challenge found in authorization".into()))?;

            let token = challenge.token.to_string();
            let key_auth = challenge.key_authorization().as_str().to_string();

            // Store in challenge store so port 80 HTTP server can serve it at:
            // /.well-known/acme-challenge/{token}
            self.challenge_store.insert(token.clone(), key_auth);
            active_tokens.push(token);

            // Signal CA that challenge is ready
            challenge
                .set_ready()
                .await
                .map_err(|e| TlsError::Acme(format!("Failed to set challenge ready: {}", e)))?;
        }

        // 5. Exponentially poll until order is ready
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| TlsError::Acme(format!("Failed waiting for order to become ready: {}", e)))?;

        // Clean up challenge tokens from store
        for token in &active_tokens {
            self.challenge_store.remove(token);
        }

        if status != OrderStatus::Ready && status != OrderStatus::Valid {
            return Err(TlsError::Acme(format!("Unexpected ACME order status: {:?}", status)));
        }

        // 6. Finalize order (generates CSR and submits to CA)
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to finalize ACME order: {}", e)))?;

        // 7. Download Certificate Chain
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to download certificate: {}", e)))?;

        Ok((cert_chain_pem, private_key_pem))
    }
}
