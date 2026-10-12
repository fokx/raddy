use crate::acme::Dns01Provider;
use crate::error::{Result, TlsError};
use async_trait::async_trait;
use parking_lot::RwLock;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

/// Validates whether a Cloudflare token conforms to standard format.
pub fn is_valid_cloudflare_token(token: &str) -> bool {
    let legacy_re = Regex::new(r"^[A-Za-z0-9_-]{35,50}$").unwrap();
    let new_re = Regex::new(r"^cf(ut|at)_[A-Za-z0-9_-]{32,256}$").unwrap();
    legacy_re.is_match(token) || new_re.is_match(token)
}

/// Resolves environment variable placeholders or falls back to standard Cloudflare env vars.
pub fn resolve_cloudflare_token(raw_token: &str) -> String {
    let trimmed = raw_token.trim().trim_matches('"').trim_matches('\'');

    // 1. Check for placeholder syntax like {env.VAR} or {$VAR} or {VAR}
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.len() > 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        if let Some(var) = inner.strip_prefix("env.") {
            if let Ok(val) = std::env::var(var) {
                return val;
            }
        } else if let Some(var) = inner.strip_prefix('$') {
            if let Ok(val) = std::env::var(var) {
                return val;
            }
        } else if let Ok(val) = std::env::var(inner) {
            return val;
        }
        // Unresolved placeholder
        return String::new();
    } else if let Some(var) = trimmed.strip_prefix('$') {
        if let Ok(val) = std::env::var(var) {
            return val;
        }
        return String::new();
    }

    // 2. If empty, check standard environment variables
    if trimmed.is_empty() {
        if let Ok(val) = std::env::var("CLOUDFLARE_API_TOKEN").or_else(|_| std::env::var("CF_API_TOKEN")) {
            return val;
        }
    }

    trimmed.to_string()
}

/// Cloudflare DNS-01 ACME challenge provider plugin.
/// Implements DNS record creation and deletion for automated ACME verification.
#[derive(Clone)]
pub struct CloudflareDnsProvider {
    api_token: String,
    zone_token: Option<String>,
    base_url: String,
    client: reqwest::Client,
    zone_cache: Arc<RwLock<HashMap<String, String>>>,
    created_records: Arc<RwLock<HashMap<(String, String), (String, String)>>>,
    propagation_delay: Duration,
    resolvers: Vec<String>,
}

impl CloudflareDnsProvider {
    /// Creates a new `CloudflareDnsProvider` with the specified API token.
    /// Placeholders in `api_token` (e.g. `{env.CLOUDFLARE_API_TOKEN}`) and fallback environment variables are automatically resolved.
    pub fn new(api_token: impl Into<String>) -> Result<Self> {
        let raw = api_token.into();
        let resolved = resolve_cloudflare_token(&raw);

        // Disallow unresolved placeholders or empty tokens
        if resolved.is_empty() || resolved.contains('{') || resolved.contains('}') || resolved.contains('"') {
            return Err(TlsError::Acme(format!(
                "Cloudflare API token appears missing or invalid ('{}'); ensure the environment variable is set and not wrapped in braces nor quotes",
                raw
            )));
        }

        // Validate token format if not in testing/mock mode
        let is_mock = std::env::var("MOCK_CLOUDFLARE").map(|v| v == "1" || v == "true").unwrap_or(false);
        if !is_mock && !is_valid_cloudflare_token(&resolved) {
            return Err(TlsError::Acme(format!(
                "Cloudflare API token '{}' appears invalid; ensure it's correctly entered and not wrapped in braces nor quotes",
                resolved
            )));
        }

        let base_url = std::env::var("CLOUDFLARE_API_URL")
            .unwrap_or_else(|_| DEFAULT_CLOUDFLARE_API_URL.to_string());

        let propagation_delay = if let Ok(s) = std::env::var("RADDY_DNS_PROPAGATION_DELAY_SECS") {
            s.parse::<u64>().map(Duration::from_secs).unwrap_or(Duration::from_secs(5))
        } else {
            Duration::from_secs(5)
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| TlsError::Acme(format!("Failed to build HTTP client for Cloudflare: {}", e)))?;

        Ok(Self {
            api_token: resolved,
            zone_token: None,
            base_url,
            client,
            zone_cache: Arc::new(RwLock::new(HashMap::new())),
            created_records: Arc::new(RwLock::new(HashMap::new())),
            propagation_delay,
            resolvers: Vec::new(),
        })
    }

    pub fn with_zone_token(mut self, token: impl Into<String>) -> Self {
        let raw = token.into();
        let resolved = resolve_cloudflare_token(&raw);
        if !resolved.is_empty() {
            self.zone_token = Some(resolved);
        }
        self
    }

    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_propagation_delay(mut self, delay: Duration) -> Self {
        self.propagation_delay = delay;
        self
    }

    pub fn with_resolvers(mut self, resolvers: Vec<String>) -> Self {
        self.resolvers = resolvers;
        self
    }

    pub fn api_token(&self) -> &str {
        &self.api_token
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn propagation_delay(&self) -> Duration {
        self.propagation_delay
    }

    /// Resolves the Cloudflare Zone ID for a given domain name.
    pub async fn get_zone_id(&self, domain: &str) -> Result<String> {
        let clean = domain.trim_start_matches("*.").trim_end_matches('.');

        // 1. Check cache
        if let Some(zone_id) = self.zone_cache.read().get(clean) {
            return Ok(zone_id.clone());
        }

        // 2. Generate candidate suffixes from domain down to apex
        let labels: Vec<&str> = clean.split('.').collect();
        if labels.is_empty() {
            return Err(TlsError::Acme(format!("Invalid domain name '{}'", domain)));
        }

        let mut candidates = Vec::new();
        for i in 0..labels.len() {
            if i + 1 < labels.len() {
                candidates.push(labels[i..].join("."));
            }
        }

        let auth_token = self.zone_token.as_deref().unwrap_or(&self.api_token);

        for candidate in &candidates {
            let url = format!("{}/zones?name={}", self.base_url, candidate);
            tracing::debug!("Querying Cloudflare for zone candidate '{}'...", candidate);

            let res = match self
                .client
                .get(&url)
                .bearer_auth(auth_token)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed HTTP request to Cloudflare for zone candidate '{}': {}", candidate, e);
                    continue;
                }
            };

            if !res.status().is_success() {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                tracing::warn!(
                    "Cloudflare returned error status {} querying zone for '{}': {}",
                    status,
                    candidate,
                    body
                );
                continue;
            }

            let json: Value = match res.json().await {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!("Failed to parse Cloudflare JSON for zone '{}': {}", candidate, e);
                    continue;
                }
            };

            if let Some(zones) = json.get("result").and_then(|r| r.as_array()) {
                if let Some(first) = zones.first() {
                    if let Some(id) = first.get("id").and_then(|i| i.as_str()) {
                        let zone_id = id.to_string();
                        tracing::info!("Found Cloudflare Zone ID '{}' for domain '{}' (matched candidate '{}')", zone_id, domain, candidate);
                        self.zone_cache.write().insert(clean.to_string(), zone_id.clone());
                        self.zone_cache.write().insert(candidate.clone(), zone_id.clone());
                        return Ok(zone_id);
                    }
                }
            }
        }

        Err(TlsError::Acme(format!(
            "No Cloudflare zone found for domain '{}'. Ensure the domain is managed in your Cloudflare account and the API token has Zone:Read and DNS:Edit permissions.",
            domain
        )))
    }
}

#[async_trait]
impl Dns01Provider for CloudflareDnsProvider {
    async fn present(&self, domain: &str, key_auth_dns_value: &str) -> Result<()> {
        let clean = domain.trim_start_matches("*.").trim_end_matches('.');
        let zone_id = self.get_zone_id(clean).await?;
        let record_name = format!("_acme-challenge.{}", clean);

        tracing::info!(
            "Creating Cloudflare DNS TXT record for '{}' in zone '{}' (content: '{}')...",
            record_name,
            zone_id,
            key_auth_dns_value
        );

        let url = format!("{}/zones/{}/dns_records", self.base_url, zone_id);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": key_auth_dns_value,
            "ttl": 60
        });

        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to send DNS record creation request: {}", e)))?;

        let status = res.status();
        let json: Value = res
            .json()
            .await
            .map_err(|e| TlsError::Acme(format!("Failed to parse Cloudflare JSON response: {}", e)))?;

        let success = json.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
        if !status.is_success() || !success {
            let mut err_details = Vec::new();
            if let Some(errors) = json.get("errors").and_then(|e| e.as_array()) {
                for err in errors {
                    let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error");
                    let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                    err_details.push(format!("code {}: {}", code, msg));
                }
            }
            let err_summary = if err_details.is_empty() {
                format!("HTTP status {}", status)
            } else {
                err_details.join("; ")
            };
            return Err(TlsError::Acme(format!(
                "Failed to create Cloudflare DNS TXT record for '{}': {}",
                record_name, err_summary
            )));
        }

        let record_id = json
            .get("result")
            .and_then(|r| r.get("id"))
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();

        self.created_records.write().insert(
            (clean.to_string(), key_auth_dns_value.to_string()),
            (zone_id.clone(), record_id.clone()),
        );

        tracing::info!(
            "Successfully created Cloudflare DNS TXT record for '{}' (record ID: '{}')",
            record_name,
            record_id
        );

        // Sleep for propagation delay if configured
        if self.propagation_delay > Duration::ZERO {
            tracing::info!(
                "Waiting {:?} for Cloudflare DNS TXT record propagation...",
                self.propagation_delay
            );
            tokio::time::sleep(self.propagation_delay).await;
        }

        Ok(())
    }

    async fn clean_up(&self, domain: &str, key_auth_dns_value: &str) -> Result<()> {
        let clean = domain.trim_start_matches("*.").trim_end_matches('.');
        let record_entry = self
            .created_records
            .write()
            .remove(&(clean.to_string(), key_auth_dns_value.to_string()));

        if let Some((zone_id, record_id)) = record_entry {
            tracing::info!(
                "Deleting Cloudflare DNS TXT record '{}' from zone '{}'...",
                record_id,
                zone_id
            );
            let url = format!("{}/zones/{}/dns_records/{}", self.base_url, zone_id, record_id);
            let res = self
                .client
                .delete(&url)
                .bearer_auth(&self.api_token)
                .send()
                .await;

            match res {
                Ok(r) => {
                    if r.status().is_success() || r.status().as_u16() == 404 {
                        tracing::debug!("Cloudflare DNS TXT record '{}' successfully deleted", record_id);
                        return Ok(());
                    } else {
                        let status = r.status();
                        let body = r.text().await.unwrap_or_default();
                        tracing::warn!(
                            "Cloudflare returned {} deleting DNS record '{}': {}",
                            status,
                            record_id,
                            body
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed HTTP DELETE for Cloudflare record '{}': {}", record_id, e);
                }
            }
        } else {
            // Fallback: lookup zone and find matching records
            if let Ok(zone_id) = self.get_zone_id(clean).await {
                let record_name = format!("_acme-challenge.{}", clean);
                let url = format!(
                    "{}/zones/{}/dns_records?type=TXT&name={}",
                    self.base_url, zone_id, record_name
                );
                if let Ok(res) = self.client.get(&url).bearer_auth(&self.api_token).send().await {
                    if let Ok(json) = res.json::<Value>().await {
                        if let Some(records) = json.get("result").and_then(|r| r.as_array()) {
                            for rec in records {
                                let content = rec.get("content").and_then(|c| c.as_str()).unwrap_or("");
                                if content == key_auth_dns_value || content.trim_matches('"') == key_auth_dns_value {
                                    if let Some(rid) = rec.get("id").and_then(|i| i.as_str()) {
                                        let del_url = format!(
                                            "{}/zones/{}/dns_records/{}",
                                            self.base_url, zone_id, rid
                                        );
                                        let _ = self
                                            .client
                                            .delete(&del_url)
                                            .bearer_auth(&self.api_token)
                                            .send()
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
