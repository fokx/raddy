use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use http::HeaderValue;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("Proxy-Authorization is required! Expected format: <type> <credentials>")]
    Missing,

    #[error("Auth type is not supported")]
    UnsupportedScheme,

    #[error("Invalid base64 in credentials")]
    InvalidBase64,

    #[error("Invalid credentials")]
    InvalidCredentials(Option<String>),
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub credentials: Vec<String>,
}

impl AuthConfig {
    pub fn new(credentials: Vec<String>) -> Self {
        Self { credentials }
    }

    pub fn encode_credentials(username: &str, password: &str) -> String {
        BASE64.encode(format!("{}:{}", username, password))
    }

    pub fn check(&self, header: Option<&HeaderValue>) -> Result<String, AuthError> {
        let val = header.ok_or(AuthError::Missing)?;
        let val_str = val.to_str().map_err(|_| AuthError::Missing)?;
        let mut parts = val_str.split_whitespace();
        let scheme = parts.next().ok_or(AuthError::Missing)?;
        let raw_b64 = parts.next().ok_or(AuthError::Missing)?;

        if parts.next().is_some() || !scheme.eq_ignore_ascii_case("basic") {
            return Err(AuthError::UnsupportedScheme);
        }

        // Check against credentials using constant time comparison
        for cred in &self.credentials {
            if cred.as_bytes().ct_eq(raw_b64.as_bytes()).into() {
                // Decode username from cred
                if let Ok(decoded) = BASE64.decode(cred) {
                    if let Ok(s) = String::from_utf8(decoded) {
                        let username = s.split(':').next().unwrap_or(&s).to_string();
                        return Ok(username);
                    }
                }
                return Ok("".to_string());
            }
        }

        // Try extracting username for context placeholder
        let user_id = if let Ok(decoded) = BASE64.decode(raw_b64) {
            if let Ok(s) = String::from_utf8(decoded) {
                s.split(':').next().map(|u| u.to_string())
            } else {
                None
            }
        } else {
            None
        };

        Err(AuthError::InvalidCredentials(user_id))
    }
}
