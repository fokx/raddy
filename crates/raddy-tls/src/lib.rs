//! Raddy TLS and ACME automation crate
//! Provides certificate storage, local development CA (rcgen),
//! ACME client for public domains & short-lived public IPs (instant-acme),
//! dynamic SNI certificate resolution (rustls), and TLS acceptor generation.

pub mod acme;
pub mod error;
pub mod local_ca;
pub mod manager;
pub mod matchers;
pub mod sni;
pub mod storage;

pub use acme::{AcmeClient, Http01ChallengeStore, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING};
pub use error::{Result, TlsError};
pub use local_ca::LocalCa;
pub use manager::{is_local_or_private, TlsManager};
pub use matchers::{RemoteIpMatcher, ServerNameMatcher, ServerNameREMatcher};
pub use sni::SniResolver;
pub use storage::{parse_certified_key, CertStorage, FileCertStorage};

/// Installs the default process-level CryptoProvider (AWS-LC-RS) for Rustls.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
