//! Raddy TLS and ACME automation crate
//! Provides certificate storage, local development CA (rcgen),
//! ACME client for public domains & short-lived public IPs (instant-acme),
//! dynamic SNI certificate resolution (rustls), and TLS acceptor generation.

pub mod acme;
pub mod error;
pub mod local_ca;
pub mod manager;
pub mod sni;
pub mod storage;

pub use acme::{AcmeClient, Http01ChallengeStore, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING};
pub use error::{Result, TlsError};
pub use local_ca::LocalCa;
pub use manager::{is_local_or_private, TlsManager};
pub use sni::SniResolver;
pub use storage::{parse_certified_key, CertStorage, FileCertStorage};
