use crate::error::{Result, TlsError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use std::net::IpAddr;

/// Internal Certificate Authority for self-signed development certificates.
pub struct LocalCa {
    ca_cert: rcgen::Certificate,
    ca_cert_pem: String,
    ca_key_pem: String,
}

impl LocalCa {
    /// Generates or initializes a Local Root CA.
    pub fn new() -> Result<Self> {
        crate::install_default_crypto_provider();

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Raddy Local Authority - Development CA");
        dn.push(DnType::OrganizationName, "Raddy Web Server");
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let ca_cert = params.self_signed(&key_pair)?;

        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = key_pair.serialize_pem();

        Ok(Self {
            ca_cert,
            ca_cert_pem,
            ca_key_pem,
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// Issues a leaf certificate signed by this CA for domain names and/or IP addresses.
    pub fn issue_certificate(&self, names_or_ips: &[String]) -> Result<(String, String)> {
        let mut params = CertificateParams::default();

        let mut san_list = Vec::new();
        for item in names_or_ips {
            if let Ok(ip) = item.parse::<IpAddr>() {
                san_list.push(SanType::IpAddress(ip));
            } else {
                san_list.push(SanType::DnsName(item.clone().try_into().map_err(|e| {
                    TlsError::Certificate(format!("Invalid DNS name '{}': {:?}", item, e))
                })?));
            }
        }

        if let Some(first) = names_or_ips.first() {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, first.as_str());
            params.distinguished_name = dn;
        }

        params.subject_alt_names = san_list;

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let leaf_cert = params.signed_by(
            &leaf_key,
            &self.ca_cert,
            &KeyPair::from_pem(&self.ca_key_pem)?,
        )?;

        // Chain contains the leaf certificate followed by the CA certificate
        let cert_chain_pem = format!("{}\n{}", leaf_cert.pem(), self.ca_cert_pem);
        let key_pem = leaf_key.serialize_pem();

        Ok((cert_chain_pem, key_pem))
    }
}
