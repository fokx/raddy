use raddy_tls::local_ca::LocalCa;
use raddy_tls::manager::{TlsManager, is_local_or_private};
use raddy_tls::sni::SniResolver;
use raddy_tls::storage::{CertStorage, FileCertStorage, parse_certified_key};
use std::sync::Arc;

#[tokio::test]
async fn test_local_ca_generation() {
    let ca = LocalCa::new().expect("Failed to create LocalCa");
    assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(ca.ca_key_pem().contains("BEGIN PRIVATE KEY"));

    // Issue leaf cert for domain and IP
    let (cert_pem, key_pem) = ca
        .issue_certificate(&["localhost".into(), "127.0.0.1".into()])
        .expect("Failed to issue cert");

    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(key_pem.contains("BEGIN PRIVATE KEY"));

    let certified_key =
        parse_certified_key(&cert_pem, &key_pem).expect("Failed to parse certified key");
    assert!(!certified_key.as_ref().cert.is_empty());
}

#[tokio::test]
async fn test_file_cert_storage() {
    let temp_dir = std::env::temp_dir().join("raddy_tls_test_storage");
    let storage = FileCertStorage::new(&temp_dir);

    let identifier = "test.example.com";
    assert!(!storage.exists(identifier).await);

    storage
        .store(identifier, "CERT_CONTENT", "KEY_CONTENT")
        .await
        .expect("Failed to store cert");

    assert!(storage.exists(identifier).await);

    let loaded = storage
        .load(identifier)
        .await
        .expect("Failed to load")
        .expect("Cert not found");
    assert_eq!(loaded.0, "CERT_CONTENT");
    assert_eq!(loaded.1, "KEY_CONTENT");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_sni_resolver() {
    let ca = LocalCa::new().unwrap();
    let (cert1, key1) = ca.issue_certificate(&["site.local".into()]).unwrap();
    let (cert2, key2) = ca.issue_certificate(&["*.sub.local".into()]).unwrap();

    let ck1 = parse_certified_key(&cert1, &key1).unwrap();
    let ck2 = parse_certified_key(&cert2, &key2).unwrap();

    let resolver = SniResolver::new();
    resolver.insert("site.local", ck1.clone());
    resolver.insert("*.sub.local", ck2.clone());
    resolver.set_default(ck1.clone());

    assert_eq!(resolver.cert_count(), 2);
}

#[test]
fn test_is_local_or_private_classification() {
    // Local / private -> Local CA
    assert!(is_local_or_private("localhost"));
    assert!(is_local_or_private("api.localhost"));
    assert!(is_local_or_private("service.local"));
    assert!(is_local_or_private("app.internal"));
    assert!(is_local_or_private("127.0.0.1"));
    assert!(is_local_or_private("192.168.1.1"));
    assert!(is_local_or_private("10.0.0.1"));
    assert!(is_local_or_private("172.16.0.1"));

    // Public domains / public IPs -> ACME
    assert!(!is_local_or_private("example.com"));
    assert!(!is_local_or_private("api.raddy.dev"));
    assert!(!is_local_or_private("1.1.1.1"));
    assert!(!is_local_or_private("8.8.8.8"));
}

#[tokio::test]
async fn test_tls_manager_provision_internal() {
    let temp_dir = std::env::temp_dir().join("raddy_tls_test_manager");
    let storage = Arc::new(FileCertStorage::new(&temp_dir));

    let manager = TlsManager::new(None, true)
        .expect("Failed to create TlsManager")
        .with_storage(storage);

    manager
        .provision_identifier("localhost", true)
        .await
        .expect("Failed to provision localhost");

    assert_eq!(manager.sni_resolver().cert_count(), 1);

    // Build ServerConfig & TlsAcceptor
    let _acceptor = manager
        .build_tls_acceptor()
        .expect("Failed to build TLS acceptor");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_caddy_compatibility_and_account_storage() {
    use raddy_tls::storage::ca_dir_key;

    // Test CA directory key calculation matching Caddy
    assert_eq!(
        ca_dir_key("https://acme-v02.api.letsencrypt.org/directory"),
        "acme-v02.api.letsencrypt.org-directory"
    );
    assert_eq!(
        ca_dir_key("https://acme-staging-v02.api.letsencrypt.org/directory"),
        "acme-staging-v02.api.letsencrypt.org-directory"
    );
    assert_eq!(
        ca_dir_key("https://acme.zerossl.com/v2/DV90"),
        "acme.zerossl.com-v2-dv90"
    );

    let temp_dir = std::env::temp_dir().join("raddy_caddy_compat_test");
    let storage = FileCertStorage::new(&temp_dir);

    let ca = "https://acme-v02.api.letsencrypt.org/directory";
    let domain = "xjtu.app";

    // Store cert with CA
    storage
        .store_with_ca(domain, "CERT_CHAIN_PEM", "KEY_PEM", Some(ca))
        .await
        .expect("Failed to store cert with CA");

    // Verify file layout matches Caddy:
    // certificates/acme-v02.api.letsencrypt.org-directory/xjtu.app/xjtu.app.crt, .key, .json
    let caddy_layout_dir = temp_dir
        .join("certificates")
        .join("acme-v02.api.letsencrypt.org-directory")
        .join("xjtu.app");

    assert!(caddy_layout_dir.join("xjtu.app.crt").exists());
    assert!(caddy_layout_dir.join("xjtu.app.key").exists());
    assert!(caddy_layout_dir.join("xjtu.app.json").exists());

    // Verify metadata JSON contents
    let json_str = tokio::fs::read_to_string(caddy_layout_dir.join("xjtu.app.json"))
        .await
        .unwrap();
    assert!(json_str.contains("xjtu.app"));
    assert!(json_str.contains("acme-v02.api.letsencrypt.org"));

    // Verify loading and existence check
    assert!(storage.exists(domain).await);
    let loaded = storage.load(domain).await.unwrap().expect("Cert not found");
    assert_eq!(loaded.0, "CERT_CHAIN_PEM");
    assert_eq!(loaded.1, "KEY_PEM");

    // Test ACME account persistence
    let account_json = r#"{"id":"https://acme-v02.api.letsencrypt.org/acme/acct/12345"}"#;
    let account_key = "ACME_PRIV_KEY";
    storage
        .store_account(ca, Some("you@example.com"), account_json, Some(account_key))
        .await
        .expect("Failed to store ACME account");

    let account_dir = temp_dir
        .join("acme")
        .join("acme-v02.api.letsencrypt.org-directory")
        .join("users")
        .join("you@example.com");

    assert!(account_dir.join("you@example.com.json").exists());
    assert!(account_dir.join("you@example.com.key").exists());

    let loaded_account = storage
        .load_account(ca, Some("you@example.com"))
        .await
        .unwrap()
        .expect("Account not found");
    assert_eq!(loaded_account, account_json);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_tls_alpn_challenge_cert_generation_and_sni_resolution() {
    use raddy_tls::ChallengeTypePreference;
    use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
    use ring::digest::{SHA256, digest};

    // Simulate ACME key authorization and SHA-256 digest calculation (RFC 8737 §3)
    let domain = "ams.eeeu.de";
    let key_auth = "dummy_token.dummy_thumbprint_key_auth_string";
    let key_digest = digest(&SHA256, key_auth.as_bytes());

    let mut params = CertificateParams::default();
    let ext = CustomExtension::new_acme_identifier(key_digest.as_ref());
    params.custom_extensions.push(ext);

    let dns_name: rcgen::Ia5String = domain.try_into().unwrap();
    params.subject_alt_names.push(SanType::DnsName(dns_name));

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_cert = params.self_signed(&leaf_key).unwrap();
    let certified_key = parse_certified_key(&leaf_cert.pem(), &leaf_key.serialize_pem()).unwrap();

    let resolver = SniResolver::new();
    assert_eq!(resolver.alpn_challenge_count(), 0);

    // Insert ALPN challenge
    resolver.insert_alpn_challenge(domain, certified_key.clone());
    assert_eq!(resolver.alpn_challenge_count(), 1);

    // Test case insensitive and dot-normalized retrieval
    resolver.insert_alpn_challenge("AMS.EEEU.DE.", certified_key.clone());
    assert_eq!(resolver.alpn_challenge_count(), 1);

    // Remove ALPN challenge
    resolver.remove_alpn_challenge("ams.eeeu.de");
    assert_eq!(resolver.alpn_challenge_count(), 0);

    // Test TlsManager default challenge preference is TlsAlpnFirst
    let manager = TlsManager::new(None, true).unwrap();
    assert_eq!(
        manager.challenge_preference(),
        ChallengeTypePreference::TlsAlpnFirst
    );

    // Test with_challenge_preference
    let manager = manager.with_challenge_preference(ChallengeTypePreference::TlsAlpnOnly);
    assert_eq!(
        manager.challenge_preference(),
        ChallengeTypePreference::TlsAlpnOnly
    );
}
