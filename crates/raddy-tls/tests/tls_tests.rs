use std::sync::Arc;
use raddy_tls::local_ca::LocalCa;
use raddy_tls::manager::{is_local_or_private, TlsManager};
use raddy_tls::sni::SniResolver;
use raddy_tls::storage::{parse_certified_key, CertStorage, FileCertStorage};

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

    let certified_key = parse_certified_key(&cert_pem, &key_pem).expect("Failed to parse certified key");
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

    let loaded = storage.load(identifier).await.expect("Failed to load").expect("Cert not found");
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
    let _acceptor = manager.build_tls_acceptor().expect("Failed to build TLS acceptor");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}
