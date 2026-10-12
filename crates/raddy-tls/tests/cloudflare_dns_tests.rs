use axum::{
    Json, Router,
    extract::{Path as AxPath, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use parking_lot::RwLock;
use raddy_tls::acme::{ChallengeTypePreference, Dns01Provider};
use raddy_tls::cloudflare::{
    CloudflareDnsProvider, is_valid_cloudflare_token, resolve_cloudflare_token,
};
use raddy_tls::manager::TlsManager;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_token_validation_and_placeholders() {
    // 1. Classic API token (35-50 chars)
    assert!(is_valid_cloudflare_token(
        "12345678901234567890123456789012345"
    ));
    assert!(is_valid_cloudflare_token(
        "v1234567890123456789012345678901234567890123456789"
    ));
    // 2. New token formats
    assert!(is_valid_cloudflare_token(
        "cfut_12345678901234567890123456789012"
    ));
    assert!(is_valid_cloudflare_token(
        "cfat_12345678901234567890123456789012"
    ));
    // 3. Invalid tokens
    assert!(!is_valid_cloudflare_token("too_short"));
    assert!(!is_valid_cloudflare_token("{env.CF_TOKEN}"));

    // 4. Placeholder resolution
    unsafe {
        std::env::set_var("TEST_RAD_CF_TOKEN", "cfut_12345678901234567890123456789012");
    }
    assert_eq!(
        resolve_cloudflare_token("{env.TEST_RAD_CF_TOKEN}"),
        "cfut_12345678901234567890123456789012"
    );
    assert_eq!(
        resolve_cloudflare_token("{$TEST_RAD_CF_TOKEN}"),
        "cfut_12345678901234567890123456789012"
    );

    // 5. Fallback to CLOUDFLARE_API_TOKEN
    unsafe {
        std::env::set_var("CLOUDFLARE_API_TOKEN", "cfat_12345678901234567890123456789012");
    }
    assert_eq!(
        resolve_cloudflare_token(""),
        "cfat_12345678901234567890123456789012"
    );

    // 6. Error handling on empty token without env vars
    unsafe {
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        std::env::remove_var("CF_API_TOKEN");
    }
    assert!(CloudflareDnsProvider::new("").is_err());
    assert!(CloudflareDnsProvider::new("{env.NON_EXISTENT_TOKEN}").is_err());
}

#[derive(Clone, Default)]
struct MockCloudflareState {
    records: Arc<RwLock<HashMap<String, Value>>>,
    created_count: Arc<RwLock<usize>>,
    deleted_count: Arc<RwLock<usize>>,
}

#[derive(Deserialize)]
struct ZoneQuery {
    name: Option<String>,
}

#[tokio::test]
async fn test_cloudflare_dns_provider_lifecycle() {
    unsafe {
        std::env::set_var("MOCK_CLOUDFLARE", "1");
        std::env::set_var("RADDY_DNS_PROPAGATION_DELAY_SECS", "0");
    }

    let state = MockCloudflareState::default();
    let state_clone = state.clone();

    let app = Router::new()
        .route(
            "/zones",
            get(|Query(q): Query<ZoneQuery>, headers: HeaderMap| async move {
                let auth = headers.get("authorization").and_then(|h| h.to_str().ok());
                if auth != Some("Bearer mock-token-123456789012345678901234567890") {
                    return (StatusCode::UNAUTHORIZED, Json(json!({"errors": ["unauthorized"]}))).into_response();
                }

                if q.name.as_deref() == Some("example.com") {
                    Json(json!({
                        "success": true,
                        "result": [
                            {
                                "id": "zone_example_123",
                                "name": "example.com",
                                "status": "active"
                            }
                        ]
                    })).into_response()
                } else {
                    Json(json!({
                        "success": true,
                        "result": []
                    })).into_response()
                }
            }),
        )
        .route(
            "/zones/{zone_id}/dns_records",
            post({
                let state = state_clone.clone();
                move |AxPath(zone_id): AxPath<String>, Json(payload): Json<Value>| {
                    let state = state.clone();
                    async move {
                        assert_eq!(zone_id, "zone_example_123");
                        assert_eq!(payload["type"], "TXT");
                        assert_eq!(payload["name"], "_acme-challenge.sub.example.com");
                        assert_eq!(payload["content"], "acme-digest-sample-value");
                        assert_eq!(payload["ttl"], 60);

                        let rec_id = "rec_999";
                        state.records.write().insert(rec_id.to_string(), payload.clone());
                        *state.created_count.write() += 1;

                        Json(json!({
                            "success": true,
                            "result": {
                                "id": rec_id,
                                "type": "TXT",
                                "name": payload["name"],
                                "content": payload["content"],
                                "ttl": 60
                            }
                        }))
                    }
                }
            }),
        )
        .route(
            "/zones/{zone_id}/dns_records/{rec_id}",
            delete({
                let state = state_clone.clone();
                move |AxPath((zone_id, rec_id)): AxPath<(String, String)>| {
                    let state = state.clone();
                    async move {
                        assert_eq!(zone_id, "zone_example_123");
                        assert_eq!(rec_id, "rec_999");
                        state.records.write().remove(&rec_id);
                        *state.deleted_count.write() += 1;

                        Json(json!({
                            "success": true,
                            "result": {
                                "id": rec_id
                            }
                        }))
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let provider = CloudflareDnsProvider::new("mock-token-123456789012345678901234567890")
        .expect("Provider creation failed")
        .with_base_url(&mock_url)
        .with_propagation_delay(Duration::ZERO);

    // 1. Zone lookup: sub.example.com should resolve to example.com zone_id
    let zone_id = provider.get_zone_id("sub.example.com").await.unwrap();
    assert_eq!(zone_id, "zone_example_123");

    // 2. Present challenge TXT record
    provider
        .present("sub.example.com", "acme-digest-sample-value")
        .await
        .expect("Failed to present DNS record");

    assert_eq!(*state.created_count.read(), 1);
    assert_eq!(state.records.read().len(), 1);

    // 3. Clean up challenge TXT record
    provider
        .clean_up("sub.example.com", "acme-digest-sample-value")
        .await
        .expect("Failed to clean up DNS record");

    assert_eq!(*state.deleted_count.read(), 1);
    assert_eq!(state.records.read().len(), 0);
}

#[tokio::test]
async fn test_tls_manager_with_dns_provider() {
    unsafe {
        std::env::set_var("MOCK_CLOUDFLARE", "1");
    }

    let provider = Arc::new(
        CloudflareDnsProvider::new("cfut_12345678901234567890123456789012")
            .unwrap()
            .with_propagation_delay(Duration::ZERO),
    );

    let manager = TlsManager::new(None, true)
        .expect("Failed to create manager")
        .with_challenge_preference(ChallengeTypePreference::Dns01Only)
        .with_dns_provider(provider);

    assert_eq!(
        manager.challenge_preference(),
        ChallengeTypePreference::Dns01Only
    );
    assert!(manager.dns_provider().is_some());

    // Verify storage swapping preserves dns_provider
    let storage = raddy_tls::storage::FileCertStorage::new(std::env::temp_dir().join("raddy_test_dns_swap"));
    let manager = manager.with_storage(std::sync::Arc::new(storage));
    assert!(manager.dns_provider().is_some());
    assert_eq!(
        manager.challenge_preference(),
        ChallengeTypePreference::Dns01Only
    );
}
