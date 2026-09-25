use std::sync::Arc;
use raddy_admin::{AdminServer, AppState};
use raddy_caddyfile::{parse_caddyfile, Adapter};
use raddy_core::module::ModuleRegistry;

#[tokio::test]
async fn test_admin_api_status_and_config_endpoints() {
    let initial_caddyfile = r#"
    :0 {
        respond "Initial V1" 200
    }
    "#;
    let parsed = parse_caddyfile(initial_caddyfile).unwrap();
    let mut adapter = Adapter::new();
    let config = adapter.adapt(&parsed).unwrap();

    let registry = Arc::new(ModuleRegistry::new());
    let state = Arc::new(AppState::new(config, registry, None));

    // Bind and run admin server on ephemeral port
    let mut admin_server = AdminServer::new("127.0.0.1:0", state.clone());
    admin_server.bind().await.unwrap();
    let admin_addr = admin_server.local_addr().unwrap();
    let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);

    // Initial server start
    state.reload(state.config.load().as_ref().clone()).await.unwrap();

    let server_task = tokio::spawn(async move {
        admin_server.run(admin_shutdown_rx).await
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", admin_addr.port());

    // 1. GET /
    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let val: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(val["app"], "raddy");
    assert_eq!(val["status"], "ok");

    // 2. GET /config/
    let resp = client.get(format!("{}/config/", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let config_val: serde_json::Value = resp.json().await.unwrap();
    assert!(config_val.get("apps").is_some());

    // 3. GET /config/apps/http/servers
    let resp = client.get(format!("{}/config/apps/http/servers", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 4. GET /config/non_existent -> 404
    let resp = client.get(format!("{}/config/non_existent_path", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    // 5. POST /config/custom_meta (insert new config node)
    let post_resp = client
        .post(format!("{}/config/custom_meta", base_url))
        .json(&serde_json::json!({"version": "v1.0.0", "author": "raddy"}))
        .send()
        .await
        .unwrap();
    assert_eq!(post_resp.status(), reqwest::StatusCode::OK);

    // 6. GET /config/custom_meta
    let get_custom = client.get(format!("{}/config/custom_meta", base_url)).send().await.unwrap();
    assert_eq!(get_custom.status(), reqwest::StatusCode::OK);
    let meta_val: serde_json::Value = get_custom.json().await.unwrap();
    assert_eq!(meta_val["version"], "v1.0.0");
    assert_eq!(meta_val["author"], "raddy");

    // 7. PATCH /config/custom_meta
    let patch_resp = client
        .patch(format!("{}/config/custom_meta", base_url))
        .json(&serde_json::json!({"version": "v1.1.0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(patch_resp.status(), reqwest::StatusCode::OK);

    let get_patched = client.get(format!("{}/config/custom_meta", base_url)).send().await.unwrap();
    let patched_val: serde_json::Value = get_patched.json().await.unwrap();
    assert_eq!(patched_val["version"], "v1.1.0");
    assert_eq!(patched_val["author"], "raddy");

    // 8. DELETE /config/custom_meta
    let del_resp = client
        .delete(format!("{}/config/custom_meta", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), reqwest::StatusCode::OK);

    let get_deleted = client.get(format!("{}/config/custom_meta", base_url)).send().await.unwrap();
    assert_eq!(get_deleted.status(), reqwest::StatusCode::NOT_FOUND);

    // 9. GET /pki/ca/local (without TLS Manager -> 404)
    let pki_resp = client.get(format!("{}/pki/ca/local", base_url)).send().await.unwrap();
    assert_eq!(pki_resp.status(), reqwest::StatusCode::NOT_FOUND);

    admin_shutdown_tx.send(true).unwrap();
    state.stop_all();
    let _ = server_task.await;
}

#[tokio::test]
async fn test_zero_downtime_hot_reload() {
    // 1. Prepare initial config: site on port 28091 returning "Hello from V1"
    let caddyfile_v1 = r#"
    127.0.0.1:28091 {
        respond "Hello from V1" 200
    }
    "#;
    let parsed_v1 = parse_caddyfile(caddyfile_v1).unwrap();
    let mut adapter = Adapter::new();
    let config_v1 = adapter.adapt(&parsed_v1).unwrap();

    let registry = Arc::new(ModuleRegistry::new());
    let state = Arc::new(AppState::new(config_v1.clone(), registry, None));

    // Spin up admin server with synchronous bind
    let mut admin_server = AdminServer::new("127.0.0.1:0", state.clone());
    admin_server.bind().await.unwrap();
    let admin_addr = admin_server.local_addr().unwrap();
    let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);
    let admin_task = tokio::spawn(async move {
        admin_server.run(admin_shutdown_rx).await
    });

    // Start initial HTTP server
    state.reload(config_v1).await.expect("Failed to start V1");

    let client = reqwest::Client::new();
    let admin_url = format!("http://127.0.0.1:{}", admin_addr.port());
    let site_url = "http://127.0.0.1:28091";

    // 2. Query site: should receive V1
    let resp_v1 = client.get(site_url).send().await.expect("Failed to query V1");
    assert_eq!(resp_v1.status(), reqwest::StatusCode::OK);
    assert_eq!(resp_v1.text().await.unwrap(), "Hello from V1");

    // 3. Hot reload via POST /load with V2 config
    let caddyfile_v2 = r#"
    127.0.0.1:28091 {
        respond "Hello from V2 (Hot Reloaded!)" 200
    }
    "#;

    let reload_resp = client
        .post(format!("{}/load", admin_url))
        .header("content-type", "text/caddyfile")
        .body(caddyfile_v2)
        .send()
        .await
        .expect("Failed to call /load");

    assert_eq!(reload_resp.status(), reqwest::StatusCode::OK);

    // 4. Query site again: should immediately receive V2!
    let resp_v2 = client.get(site_url).send().await.expect("Failed to query V2");
    assert_eq!(resp_v2.status(), reqwest::StatusCode::OK);
    assert_eq!(resp_v2.text().await.unwrap(), "Hello from V2 (Hot Reloaded!)");

    // 5. Hot reload with invalid config: old server should continue serving V2!
    let bad_caddyfile = "invalid caddyfile syntax {{{{";
    let bad_reload = client
        .post(format!("{}/load", admin_url))
        .header("content-type", "text/caddyfile")
        .body(bad_caddyfile)
        .send()
        .await
        .unwrap();

    assert_eq!(bad_reload.status(), reqwest::StatusCode::BAD_REQUEST);

    // Site still alive and serves V2
    let resp_still_v2 = client.get(site_url).send().await.unwrap();
    assert_eq!(resp_still_v2.status(), reqwest::StatusCode::OK);
    assert_eq!(resp_still_v2.text().await.unwrap(), "Hello from V2 (Hot Reloaded!)");

    // Clean shutdown
    admin_shutdown_tx.send(true).unwrap();
    state.stop_all();
    let _ = admin_task.await;
}

#[tokio::test]
async fn test_admin_stop_endpoint() {
    let initial_caddyfile = r#"
    127.0.0.1:28092 {
        respond "Alive" 200
    }
    "#;
    let parsed = parse_caddyfile(initial_caddyfile).unwrap();
    let mut adapter = Adapter::new();
    let config = adapter.adapt(&parsed).unwrap();

    let registry = Arc::new(ModuleRegistry::new());
    let state = Arc::new(AppState::new(config.clone(), registry, None));

    let mut admin_server = AdminServer::new("127.0.0.1:0", state.clone());
    admin_server.bind().await.unwrap();
    let admin_addr = admin_server.local_addr().unwrap();
    let (_admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);
    let admin_task = tokio::spawn(async move {
        admin_server.run(admin_shutdown_rx).await
    });

    state.reload(config).await.unwrap();

    let client = reqwest::Client::new();
    let admin_url = format!("http://127.0.0.1:{}", admin_addr.port());

    // Call POST /stop
    let stop_resp = client.post(format!("{}/stop", admin_url)).send().await.unwrap();
    assert_eq!(stop_resp.status(), reqwest::StatusCode::OK);

    // Wait for server task to finish gracefully
    let _ = admin_task.await;
}
