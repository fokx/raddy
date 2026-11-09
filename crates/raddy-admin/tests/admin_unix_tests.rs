#[cfg(unix)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use raddy_admin::{AdminClient, AdminServer, AppState};
    use raddy_caddyfile::{Adapter, parse_caddyfile};
    use raddy_core::module::ModuleRegistry;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_admin_api_unix_socket_lifecycle_and_permissions() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("raddy-admin.sock");
        let listen_arg = format!("unix/{}|0660", sock_path.display());

        let initial_caddyfile = r#"
        :0 {
            respond "Unix Admin Test" 200
        }
        "#;
        let parsed = parse_caddyfile(initial_caddyfile).unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&parsed).unwrap();

        let registry = Arc::new(ModuleRegistry::new());
        let state = Arc::new(AppState::new(config, registry, None));

        // 1. Bind AdminServer to Unix domain socket
        let mut admin_server = AdminServer::new(&listen_arg, state.clone());
        admin_server.bind().await.unwrap();

        assert_eq!(admin_server.socket_path(), Some(sock_path.as_path()));
        assert!(sock_path.exists(), "Socket file should exist after bind");

        // Verify socket permissions (0660)
        let metadata = std::fs::metadata(&sock_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "Permissions should match 0660");

        // 2. Start AdminServer task
        let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::watch::channel(false);
        state
            .reload(state.config.load().as_ref().clone())
            .await
            .unwrap();

        let server_task = tokio::spawn(async move { admin_server.run(admin_shutdown_rx).await });

        // 3. AdminClient requests over Unix domain socket
        let client = AdminClient::new(format!("unix/{}", sock_path.display()));

        // GET /
        let resp = client.get("/").await.unwrap();
        assert!(resp.is_success());
        let val: serde_json::Value = resp.json().unwrap();
        assert_eq!(val["app"], "raddy");
        assert_eq!(val["status"], "ok");

        // GET /config/
        let resp = client.get("/config/").await.unwrap();
        assert!(resp.is_success());
        let cfg_val: serde_json::Value = resp.json().unwrap();
        assert!(cfg_val.get("apps").is_some());

        // POST /stop
        let resp = client.post("/stop", bytes::Bytes::new(), None).await.unwrap();
        assert!(resp.is_success());

        // Await graceful termination of AdminServer
        let _ = admin_shutdown_tx.send(true);
        let res = server_task.await.unwrap();
        assert!(res.is_ok());

        // Verify socket file was cleaned up on shutdown
        assert!(!sock_path.exists(), "Socket file should be removed upon shutdown");
    }

    #[tokio::test]
    async fn test_admin_api_unix_socket_stale_cleanup_and_in_use_detection() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("stale.sock");

        // Create a stale file where the socket will be
        std::fs::write(&sock_path, b"stale").unwrap();
        assert!(sock_path.exists());

        let initial_caddyfile = ":0 { respond ok 200 }";
        let parsed = parse_caddyfile(initial_caddyfile).unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&parsed).unwrap();

        let registry = Arc::new(ModuleRegistry::new());
        let state = Arc::new(AppState::new(config, registry, None));

        // 1. Should safely remove stale socket/file and bind
        let mut s1 = AdminServer::new(format!("unix//{}", sock_path.display()), state.clone());
        s1.bind().await.unwrap();
        assert!(sock_path.exists());

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let s1_task = tokio::spawn(async move { s1.run(shutdown_rx).await });

        // Wait brief moment for s1 to start listening
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2. Second instance attempting to bind same active socket should fail
        let mut s2 = AdminServer::new(format!("unix//{}", sock_path.display()), state.clone());
        let bind_res = s2.bind().await;
        assert!(bind_res.is_err(), "Second bind should fail because socket is actively in use");
        let err_msg = bind_res.unwrap_err().to_string();
        assert!(err_msg.contains("in use by another running process"));

        // Clean up s1
        let _ = shutdown_tx.send(true);
        let _ = s1_task.await;
    }

    #[tokio::test]
    async fn test_admin_api_forceful_shutdown_residual_socket_recovery() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("residual_forceful.sock");

        let initial_caddyfile = ":0 { respond ok 200 }";
        let parsed = parse_caddyfile(initial_caddyfile).unwrap();
        let mut adapter = Adapter::new();
        let config = adapter.adapt(&parsed).unwrap();

        let registry = Arc::new(ModuleRegistry::new());
        let state = Arc::new(AppState::new(config, registry, None));

        // Simulate a previous instance that was forcefully terminated (SIGKILL / power cut):
        // It bound a real Unix domain socket, but was killed without deleting the socket file.
        {
            let raw_listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
            // Intentionally don't run graceful shutdown cleanup and drop listener
            drop(raw_listener);
        }

        // The socket file still remains on disk, exactly like after a forceful kill
        assert!(sock_path.exists());

        // A new Raddy instance starts up:
        // It must detect that no process is listening, treat it as residual, safely delete it, and bind successfully!
        let mut new_server = AdminServer::new(format!("unix//{}", sock_path.display()), state.clone());
        let bind_result = new_server.bind().await;
        assert!(bind_result.is_ok(), "Raddy should recover from residual socket file after forceful shutdown");

        // Verify the new server is actively listening on the socket
        let client = AdminClient::new(format!("unix//{}", sock_path.display()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { new_server.run(shutdown_rx).await });

        let resp = client.get("/").await.unwrap();
        assert!(resp.is_success());

        let _ = shutdown_tx.send(true);
        let _ = task.await;
    }
}
