#[cfg(unix)]
mod tests {
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_systemd_notifications_protocol() {
        let dir = TempDir::new().expect("Failed to create tempdir");
        let sock_path = dir.path().join("notify.sock");

        let listener = UnixDatagram::bind(&sock_path).expect("Failed to bind test notify socket");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("Failed to set read timeout");

        // Set NOTIFY_SOCKET for the test process
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        // 1. Startup notification
        if let Err(err) = raddy_server::systemd::notify(&[
            raddy_server::systemd::NotifyState::Ready,
            raddy_server::systemd::NotifyState::Status("Serving HTTP requests"),
        ]) {
            panic!("systemd notification failed: {err}");
        }

        let mut buf = [0u8; 1024];
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive startup notification");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.contains("READY=1\n"));
        assert!(msg.contains("STATUS=Serving HTTP requests\n"));

        // 2. Reloading notification (with monotonic usec)
        let monotonic_usec = raddy_server::systemd::NotifyState::monotonic_usec_now()
            .expect("Failed to get monotonic time");
        if let Err(err) = raddy_server::systemd::notify(&[
            raddy_server::systemd::NotifyState::Reloading,
            monotonic_usec,
            raddy_server::systemd::NotifyState::Status("Reloading configuration"),
        ]) {
            panic!("systemd notification failed: {err}");
        }

        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive reloading notification");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.contains("RELOADING=1\n"));
        assert!(msg.contains("MONOTONIC_USEC="));
        assert!(msg.contains("STATUS=Reloading configuration\n"));

        // Reload error case re-asserts Ready with previous config status
        let _ = raddy_server::systemd::notify(&[
            raddy_server::systemd::NotifyState::Ready,
            raddy_server::systemd::NotifyState::Status("Config error; running on previous config"),
        ]);
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive reload error notification");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.contains("READY=1\n"));
        assert!(msg.contains("STATUS=Config error; running on previous config\n"));

        // 3. Stopping notification
        if let Err(err) = raddy_server::systemd::notify(&[
            raddy_server::systemd::NotifyState::Stopping,
            raddy_server::systemd::NotifyState::Status("Shutting down"),
        ]) {
            panic!("systemd notification failed: {err}");
        }

        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive stopping notification");
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.contains("STOPPING=1\n"));
        assert!(msg.contains("STATUS=Shutting down\n"));

        // Cleanup env
        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
    }

    #[tokio::test]
    async fn test_systemd_notifications_live_lifecycle() {
        let dir = TempDir::new().expect("Failed to create tempdir");
        let sock_path = dir.path().join("notify_lifecycle.sock");

        let listener = UnixDatagram::bind(&sock_path).expect("Failed to bind notify socket");
        listener
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("Failed to set read timeout");

        let caddyfile_path = dir.path().join("Caddyfile");
        let admin_sock = dir.path().join("admin.sock");
        let port = 28240;

        let initial_caddyfile = format!(
            "{{\n  admin unix/{}\n}}\n:{} {{\n  respond \"v1\"\n}}\n",
            admin_sock.display(),
            port
        );
        std::fs::write(&caddyfile_path, &initial_caddyfile).expect("Failed to write Caddyfile");

        let raddy_path = env!("CARGO_BIN_EXE_raddy");

        // Spawn raddy run with NOTIFY_SOCKET set
        let mut child = std::process::Command::new(raddy_path)
            .arg("run")
            .arg("--config")
            .arg(&caddyfile_path)
            .env("NOTIFY_SOCKET", &sock_path)
            .spawn()
            .expect("Failed to spawn raddy run");

        // Wait for READY notification
        let mut buf = [0u8; 1024];
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive startup READY notification from raddy run");
        let startup_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(startup_msg.contains("READY=1"));
        assert!(startup_msg.contains("STATUS=Serving HTTP requests"));

        // Now test `raddy reload` with NOTIFY_SOCKET
        let updated_caddyfile = format!(
            "{{\n  admin unix/{}\n}}\n:{} {{\n  respond \"v2\"\n}}\n",
            admin_sock.display(),
            port
        );
        std::fs::write(&caddyfile_path, &updated_caddyfile).expect("Failed to update Caddyfile");

        let reload_output = std::process::Command::new(raddy_path)
            .arg("reload")
            .arg("--config")
            .arg(&caddyfile_path)
            .arg("--address")
            .arg(format!("unix/{}", admin_sock.display()))
            .env("NOTIFY_SOCKET", &sock_path)
            .output()
            .expect("Failed to run raddy reload");

        assert!(
            reload_output.status.success(),
            "raddy reload failed: {}",
            String::from_utf8_lossy(&reload_output.stderr)
        );

        // Receive RELOADING message
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive RELOADING message from raddy reload");
        let reload_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(reload_msg.contains("RELOADING=1"));
        assert!(reload_msg.contains("MONOTONIC_USEC="));
        assert!(reload_msg.contains("STATUS=Reloading configuration"));

        // Receive READY message after reload
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive READY message after raddy reload");
        let ready_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(ready_msg.contains("READY=1"));
        assert!(ready_msg.contains("STATUS=Serving HTTP requests"));

        // Now test `raddy reload` with an invalid config: reload should fail, but notify READY with error status
        let bad_caddyfile = dir.path().join("BadCaddyfile");
        std::fs::write(&bad_caddyfile, "invalid {{{ caddyfile syntax").unwrap();

        let reload_bad = std::process::Command::new(raddy_path)
            .arg("reload")
            .arg("--config")
            .arg(&bad_caddyfile)
            .arg("--address")
            .arg(format!("unix/{}", admin_sock.display()))
            .env("NOTIFY_SOCKET", &sock_path)
            .output()
            .expect("Failed to run raddy reload with bad config");

        assert!(!reload_bad.status.success());

        // Receive RELOADING message
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive RELOADING message for failed reload");
        let reload_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(reload_msg.contains("RELOADING=1"));
        assert!(reload_msg.contains("STATUS=Reloading configuration"));

        // Receive READY message with config error status
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive READY error message for failed reload");
        let ready_err_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(ready_err_msg.contains("READY=1"));
        assert!(ready_err_msg.contains("STATUS=Config error; running on previous config"));

        // Now test `raddy stop`
        let stop_output = std::process::Command::new(raddy_path)
            .arg("stop")
            .arg("--address")
            .arg(format!("unix/{}", admin_sock.display()))
            .output()
            .expect("Failed to run raddy stop");

        assert!(stop_output.status.success());

        // Receive STOPPING message
        let n = listener
            .recv(&mut buf)
            .expect("Failed to receive STOPPING message from raddy run");
        let stopping_msg = String::from_utf8_lossy(&buf[..n]);
        assert!(stopping_msg.contains("STOPPING=1"));
        assert!(stopping_msg.contains("STATUS=Shutting down"));

        let _ = child.wait();
    }
}
