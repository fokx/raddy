use std::fs;
use std::process::Command;

fn raddy_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_raddy"))
}

#[test]
fn test_cli_version() {
    let output = raddy_bin()
        .arg("version")
        .output()
        .expect("Failed to execute raddy version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("raddy v{}", env!("CARGO_PKG_VERSION"))));
}

#[test]
fn test_cli_environ() {
    let output = raddy_bin()
        .arg("environ")
        .output()
        .expect("Failed to execute raddy environ");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("Raddy Version: v{}", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.contains("OS:"));
    assert!(stdout.contains("Architecture:"));
    assert!(stdout.contains("Environment Variables:"));
}

#[test]
fn test_cli_list_modules() {
    // Human readable table
    let output = raddy_bin()
        .arg("list-modules")
        .output()
        .expect("Failed to execute raddy list-modules");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("http.handlers.respond"));
    assert!(stdout.contains("http.handlers.reverse_proxy"));
    assert!(stdout.contains("http.handlers.file_server"));
    assert!(stdout.contains("tls.issuance.acme"));

    // JSON output
    let output_json = raddy_bin()
        .arg("list-modules")
        .arg("--json")
        .output()
        .expect("Failed to execute raddy list-modules --json");

    assert!(output_json.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("Failed to parse JSON module list");
    assert!(val.is_array());
    let list = val.as_array().unwrap();
    assert!(
        list.iter()
            .any(|m| m["name"] == "http.handlers.reverse_proxy")
    );
}

#[test]
fn test_cli_adapt_and_validate() {
    let temp_dir = std::env::temp_dir();
    let caddyfile_path = temp_dir.join("test_adapt.caddyfile");

    let caddyfile_content = r#"
    localhost:9090 {
        respond "CLI Adapt Test" 200
    }
    "#;
    fs::write(&caddyfile_path, caddyfile_content).unwrap();

    // 1. Adapt
    let output = raddy_bin()
        .arg("adapt")
        .arg("--config")
        .arg(&caddyfile_path)
        .output()
        .expect("Failed to run raddy adapt");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed_json: serde_json::Value =
        serde_json::from_str(&stdout).expect("raddy adapt did not return valid JSON");
    assert!(parsed_json.get("apps").is_some());

    // 2. Validate valid file
    let val_output = raddy_bin()
        .arg("validate")
        .arg("--config")
        .arg(&caddyfile_path)
        .output()
        .expect("Failed to run raddy validate");

    assert!(val_output.status.success());
    let val_stdout = String::from_utf8_lossy(&val_output.stdout);
    assert!(val_stdout.contains("Valid configuration"));
    assert!(val_stdout.contains("Servers : 1"));

    // 3. Validate non-existent file
    let bad_output = raddy_bin()
        .arg("validate")
        .arg("--config")
        .arg(temp_dir.join("non_existent_caddyfile_path_12345"))
        .output()
        .expect("Failed to run raddy validate on non-existent file");

    assert!(!bad_output.status.success());

    let _ = fs::remove_file(caddyfile_path);
}

#[test]
fn test_cli_fmt() {
    let temp_dir = std::env::temp_dir();
    let caddyfile_path = temp_dir.join("test_fmt.caddyfile");

    let unformatted = "localhost:9091 {\n   respond    \"Fmt Test\"   200\n}\n";
    fs::write(&caddyfile_path, unformatted).unwrap();

    // 1. fmt to stdout
    let output = raddy_bin()
        .arg("fmt")
        .arg("--config")
        .arg(&caddyfile_path)
        .output()
        .expect("Failed to run raddy fmt");

    if !output.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("localhost:9091 {\n"));
    assert!(stdout.contains("\trespond \"Fmt Test\" 200\n"));

    // 2. fmt in-place with --overwrite
    let output_overwrite = raddy_bin()
        .arg("fmt")
        .arg("--config")
        .arg(&caddyfile_path)
        .arg("--overwrite")
        .output()
        .expect("Failed to run raddy fmt --overwrite");

    assert!(output_overwrite.status.success());
    let file_content = fs::read_to_string(&caddyfile_path).unwrap();
    assert!(file_content.contains("localhost:9091 {\n"));
    assert!(file_content.contains("\trespond \"Fmt Test\" 200\n"));

    let _ = fs::remove_file(caddyfile_path);
}

#[tokio::test]
async fn test_cli_run_reload_and_stop() {
    let temp_dir = std::env::temp_dir();
    let caddyfile_v1 = temp_dir.join("test_run_v1.caddyfile");
    let caddyfile_v2 = temp_dir.join("test_run_v2.caddyfile");
    let pid_file = temp_dir.join("raddy_test.pid");

    let v1_content = r#"
    {
        admin 127.0.0.1:28199
    }
    127.0.0.1:28198 {
        respond "CLI Run V1" 200
    }
    "#;

    let v2_content = r#"
    {
        admin 127.0.0.1:28199
    }
    127.0.0.1:28198 {
        respond "CLI Run V2 (Reloaded)" 200
    }
    "#;

    fs::write(&caddyfile_v1, v1_content).unwrap();
    fs::write(&caddyfile_v2, v2_content).unwrap();

    // 1. Launch raddy run
    let mut child = Command::new(env!("CARGO_BIN_EXE_raddy"))
        .arg("run")
        .arg("--config")
        .arg(&caddyfile_v1)
        .arg("--pidfile")
        .arg(&pid_file)
        .spawn()
        .expect("Failed to spawn raddy run");

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let site_url = "http://127.0.0.1:28198";
    let admin_url = "http://127.0.0.1:28199";

    // Wait for server to be responsive
    let mut ready = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(resp) = client.get(site_url).send().await {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
    }
    assert!(ready, "Server failed to start within 4s");

    // 2. Query V1
    let resp = client.get(site_url).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "CLI Run V1");

    // 3. Reload to V2 via CLI
    let reload_output = raddy_bin()
        .arg("reload")
        .arg("--config")
        .arg(&caddyfile_v2)
        .arg("--address")
        .arg(admin_url)
        .output()
        .expect("Failed to run raddy reload");

    if !reload_output.status.success() {
        eprintln!(
            "reload stdout: {}",
            String::from_utf8_lossy(&reload_output.stdout)
        );
        eprintln!(
            "reload stderr: {}",
            String::from_utf8_lossy(&reload_output.stderr)
        );
    }
    assert!(reload_output.status.success());

    // 4. Query again: should receive V2
    let resp_v2 = client.get(site_url).send().await.unwrap();
    assert_eq!(resp_v2.text().await.unwrap(), "CLI Run V2 (Reloaded)");

    // 5. Stop via CLI
    let stop_output = raddy_bin()
        .arg("stop")
        .arg("--address")
        .arg(admin_url)
        .output()
        .expect("Failed to run raddy stop");

    assert!(stop_output.status.success());

    // Wait for child process to exit gracefully
    let status = child.wait().expect("Failed to wait on child process");
    assert!(status.success() || status.code() == Some(0));

    let _ = fs::remove_file(caddyfile_v1);
    let _ = fs::remove_file(caddyfile_v2);
    let _ = fs::remove_file(pid_file);
}

#[tokio::test]
async fn test_cli_file_server() {
    let temp_root = std::env::temp_dir().join("raddy_fs_test");
    let _ = fs::create_dir_all(&temp_root);

    let hello_path = temp_root.join("hello.txt");
    fs::write(&hello_path, "Static File Content").unwrap();

    let index_path = temp_root.join("index.html");
    fs::write(&index_path, "Hello from Raddy File Server!").unwrap();

    let listen_addr = "127.0.0.1:28201";

    let mut child = Command::new(env!("CARGO_BIN_EXE_raddy"))
        .arg("file-server")
        .arg("--listen")
        .arg(listen_addr)
        .arg("--root")
        .arg(&temp_root)
        .spawn()
        .expect("Failed to spawn raddy file-server");

    let client = reqwest::Client::new();
    let base_url = format!("http://{}", listen_addr);

    // Poll until ready
    let mut ready = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(resp) = client.get(format!("{}/hello.txt", base_url)).send().await {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
    }
    assert!(ready, "File server failed to start within 4s");

    // 1. Get hello.txt
    let resp = client
        .get(format!("{}/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "Static File Content");

    // 2. Get / (index.html)
    let resp_index = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp_index.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp_index.text().await.unwrap(),
        "Hello from Raddy File Server!"
    );

    // Terminate child
    let _ = child.kill();
    let _ = child.wait();

    let _ = fs::remove_dir_all(&temp_root);
}
