use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE};
use raddy_caddyfile::{Adapter, Lexer, Parser};
use raddy_core::module::ModuleRegistry;
use raddy_http::ServerManager;

fn parse_and_adapt(input: &str) -> raddy_core::Config {
    let tokens = Lexer::new(input).tokenize().unwrap();
    let caddyfile = Parser::new(tokens).parse().unwrap();
    let mut adapter = Adapter::new();
    adapter.adapt(&caddyfile).unwrap()
}

#[tokio::test]
async fn test_live_access_logging_and_redaction() {
    let test_dir = std::env::temp_dir().join(format!("raddy_log_redact_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&test_dir);
    let log_file = test_dir.join("access.log");
    let log_path_str = log_file.to_str().unwrap().replace('\\', "/");

    let caddyfile = format!(
        r#"
:29101 {{
    log {{
        output file {} {{
            roll_disabled
        }}
        format json
    }}
    respond /hello "world" 200
}}
"#,
        log_path_str
    );

    let config = parse_and_adapt(&caddyfile);
    let registry = ModuleRegistry::new();
    let mut manager = ServerManager::from_config(&config, &registry, None).await.unwrap();
    manager.bind_all().await.unwrap();

    let (_join_set, shutdown_tx) = manager.spawn_all();

    // Give server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send HTTP request with sensitive headers
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static("session_id=secret123; tracking=abc"));
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer super_secret_token"));
    headers.insert("X-Custom", HeaderValue::from_static("public_data"));

    let resp = client
        .get("http://127.0.0.1:29101/hello?param=val")
        .headers(headers)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "world");

    // Wait for log to be flushed to file
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Read log file
    let file = File::open(&log_file).expect("log file should exist");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

    assert_eq!(lines.len(), 1, "expected 1 log line");
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

    assert_eq!(entry["msg"], "handled request");
    assert_eq!(entry["status"], 200);
    assert_eq!(entry["request"]["method"], "GET");
    assert_eq!(entry["request"]["uri"], "/hello?param=val");

    // Verify sensitive headers are REDACTED by default
    let req_headers = &entry["request"]["headers"];
    assert_eq!(req_headers["Cookie"], serde_json::json!(["REDACTED"]));
    assert_eq!(req_headers["Authorization"], serde_json::json!(["REDACTED"]));
    assert_eq!(req_headers["X-Custom"], serde_json::json!(["public_data"]));

    // Graceful shutdown
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_log_skip_and_log_append() {
    let tmp_dir = std::env::temp_dir().join(format!("raddy_log_skip_append_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("skip_append.log");
    let log_path_str = log_file.to_str().unwrap().replace('\\', "/");

    let caddyfile = format!(
        r#"
:29102 {{
    log {{
        output file {} {{
            roll_disabled
        }}
        format json
    }}
    log_skip /health
    log_append user {{header.X-User}}
    log_append cluster prod-us-1
    respond /health "ok" 200
    respond /app "app_ok" 200
}}
"#,
        log_path_str
    );

    let config = parse_and_adapt(&caddyfile);
    let registry = ModuleRegistry::new();
    let mut manager = ServerManager::from_config(&config, &registry, None).await.unwrap();
    manager.bind_all().await.unwrap();

    let (_join_set, shutdown_tx) = manager.spawn_all();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // 1. Request to /health should be SKIPPED from logging
    let resp1 = client.get("http://127.0.0.1:29102/health").send().await.unwrap();
    assert_eq!(resp1.status(), 200);

    // 2. Request to /app should be LOGGED with appended fields
    let resp2 = client
        .get("http://127.0.0.1:29102/app")
        .header("X-User", "john_doe")
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let file = File::open(&log_file).expect("log file should exist");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

    assert_eq!(lines.len(), 1, "only /app request should be logged");
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

    assert_eq!(entry["request"]["uri"], "/app");
    assert_eq!(entry["user"], "john_doe");
    assert_eq!(entry["cluster"], "prod-us-1");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_filter_encoder() {
    let tmp_dir = std::env::temp_dir().join(format!("raddy_log_filter_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("filter.log");
    let log_path_str = log_file.to_str().unwrap().replace('\\', "/");

    let caddyfile = format!(
        r#"
:29103 {{
    log {{
        output file {} {{
            roll_disabled
        }}
        format filter {{
            request>headers>User-Agent delete
            request>remote_ip ip_mask 16 32
            request>uri query {{
                delete secret
                replace token REDACTED
            }}
            wrap json
        }}
    }}
    respond /search "found" 200
}}
"#,
        log_path_str
    );

    let config = parse_and_adapt(&caddyfile);
    let registry = ModuleRegistry::new();
    let mut manager = ServerManager::from_config(&config, &registry, None).await.unwrap();
    manager.bind_all().await.unwrap();

    let (_join_set, shutdown_tx) = manager.spawn_all();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:29103/search?secret=xyz&token=abc1234&q=rust")
        .header("User-Agent", "TestAgent/1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let file = File::open(&log_file).expect("log file should exist");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

    assert_eq!(lines.len(), 1);
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

    // User-Agent was deleted
    assert!(entry["request"]["headers"].get("User-Agent").is_none());

    // remote_ip was masked with /16 (127.0.0.1 -> 127.0.0.0)
    assert_eq!(entry["request"]["remote_ip"], "127.0.0.0");

    // uri query: secret deleted, token replaced, q kept
    let uri = entry["request"]["uri"].as_str().unwrap();
    assert!(!uri.contains("secret"));
    assert!(uri.contains("token=REDACTED"));
    assert!(uri.contains("q=rust"));

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_live_log_rolling_and_compression() {
    let tmp_dir = std::env::temp_dir().join(format!("raddy_log_rolling_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("roll.log");
    let log_path_str = log_file.to_str().unwrap().replace('\\', "/");

    let caddyfile = format!(
        r#"
:29104 {{
    log {{
        output file {} {{
            roll_size 200b
            roll_keep 5
        }}
        format json
    }}
    respond /test "ok" 200
}}
"#,
        log_path_str
    );

    let config = parse_and_adapt(&caddyfile);
    let registry = ModuleRegistry::new();
    let mut manager = ServerManager::from_config(&config, &registry, None).await.unwrap();
    manager.bind_all().await.unwrap();

    let (_join_set, shutdown_tx) = manager.spawn_all();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // Each access log is ~400-500 bytes. With roll_size 200b, multiple requests will trigger log rolling!
    for _ in 0..5 {
        let resp = client.get("http://127.0.0.1:29104/test").send().await.unwrap();
        assert_eq!(resp.status(), 200);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Check directory for rolled files (.gz)
    let mut rolled_gz_files = Vec::new();
    for entry in std::fs::read_dir(&tmp_dir).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().into_string().unwrap();
        if fname.starts_with("roll-") && fname.ends_with(".gz") {
            rolled_gz_files.push(fname);
        }
    }

    assert!(
        !rolled_gz_files.is_empty(),
        "expected at least one compressed rolled log file (.gz), found: {:?}",
        rolled_gz_files
    );

    let _ = shutdown_tx.send(true);
}
