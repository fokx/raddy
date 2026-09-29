use std::env;

/// Prints the Raddy version, architecture, OS, and toolchain info.
pub fn print_version() {
    println!(
        "raddy v{} ({}-{}, rustc 1.96)",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS,
        env::consts::ARCH,
    );
}

/// Prints current process runtime environment details.
pub fn print_environ() {
    println!("Raddy Version: v{}", env!("CARGO_PKG_VERSION"));
    println!("OS: {}", env::consts::OS);
    println!("Architecture: {}", env::consts::ARCH);
    println!("Family: {}", env::consts::FAMILY);
    println!("Process ID: {}", std::process::id());
    if let Ok(cwd) = env::current_dir() {
        println!("Working Directory: {}", cwd.display());
    }

    println!("\nEnvironment Variables:");
    let mut vars: Vec<_> = env::vars().collect();
    vars.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in vars {
        println!("{}={}", k, v);
    }
}

/// Lists all registered Raddy modules and directives.
pub fn list_modules(as_json: bool) {
    let modules = vec![
        ("http.handlers.respond", "Synthesize static HTTP responses with status code and body"),
        ("http.handlers.file_server", "Static file server with index and directory browsing"),
        ("http.handlers.forward_proxy", "Forward and CONNECT tunnel proxy with ACL, authentication, and probe resistance"),
        ("http.handlers.reverse_proxy", "Reverse proxy with dynamic load balancing and active health checks"),
        ("http.handlers.encode", "HTTP response body compression (gzip, zstd, deflate)"),
        ("http.handlers.templates", "MiniJinja dynamic template rendering with request context"),
        ("http.handlers.basic_auth", "HTTP Basic Authentication with bcrypt password verification"),
        ("http.handlers.forward_auth", "Delegate authentication to external auth service"),
        ("http.handlers.request_body", "Enforce maximum incoming HTTP request body size"),
        ("http.handlers.headers", "Manipulate request and response HTTP headers"),
        ("http.handlers.rewrite", "URI rewriting and path normalization"),
        ("http.handlers.map", "Variable table mapping based on input placeholders"),
        ("http.handlers.abort", "Immediate TCP/HTTP connection abortion"),
        ("http.handlers.error", "Synthesize custom error responses and status codes"),
        ("http.matchers.path", "Match request URI path prefixes and glob patterns"),
        ("http.matchers.path_regexp", "Match request URI path using regular expressions"),
        ("http.matchers.host", "Match request virtual hosts and domain wildcards"),
        ("http.matchers.method", "Match HTTP request methods (GET, POST, etc.)"),
        ("http.matchers.header", "Match HTTP request header presence and values"),
        ("http.matchers.header_regexp", "Match HTTP request headers via regex"),
        ("http.matchers.query", "Match HTTP query parameters"),
        ("http.matchers.protocol", "Match protocol scheme (http, https)"),
        ("http.matchers.remote_ip", "Match client IP addresses and CIDR subnets"),
        ("http.matchers.expression", "Match dynamic CEL and placeholder expressions"),
        ("http.matchers.not", "Invert wrapped matcher evaluation"),
        ("tls.issuance.acme", "ACME automated certificate management (HTTP-01, TLS-ALPN-01)"),
        ("tls.issuance.internal", "Embedded local CA automated certificate issuance"),
        ("admin.api", "Axum-powered REST Admin API for runtime configuration and control"),
    ];

    if as_json {
        let list: Vec<serde_json::Value> = modules
            .into_iter()
            .map(|(id, desc)| serde_json::json!({ "name": id, "description": desc }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
    } else {
        println!("{:<32} {:<60}", "MODULE", "DESCRIPTION");
        println!("{}", "-".repeat(92));
        for (id, desc) in modules {
            println!("{:<32} {:<60}", id, desc);
        }
    }
}
