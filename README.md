# Raddy

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust: 2024 Edition](https://img.shields.io/badge/Rust-2024%20Edition-orange.svg)](https://www.rust-lang.org)
[![Protocols: HTTP/1.1 · HTTP/2 · HTTP/3](https://img.shields.io/badge/Protocols-HTTP%2F1.1%20%7C%20HTTP%2F2%20%7C%20HTTP%2F3%20QUIC-brightgreen.svg)]()
[![Caddyfile Compatible](https://img.shields.io/badge/Config-Caddyfile%20Compatible-teal.svg)]()

**Raddy** is a high-performance, memory-safe, and extensible web server and reverse proxy written in modern Rust. Built as a ground-up Rust implementation compatible with Caddy, Raddy combines the beloved developer experience and human-friendly syntax of the **Caddyfile** with the performance, predictable latency, and zero-cost abstractions of the Rust ecosystem (Tokio, Hyper, Quinn, Rustls, and Axum).

> [!NOTE]
> **Trademark & Disclaimer:** "Caddy" is a trademark of its respective owner(s). **Raddy** is an independent open-source project and is neither affiliated with, endorsed by, nor sponsored by the Caddy project or its creators.
>
> The name **Raddy** was chosen simply for brevity and convenience: the initial **"R"** highlights **Rust**, and the name is short and easy to type and remember as a modern, high-performance drop-in replacement for Caddy. Its use is strictly descriptive and not intended to imitate or infringe upon any trademarks.

---

## Table of Contents

- [Why Raddy?](#why-raddy)
- [Key Features](#key-features)
- [Architecture & Crates](#architecture--crates)
- [Documentation Chapters](#documentation-chapters)
- [Installation & Build](#installation--build)
- [Quick Start](#quick-start)
  - [1. Instant Static File Server](#1-instant-static-file-server)
  - [2. Reverse Proxy with Caddyfile](#2-reverse-proxy-with-caddyfile)
  - [3. Running as a Daemon](#3-running-as-a-daemon)
  - [4. Zero-Downtime Hot Reload](#4-zero-downtime-hot-reload)
- [Configuration Guide](#configuration-guide)
  - [Directives & Matchers](#directives--matchers)
  - [Production Caddyfile Example](#production-caddyfile-example)
  - [Forward Proxy & HTTP CONNECT Tunneling](#forward-proxy--http-connect-tunneling)
- [Command Line Interface (CLI)](#command-line-interface-cli)
- [Admin API](#admin-api)
- [Testing](#testing)
- [License](#license)

---

## Why Raddy?

Caddy revolutionized web serving with human-friendly configuration and automatic HTTPS out of the box. Raddy takes those proven design patterns and reimagines them in **Rust**:

- **No Garbage Collection Pauses:** Consistent, ultra-low tail latencies under heavy load.
- **Minimal Memory Footprint:** Safe, compact resource usage suitable for resource-constrained edge nodes, containers, and high-density multi-tenant environments.
- **Native HTTP/3 (QUIC):** True native QUIC streaming powered by Quinn and h3 with automatic `Alt-Svc` negotiation.
- **Caddyfile Syntax Compatibility:** Seamless migration from existing Caddy setups with full support for snippets, imports, named matchers, and directives.
- **Atomic Hot-Reloading:** Dynamic configuration updates via Admin API or file watching with zero dropped requests, powered by `ArcSwap`.

---

## Key Features

### 🌐 Modern Protocol Engine
- **HTTP/1.1 & HTTP/2:** Powered by Hyper and Tokio with full support for both cleartext (`h2c`) and TLS-negotiated ALPN connections.
- **Native HTTP/3 over QUIC:** High-speed, UDP-based HTTP/3 using Quinn and h3, advertising `Alt-Svc: h3=":443"` automatically.
- **Graceful Shutdown:** Zero dropped connections during restarts and reloads.

### 🔒 Automated TLS & Certificate Management
- **Zero-Config ACME:** Automatic HTTPS with Let's Encrypt and ZeroSSL via `instant-acme`.
- **Challenge Solvers:** Built-in automated TLS-ALPN-01 and HTTP-01 challenge handling.
- **Internal PKI / Local CA:** Automatic self-signed root and leaf certificate generation via `rcgen` for local development (`tls internal`).
- **Dynamic SNI Matching:** Multi-domain routing with lazy certificate loading, background renewals, and public/private IP SAN support.

### 🔀 Reverse Proxy & Load Balancing
- **Load Balancing Algorithms:** `round_robin`, `least_conn`, `random`, and `ip_hash`.
- **Health Checks:** Active background HTTP probing (`interval`, `timeout`, `path`) and passive circuit-breaking on connection failures.
- **Bidirectional Streaming:** Native WebSocket proxying and chunked HTTP streaming without buffering large bodies.
- **Header Manipulation:** Inject, modify, or strip upstream and downstream headers (`header_up`, `header_down`).
- **Forward Proxy & CONNECT Tunneling:** Built-in forward proxy with HTTP `CONNECT` tunneling for outbound proxying and traffic gatewaying.

### 📁 Static File Serving
- **Zero-Copy Serving:** Fast, non-blocking asynchronous file delivery.
- **Directory Browsing:** Mobile-friendly HTML index generation with breadcrumbs and human-readable file sizes (`file_server browse`).
- **Single-Page Application (SPA) Support:** Fallback rewrites and file resolution with `try_files`.
- **MIME Type Detection:** Accurate MIME inference with `mime_guess`.

### ⚡ Directives & Middleware
- `encode`: Streaming on-the-fly response compression supporting both **Gzip** and **Zstandard (zstd)**.
- `templates`: Dynamic server-side templating powered by MiniJinja with access to request headers, path, and variables.
- `basic_auth`: Secure HTTP Basic Authentication backed by `bcrypt` password hashes.
- `forward_auth`: Delegation of authentication checks to external services (Authelia, Authentik, etc.).
- `request_body limits`: Enforcement of maximum payload sizes to guard against DoS attacks.
- `log`: Structured JSON or console access logs with customizable fields, path/header redactions, log rotation, and automated gzip log file rolling.
- `rewrite`, `respond`, `redir`, `abort`, `error`: Expressive routing rules and customizable status responses.

---

## Architecture & Crates

Raddy is structured as a modular Cargo workspace:

```text
raddy/
├── Cargo.toml                     # Workspace root manifest (package: raddy-server, bin: raddy)
├── Caddyfile                      # Sample configuration
├── src/                           # CLI binary entrypoint & commands
├── docs/                          # In-depth architectural & functional chapters
└── crates/
    ├── raddy-core/              # Core traits, Matcher/Handler interfaces, placeholders, AST
    ├── raddy-caddyfile/         # Lexer, recursive-descent parser, AST adapter, snippet/import expander
    ├── raddy-http/              # HTTP/1.1, HTTP/2, HTTP/3 servers, routing engine, middleware handlers
    ├── raddy-tls/               # Automated ACME client, local CA/PKI, SNI resolver, challenge solvers
    ├── raddy-proxy/             # Reverse proxy, load balancers, health checks, forward proxy & tunneling
    └── raddy-admin/             # Axum REST Admin API (:2019) and atomic ArcSwap config state manager
```

---

## Documentation Chapters

Comprehensive technical documentation and deep dives are organized into functional chapters in the [`docs/`](docs/) directory:

- **[Chapter 1: Architecture & Core Runtime](docs/01_architecture_and_core.md)**: Three pillars, module lifecycle, Go-to-Rust paradigm mappings, configuration schema, request context, placeholders, matchers, and atomic state.
- **[Chapter 2: Caddyfile Engine & Parser](docs/02_caddyfile_engine.md)**: Grammar specification, lexer, token dispenser, AST parser, preprocessor (imports/snippets), adapter pipeline, and canonical formatter.
- **[Chapter 3: HTTP Engine & Multi-Protocol Transport](docs/03_http_engine_and_protocols.md)**: HTTP/1.1, HTTP/2 (cleartext & ALPN), native HTTP/3 over QUIC (`Alt-Svc`), VirtualHostRouter, and zero-copy static file server.
- **[Chapter 4: Automated TLS & Certificate Management](docs/04_tls_and_acme.md)**: ACME client (`instant-acme`), challenge solvers (TLS-ALPN-01 & HTTP-01), embedded local CA/PKI (`rcgen`), and dynamic SNI resolution.
- **[Chapter 5: Reverse Proxy, Load Balancing & Forward Proxy](docs/05_reverse_and_forward_proxy.md)**: Upstream pooling, load balancing algorithms, health checks, header manipulation, WebSocket proxying, and HTTP CONNECT forward proxy tunneling.
- **[Chapter 6: HTTP Directives & Middleware Pipeline](docs/06_directives_and_middleware.md)**: Response compression (`encode`), dynamic MiniJinja templating, authentication (`basic_auth`, `forward_auth`), payload limits, variable mapping, flow directives, and access logging.
- **[Chapter 7: Admin REST API & Atomic Hot Reload](docs/07_admin_api_and_hot_reload.md)**: Axum-powered REST Admin API (`:2019`), JSON config traversal, origin validation, and lock-free zero-downtime hot reloads.
- **[Chapter 8: Command Line Interface (CLI) & Tooling](docs/08_cli_and_tooling.md)**: CLI subcommands (`run`, `start`, `stop`, `reload`, `adapt`, `validate`, `fmt`, `list-modules`, `environ`, `version`, `file-server`, `hash-password`, `respond`, `reverse-proxy`).


---

## Installation & Build

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) **1.85+** (Rust 2024 Edition support required)
- `cmake` and a C/C++ compiler (for native crypto libraries like `aws-lc-sys` / `ring`)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/raddy.git
cd raddy

# Build release binary
cargo build --release

# The compiled binary will be located at:
./target/release/raddy --version
```

---

## Quick Start

### 1. Instant Static File Server

Serve any directory immediately with optional directory browsing and access logging:

```bash
# Serve the current directory on port 8000 with directory browsing enabled
raddy file-server --listen 127.0.0.1:8000 --browse --access-log
```

### 2. Reverse Proxy with Caddyfile

Create a `Caddyfile` in your project directory:

```caddyfile
:8080 {
    # Compress responses using gzip or zstd
    encode gzip zstd

    # Route /api/* requests to backend cluster with round-robin load balancing
    reverse_proxy /api/* 127.0.0.1:5001 127.0.0.1:5002 {
        lb_policy round_robin
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote_host}
    }

    # Serve static assets for all other paths
    root * /var/www/html
    file_server browse
}
```

Run Raddy in the foreground:

```bash
raddy run --config Caddyfile
```

### 3. Running as a Daemon

Start Raddy in the background:

```bash
# Start background process
raddy start --config Caddyfile

# Stop the running background process via Admin API
raddy stop
```

### 4. Zero-Downtime Hot Reload

Modify your `Caddyfile` and reload without dropping any client connections:

```bash
# Reload via Admin API
raddy reload --config Caddyfile

# Or run with auto-watch enabled to reload on file save automatically
raddy run --config Caddyfile --watch
```

---

## Configuration Guide

### Directives & Matchers

Raddy supports standard Caddy matchers:
- **Path matchers:** `/api/*`, `/static/`
- **Named matchers:** `@custom { path /v1/*; method POST PUT; header X-Key * }`
- **Placeholders:** `{path}`, `{host}`, `{method}`, `{remote_host}`, `{http.request.header.Authorization}`, etc.

Directives are automatically reordered according to standard production priority:
`basic_auth` &rarr; `rewrite` &rarr; `encode` &rarr; `templates` &rarr; `reverse_proxy` &rarr; `file_server` &rarr; `respond`.

### Production Caddyfile Example

```caddyfile
# Global Options Block
{
    email admin@example.com
    http_port 80
    https_port 443
}

# Reusable Snippet
(security_headers) {
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
        -Server
    }
}

example.com {
    import security_headers

    # Transparent compression
    encode gzip zstd

    # Health check endpoint
    handle /healthz {
        respond "OK" 200
    }

    # API Proxy with active health checks
    @api path /api/*
    reverse_proxy @api 10.0.0.1:8080 10.0.0.2:8080 {
        lb_policy least_conn
        health_interval 5s
        health_timeout 2s
        health_path /health
    }

    # Static Website
    root * /var/www/site
    file_server browse
}

# Internal Gateway with Local Self-Signed CA
internal.lan {
    tls internal
    respond "Hello from private network!" 200
}
```

### Forward Proxy & HTTP CONNECT Tunneling

Raddy also includes forward proxy capabilities with HTTP `CONNECT` tunneling:

```caddyfile
:8888 {
    forward_proxy {
        # Optional: Hide user IP from forwarded headers
        hide_ip
        # Optional: Chain through an upstream proxy
        # upstream http://upstream-proxy:3128
    }
}
```

---

## Command Line Interface (CLI)

```text
Usage: raddy <COMMAND>

Commands:
  run           Runs Raddy with the specified configuration in foreground
  start         Starts Raddy in the background (daemon mode)
  stop          Stops a running Raddy instance via Admin API
  reload        Sends a zero-downtime configuration reload request
  validate      Validates a Caddyfile or JSON configuration without running
  adapt         Adapts a Caddyfile to Raddy internal JSON configuration
  fmt           Formats or normalizes a Caddyfile to canonical syntax
  list-modules  Lists all registered modules, directives, and matchers
  environ       Prints runtime environment variables
  version       Prints detailed version information
  file-server   Instant zero-config static file server
  help          Print this message or the help of the given subcommand(s)
```

### CLI Examples

```bash
# Validate config syntax
raddy validate --config Caddyfile

# Convert Caddyfile into JSON config
raddy adapt --config Caddyfile --pretty

# Format Caddyfile in place
raddy fmt --config Caddyfile --overwrite

# Inspect all registered modules and handlers
raddy list-modules --json
```

---

## Admin API

Raddy exposes a RESTful Admin API (default: `http://127.0.0.1:2019`) for dynamic, programmatic management:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/load` | Load and apply a new JSON or Caddyfile configuration without downtime |
| `GET` | `/config/` | Retrieve the active running JSON configuration |
| `POST` | `/stop` | Gracefully shut down the server and active listeners |

### Admin API Usage Examples

```bash
# Query the active configuration
curl http://127.0.0.1:2019/config/

# Dynamically reload configuration
curl -X POST http://127.0.0.1:2019/load \
     -H "Content-Type: text/caddyfile" \
     --data-binary @Caddyfile

# Gracefully stop the server
curl -X POST http://127.0.0.1:2019/stop
```

---

## Testing

Run the full automated test suite (including unit tests, CLI tests, log rolling tests, and integration tests):

```bash
cargo test
```

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
