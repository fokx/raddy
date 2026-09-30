# raddyserver

`raddyserver` is an alias and wrapper package for [`raddy-server`](https://crates.io/crates/raddy-server), the fast, extensible, memory-safe web server and reverse proxy in Rust (Caddy drop-in replacement).

## Installation

You can install Raddy using either package name:

```bash
cargo install raddyserver
# or
cargo install raddy-server
```

Both install the `raddy` command-line binary.

## Usage

```bash
# Run with Caddyfile
raddy run

# Instant reverse proxy
raddy reverse-proxy --from :8080 --to 127.0.0.1:9000

# Instant file server
raddy file-server --listen :8080 --root ./public
```

For more documentation and full features, visit the [main repository](https://github.com/fokx/raddy).
