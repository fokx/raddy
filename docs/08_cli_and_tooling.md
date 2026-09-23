# Chapter 8: Command Line Interface (CLI) & Tooling (`raddy`)

## 1. CLI Commands

The `raddy` executable provides complete command-line parity with Caddy:

```text
Usage: raddy <COMMAND>

Commands:
  run           Runs Raddy in foreground with active configuration
  start         Starts Raddy in background as a daemon
  stop          Stops a running Raddy daemon via Admin API
  reload        Sends zero-downtime reload request to running instance
  validate      Validates Caddyfile or JSON syntax without running
  adapt         Adapts a Caddyfile to internal JSON configuration
  fmt           Formats a Caddyfile to canonical syntax
  list-modules  Lists all registered modules, matchers, and directives
  environ       Prints runtime environment variables
  version       Prints detailed version, architecture, and toolchain info
  file-server   Instant zero-config static file server
  hash-password Hashes passwords using bcrypt
  respond       Instant zero-config HTTP response server
  reverse-proxy Instant zero-config reverse proxy
```

---

## 2. Command Details & Usage Examples

### `raddy run` & `raddy start`
```bash
# Run in foreground with auto-reload on file change
raddy run --config Caddyfile --watch

# Run in background as daemon
raddy start --config Caddyfile

# Stop running daemon
raddy stop
```

### `raddy adapt`, `raddy validate` & `raddy fmt`
```bash
# Convert Caddyfile to formatted JSON configuration
raddy adapt --config Caddyfile --pretty

# Validate syntax without starting server
raddy validate --config Caddyfile

# Format Caddyfile in-place
raddy fmt --config Caddyfile --overwrite
```

### Ad-Hoc Servers
```bash
# Instant file server with directory browsing
raddy file-server --listen :8000 --browse

# Instant reverse proxy
raddy reverse-proxy --from :8000 --to 127.0.0.1:3000

# Ad-hoc HTTP mock response
raddy respond --listen :8080 --status 200 "OK"
```
