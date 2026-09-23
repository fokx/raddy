# Chapter 6: HTTP Directives & Middleware Pipeline (`raddy-http`)

## 1. Middleware Architecture

HTTP request processing in Raddy uses a decoupled pipeline of pre-processors, handlers, and response transformers.

---

## 2. Directives Overview

### `encode` (Response Compression)
- Streaming on-the-fly compression supporting **Gzip** and **Zstandard (zstd)**.
- Inspects client `Accept-Encoding` headers and negotiates the optimal algorithm.

### `templates` (Server-Side Dynamic Rendering)
- Dynamic template rendering powered by MiniJinja.
- Exposes request metadata, headers, client IP, query parameters, and custom variables to HTML/text templates.

### `basic_auth` & `forward_auth` (Authentication)
- **`basic_auth`**: RFC 7617 HTTP Basic Authentication verified against secure `bcrypt` password hashes.
- **`forward_auth`**: Delegates authorization decisions to external authentication services (Authelia, Authentik, etc.), copying upstream headers upon successful authentication.

### `request_body` (Payload Limits)
- Enforces strict maximum request body sizes (`max_size`) to protect backends against denial-of-service (DoS) attacks.

### `map` (Variable Mapping)
- Maps input placeholders against lookup tables or regular expressions to populate custom context variables.

### `rewrite` & `method` (Request Mutation)
- **`rewrite`**: Rewrites URI paths and query strings internally without issuing client redirects.
- **`method`**: Dynamically overrides request HTTP verbs (e.g. mapping `POST` to `PUT`).

### `flow` (`abort` & `error`)
- **`abort`**: Immediately closes underlying TCP connections without sending any response data.
- **`error`**: Synthesizes custom error responses and triggers error handling pipelines.

---

## 3. Access Logging Engine (`raddy_http::logging`)

- **Structured Formats**: Emits structured JSON or human-friendly console access logs on request completion.
- **Log Encoders & Filters**:
  - `delete` / `rename`: Omit or rename fields in log output.
  - `ip_mask`: Mask IPv4 and IPv6 client addresses while preserving port information.
  - `query` / `cookie`: Sort, redact, or hash sensitive query parameters and cookie values.
- **Log Outputs & Rolling**:
  - Directs logs to stdout, stderr, or rolling log files.
  - Automated log rotation based on file size, time interval, or retention age.
  - Background asynchronous Gzip compression of rolled log files.
