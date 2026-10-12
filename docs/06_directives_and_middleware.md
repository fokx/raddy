# Chapter 6: HTTP Directives & Middleware Pipeline (`raddy-http`)

## 1. Middleware Architecture

HTTP request processing in Raddy uses a decoupled pipeline of pre-processors, handlers, and response transformers.

---

## 2. Directives Overview

### `encode` (Response Compression)
- Streaming on-the-fly compression supporting **Gzip** and **Zstandard (zstd)**.
- Inspects client `Accept-Encoding` headers and negotiates the optimal algorithm.

### `cache` (`caddyserver/cache-handler` / Souin HTTP Cache Drop-in Parity)
- Fully distributed and in-memory HTTP cache complying with **RFC 7234** and **RFC 9111**.
- Supports both **global options block** (`cache { ... }`) and site/route-level directive (`cache { ... }`).
- Standard RFC `Cache-Status` response header emission:
  - `<cache_name>; hit; ttl=<remaining_ttl>` (fresh cache hit)
  - `<cache_name>; fwd=uri-miss; ttl=<ttl>` (cache miss, cached from upstream)
  - `<cache_name>; fwd=bypass` (uncacheable request or response, e.g. `Cache-Control: no-store, private`)
  - `<cache_name>; stale` (stale-while-revalidate serving)
- **Cache-Control & Revalidation**:
  - Automatically evaluates `s-maxage`, `max-age`, `stale-while-revalidate`, `no-store`, `no-cache`, and `private`.
  - Conditional revalidation: evaluates incoming `If-None-Match` against cached `ETag` and `If-Modified-Since` against `Last-Modified`, returning `304 Not Modified` with zero-length body.
  - Automatically satisfies `HEAD` requests using cached `GET` responses with body stripped.
- **Cache Keys & Normalization**:
  - Customizable cache keys via `key { disable_host, disable_scheme, disable_query, sort_query, hash, headers ... }`.
  - Query parameter canonical sorting (`sort_query`) to avoid duplicate cache entries.
  - Regex exclude patterns (`regex { exclude <pattern> }`) and route-specific rules (`cache_keys { <pattern> { ... } }`).
- **Storage Providers**:
  - In-memory lock-free storage pools shared across reloads.
  - Persistent filesystem storage (`badger` / `nuts` / `simplefs` with `path <dir>`).
  - Redis storage integration (`redis { url <redis_url> }`).

### `templates` (Server-Side Dynamic Rendering)
- Dynamic template rendering powered by MiniJinja.
- Exposes request metadata, headers, client IP, query parameters, and custom variables to HTML/text templates.

### `basic_auth` & `forward_auth` (Authentication)
- **`basic_auth`**: RFC 7617 HTTP Basic Authentication verified against secure `bcrypt` password hashes.
- **`forward_auth`**: Delegates authorization decisions to external authentication services (Authelia, Authentik, etc.), copying upstream headers upon successful authentication.

### `request_body` & `rate_limit` (Traffic & Payload Limits)
- **`request_body`**: Enforces strict maximum request body sizes (`max_size`) to protect backends against denial-of-service (DoS) attacks.
- **`rate_limit`** (`github.com/mholt/caddy-ratelimit` drop-in parity):
  - Sliding window rate limiting implemented with scalable ring buffers.
  - Multi-zone configurations with static keys or dynamic placeholders (`{remote_host}`, `{http.request.uri}`, etc.).
  - Automatic `Retry-After` header emission and `429 Too Many Requests` responses.
  - Subnet aggregation using `ipv4_prefix` and `ipv6_prefix` CIDR masking.
  - Zone request matchers (`match { method ... path ... }`).
  - Rate limit state persistence across hot reloads.
  - Optional jitter, background expired bucket sweep, and placeholder `{http.rate_limit.exceeded.name}`.

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
