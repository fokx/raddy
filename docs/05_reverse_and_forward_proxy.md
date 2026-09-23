# Chapter 5: Reverse Proxy, Load Balancing & Forward Proxy (`raddy-proxy`)

## 1. Reverse Proxy Engine

`raddy-proxy` provides a production-grade reverse proxy engine modeled after Caddy:

- **Streaming Transport**: Full HTTP/1.1 and HTTP/2 request and response body streaming without buffering large payloads in memory.
- **WebSocket Proxying**: Transparent protocol upgrades supporting long-lived bidirectional WebSocket connections.
- **Header Sanitization**: Hop-by-hop header removal according to RFC 9110 (`Connection`, `Keep-Alive`, `Upgrade`, `Transfer-Encoding`).
- **Header Mutation**: Dynamic injection, rewriting, and deletion of upstream (`header_up`) and downstream (`header_down`) headers with placeholder support.
- **Host Header Synthesis**: Ensures upstream requests include a valid `Host` header synthesized from URI authority, host headers, or TLS SNI.

---

## 2. Load Balancing Algorithms

Multiple backend upstreams are load balanced according to configurable policies:

| Policy | Description | Use Case |
|---|---|---|
| `round_robin` | Standard sequential distribution across healthy backends | Equal-capacity homogeneous clusters |
| `least_conn` | Routes requests to the backend with fewest active connections | Long-lived requests and variable latency services |
| `random` | Uniformly distributed random selection | Stateless microservices |
| `ip_hash` | Consistent hashing based on client IP address | Session affinity / sticky sessions |

---

## 3. Health Checks & Circuit Breaking

- **Active Health Probing**: Periodic background HTTP requests (`interval`, `timeout`, `path`) checking for expected HTTP 2xx/3xx response status codes.
- **Passive Health Checking**: Immediately detects connection failures or timeout thresholds and temporarily marks upstreams as down.
- **Exponential Backoff**: Gradually restores traffic to recovered upstreams.

---

## 4. Forward Proxy & HTTP CONNECT Tunneling

`raddy-proxy` includes built-in forward proxying capabilities:

- **HTTP CONNECT Tunneling**: Facilitates arbitrary TCP tunneling (HTTPS, SSH) with full Hyper protocol upgrades.
- **Standard Forward Proxy**: Transparent proxying of plain HTTP requests with `Via` and `Forwarded` header synthesis.
- **ACL Enforcement**: Whitelist and blacklist rules based on client IP subnets (CIDR) and destination domain names.
- **Authentication**: HTTP Basic Authentication (`Proxy-Authorization`) with constant-time credential comparison.
- **Probe Resistance**: Serves an innocuous decoy site when unauthenticated requests are received, preventing proxy detection.
- **Chained Upstream Proxies**: Supports upstream proxy chaining via HTTP, HTTPS CONNECT, and SOCKS5.
