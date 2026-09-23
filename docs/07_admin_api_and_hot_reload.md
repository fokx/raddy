# Chapter 7: Admin REST API & Atomic Hot Reload (`raddy-admin`)

## 1. REST Admin API (`:2019`)

Raddy exposes a RESTful Admin API (default: `http://127.0.0.1:2019`) for dynamic, programmatically managed deployments:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Returns server identity and status (`{"app": "raddy", "status": "ok"}`) |
| `POST` | `/load` | Replaces active configuration with a new JSON or Caddyfile with zero downtime |
| `POST` | `/adapt` | Compiles a Caddyfile to JSON configuration without applying it |
| `POST` | `/stop` | Gracefully terminates server processes and listeners |
| `GET` | `/config/` | Retrieves the active JSON configuration tree |
| `GET` | `/config/{*path}` | Retrieves a subtree from the active configuration |
| `POST` | `/config/{*path}` | Inserts a new node into the configuration hierarchy |
| `PUT` | `/config/{*path}` | Replaces a node at the specified configuration path |
| `PATCH` | `/config/{*path}` | Deeply merges configuration changes into an existing node |
| `DELETE` | `/config/{*path}` | Removes a node from the configuration |
| `GET` | `/reverse_proxy/upstreams` | Returns real-time status and health metrics of proxy upstreams |
| `GET` | `/pki/ca/local` | Downloads the local CA development certificate in PEM format |

---

## 2. Security & DNS Rebinding Protection

- **Host Header Validation**: Strictly enforces that incoming Admin API requests target authorized hostnames (`localhost`, `127.0.0.1`, `[::1]`).
- **RFC 3986 Origin Validation**: Validates the `Origin` header on mutating requests (`POST`, `PUT`, `DELETE`) to prevent Cross-Site Request Forgery (CSRF) and DNS rebinding attacks.

---

## 3. Lock-Free Zero-Downtime Hot Reload

1. New configuration payload is received via `POST /load`.
2. Configuration is validated and new runtime servers/listeners are bound using socket reuse (`SO_REUSEPORT`).
3. If provisioning succeeds, `AppState::reload` atomically swaps the active `ArcSwap<Config>` pointer.
4. Old servers receive a graceful shutdown signal, draining in-flight requests before terminating.
5. If provisioning fails at any stage, the reload is aborted, an error is returned, and the previous configuration continues serving uninterrupted.
