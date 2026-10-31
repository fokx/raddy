# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build the release binary
# ==============================================================================
FROM rust:bookworm AS builder

# Install build dependencies for native C/crypto libraries (e.g. aws-lc-sys)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    gcc \
    libclang-dev \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/raddy

# Copy project manifests and source files
COPY Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY src ./src

# Compile release binary and strip debug symbols
RUN cargo build --release --bin raddy && \
    strip /usr/src/raddy/target/release/raddy

# ==============================================================================
# Stage 2: Minimal runtime image
# ==============================================================================
FROM debian:bookworm-slim AS runner

# Install essential runtime dependencies:
# - ca-certificates: TLS root verification for ACME (Let's Encrypt / ZeroSSL) and reverse proxy upstreams
# - curl: container healthchecks and Admin API interaction
# - tzdata: accurate timezone support
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set default data and configuration directories
ENV RADDY_DATA_DIR=/data \
    XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

# Create required directories
RUN mkdir -p /data /config /etc/caddy /srv /usr/share/caddy

# Copy binary from builder
COPY --from=builder /usr/src/raddy/target/release/raddy /usr/local/bin/raddy

# Default fallback Caddyfile and welcome page
COPY docker/Caddyfile /etc/caddy/Caddyfile
COPY docker/index.html /usr/share/caddy/index.html

# Expose HTTP, HTTPS (TCP & UDP for HTTP/3), and Admin API ports
EXPOSE 80 443 443/udp 2019

# Persistent data volumes for TLS certificates and runtime configs
VOLUME ["/data", "/config"]

# Signal for graceful shutdown
STOPSIGNAL SIGINT

WORKDIR /srv

# Default command: launch Raddy server with the default Caddyfile
ENTRYPOINT ["raddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
