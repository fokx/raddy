# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build statically linked musl binary
# ==============================================================================
FROM rust:alpine AS builder

# Install build dependencies for native C/crypto libraries (aws-lc-sys, ring)
RUN apk add --no-cache \
    cmake \
    clang \
    clang-dev \
    make \
    gcc \
    g++ \
    musl-dev \
    linux-headers \
    binutils \
    perl

WORKDIR /usr/src/raddy

# Copy project manifests and source files
COPY Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY src ./src

# Compile statically linked release binary and strip debug symbols
RUN cargo build --release --bin raddy && \
    strip /usr/src/raddy/target/release/raddy

# Create application directories owned by nonroot (UID:GID 65532:65532)
RUN mkdir -p /data /config /etc/caddy /srv /usr/share/caddy && \
    chown -R 65532:65532 /data /config /etc/caddy /srv /usr/share/caddy

# ==============================================================================
# Stage 2: Minimal Distroless Static Non-Root Runtime
# ==============================================================================
# Based on Google Container Tools distroless static Debian 13 (Trixie).
# Contains ZERO package managers, shells, or coreutils for minimal attack surface.
FROM gcr.io/distroless/static-debian13:nonroot

# Set default data and configuration directories
ENV RADDY_DATA_DIR=/data \
    XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

# Copy pre-configured nonroot-owned directories
COPY --from=builder --chown=65532:65532 /data /data
COPY --from=builder --chown=65532:65532 /config /config
COPY --from=builder --chown=65532:65532 /etc/caddy /etc/caddy
COPY --from=builder --chown=65532:65532 /srv /srv
COPY --from=builder --chown=65532:65532 /usr/share/caddy /usr/share/caddy

# Copy binary from builder
COPY --from=builder --chown=65532:65532 /usr/src/raddy/target/release/raddy /usr/local/bin/raddy

# Default fallback Caddyfile and welcome page
COPY --chown=65532:65532 docker/Caddyfile /etc/caddy/Caddyfile
COPY --chown=65532:65532 docker/index.html /usr/share/caddy/index.html

# Expose HTTP, HTTPS (TCP & UDP for HTTP/3), and Admin API ports
EXPOSE 80 443 443/udp 2019

# Persistent data volumes for TLS certificates and runtime configs
VOLUME ["/data", "/config"]

# Run strictly as unprivileged nonroot user (UID 65532)
USER nonroot:nonroot

WORKDIR /srv

# Signal for graceful shutdown
STOPSIGNAL SIGINT

# Default command: launch Raddy server with the default Caddyfile
ENTRYPOINT ["/usr/local/bin/raddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
