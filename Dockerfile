# syntax=docker/dockerfile:1.7
# Use the latest stable Rust 1.x image. clap_builder 4.6.0 requires edition 2024,
# which needs Rust 1.85 or newer.
FROM rust:1-slim AS builder
WORKDIR /app
# rustls-tls is used (no OpenSSL dep). build-essential is required because
# tree-sitter and tree-sitter-bash compile a small C parser at build time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/warden /usr/local/bin/warden

LABEL org.opencontainers.image.source="https://github.com/projectwarden/warden"
LABEL org.opencontainers.image.description="CI/CD security scanner for GitHub Actions workflows"
LABEL org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/warden"]
