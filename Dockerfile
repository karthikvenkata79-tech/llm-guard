# syntax=docker/dockerfile:1

# ---------- build stage ----------
# Compiles the release binary. Uses the full Rust image, which already includes
# the C toolchain that some dependencies need. This stage is thrown away after.
FROM rust:1-bookworm AS build
WORKDIR /app

# Copy the project and build an optimized binary.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY rules.json ./rules.json
RUN cargo build --release

# ---------- runtime stage ----------
# A tiny image with just the binary — no Rust, no source code.
FROM debian:bookworm-slim
WORKDIR /app

COPY --from=build /app/target/release/llm-guard /usr/local/bin/llm-guard
COPY --from=build /app/rules.json ./rules.json

# Listen on all interfaces so the container is reachable from the host.
ENV GUARD_LISTEN=0.0.0.0:8080
EXPOSE 8080

CMD ["llm-guard"]
