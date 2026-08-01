# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM rust:1-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY rules.json ./rules.json
RUN cargo build --release

# ---------- runtime stage ----------
FROM debian:bookworm-slim
# Security: create a non-root user. Never run a container as root.
RUN useradd -r -u 10001 -g root nonroot
WORKDIR /app
COPY --from=build /app/target/release/llm-guard /usr/local/bin/llm-guard
COPY --from=build /app/rules.json ./rules.json

ENV GUARD_LISTEN=0.0.0.0:8080
EXPOSE 8080
# Security: drop to the non-root user for everything that follows.
USER 10001
CMD ["llm-guard"]
