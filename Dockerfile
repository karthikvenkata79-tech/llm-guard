FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:stable-slim
COPY --from=build /app/target/release/llm-guard /usr/local/bin/llm-guard
EXPOSE 8080
ENV GUARD_LISTEN=0.0.0.0:8080
CMD ["llm-guard"]
