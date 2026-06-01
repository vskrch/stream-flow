FROM rust:1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p stream-flow-bin

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/stream-flow /usr/local/bin/stream-flow
ENV APP__SERVER__HOST=0.0.0.0
ENV APP__SERVER__PORT=8080
EXPOSE 8080
USER 65532:65532
CMD ["sh", "-c", "APP__SERVER__PORT=\"${APP__SERVER__PORT:-${PORT:-8080}}\" exec /usr/local/bin/stream-flow"]
