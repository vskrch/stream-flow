FROM rust:1-bookworm AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libclang-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p zippy-panther-bin

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ffmpeg curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Cloudflare WARP
RUN curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
      | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
      > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflare-warp \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zippy-panther /usr/local/bin/zippy-panther
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV APP__SERVER__HOST=0.0.0.0
ENV APP__EGRESS__TUNNEL_MODE=proxy
ENV APP__EGRESS__TUNNEL_URL=socks5://127.0.0.1:40000
ENV APP__EGRESS__POLICY=fail-open
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
