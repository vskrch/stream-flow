FROM rust:1-bookworm AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libclang-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p zippy-panther-bin

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ffmpeg \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zippy-panther /usr/local/bin/zippy-panther
ENV APP__SERVER__HOST=0.0.0.0
EXPOSE 8080
CMD ["/usr/local/bin/zippy-panther"]
