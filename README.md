<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/your-org/zippy-panther/main/assets/logo-dark.svg">
    <img alt="ZippyPanther" src="https://raw.githubusercontent.com/your-org/zippy-panther/main/assets/logo-light.svg" width="480">
  </picture>
</p>

<p align="center">
  <strong>A high-performance Stremio streaming proxy, debrid orchestration engine, and media gateway written in Rust.</strong>
</p>

<p align="center">
  <a href="#"><img alt="Rust" src="https://img.shields.io/badge/rust-1.85+-orange?logo=rust&style=flat-square"></a>
  <a href="#"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
  <a href="#"><img alt="CI" src="https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square"></a>
  <a href="#"><img alt="Coverage" src="https://img.shields.io/badge/coverage-%3E%3D90%25-brightgreen?style=flat-square"></a>
  <a href="#"><img alt="Docker" src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker&style=flat-square"></a>
  <a href="#"><img alt="Heroku" src="https://img.shields.io/badge/heroku-ready-430098?logo=heroku&style=flat-square"></a>
  <a href="#"><img alt="FFI" src="https://img.shields.io/badge/FFI-C%20ABI-555555?style=flat-square"></a>
</p>

---

## What is ZippyPanther?

ZippyPanther is a **unified streaming proxy and debrid-service orchestration engine** purpose-built for [Stremio](https://www.stremio.com/). It acts as the middleware layer between Stremio clients and third-party debrid providers, proxying media streams, resolving torrent magnets, generating secure proxy links, and exposing Stremio-addon-compatible APIs — all while keeping your real IP hidden behind a fail-closed egress tunnel.

Think of it as the **traffic controller** for your personal media infrastructure: it manages 9 debrid services, transparently handles HLS/DASH manifest rewriting, decrypts ClearKey DRM, transcodes on the fly, and provides a dual-surface HTTP API compatible with both `mediaflow-proxy-light` and `stremthru` clients.

---

## Features

### 🎬 Streaming Proxy Core

- **Byte-range-aware streaming proxy** — generic ranged proxy with `RangeSpec` parser (Full/FromOffset/Inclusive/Suffix), adaptive jitter buffer for backpressure, and proper `206 Partial Content` / `416 Range Not Satisfiable` responses
- **ResilientStream state machine** — 7-state streaming engine (Opening → Streaming → Reconnecting → Renewing → Seeking → Failed) with automatic reconnection and link renewal
- **AdaptiveJitterBuffer** — bounded ring buffer with offset-driven refill sizing and configurable jitter for upstream/downstream decoupling
- **Per-pattern transport routing** — route-specific forwarding proxies with most-specific-wins matching (`example.com` → `socks5://...`), supporting HTTP/HTTPS/SOCKS4/SOCKS5 schemes, per-route SSL policy, and a client LRU cache

### 🔗 Debrid Service Orchestration

| Service | Code | Status |
|---------|------|--------|
| [RealDebrid](https://real-debrid.com) | `rd` | ✅ |
| [AllDebrid](https://alldebrid.com) | `ad` | ✅ |
| [Premiumize](https://www.premiumize.me) | `pm` | ✅ |
| [TorBox](https://torbox.app) | `tb` | ✅ |
| [Debrid-Link](https://debrid-link.com) | `dl` | ✅ |
| [Offcloud](https://offcloud.com) | `oc` | ✅ |
| [PikPak](https://mypikpak.com) | `pp` | ✅ |
| [EasyDebrid](https://easydebrid.com) | `ed` | ✅ |
| [Debrider](https://debrider.com) | `dr` | ✅ |

Each service implements a unified `Store` trait with normalized error mapping, magnet lifecycle management, and link generation.

### 🛡️ Egress Isolation & Security

- **Single outbound seam** — every upstream HTTP call flows through `OutboundClient` (fail-closed by default)
- **Egress tunnel** — proxy mode (HTTP/SOCKS) or network namespace, with leak-verified IP reflection
- **Client-IP sanitization** — 9 named headers stripped + by-value IP matching, built-in `sanitize_outbound`
- **SSRF guard** — configurable allowlist/denylist, private-range blocking, body-size caps (50 MiB / 10 MiB)
- **AES-256-CBC proxy-link encryption** — mediaflow-compatible encrypted token generation
- **Secret redaction** — `Secret` newtype with Debug redaction, Redactor for structured logging

### ⚡ Resilience Stack

| Layer | Pattern | Purpose |
|-------|---------|---------|
| 🚦 **Circuit Breaker** | `Closed → Open → HalfOpen` | Per-dependency fault isolation, 3-state with probe recovery and cooldown reconciliation |
| 🔄 **Retry** | Exponential full-jitter backoff | `is_retryable()` taxonomy — only transient (503/504/502/429) errors retried |
| 🪣 **Bulkhead** | Per-dependency semaphore pools | One slow upstream can't starve others; RAII permit release |
| ⏰ **Deadline** | Request-scoped timeout budget | Control-plane vs streaming distinction; 504 on elapse |
| ⚡ **Hedge** | Speculative requests | Tail-latency trimming for `CheckMagnet` / `GenerateLink` across cache tiers or stores |
| 🔁 **Store Fallback** | Cooldown reconciliation | Circuit breaker + account-level cooldown; automatically rotates between configured stores |

### 📡 Protocol Support

- **HLS** — manifest rewrite, segment prefetching & caching, inactivity timeout
- **MPD → HLS conversion** — DASH manifest parser, live playlist support, TS remuxing
- **ClearKey DRM** — CENC decryption (mp4_atom parser, clearkey store, cbc decryptor)
- **On-the-fly transcoding** — FFmpeg-based with GPU preference, configurable bitrate
- **Subtitle proxy** — SRT/VTT/ASS passthrough, merging, and proxy endpoint
- **EPG / XMLTV** — electronic program guide caching and proxy
- **Xtream-Codes** — IPTV proxy with `/player_api.php`, `/xmltv.php`, `/get.php`
- **Acestream** — P2P streaming proxy with session multiplexing
- **Telegram MTProto** — chunked file download via Telegram API

### 🔌 Dual HTTP Surface

The server exposes **two path namespaces** on a single listener, sharing one `AppState`:

| Surface | Path Prefix | Auth | Purpose |
|---------|-------------|------|---------|
| **mediaflow** | `/proxy/*`, `/base64/*`, `/generate_url`, etc. | `X-API-Password` / AES-CBC `d` params | Streaming proxy, content proxying, utilities |
| **stremthru** | `/v0/*`, `/stremio/*` | `X-StremThru-Authorization` / Basic | Store management, magnet ops, Stremio addons |

### 🧩 Stremio Addon Protocol

- **Store Addon** (`/stremio/store/{name}/manifest.json`) — exposes debrid service as a Stremio addon
- **Wrap Addon** (`/stremio/wrap/manifest.json`) — aggregates upstream Stremio addon URLs
- **Sidekick** — Stremio companion helpers
- **Torz** — magnet-to-stream resolution
- Full serde-compatible types matching Go `stremthru` output (string-or-object `Resource`, `CatalogExtraOptions` coercion)

### 📊 Observability

- **Prometheus metrics** — counters/latencies for proxy, store ops, cache hit/miss, upstream failures, circuit breaker transitions
- **Health endpoint** — 3-probe model (liveness/readiness/startup), per-component breakdown, load state
- **Structured tracing** — `tracing-subscriber` with env-filter, Redactor for secrets scrubbing
- **Degradation guard** — RSS + connection-count high-water-mark load shedding with hysteresis

### 💾 Persistence & Caching

- **Two-tier cache** — `moka` in-process (always on) + optional Redis with `FailoverCache` (hot-swap on Redis outage)
- **SQLite** — WAL mode, busy timeout, migrations, encrypted vault for credentials
- **Warmup pool** — keep popular magnet links fresh from debrid services

### 🌐 Client SDKs

- **Rust SDK** — `zippy-panther-sdk` crate with typed `ZippyPantherClient` (health, proxify, store ops, Stremio manifests)
- **FFI** — C-ABI staticlib/cdylib for embedding in non-Rust hosts (Swift, Kotlin, etc.)
- **JS/Python** — SDK directory scaffolded (contributors welcome!)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HTTP Listener                                  │
│                    actix-web 4 (shared AppState via Arc)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                        Dual-Surface Router                                   │
│  ┌──────────────────────────────┐  ┌──────────────────────────────────────┐  │
│  │       mediaflow surface       │  │          stremthru surface           │  │
│  │  /proxy/stream, /proxy/hls,  │  │  /v0/proxy, /v0/store/*, /stremio/* │  │
│  │  /proxy/mpd, /proxy/ip, ...  │  │  /v0/meta/id-map/*, ...             │  │
│  └──────────┬───────────────────┘  └──────────┬───────────────────────────┘  │
└─────────────┼──────────────────────────────────┼────────────────────────────┘
              │                                  │
              ▼                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Middleware Stack                                       │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐                │
│  │ PanicBoundary │→│ DegradationGuard│→│ RateLimiter       │                │
│  │  catch_unwind │  │ load shedding  │  │ token-bucket     │                │
│  │  panic→500    │  │ conn/RSS HWM   │  │ per-user/per-IP  │                │
│  └──────────────┘  └────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Shared Service Graph                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐               │
│  │  Proxy    │  │  Store   │  │  Egress   │  │  Cache    │               │
│  │  Core     │  │  Trait   │  │  Isolation│  │  Backend  │               │
│  │  (stream) │  │  (9 impls)│  │  (tunnel, │  │  (moka +  │               │
│  │           │  │          │  │   sanitize)│  │   Redis)  │               │
│  └───────────┘  └──────────┘  └───────────┘  └────────────┘               │
│                                                                              │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐               │
│  │ Resilience│  │ Health  │  │  Stremio  │  │ Persistence│               │
│  │ Breaker,  │  │ 3-probe │  │  Addons   │  │  SQLite    │               │
│  │ Retry,    │  │ liveness│  │  Store/   │  │  Vault     │               │
│  │ Bulkhead, │  │ readiness│  │  Wrap     │  │  Migrations│               │
│  │ Deadline, │  │ startup │  │           │  │            │               │
│  │ Hedge     │  │         │  │           │  │            │               │
│  └───────────┘  └──────────┘  └───────────┘  └────────────┘               │
│                                                                              │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐               │
│  │   HLS    │  │   MPD   │  │    DRM    │  │ Transcode │               │
│  │  rewrite  │  │ DASH→HLS│  │  ClearKey │  │  FFmpeg   │               │
│  │  prefetch │  │ convert │  │  CENC dec │  │  GPU pref │               │
│  └───────────┘  └──────────┘  └───────────┘  └────────────┘               │
│                                                                              │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐               │
│  │  Extractor│  │ EPG/XTV │  │ Acestream │  │ Telegram  │               │
│  │  24 hosts │  │ XMLTV   │  │ P2P proxy │  │ MTProto   │               │
│  └───────────┘  └──────────┘  └───────────┘  └────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Outbound (Egress) Seam                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  OutboundClient (single outbound seam, fail-closed by default)       │   │
│  │  ┌──────────────────┐  ┌────────────────┐  ┌──────────────────────┐ │   │
│  │  │  reqwest (rustls)│  │  wreq (Boring) │  │  EgressResolver      │ │   │
│  │  │  default client  │  │  Chrome JA3/4  │  │  ipify reflection    │ │   │
│  │  └──────────────────┘  └────────────────┘  │  leak check          │ │   │
│  │                                              └──────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │  Debrid Services / Media CDNs        │
                    │  (RealDebrid, AllDebrid, Premiumize, │
                    │   TorBox, PikPak, CDNs, ...)         │
                    └─────────────────────────────────────┘
```

### Module Map

```
zippy-panther/src/
├── lib.rs               # Crate root — build_app() factory
├── app.rs               # AppState — Arc-wrapped shared dependency container
├── errors.rs            # Canonical error taxonomy (14 categories, HTTP mapping)
├── config/mod.rs        # Layered config (defaults → file → env → override)
├── http/                # HTTP edge: middleware, router, client_ip, protocol
│   ├── router.rs        # Dual-surface router (mediaflow + stremthru + shared)
│   ├── panic_boundary.rs# catch_unwind per-request middleware
│   ├── degradation.rs   # Load controller, RSS sampler, connection HWM
│   └── client_ip.rs     # Client-IP resolution (X-Real-IP → X-Forwarded-For → TCP)
├── proxy/               # Streaming proxy core
│   ├── core.rs          # Generic ranged proxy, relay_stream, proxy_ip
│   ├── buffer.rs        # AdaptiveJitterBuffer ring buffer
│   ├── range.rs         # RangeSpec parser + ResponseMetadata computation
│   ├── routing.rs       # RoutePattern, RoutingTable, ClientCache LRU
│   ├── source.rs        # UpstreamSource trait + DirectSource
│   └── resilient.rs     # 7-state ResilientStream
├── store/               # Debrid service abstraction
│   ├── mod.rs           # Store trait, StoreName/StoreCode (9 services)
│   ├── types.rs         # Normalized value types (User, MagnetStatus, etc.)
│   ├── endpoints.rs     # Store HTTP endpoints
│   ├── fallback.rs      # StoreFallbackChain + StoreBreakerSet
│   ├── link.rs          # DebridSource as UpstreamSource with renewal
│   └── impls/           # 9 concrete store implementations
├── egress/              # Egress isolation (single outbound seam)
│   ├── mod.rs           # OutboundClient — the only way to make upstream calls
│   ├── tunnel.rs        # Tunnel modes (Proxy/Netns), LeakCheck
│   ├── resolver.rs      # EgressResolver with ArcSwap cache
│   ├── reflector.rs     # HttpIpReflector (ipify)
│   ├── sanitize.rs      # Header stripping (9 + by-value IP)
│   └── policy.rs        # Fail-closed/fail-open decision
├── resilience/          # Resilience primitives
│   ├── breaker.rs       # CircuitBreaker — 3-state, guarded/select_available
│   ├── retry.rs         # RetryPolicy — exponential full-jitter backoff
│   ├── bulkhead.rs      # Bulkhead — per-dependency semaphore pools
│   ├── deadline.rs      # Deadline — request-scoped timeout budget (504 on elapse)
│   └── hedge.rs         # Hedge — speculative requests across tiers
├── cache/               # Cache abstraction
│   ├── mod.rs           # CacheBackend trait, namespaced_key
│   ├── local.rs         # moka in-process cache
│   ├── redis.rs         # deadpool-redis backend
│   └── failover.rs      # ArcSwapOption hot-swap, write-through to local
├── health/              # Health model (3-probe: liveness/readiness/startup)
├── stremio/             # Stremio protocol addon types
│   ├── types.rs         # Manifest, Stream, Meta, Resource (Go-compatible)
│   ├── store_addon.rs   # Store-backed Stremio addon
│   └── wrap_addon.rs    # Upstream-aggregating wrap addon
├── auth/                # Authentication
│   ├── mod.rs           # 4 verifiers (api_password, proxy_auth, store, admin)
│   ├── encryption.rs    # AES-256-CBC proxy-link encryption
│   └── middleware.rs    # actix extraction glue
├── hls/                 # HLS manifest rewrite + prefetch
├── mpd/                 # DASH→HLS conversion
├── drm/                 # ClearKey CENC decryption
├── transcode/           # FFmpeg on-the-fly transcoding
├── subtitles/           # Subtitle proxy (SRT/VTT/ASS)
├── extractor/           # 24 video-host extractors
├── acestream/           # Acestream P2P proxy
├── telegram/            # Telegram MTProto chunked downloads
├── content_proxy/       # Content proxy connection registry
├── proxylink/           # Encrypted proxy-link generation
├── meta/                # Meta resolvers, ID-map cache
├── security/            # SSRF guard, header sanitization, CSP/CORS
├── integrations/        # 3rd-party integrations (Trakt, TMDB, AniList, etc.)
├── observability/       # Prometheus metrics, structured logging, Redactor
├── persistence/         # SQLite pool, migrations, vault, repos
├── sse/                 # Server-Sent Events (per-user broadcast)
├── supervisor/          # Background-task supervision (crash-loop guard)
├── web_ui/              # Embedded web UI assets
├── rate_limit/          # Token-bucket rate limiter
├── quality/             # Quality selection
├── prebuffer/           # Pre-buffering tunables
├── epg/                 # EPG / XMLTV proxy
├── xtream/              # Xtream-Codes IPTV proxy
├── warmup/              # Popular-magnet link warmup pool
└── utils/               # Utilities (base64, playlist builder, speedtest, etc.)
```

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.85+ (edition 2021)
- [FFmpeg](https://ffmpeg.org/) (for on-the-fly transcoding)
- Optional: [Redis](https://redis.io/) (for distributed caching)

### Run with Docker

```bash
docker run -d \
  -p 8080:8080 \
  -e APP__AUTH__API_PASSWORD=change-me \
  --name zippy-panther \
  zippy-panther:latest
```

### Run from source

```bash
# Clone & build
git clone <repo-url>
cd stream-flow
cargo build --release -p zippy-panther-bin

# Run
APP__AUTH__API_PASSWORD=change-me \
APP__SERVER__HOST=0.0.0.0 \
APP__SERVER__PORT=8080 \
cargo run -p zippy-panther-bin
```

### Verify it's alive

```bash
curl http://localhost:8080/health
# {"status":"starting","load":"normal","components":[...]}
```

---

## Configuration

ZippyPanther uses a layered configuration model: **defaults → file → `STREMTHRU_*` env → `APP__*` env** (later layers override earlier ones).

### Via environment variables

```bash
# Required
APP__AUTH__API_PASSWORD=your-secret-key

# Server
APP__SERVER__HOST=0.0.0.0
APP__SERVER__PORT=8080
APP__SERVER__WORKERS=4
APP__SERVER__PATH_PREFIX=/my-prefix

# Egress tunnel (SOCKS5 proxy for all outbound traffic)
APP__EGRESS__TUNNEL_MODE=proxy
APP__EGRESS__TUNNEL_URL=socks5://127.0.0.1:9050

# Redis cache
APP__CACHE__REDIS_URL=redis://localhost:6379

# Per-pattern transport routes (JSON)
APP__PROXY__TRANSPORT_ROUTES='{"api.real-debrid.com":{"proxy":true,"proxy_url":"socks5://127.0.0.1:9050"}}'
```

### Via config file

```bash
CONFIG_PATH=/etc/zippy-panther/config.toml cargo run -p zippy-panther-bin
```

```toml
[auth]
api_password = "change-me"

[server]
host = "0.0.0.0"
port = 8080

[egress]
tunnel_mode = "proxy"
tunnel_url = "socks5://127.0.0.1:9050"
policy = "fail-closed"

[cache]
redis_url = "redis://localhost:6379"
namespace = "ZippyPanther"
```

### Configuration Hierarchy

| Section | Key Configs | Default |
|---------|------------|---------|
| `server` | `host`, `port`, `workers`, `path_prefix` | `127.0.0.1:8080` |
| `proxy` | `connect_timeout`, `buffer_size`, `follow_redirects`, `transport_routes` | 30s/256KiB |
| `auth` | `api_password` **(required)** , `proxy_auth`, `admins` | — |
| `egress` | `tunnel_mode`, `tunnel_url`, `policy`, `ip_reflection_url` | Disabled/FailClosed |
| `cache` | `redis_url`, `namespace`, `default_ttl_secs` | Local only, 5 min |
| `db` | `path`, `busy_timeout_secs`, `max_connections` | `ZippyPanther.db`, 5s |
| `hls` | `prebuffer_segments`, `segment_cache_ttl_secs` | 5, 5 min |
| `mpd` | `live_playlist_depth`, `remux_to_ts` | 8, false |
| `transcode` | `enabled`, `prefer_gpu`, `video_bitrate` | true, true, 4M |
| `drm` | `key_cache_ttl_secs` | 3600s |
| `security` | `ssrf_allowlist`, `ssrf_denylist`, `allow_private_ranges` | Deny private |
| `degradation` | `conn_high_water`, `conn_low_water`, `memory_high_water` | 1000/800/400MB |
| `ratelimit` | `enabled`, `requests_per_minute` | false, 600 |
| `warmup` | `enabled`, `pool_size` | false, 100 |

---

## API Reference

### Mediaflow Surface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/proxy/stream` | Byte-range streaming proxy (HEAD also supported) |
| `GET` | `/proxy/ip` | Returns the tunnel-observed Egress_IP |
| `GET` | `/proxy/subtitle` | Subtitle proxy passthrough |
| `GET` | `/base64/encode` | Base64 encode utility |
| `GET` | `/base64/decode` | Base64 decode utility |
| `GET` | `/base64/check` | Base64 validity check |
| `POST` | `/generate_url` | Generate an encrypted proxy URL |
| `POST` | `/playlist/builder` | Build an M3U playlist |
| `GET` | `/speedtest` | Speed test endpoint |

### Stremthru Surface

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/v0/proxy` | Proxify upstream URLs into proxy links |
| `GET` | `/v0/store/magnets/check` | Check magnet cache status |
| `GET` | `/v0/store/magnets` | List stored magnets |
| `POST` | `/v0/store/magnets` | Add a magnet |
| `GET` | `/v0/store/magnets/{id}` | Get magnet details |
| `DELETE` | `/v0/store/magnets/{id}` | Remove a magnet |
| `GET` | `/v0/store/user` | Get authenticated user info |
| `GET` | `/v0/meta/id-map/{namespace}/{id}` | Meta ID map resolution |
| `GET` | `/stremio/store/{name}/manifest.json` | Store addon manifest |
| `GET` | `/stremio/wrap/manifest.json` | Wrap addon manifest |

### Shared Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (liveness/readiness/startup via `?probe=`) |
| `GET` | `/metrics` | Prometheus metrics (guarded by `metrics_password`) |
| `GET` | `/v0/events` | Server-Sent Events stream |
| `GET` | `/` | Embedded Web UI |

### Error Response Format

```json
{
  "error": {
    "code": "store-limit-exceeded",
    "message": "RealDebrid: active download limit reached",
    "store": "realdebrid",
    "upstream_status": 429
  }
}
```

#### Error Taxonomy

| Code | HTTP | Description |
|------|------|-------------|
| `invalid-store-name` | 400 | Unknown store name or code |
| `bad-request` | 400 | Invalid client input |
| `unauthorized` | 401 | Missing/incorrect credentials |
| `payment-required` | 402 | Debrid plan expired |
| `forbidden` | 403 | Access denied (with optional `ip_restricted` flag) |
| `not-found` | 404 | Resource absent |
| `payload-too-large` | 413 | Body exceeds configured cap |
| `range-not-satisfiable` | 416 | Byte range unsatisfiable |
| `too-many-requests` | 429 | Rate limit hit |
| `store-limit-exceeded` | 429 | Account cap (distinct from rate limit) |
| `infringing-content` | 451 | Legally unavailable file |
| `hoster-unavailable` | 502 | Hoster down or circuit open |
| `upstream-unavailable` | 503/504 | Unreachable/timeout/deadline exceeded |
| `unknown` | 500 | Panic boundary or unclassified failure |

---

## Rust SDK Usage

```rust
use zippy_panther_sdk::{ZippyPantherClient, ProxifyOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with API password auth
    let client = ZippyPantherClient::new("https://flow.example")?
        .with_api_password("change-me");

    // Check health
    let health = client.health().await?;
    println!("{:?}", health["status"]);

    // Proxify URLs
    let result = client
        .proxify(&["https://cdn.example/video.mkv"], &ProxifyOptions::default())
        .await?;
    println!("{:?}", result);

    // Store operations
    let user = client.store_user("rd").await?;
    let magnets = client.check_magnets("rd", &["magnet:?xt=urn:btih:abc"], None).await?;

    Ok(())
}
```

### FFI (C-ABI)

```c
#include "zippy_panther.h"

int main() {
    // Validate a config JSON
    const char* config = "{\"auth\":{\"api_password\":\"secret\"}}";
    int result = zippy_panther_validate_config_json(config);
    assert(result == ZIPPY_PANTHER_OK);

    // Generate a proxy URL
    const char* req = "{\"mediaflow_proxy_url\":\"https://flow.example\",\"destination_url\":\"https://cdn.example/video.mkv\"}";
    char* out = NULL;
    zippy_panther_generate_proxy_url_json(config, req, &out);
    printf("Proxy URL: %s\n", out);
    zippy_panther_string_free(out);

    // List all stores
    zippy_panther_store_catalog_json(&out);
    printf("Stores: %s\n", out);
    zippy_panther_string_free(out);

    return 0;
}
```

---

## Project Structure

```
stream-flow/
├── Cargo.toml                  # Workspace root (5 crates)
├── Cargo.lock
├── Dockerfile                  # Multi-stage Docker build (bookworm)
├── heroku.yml                  # Heroku container registry config
├── README.md
├── .github/workflows/ci.yml    # CI: tests → 90% coverage gate → artifacts
├── crates/
│   ├── zippy-panther/          # Core library (54 modules)
│   ├── zippy-panther-bin/      # Server binary (~73 lines)
│   ├── zippy-panther-ffi/      # C-ABI staticlib/cdylib bridge
│   ├── zippy-panther-sdk/      # Rust HTTP client SDK
│   └── os_info_stub/           # ~100-line stub replacing 23MB os_info crate
└── sdk/
    ├── js/                     # JavaScript SDK (scaffold)
    └── python/                 # Python SDK (scaffold)
```

---

## CI/CD

The CI pipeline enforces quality gates:

1. **`cargo test --workspace`** — all unit, property, and integration tests
2. **`cargo llvm-cov --fail-under-lines 90`** — ≥90% line coverage on the library crate
3. **Build artifacts** — server binary, FFI staticlib (Linux x86_64, macOS ARM64, Windows x86_64), Docker image

---

## Development

```bash
# Run all tests
cargo test --workspace --all-features

# Lint
cargo clippy --workspace --all-features --all-targets -- -D warnings

# Build with release optimizations
cargo build --release -p zippy-panther-bin

# Build FFI staticlib
cargo build --profile release-ffi -p zippy-panther-ffi --features ffi

# Run with local config
CONFIG_PATH=./config.toml cargo run -p zippy-panther-bin
```

### Design Principles

- **Single outbound seam** — every upstream HTTP call flows through `OutboundClient` with fail-closed egress
- **Unified error taxonomy** — 14 error categories, each with a deterministic HTTP status and retryability
- **Composable resilience** — `Deadline → Bulkhead → Breaker → Retry` stack layered via combinators
- **Dual-surface parity** — both mediaflow and stremthru surfaces share identical `AppState` and internal handlers
- **Testable by construction** — pure predicates, seeded RNG for backoff, clock abstraction, deterministic config loading

---

## Debugging

- Check `/health?probe=liveness` — returns `200` if the runtime watchdog heartbeat is fresh
- Check `/health?probe=readiness` — returns `200` if SQLite is reachable, load is normal, and not all store breakers are open
- Check `/metrics` — Prometheus exposition for debugging bottlenecks
- Check `/proxy/ip` — returns the tunnel-observed egress IP (useful for verifying egress isolation)

---

## Contributing

Contributions are welcome! Areas that would benefit most:

- JavaScript / Python SDK implementations
- Additional debrid service implementations
- Extractor host support for more video platforms
- Documentation and usage examples

---

## License

MIT — see [LICENSE](LICENSE) for details.
