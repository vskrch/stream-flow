//! Configuration model (`config`) — Req 31, 36.3/36.4.
//!
//! There is exactly **one** root [`Config`] tree, assembled by [`Config::load`]
//! in the layered order **defaults → file → `STREMTHRU_*` env → `APP__*` env**
//! (later layers override earlier ones, so environment overrides file, which
//! overrides the documented defaults — Req 31.1, 31.2). Every sub-config
//! carries a `Default` so an omitted value falls back to its documented default
//! (Req 31.2), and a missing **required** value (`auth.api_password`) aborts the
//! load naming the offending value (Req 31.7).
//!
//! `transport_routes` are accepted as a JSON document via the
//! `APP__PROXY__TRANSPORT_ROUTES` environment variable and rejected when the
//! JSON is invalid (Req 31.6). Validation of the individual route *patterns*
//! (Req 13.8) lands with transport routing (task 14.1).
//!
//! ## Scope of this task (3.1)
//!
//! This module owns the **struct hierarchy, defaults, required-value
//! validation, `transport_routes` JSON parsing, and the basic `load()`
//! layering**. Two pieces are intentionally left as hooks for their dedicated
//! later tasks:
//!
//! * `Server_Path_Prefix` normalization + validation (Req 31.4, 31.5) — the
//!   normalizer lives in the [`path_prefix`] submodule (task 3.2) and is wired
//!   into [`Config::load`], which rewrites the value in place / rejects it.
//! * The detailed `APP__*` / `STREMTHRU_*` translation table (Req 36.3, 36.4)
//!   — [`apply_compat_sources`] is the wired-in hook completed in task 3.3.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

/// `Server_Path_Prefix` normalization + validation (Req 31.4, 31.5) — task 3.2.
pub mod path_prefix;

/// `APP__*` / `STREMTHRU_*` compatibility / translation layer (Req 36.3, 36.4)
/// — task 3.3.
mod compat;

pub use path_prefix::{normalize_path_prefix, PathPrefixError};

/// A secret string whose value is kept out of `Debug` output.
///
/// Used for credentials so a `{:?}`-logged [`Config`] never leaks the API
/// password, metrics password, or vault secret (security: secret redaction).
#[derive(Clone, Deserialize, serde::Serialize)]
pub struct Secret(String);

impl Secret {
    /// Borrow the underlying secret. Call sites should avoid logging the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `true` when the secret is the empty string (treated as "absent").
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}

/// Failure modes of [`Config::load`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// A required configuration value was absent at startup (Req 31.7). The
    /// payload names the offending dotted key (e.g. `auth.api_password`).
    #[error("required configuration value `{0}` is missing")]
    MissingRequired(String),
    /// `transport_routes` were supplied via env but were not valid JSON
    /// (Req 31.6).
    #[error("invalid transport_routes JSON: {0}")]
    InvalidTransportRoutes(String),
    /// The configured `server.path_prefix` contained a forbidden character and
    /// was rejected at load (Req 31.5). The payload names the offending value.
    #[error("invalid server.path_prefix: {0}")]
    InvalidPathPrefix(#[from] path_prefix::PathPrefixError),
    /// The underlying `config` crate could not build or deserialize the tree.
    #[error(transparent)]
    Source(#[from] ::config::ConfigError),
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// HTTP server binding + public path prefix (Req 31.3, 31.4).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address. Default `127.0.0.1` (loopback) so an out-of-the-box run
    /// is not exposed to the network until the operator opts in.
    pub host: String,
    /// Bind port. Default `8080`.
    pub port: u16,
    /// actix worker count. `0` means "one per logical CPU" (actix default).
    pub workers: usize,
    /// Public URL path prefix for generated URLs behind a reverse proxy.
    ///
    /// Normalized at load to start with `/`, not end with `/`, and collapse
    /// repeated slashes (Req 31.4); a value containing whitespace, control, or
    /// URL-delimiter characters is rejected at load (Req 31.5). See
    /// [`path_prefix::normalize_path_prefix`].
    pub path_prefix: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: 0,
            path_prefix: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy + transport routing
// ---------------------------------------------------------------------------

/// A single transport-route override keyed by a URL pattern (Req 13).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct TransportRouteConfig {
    /// Whether matching requests are forced through `proxy_url`.
    pub proxy: bool,
    /// The forwarding proxy URL (http/https/socks4/socks5) for this route.
    pub proxy_url: Option<String>,
    /// Whether TLS certificates are verified for this route. Default `true`.
    pub verify_ssl: bool,
}

impl Default for TransportRouteConfig {
    fn default() -> Self {
        Self {
            proxy: false,
            proxy_url: None,
            verify_ssl: true,
        }
    }
}

/// Proxy timeouts, buffering, redirect/forwarding behaviour, and the
/// per-pattern transport-route table (Req 13, 31.3, 35).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// TCP+TLS handshake timeout for a new upstream connection (seconds).
    pub connect_timeout_secs: u64,
    /// Overall request timeout covering pool-wait + connect + response headers
    /// (seconds).
    pub request_timeout_secs: u64,
    /// Timeout for fully reading a small in-memory body (manifests, EPG, …).
    pub body_read_timeout_secs: u64,
    /// Streaming relay chunk buffer size in bytes. Default 256 KiB.
    pub buffer_size: usize,
    /// Whether 3xx redirects are followed server-side. Default `true`.
    pub follow_redirects: bool,
    /// Optional default forwarding proxy URL.
    pub forwarding_proxy: Option<String>,
    /// When `true`, route **all** upstream traffic through `forwarding_proxy`.
    pub all_proxy: bool,
    /// Per-pattern transport overrides. Settable via the
    /// `APP__PROXY__TRANSPORT_ROUTES` JSON env var (Req 31.6).
    pub transport_routes: HashMap<String, TransportRouteConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 30,
            request_timeout_secs: 240,
            body_read_timeout_secs: 60,
            buffer_size: 262_144,
            follow_redirects: true,
            forwarding_proxy: None,
            all_proxy: false,
            transport_routes: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Authentication + authorization material (Req 28).
///
/// `api_password` is the single **required** value of the whole config; all
/// other fields default to empty.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    /// The API password (required — Req 28.1, 31.7). Kept as a [`Secret`].
    pub api_password: Option<Secret>,
    /// Optional separate password guarding `/metrics` (Req 32.2).
    pub metrics_password: Option<Secret>,
    /// HTTP-Basic proxy-auth credentials, one `user:pass` entry per element
    /// (structured parsing of the compat CSV form lands in task 3.3 / 9).
    pub proxy_auth: Vec<String>,
    /// Per-user store credentials, one `user:store:token` entry per element.
    pub per_user_store: Vec<String>,
    /// Admin usernames (Req 28.6).
    pub admins: Vec<String>,
}

// ---------------------------------------------------------------------------
// Streaming-engine sub-configs (HLS / MPD / DRM / transcode / EPG / extractor)
// ---------------------------------------------------------------------------

/// HLS proxying / prefetch tunables (Req 1, 7).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct HlsConfig {
    pub prebuffer_segments: usize,
    pub prebuffer_cache_size: usize,
    pub segment_cache_ttl_secs: u64,
    pub inactivity_timeout_secs: u64,
}

impl Default for HlsConfig {
    fn default() -> Self {
        Self {
            prebuffer_segments: 5,
            prebuffer_cache_size: 50,
            segment_cache_ttl_secs: 300,
            inactivity_timeout_secs: 60,
        }
    }
}

/// MPD / DASH→HLS tunables (Req 2, 3).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct MpdConfig {
    pub live_playlist_depth: usize,
    pub live_init_cache_ttl_secs: u64,
    pub remux_to_ts: bool,
}

impl Default for MpdConfig {
    fn default() -> Self {
        Self {
            live_playlist_depth: 8,
            live_init_cache_ttl_secs: 60,
            remux_to_ts: false,
        }
    }
}

/// ClearKey DRM tunables (Req 4).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DrmConfig {
    pub key_cache_ttl_secs: u64,
}

impl Default for DrmConfig {
    fn default() -> Self {
        Self {
            key_cache_ttl_secs: 3600,
        }
    }
}

/// On-the-fly transcode/remux tunables (Req 9).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct TranscodeConfig {
    pub enabled: bool,
    pub prefer_gpu: bool,
    pub video_bitrate: String,
    pub audio_bitrate: u32,
}

impl Default for TranscodeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_gpu: true,
            video_bitrate: "4M".to_string(),
            audio_bitrate: 192_000,
        }
    }
}

/// EPG / XMLTV caching tunables (Req 8).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct EpgConfig {
    pub cache_ttl_secs: u64,
}

impl Default for EpgConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 3600,
        }
    }
}

/// Video-extractor settings (Req 12).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ExtractorConfig {
    pub byparr_url: Option<String>,
    pub byparr_timeout_secs: u64,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            byparr_url: None,
            byparr_timeout_secs: 60,
        }
    }
}

/// Xtream-Codes settings (Req 8).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct XtreamConfig {
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<Secret>,
}

/// Acestream engine settings (Req 10).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AcestreamConfig {
    pub host: String,
    pub port: u16,
    pub buffer_size: usize,
    pub access_token: Option<String>,
}

impl Default for AcestreamConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 6878,
            buffer_size: 4 * 1024 * 1024,
            access_token: None,
        }
    }
}

/// Telegram MTProto settings (Req 11).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct TelegramConfig {
    pub api_id: i32,
    pub api_hash: Option<Secret>,
    pub session_string: Option<Secret>,
    pub max_connections: usize,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            api_id: 0,
            api_hash: None,
            session_string: None,
            max_connections: 8,
        }
    }
}

/// Pre-buffering tunables (Req 37.11).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct PrebufferConfig {
    pub enabled: bool,
    pub initial_window_bytes: usize,
    pub initial_buffer_bytes: usize,
    pub steady_buffer_bytes: usize,
}

impl Default for PrebufferConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_window_bytes: 2 * 1024 * 1024,
            initial_buffer_bytes: 512 * 1024,
            steady_buffer_bytes: 256 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache + persistence
// ---------------------------------------------------------------------------

/// Cache layer settings (Req 30).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Redis connection URL. `None`/empty disables Redis (local cache only).
    pub redis_url: Option<String>,
    /// Namespace prefix applied to every cache key.
    pub namespace: String,
    /// Default TTL (seconds) for cached values lacking a specific TTL.
    pub default_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            namespace: "stream-flow".to_string(),
            default_ttl_secs: 300,
        }
    }
}

/// Embedded-SQLite settings (Req 29).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    /// Filesystem path to the SQLite database file.
    pub path: String,
    /// `busy_timeout` applied at pool build (Req 29.6). Default 5s.
    pub busy_timeout_secs: u64,
    /// Max pooled connections. Default 5.
    pub max_connections: u32,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            path: "stream-flow.db".to_string(),
            busy_timeout_secs: 5,
            max_connections: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Stremio / integrations / rate-limit / warmup / quality / http2 / peer
// ---------------------------------------------------------------------------

/// Stremio addon settings (Req 17–26).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct StremioConfig {
    pub addon_name: Option<String>,
    pub base_url: Option<String>,
}

/// Third-party integration credentials (Trakt/MDBList/etc — Req 27).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct IntegrationsConfig {
    /// Opaque `name -> credential` map; typed parsing lands with the relevant
    /// integration tasks. Detailed `STREMTHRU_*` mapping is task 3.3.
    pub credentials: HashMap<String, String>,
}

/// Rate-limit settings (Req 40).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_minute: 600,
        }
    }
}

/// Warmup-pool settings (Req 45).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct WarmupConfig {
    pub enabled: bool,
    pub pool_size: usize,
}

/// Quality-selection settings (Req 38).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct QualityConfig {
    pub preferred: Option<String>,
}

/// HTTP/2 settings (Req 43).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Http2Config {
    pub enabled: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Peer-sharing settings (Req 29.7).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct PeerConfig {
    pub url: Option<String>,
    pub token: Option<Secret>,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Egress / security / degradation (Req 51 / 46 / 44)
// ---------------------------------------------------------------------------

/// How outbound traffic reaches the public internet (Req 51).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EgressTunnelMode {
    /// No tunnel configured (default). Enforcement of fail-closed behaviour
    /// against this state lands in the egress layer (task 8).
    #[default]
    Disabled,
    /// Dial through an HTTP/SOCKS proxy.
    Proxy,
    /// Dial inside a dedicated network namespace.
    Netns,
}

/// Behaviour when the egress tunnel is unavailable or leaking (Req 51.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EgressPolicy {
    /// Refuse to dial rather than leak the host's real IP (the safe default).
    #[default]
    FailClosed,
    /// Proceed directly (and warn) when the tunnel is down.
    FailOpen,
}

/// Egress tunnel + client-IP isolation settings (Req 51).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct EgressConfig {
    /// Tunnel transport mode.
    pub tunnel_mode: EgressTunnelMode,
    /// Tunnel URL (proxy mode) or namespace identifier (netns mode).
    pub tunnel_url: Option<String>,
    /// Fail-closed (default) vs fail-open behaviour.
    pub policy: EgressPolicy,
    /// IP-reflection service queried *through the tunnel* to learn the
    /// Egress_IP (Req 51.5).
    pub ip_reflection_url: String,
    /// How often (seconds) the Egress_IP is refreshed.
    pub refresh_interval_secs: u64,
    /// Client-identifying headers stripped from every outbound request
    /// (Req 51.2, 51.3). The egress layer also strips a hardcoded baseline;
    /// this list augments it.
    pub strip_headers: Vec<String>,
    /// Optional `host -> tunnel URL` overrides so specific stores/hosts pin a
    /// specific tunnel (Req 51.9).
    pub per_host: HashMap<String, String>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            tunnel_mode: EgressTunnelMode::Disabled,
            tunnel_url: None,
            policy: EgressPolicy::FailClosed,
            ip_reflection_url: "https://api.ipify.org".to_string(),
            refresh_interval_secs: 300,
            strip_headers: default_strip_headers(),
            per_host: HashMap::new(),
        }
    }
}

/// The baseline client-identifying headers stripped from outbound requests
/// (Req 51.2, 51.3). Mirrors the design's Layer-1 sanitization list.
fn default_strip_headers() -> Vec<String> {
    [
        "X-Forwarded-For",
        "X-Real-IP",
        "Forwarded",
        "Via",
        "X-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Cluster-Client-IP",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// SSRF guard + body-size caps (Req 46).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Hosts/CIDRs explicitly permitted even if private/loopback (Req 46.2).
    pub ssrf_allowlist: Vec<String>,
    /// Hosts/CIDRs explicitly denied (Req 46.3).
    pub ssrf_denylist: Vec<String>,
    /// When `false` (default), private/loopback/link-local targets are denied
    /// unless allowlisted (Req 46.1).
    pub allow_private_ranges: bool,
    /// Max inbound request body in bytes (Req 46.4). Default 50 MiB.
    pub max_request_body_bytes: usize,
    /// Max buffered upstream response body in bytes (Req 46.5). Default 10 MiB.
    pub max_response_body_bytes: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            ssrf_allowlist: Vec::new(),
            ssrf_denylist: Vec::new(),
            allow_private_ranges: false,
            max_request_body_bytes: 50 * 1024 * 1024,
            max_response_body_bytes: 10 * 1024 * 1024,
        }
    }
}

/// Degradation-guard high-water marks (Req 44).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DegradationConfig {
    /// Whether the degradation guard is active.
    pub enabled: bool,
    /// Active-connection count at which new non-streaming requests are shed.
    pub conn_high_water: usize,
    /// Active-connection count below which normal service resumes
    /// (hysteresis).
    pub conn_low_water: usize,
    /// Process RSS (bytes) high-water mark that triggers memory reclamation.
    pub memory_high_water_bytes: u64,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            conn_high_water: 1000,
            conn_low_water: 800,
            memory_high_water_bytes: 400 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Root config
// ---------------------------------------------------------------------------

/// The single root configuration tree (design: Configuration Model).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub auth: AuthConfig,
    pub hls: HlsConfig,
    pub mpd: MpdConfig,
    pub drm: DrmConfig,
    pub transcode: TranscodeConfig,
    pub epg: EpgConfig,
    pub extractor: ExtractorConfig,
    pub xtream: XtreamConfig,
    pub acestream: AcestreamConfig,
    pub telegram: TelegramConfig,
    pub prebuffer: PrebufferConfig,
    pub cache: CacheConfig,
    pub db: DbConfig,
    pub vault_secret: Option<Secret>,
    pub stremio: StremioConfig,
    pub integrations: IntegrationsConfig,
    pub ratelimit: RateLimitConfig,
    pub warmup: WarmupConfig,
    pub quality: QualityConfig,
    pub http2: Http2Config,
    pub degradation: DegradationConfig,
    pub security: SecurityConfig,
    pub egress: EgressConfig,
    pub peer: Option<PeerConfig>,
}

/// Inputs to [`Config::load`].
///
/// `env` lets tests inject a deterministic environment map; when `None`, the
/// process environment is used.
#[derive(Debug, Default)]
pub struct LoadOptions {
    /// Optional configuration file (format inferred from its extension).
    pub file: Option<PathBuf>,
    /// Explicit environment map for `APP__*` lookups. `None` ⇒ process env.
    pub env: Option<HashMap<String, String>>,
}

impl LoadOptions {
    /// An empty option set (no file, process environment).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the configuration file path.
    pub fn with_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Use an explicit environment map instead of the process environment.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = Some(env);
        self
    }
}

impl Config {
    /// Load and validate configuration in the layered order
    /// **defaults → file → `STREMTHRU_*` → `APP__*`** (Req 31.1, 31.2).
    ///
    /// Returns [`ConfigLoadError::MissingRequired`] when a required value is
    /// absent (Req 31.7) and [`ConfigLoadError::InvalidTransportRoutes`] when
    /// the `transport_routes` JSON env var is malformed (Req 31.6).
    pub fn load(opts: &LoadOptions) -> Result<Config, ConfigLoadError> {
        let mut builder = ::config::Config::builder();

        // Layer 2: optional file (Req 31.1). Defaults (layer 1) are supplied by
        // `#[serde(default)]` during deserialize, so no `set_default` calls are
        // needed here.
        if let Some(path) = &opts.file {
            builder = builder.add_source(::config::File::from(path.as_path()));
        }

        // Layer 3: `STREMTHRU_*` compat (hook — full mapping is task 3.3).
        builder = apply_compat_sources(builder, opts);

        // Layer 4: native nested `APP__*` env (highest precedence).
        builder = builder.add_source(app_env_source(opts));

        // `transport_routes` JSON via env (Req 31.6): the `config` env source
        // surfaces `APP__PROXY__TRANSPORT_ROUTES` as a raw *string*, which is
        // not a map and would fail deserialization. Parse it explicitly so a
        // malformed document is a hard, named error (Req 31.6) and a valid one
        // replaces the string with a proper nested map before deserialize.
        if let Some(raw) = env_lookup(opts, "APP__PROXY__TRANSPORT_ROUTES") {
            let routes: HashMap<String, TransportRouteConfig> = serde_json::from_str(&raw)
                .map_err(|e| ConfigLoadError::InvalidTransportRoutes(e.to_string()))?;
            builder = builder
                .set_override("proxy.transport_routes", transport_routes_value(&routes))?;
        }

        let built = builder.build()?;
        let mut config: Config = built.try_deserialize()?;

        // Normalize + validate `Server_Path_Prefix` in place (Req 31.4, 31.5).
        // A forbidden character aborts the load naming the offending value via
        // the `#[from]` conversion into `ConfigLoadError::InvalidPathPrefix`.
        config.server.path_prefix = path_prefix::normalize_path_prefix(&config.server.path_prefix)?;

        config.validate()?;
        Ok(config)
    }

    /// Convenience loader reading `CONFIG_PATH` + the process environment.
    pub fn from_env() -> Result<Config, ConfigLoadError> {
        let file = std::env::var("CONFIG_PATH")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists());
        Config::load(&LoadOptions { file, env: None })
    }

    /// Validate required values, naming the first missing one (Req 31.7).
    fn validate(&self) -> Result<(), ConfigLoadError> {
        match &self.auth.api_password {
            Some(secret) if !secret.is_empty() => Ok(()),
            _ => Err(ConfigLoadError::MissingRequired("auth.api_password".to_string())),
        }
    }
}

/// Build the `APP__*` environment source, honoring an explicit env map when
/// the caller supplied one (used by tests for determinism).
fn app_env_source(opts: &LoadOptions) -> ::config::Environment {
    let mut env = ::config::Environment::with_prefix("APP")
        .separator("__")
        .try_parsing(true);
    if let Some(map) = &opts.env {
        env = env.source(Some(map.clone()));
    }
    env
}

/// Convert parsed transport routes into a `config::Value` nested map so they
/// can be injected via `set_override` ahead of deserialization (Req 31.6).
fn transport_routes_value(
    routes: &HashMap<String, TransportRouteConfig>,
) -> ::config::Value {
    use ::config::{Map, Value};
    let map: Map<String, Value> = routes
        .iter()
        .map(|(pattern, route)| {
            let mut inner = Map::new();
            inner.insert("proxy".to_string(), Value::from(route.proxy));
            if let Some(url) = &route.proxy_url {
                inner.insert("proxy_url".to_string(), Value::from(url.clone()));
            }
            inner.insert("verify_ssl".to_string(), Value::from(route.verify_ssl));
            (pattern.clone(), Value::from(inner))
        })
        .collect();
    Value::from(map)
}

/// Wire the `APP__*` / `STREMTHRU_*` translation layer (Req 36.3, 36.4) into the
/// builder.
///
/// This occupies the `STREMTHRU_*` slot between the file (layer 2) and the
/// native nested `APP__*` source (layer 4): the [`compat::CompatSource`] maps
/// both projects' legacy compatibility environment variables onto the internal
/// [`Config`] dotted keys, then the native `APP__*` source added afterwards has
/// the documented final say over any genuinely overlapping scalar (Req 36.4).
/// Auth tokens are kept on separate lists (`auth.api_password` vs
/// `auth.proxy_auth[]`) so both authentication mechanisms remain active when
/// both prefixes are set (Req 36.4).
fn apply_compat_sources(
    builder: ::config::ConfigBuilder<::config::builder::DefaultState>,
    opts: &LoadOptions,
) -> ::config::ConfigBuilder<::config::builder::DefaultState> {
    builder.add_source(compat::CompatSource::from_options(opts))
}

/// Look up a raw environment value from the explicit map or the process env.
fn env_lookup(opts: &LoadOptions, key: &str) -> Option<String> {
    match &opts.env {
        Some(map) => map.get(key).cloned(),
        None => std::env::var(key).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A `LoadOptions` whose env map carries the one required value so the
    /// loader succeeds and we can assert on everything else.
    fn opts_with_api_password() -> LoadOptions {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        LoadOptions::new().with_env(env)
    }

    // -- Req 31.2: defaults applied for omitted values ----------------------

    #[test]
    fn defaults_are_applied_for_omitted_values() {
        let config = Config::load(&opts_with_api_password()).expect("load should succeed");

        // Server defaults.
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.workers, 0);
        assert_eq!(config.server.path_prefix, "");

        // Proxy defaults.
        assert_eq!(config.proxy.connect_timeout_secs, 30);
        assert_eq!(config.proxy.buffer_size, 262_144);
        assert!(config.proxy.follow_redirects);
        assert!(!config.proxy.all_proxy);
        assert!(config.proxy.transport_routes.is_empty());

        // A representative streaming sub-config default.
        assert_eq!(config.hls.prebuffer_segments, 5);
        assert_eq!(config.cache.namespace, "stream-flow");
    }

    // -- Req 31.7: missing required value aborts naming the value -----------

    #[test]
    fn missing_required_api_password_aborts_naming_the_value() {
        // Deterministic empty env so the process env can't supply the value.
        let opts = LoadOptions::new().with_env(HashMap::new());
        let err = Config::load(&opts).expect_err("missing api_password must abort");
        match err {
            ConfigLoadError::MissingRequired(name) => assert_eq!(name, "auth.api_password"),
            other => panic!("expected MissingRequired, got {other:?}"),
        }
    }

    #[test]
    fn empty_api_password_is_treated_as_missing() {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), String::new());
        let opts = LoadOptions::new().with_env(env);
        let err = Config::load(&opts).expect_err("empty api_password must abort");
        assert!(matches!(err, ConfigLoadError::MissingRequired(name) if name == "auth.api_password"));
    }

    // -- Req 31.6: transport_routes JSON parse + reject-on-invalid ----------

    #[test]
    fn transport_routes_json_is_parsed_from_env() {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        env.insert(
            "APP__PROXY__TRANSPORT_ROUTES".to_string(),
            r#"{"example.com":{"proxy":true,"proxy_url":"socks5://127.0.0.1:9050","verify_ssl":false}}"#
                .to_string(),
        );
        let config = Config::load(&LoadOptions::new().with_env(env)).expect("valid JSON loads");

        let route = config
            .proxy
            .transport_routes
            .get("example.com")
            .expect("route present");
        assert!(route.proxy);
        assert_eq!(route.proxy_url.as_deref(), Some("socks5://127.0.0.1:9050"));
        assert!(!route.verify_ssl);
    }

    #[test]
    fn transport_route_defaults_verify_ssl_true_when_omitted() {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        env.insert(
            "APP__PROXY__TRANSPORT_ROUTES".to_string(),
            r#"{"example.com":{"proxy":true}}"#.to_string(),
        );
        let config = Config::load(&LoadOptions::new().with_env(env)).expect("valid JSON loads");
        let route = config.proxy.transport_routes.get("example.com").unwrap();
        assert!(route.verify_ssl, "verify_ssl should default to true");
    }

    #[test]
    fn invalid_transport_routes_json_is_rejected() {
        let mut env = HashMap::new();
        env.insert("APP__AUTH__API_PASSWORD".to_string(), "secret".to_string());
        env.insert(
            "APP__PROXY__TRANSPORT_ROUTES".to_string(),
            "{not valid json".to_string(),
        );
        let err = Config::load(&LoadOptions::new().with_env(env))
            .expect_err("invalid JSON must be rejected");
        assert!(matches!(err, ConfigLoadError::InvalidTransportRoutes(_)));
    }

    // -- Req 31.3: egress / security / degradation / db sub-configs present -

    #[test]
    fn egress_security_degradation_db_sub_configs_present_with_defaults() {
        let config = Config::load(&opts_with_api_password()).expect("load should succeed");

        // Egress (Req 51): fail-closed default, baseline strip list, reflection.
        assert_eq!(config.egress.policy, EgressPolicy::FailClosed);
        assert_eq!(config.egress.tunnel_mode, EgressTunnelMode::Disabled);
        assert_eq!(config.egress.ip_reflection_url, "https://api.ipify.org");
        assert!(config
            .egress
            .strip_headers
            .iter()
            .any(|h| h == "X-Forwarded-For"));

        // Security (Req 46): private ranges denied by default, body caps set.
        assert!(!config.security.allow_private_ranges);
        assert_eq!(config.security.max_request_body_bytes, 50 * 1024 * 1024);
        assert_eq!(config.security.max_response_body_bytes, 10 * 1024 * 1024);

        // Degradation (Req 44): high-water marks present + hysteresis ordering.
        assert!(config.degradation.enabled);
        assert!(config.degradation.conn_high_water > 0);
        assert!(config.degradation.conn_low_water < config.degradation.conn_high_water);

        // DB (Req 29): WAL busy timeout + pool default.
        assert_eq!(config.db.busy_timeout_secs, 5);
        assert_eq!(config.db.max_connections, 5);
    }

    // -- Req 31.1: layering order (defaults < file < env) -------------------

    fn write_temp_toml(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("create temp file");
        file.write_all(contents.as_bytes()).expect("write toml");
        file.flush().expect("flush toml");
        file
    }

    #[test]
    fn file_overrides_defaults() {
        let file = write_temp_toml("[auth]\napi_password = \"frompw\"\n[server]\nport = 9000\n");
        let opts = LoadOptions::new().with_file(file.path()).with_env(HashMap::new());
        let config = Config::load(&opts).expect("load should succeed");
        assert_eq!(config.server.port, 9000, "file value overrides default");
        assert_eq!(config.auth.api_password.as_ref().unwrap().expose(), "frompw");
    }

    #[test]
    fn env_overrides_file() {
        let file = write_temp_toml("[auth]\napi_password = \"frompw\"\n[server]\nport = 9000\n");
        let mut env = HashMap::new();
        env.insert("APP__SERVER__PORT".to_string(), "9100".to_string());
        let opts = LoadOptions::new().with_file(file.path()).with_env(env);
        let config = Config::load(&opts).expect("load should succeed");
        assert_eq!(config.server.port, 9100, "env value overrides file");
    }

    #[test]
    fn secret_debug_does_not_leak_value() {
        let secret = Secret::from("topsecret");
        assert_eq!(format!("{secret:?}"), "Secret(***)");
        assert!(!format!("{secret:?}").contains("topsecret"));
    }
}
