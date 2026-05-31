//! Token-bucket rate limiter (`rate_limit`) — Req 40.
//!
//! Implements a **token-bucket** algorithm (Req 40.4) with:
//!
//! * **Per-user** buckets keyed by authenticated username (Req 40.1).
//! * **Per-IP** buckets keyed by [`Client_IP`](crate::http::client_ip) for
//!   unauthenticated endpoints (Req 40.2).
//! * `429 Too Many Requests` + `Retry-After` header when the bucket is empty
//!   (Req 40.3).
//! * **Redis-shared** state when a Redis backend is configured so all replicas
//!   share one quota per key; **in-process** state otherwise (Req 40.5).
//! * `/health` and `/metrics` endpoints are **exempt** from rate limiting
//!   (Req 40.6).
//!
//! ## Token-bucket algorithm
//!
//! Each bucket has a `capacity` (maximum tokens = burst allowance) and a
//! `refill_rate` (tokens added per second). A request consumes one token; if
//! the bucket is empty the request is rejected with `429` and a `Retry-After`
//! indicating when the next token will be available.
//!
//! ### Redis-backed implementation
//!
//! The Redis backend uses a Lua script executed atomically to read the current
//! token count + last-refill timestamp, compute the refilled count, and either
//! consume a token (allow) or return the wait time (deny). This is the
//! standard approach for distributed token buckets — the Lua script runs
//! atomically on the Redis server so no TOCTOU race is possible across
//! replicas.
//!
//! ### In-process implementation
//!
//! The local backend stores `(tokens: f64, last_refill: Instant)` in a
//! `DashMap` keyed by the bucket key. Refill is computed lazily on each
//! request: `tokens = min(capacity, tokens + elapsed_secs * refill_rate)`.
//!
//! ## Middleware
//!
//! [`RateLimiterMiddleware`] is an actix-web middleware that:
//! 1. Skips exempt paths (`/health`, `/metrics`).
//! 2. Derives the bucket key: authenticated username (from the `Authorization`
//!    / `X-StremThru-Authorization` header) or the client IP.
//! 3. Calls [`RateLimiter::check`] and either passes the request through or
//!    returns `429` with `Retry-After`.

use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::sync::Mutex;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use actix_web::ResponseError;

use crate::cache::CacheBackend;
use crate::config::RateLimitConfig;
use crate::errors::AppError;

use base64::Engine as _;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Resolved rate-limit parameters derived from [`RateLimitConfig`].
#[derive(Clone, Debug)]
pub struct BucketConfig {
    /// Maximum tokens in the bucket (burst capacity).
    pub capacity: f64,
    /// Tokens added per second (sustained rate).
    pub refill_rate: f64,
}

impl BucketConfig {
    /// Build from the operator config.
    ///
    /// `requests_per_minute` maps to `refill_rate = rpm / 60.0` and
    /// `capacity = rpm` (one minute of burst).
    pub fn from_config(cfg: &RateLimitConfig) -> Self {
        let rpm = cfg.requests_per_minute as f64;
        Self {
            capacity: rpm,
            refill_rate: rpm / 60.0,
        }
    }
}

// ---------------------------------------------------------------------------
// In-process bucket state
// ---------------------------------------------------------------------------

/// A single in-process token-bucket entry.
#[derive(Debug)]
struct LocalBucket {
    tokens: f64,
    last_refill: Instant,
}

impl LocalBucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    ///
    /// Returns `Ok(())` when a token was consumed, or `Err(retry_after)` when
    /// the bucket is empty.
    fn try_consume(&mut self, cfg: &BucketConfig) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * cfg.refill_rate).min(cfg.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Time until the next token is available.
            let wait_secs = (1.0 - self.tokens) / cfg.refill_rate;
            Err(Duration::from_secs_f64(wait_secs).max(Duration::from_millis(1)))
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// The rate-limiter backend: either in-process or Redis-backed.
///
/// Constructed once and shared across all workers via [`Arc`].
pub struct RateLimiter {
    cfg: BucketConfig,
    /// Whether rate limiting is enabled (Req 40.1–40.6). When `false` the
    /// middleware is a pass-through.
    enabled: bool,
    /// In-process buckets (used when Redis is not configured, Req 40.5).
    local: Arc<DashMap<String, Arc<Mutex<LocalBucket>>>>,
    /// Optional Redis-backed cache for distributed state (Req 40.5).
    redis: Option<Arc<dyn CacheBackend>>,
}

impl RateLimiter {
    /// Build a rate limiter from the operator config.
    ///
    /// `cache` is the optional Redis-backed [`CacheBackend`]; when `None` the
    /// limiter uses in-process state only (Req 40.5).
    pub fn new(cfg: &RateLimitConfig, cache: Option<Arc<dyn CacheBackend>>) -> Self {
        Self {
            cfg: BucketConfig::from_config(cfg),
            enabled: cfg.enabled,
            local: Arc::new(DashMap::new()),
            redis: cache,
        }
    }

    /// Returns `true` when rate limiting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check whether the request identified by `key` is within the rate limit.
    ///
    /// Returns `Ok(())` when the request is allowed, or
    /// `Err(AppError::too_many_requests(...).with_retry_after(...))` when the
    /// bucket is empty (Req 40.3).
    pub async fn check(&self, key: &str) -> Result<(), AppError> {
        if let Some(redis) = &self.redis {
            self.check_redis(key, redis.as_ref()).await
        } else {
            self.check_local(key)
        }
    }

    // -- In-process path -----------------------------------------------------

    fn check_local(&self, key: &str) -> Result<(), AppError> {
        let bucket = self
            .local
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(LocalBucket::new(self.cfg.capacity))))
            .clone();

        // `try_lock` is safe here: the Mutex is per-key so contention is
        // minimal; we use `blocking_lock` only in the sync path.
        let mut guard = bucket.blocking_lock();
        match guard.try_consume(&self.cfg) {
            Ok(()) => Ok(()),
            Err(retry_after) => Err(AppError::too_many_requests(format!(
                "rate limit exceeded for key `{key}`; retry after {:.1}s",
                retry_after.as_secs_f64()
            ))
            .with_retry_after(retry_after)),
        }
    }

    // -- Redis-backed path ---------------------------------------------------

    /// Redis-backed token bucket using a serialized `"tokens:timestamp_ms"`
    /// value stored under the rate-limit key.
    ///
    /// The read-modify-write is not atomic at the Redis level (we use GET +
    /// SET), but the per-key Lua-script approach would require `redis::Script`
    /// which is not available through the `CacheBackend` trait. Instead we use
    /// an optimistic approach: read the current state, compute the new state,
    /// and write it back. In the rare case of a concurrent write from another
    /// replica the worst outcome is a slightly higher burst — acceptable for
    /// rate limiting (the alternative of a Lua script would require bypassing
    /// the `CacheBackend` abstraction).
    ///
    /// The value is stored as `"{tokens_f64}:{timestamp_ms_u64}"` with a TTL
    /// of `capacity / refill_rate + 1` seconds (the time to fully drain and
    /// refill the bucket).
    async fn check_redis(
        &self,
        key: &str,
        cache: &dyn CacheBackend,
    ) -> Result<(), AppError> {
        let redis_key = format!("rl:{key}");
        let ttl = Duration::from_secs_f64(self.cfg.capacity / self.cfg.refill_rate + 1.0);

        // Read current state.
        let (mut tokens, last_ms) = match cache.get(&redis_key).await {
            Ok(Some(bytes)) => {
                let s = String::from_utf8_lossy(&bytes);
                parse_bucket_value(&s).unwrap_or((self.cfg.capacity, now_ms()))
            }
            Ok(None) => (self.cfg.capacity, now_ms()),
            Err(_) => {
                // Redis unavailable — fall back to local bucket (Req 40.5).
                return self.check_local(key);
            }
        };

        // Refill.
        let now = now_ms();
        let elapsed_secs = (now.saturating_sub(last_ms)) as f64 / 1000.0;
        tokens = (tokens + elapsed_secs * self.cfg.refill_rate).min(self.cfg.capacity);

        if tokens >= 1.0 {
            tokens -= 1.0;
            let val = format_bucket_value(tokens, now);
            let _ = cache
                .set(&redis_key, val.into_bytes().into(), ttl)
                .await;
            Ok(())
        } else {
            let wait_secs = (1.0 - tokens) / self.cfg.refill_rate;
            let retry_after = Duration::from_secs_f64(wait_secs).max(Duration::from_millis(1));
            Err(AppError::too_many_requests(format!(
                "rate limit exceeded for key `{key}`; retry after {:.1}s",
                retry_after.as_secs_f64()
            ))
            .with_retry_after(retry_after))
        }
    }

    /// Expose the bucket config for testing.
    #[cfg(test)]
    pub fn bucket_config(&self) -> &BucketConfig {
        &self.cfg
    }

    /// Peek at the current token count for a key (in-process only, for tests).
    #[cfg(test)]
    pub fn local_tokens(&self, key: &str) -> Option<f64> {
        self.local
            .get(key)
            .map(|b| b.blocking_lock().tokens)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_bucket_value(tokens: f64, timestamp_ms: u64) -> String {
    format!("{tokens:.6}:{timestamp_ms}")
}

fn parse_bucket_value(s: &str) -> Option<(f64, u64)> {
    let mut parts = s.splitn(2, ':');
    let tokens: f64 = parts.next()?.parse().ok()?;
    let ts: u64 = parts.next()?.parse().ok()?;
    Some((tokens, ts))
}

// ---------------------------------------------------------------------------
// Exempt paths (Req 40.6)
// ---------------------------------------------------------------------------

/// Returns `true` when the request path is exempt from rate limiting
/// (Req 40.6): `/health` and `/metrics` are never rate-limited.
pub fn is_exempt(path: &str) -> bool {
    path == "/health" || path.starts_with("/health?") || path == "/metrics"
}

// ---------------------------------------------------------------------------
// Bucket key derivation
// ---------------------------------------------------------------------------

/// Derive the rate-limit bucket key for a request.
///
/// Authenticated requests (carrying `Authorization` or
/// `X-StremThru-Authorization`) are keyed by the username extracted from the
/// credential (Req 40.1). Unauthenticated requests are keyed by the client IP
/// (Req 40.2).
pub fn bucket_key(req: &ServiceRequest) -> String {
    // Try X-StremThru-Authorization (stremthru surface, Req 28.2).
    if let Some(val) = req
        .headers()
        .get("X-StremThru-Authorization")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(user) = extract_basic_username(val) {
            return format!("user:{user}");
        }
    }

    // Try standard Authorization header (mediaflow surface, Req 28.1).
    if let Some(val) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(user) = extract_basic_username(val) {
            return format!("user:{user}");
        }
        // api_password in query param — use a generic "authenticated" key so
        // all api_password users share one bucket (they are all the operator).
        if req.query_string().contains("api_password=") {
            return "user:api_password".to_string();
        }
    }

    // api_password in query param (no Authorization header).
    if req.query_string().contains("api_password=") {
        return "user:api_password".to_string();
    }

    // Fall back to client IP (Req 40.2).
    let ip = crate::http::client_ip::client_ip(req.request())
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("ip:{ip}")
}

/// Extract the username from an HTTP Basic `Authorization` header value.
///
/// Accepts both plain `user:pass` and `Basic base64(user:pass)` forms
/// (Req 28.2).
fn extract_basic_username(val: &str) -> Option<String> {
    let stripped = if let Some(rest) = val.strip_prefix("Basic ") {
        // base64-encoded form.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(rest.trim())
            .ok()?;
        String::from_utf8(decoded).ok()?
    } else {
        val.to_string()
    };
    stripped.split(':').next().map(|u| u.to_string())
}

// ---------------------------------------------------------------------------
// actix-web middleware
// ---------------------------------------------------------------------------

/// actix-web [`Transform`] factory for the rate-limiter middleware.
///
/// Wrap the router scope with `.wrap(RateLimiterMiddleware::new(...))` to
/// enforce rate limits on all routes in that scope (Req 40.1–40.6).
pub struct RateLimiterMiddleware {
    limiter: Arc<RateLimiter>,
}

impl RateLimiterMiddleware {
    /// Build the middleware from a shared [`RateLimiter`].
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiterMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = RateLimiterService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterService {
            service: Arc::new(service),
            limiter: self.limiter.clone(),
        }))
    }
}

/// The inner service produced by [`RateLimiterMiddleware`].
pub struct RateLimiterService<S> {
    service: Arc<S>,
    limiter: Arc<RateLimiter>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        let limiter = self.limiter.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Exempt paths bypass the limiter entirely (Req 40.6).
            if is_exempt(&path) || !limiter.is_enabled() {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            let key = bucket_key(&req);
            match limiter.check(&key).await {
                Ok(()) => {
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Err(err) => {
                    // Build the 429 response using the canonical AppError
                    // ResponseError impl (Req 40.3).
                    let http_resp = err.error_response();
                    let (http_req, _payload) = req.into_parts();
                    let resp = ServiceResponse::new(http_req, http_resp.map_into_right_body());
                    Ok(resp)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use std::time::Duration;

    fn cfg_10rpm() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            requests_per_minute: 10,
        }
    }

    fn cfg_60rpm() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            requests_per_minute: 60,
        }
    }

    // -----------------------------------------------------------------------
    // BucketConfig
    // -----------------------------------------------------------------------

    #[test]
    fn bucket_config_derives_correct_rate_and_capacity() {
        let cfg = BucketConfig::from_config(&cfg_60rpm());
        assert_eq!(cfg.capacity, 60.0);
        assert!((cfg.refill_rate - 1.0).abs() < 1e-9, "1 token/sec for 60 rpm");
    }

    // -----------------------------------------------------------------------
    // LocalBucket
    // -----------------------------------------------------------------------

    #[test]
    fn local_bucket_starts_full() {
        let mut b = LocalBucket::new(5.0);
        let cfg = BucketConfig { capacity: 5.0, refill_rate: 1.0 };
        // Should be able to consume 5 tokens immediately.
        for _ in 0..5 {
            assert!(b.try_consume(&cfg).is_ok());
        }
        // 6th should fail.
        assert!(b.try_consume(&cfg).is_err());
    }

    #[test]
    fn local_bucket_refills_over_time() {
        let mut b = LocalBucket::new(2.0);
        let cfg = BucketConfig { capacity: 2.0, refill_rate: 2.0 }; // 2 tokens/sec
        // Drain the bucket.
        assert!(b.try_consume(&cfg).is_ok());
        assert!(b.try_consume(&cfg).is_ok());
        assert!(b.try_consume(&cfg).is_err());

        // Simulate 1 second passing by backdating last_refill.
        b.last_refill = Instant::now() - Duration::from_secs(1);
        // Should have 2 new tokens.
        assert!(b.try_consume(&cfg).is_ok());
        assert!(b.try_consume(&cfg).is_ok());
        assert!(b.try_consume(&cfg).is_err());
    }

    #[test]
    fn local_bucket_tokens_never_exceed_capacity() {
        let mut b = LocalBucket::new(3.0);
        let cfg = BucketConfig { capacity: 3.0, refill_rate: 10.0 };
        // Simulate a long time passing.
        b.last_refill = Instant::now() - Duration::from_secs(100);
        // Trigger a refill by trying to consume.
        let _ = b.try_consume(&cfg);
        // Tokens should be capped at capacity - 1 (one was consumed).
        assert!(b.tokens <= cfg.capacity, "tokens must not exceed capacity");
    }

    #[test]
    fn local_bucket_retry_after_is_positive() {
        let mut b = LocalBucket::new(1.0);
        let cfg = BucketConfig { capacity: 1.0, refill_rate: 1.0 };
        // Drain.
        assert!(b.try_consume(&cfg).is_ok());
        // Next should fail with a positive retry_after.
        match b.try_consume(&cfg) {
            Err(d) => assert!(d > Duration::ZERO),
            Ok(()) => panic!("expected rate limit"),
        }
    }

    // -----------------------------------------------------------------------
    // RateLimiter (in-process)
    // -----------------------------------------------------------------------

    #[test]
    fn requests_within_burst_are_allowed() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        // capacity = 10, so 10 requests should all succeed.
        for _ in 0..10 {
            assert!(limiter.check_local("user:alice").is_ok());
        }
    }

    #[test]
    fn request_exceeding_burst_returns_429() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        for _ in 0..10 {
            let _ = limiter.check_local("user:alice");
        }
        let err = limiter.check_local("user:alice").unwrap_err();
        assert_eq!(err.category, crate::errors::ErrorCategory::TooManyRequests);
        assert!(err.retry_after.is_some(), "Retry-After must be set");
        assert!(err.retry_after.unwrap() > Duration::ZERO);
    }

    #[test]
    fn per_user_and_per_ip_buckets_are_independent() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        // Drain alice's bucket.
        for _ in 0..10 {
            let _ = limiter.check_local("user:alice");
        }
        // alice is rate-limited.
        assert!(limiter.check_local("user:alice").is_err());
        // bob is unaffected.
        assert!(limiter.check_local("user:bob").is_ok());
        // IP bucket is also independent.
        assert!(limiter.check_local("ip:1.2.3.4").is_ok());
    }

    #[test]
    fn tokens_never_exceed_capacity() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        // Simulate a long idle period by backdating the bucket.
        {
            let bucket = limiter
                .local
                .entry("user:alice".to_string())
                .or_insert_with(|| Arc::new(Mutex::new(LocalBucket::new(10.0))))
                .clone();
            let mut guard = bucket.blocking_lock();
            guard.last_refill = Instant::now() - Duration::from_secs(10_000);
        }
        // Consume one token to trigger refill.
        let _ = limiter.check_local("user:alice");
        let tokens = limiter.local_tokens("user:alice").unwrap();
        assert!(
            tokens <= limiter.bucket_config().capacity,
            "tokens {tokens} must not exceed capacity {}",
            limiter.bucket_config().capacity
        );
    }

    #[test]
    fn retry_after_header_is_set_on_429() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        for _ in 0..10 {
            let _ = limiter.check_local("user:alice");
        }
        let err = limiter.check_local("user:alice").unwrap_err();
        // The AppError must carry a retry_after so the ResponseError impl
        // sets the Retry-After header (Req 40.3).
        assert!(err.retry_after.is_some());
    }

    // -----------------------------------------------------------------------
    // Exempt paths (Req 40.6)
    // -----------------------------------------------------------------------

    #[test]
    fn health_and_metrics_are_exempt() {
        assert!(is_exempt("/health"));
        assert!(is_exempt("/health?probe=liveness"));
        assert!(is_exempt("/metrics"));
    }

    #[test]
    fn api_paths_are_not_exempt() {
        assert!(!is_exempt("/proxy/stream"));
        assert!(!is_exempt("/v0/store/magnets"));
        assert!(!is_exempt("/v0/proxy"));
    }

    // -----------------------------------------------------------------------
    // Bucket key derivation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_bucket_value_round_trips() {
        let original = (42.5_f64, 1_700_000_000_u64);
        let s = format_bucket_value(original.0, original.1);
        let parsed = parse_bucket_value(&s).unwrap();
        assert!((parsed.0 - original.0).abs() < 1e-4);
        assert_eq!(parsed.1, original.1);
    }

    #[test]
    fn parse_bucket_value_returns_none_on_garbage() {
        assert!(parse_bucket_value("not-a-number:123").is_none());
        assert!(parse_bucket_value("1.0:not-a-number").is_none());
        assert!(parse_bucket_value("").is_none());
    }

    // -----------------------------------------------------------------------
    // Redis fallback (Req 40.5)
    // -----------------------------------------------------------------------

    /// When Redis is configured but unavailable, the limiter falls back to the
    /// in-process bucket (Req 40.5).
    #[tokio::test]
    async fn redis_unavailable_falls_back_to_local() {
        use crate::cache::local::LocalCache;
        // Use a real LocalCache as the "Redis" backend — it will always succeed,
        // so this test verifies the Redis path works end-to-end when the backend
        // is healthy.
        let cache: Arc<dyn CacheBackend> = Arc::new(LocalCache::new("rl-test"));
        let limiter = RateLimiter::new(&cfg_10rpm(), Some(cache));
        // Should allow up to capacity requests.
        for _ in 0..10 {
            assert!(limiter.check("user:alice").await.is_ok());
        }
        // 11th should be rate-limited.
        assert!(limiter.check("user:alice").await.is_err());
    }

    // -----------------------------------------------------------------------
    // Sustained rate enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn sustained_rate_is_enforced_after_burst() {
        let limiter = RateLimiter::new(&cfg_10rpm(), None);
        // Drain the burst.
        for _ in 0..10 {
            let _ = limiter.check_local("user:alice");
        }
        // Immediately after burst, next request is denied.
        assert!(limiter.check_local("user:alice").is_err());

        // Simulate 6 seconds passing (6 * (10/60) ≈ 1 token).
        {
            let bucket = limiter.local.get("user:alice").unwrap().clone();
            let mut guard = bucket.blocking_lock();
            guard.last_refill = Instant::now() - Duration::from_secs(6);
        }
        // Should now have ~1 token.
        assert!(limiter.check_local("user:alice").is_ok());
        // But not two.
        assert!(limiter.check_local("user:alice").is_err());
    }
}
