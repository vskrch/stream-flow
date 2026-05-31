//! Acestream P2P proxy (`acestream`) — Req 10.
//!
//! Acestream content is delivered peer-to-peer through a **local Acestream
//! engine** that exposes an HTTP API. This module sits between media clients
//! and that engine: it initiates an engine session for a requested content id,
//! discovers the engine's playback URL, and proxies the resulting stream to the
//! client through the generic streaming core (so HLS output is delivered as
//! HLS and MPEG-TS output as MPEG-TS — Req 10.1–10.3). All upstream HTTP — both
//! the engine API calls and the playback stream — goes through the single
//! [`egress::OutboundClient`](crate::egress::OutboundClient) seam, so the engine
//! and its peers observe only the Egress_IP and never a user's Client_IP
//! (Req 51.1–51.3).
//!
//! ## Session multiplexing (Req 10.4, 10.6)
//!
//! A single Acestream content id maps to **one** upstream engine session that
//! is *shared* by every client watching that content concurrently. The
//! [`AcestreamProxy`] keeps a reference-counted [`DashMap`] of live sessions
//! keyed by `(content_id, output_format)`:
//!
//! * The **first** client of a content id starts the engine session exactly
//!   once (a [`tokio::sync::OnceCell`] guarantees concurrent first-clients all
//!   await the *same* start — Req 10.4); subsequent clients reuse the already
//!   resolved playback URL without a second `getstream` call.
//! * Every client holds a [`SessionLease`]; releasing the lease decrements the
//!   shared client count. When the **last** client of a session releases (the
//!   count hits zero), the proxy stops the upstream engine session and drops
//!   the entry, releasing its resources (Req 10.6).
//!
//! The session lifecycle (`start session → resolve playback URL → refcount
//! clients → stop on last release`) lives behind the [`AcestreamEngine`] seam,
//! so multiplexing and teardown are unit-testable with an in-process fake
//! engine, and the real [`HttpAcestreamEngine`] is tested against a `wiremock`
//! mock of the engine HTTP API — neither needs a live Acestream engine.
//!
//! ## Engine access token (Req 10.5) + unreachable engine (Req 10.7)
//!
//! When an engine access token is configured it is included as the
//! `access_token` query parameter on every engine API call (Req 10.5). If the
//! engine cannot be reached (connection refused / timeout) or answers with an
//! error, the session start surfaces a typed
//! [`UpstreamUnavailable`](crate::errors::ErrorCategory::UpstreamUnavailable)
//! error indicating the engine is unavailable (Req 10.7).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use actix_web::http::header;
use actix_web::{web, HttpRequest, HttpResponse};
use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::Method;
use serde::Deserialize;
use tokio::sync::OnceCell;
use url::Url;

use crate::config::{AcestreamConfig, PrebufferConfig};
use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::source::{DirectSource, UpstreamSource};
use crate::proxy::{build_response, RangeSpec};

/// The output container the client wants the Acestream content delivered in
/// (Req 10.2, 10.3).
///
/// The choice selects which engine endpoint is called — the engine returns an
/// HLS manifest for [`Hls`](OutputFormat::Hls) and a raw MPEG-TS stream for
/// [`MpegTs`](OutputFormat::MpegTs) — and is part of the session multiplexing
/// key so HLS and MPEG-TS viewers of the same content do not share one
/// session's playback URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    /// Deliver as an HLS presentation (`/ace/manifest.m3u8`, Req 10.2).
    Hls,
    /// Deliver as an MPEG-TS stream (`/ace/getstream`, Req 10.3).
    MpegTs,
}

impl OutputFormat {
    /// The engine API path that produces this output format.
    ///
    /// `/ace/manifest.m3u8` yields an HLS manifest (Req 10.2); `/ace/getstream`
    /// yields the raw MPEG-TS stream (Req 10.3). Both are invoked with
    /// `format=json` so the engine returns the playback / command URLs envelope.
    fn engine_path(self) -> &'static str {
        match self {
            OutputFormat::Hls => "ace/manifest.m3u8",
            OutputFormat::MpegTs => "ace/getstream",
        }
    }
}

/// The session details the Acestream engine hands back from a `getstream`
/// call (design: Components → Acestream).
///
/// `playback_url` is the URL the proxy streams the content from; `command_url`
/// is the engine control URL used to stop the upstream session on teardown
/// (Req 10.6). The remaining fields are retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSession {
    /// The engine URL the content is played back from (Req 10.1).
    pub playback_url: String,
    /// The engine control URL used to stop the session (Req 10.6), when the
    /// engine supplied one.
    pub command_url: Option<String>,
    /// The engine statistics URL, when supplied (diagnostics only).
    pub stat_url: Option<String>,
    /// The engine's playback session id, when supplied (diagnostics only).
    pub session_id: Option<String>,
}

/// The seam between the [`AcestreamProxy`] and the Acestream engine HTTP API
/// (design: Components → Acestream).
///
/// Modelling the engine behind a trait keeps the session-multiplexing and
/// teardown logic in [`AcestreamProxy`] unit-testable with an in-process fake,
/// while the real [`HttpAcestreamEngine`] talks to the engine over HTTP through
/// the single egress seam (Req 51.1).
#[async_trait]
pub trait AcestreamEngine: Send + Sync {
    /// Start (or resolve) an engine session for `content_id` in `format`,
    /// returning its playback / command URLs (Req 10.1).
    ///
    /// Surfaces a typed
    /// [`UpstreamUnavailable`](crate::errors::ErrorCategory::UpstreamUnavailable)
    /// error when the engine is unreachable or answers with an error
    /// (Req 10.7).
    async fn start_session(
        &self,
        content_id: &str,
        format: OutputFormat,
    ) -> Result<EngineSession, AppError>;

    /// Stop an upstream engine session, releasing its peers/resources
    /// (Req 10.6). Best-effort: a failure to reach the control URL is reported
    /// but never blocks teardown of the local bookkeeping.
    async fn stop_session(&self, session: &EngineSession) -> Result<(), AppError>;
}

/// The real Acestream engine client: calls the engine HTTP API through the
/// single [`OutboundClient`] seam (Req 51.1) and includes the configured
/// access token on every call (Req 10.5).
pub struct HttpAcestreamEngine {
    /// The single outbound seam — the only path to the network (Req 51.1).
    egress: Arc<OutboundClient>,
    /// The engine base URL (`http://host:port`, no trailing slash).
    base_url: String,
    /// The engine access token, included as `access_token` when configured
    /// (Req 10.5).
    access_token: Option<String>,
}

impl HttpAcestreamEngine {
    /// Build an engine client for the `host:port` base with an optional access
    /// token.
    pub fn new(
        egress: Arc<OutboundClient>,
        base_url: impl Into<String>,
        access_token: Option<String>,
    ) -> Self {
        Self {
            egress,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            access_token,
        }
    }

    /// Build an engine client from the [`AcestreamConfig`] (`http://host:port`
    /// + access token, Req 10.5).
    pub fn from_config(cfg: &AcestreamConfig, egress: Arc<OutboundClient>) -> Self {
        Self::new(
            egress,
            format!("http://{}:{}", cfg.host, cfg.port),
            cfg.access_token.clone(),
        )
    }

    /// Build the `getstream`/`manifest.m3u8` engine URL for `content_id`,
    /// appending `id`, `format=json`, and the configured `access_token`
    /// (Req 10.5).
    fn getstream_url(&self, content_id: &str, format: OutputFormat) -> Result<Url, AppError> {
        let raw = format!("{}/{}", self.base_url, format.engine_path());
        let mut url = Url::parse(&raw).map_err(|e| {
            AppError::upstream_unavailable(format!("invalid Acestream engine URL `{raw}`: {e}"))
        })?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("id", content_id);
            qp.append_pair("format", "json");
            if let Some(token) = &self.access_token {
                qp.append_pair("access_token", token);
            }
        }
        Ok(url)
    }
}

/// The engine `getstream` JSON envelope: `{ "response": {...}, "error": null }`.
#[derive(Debug, Deserialize)]
struct GetStreamEnvelope {
    response: Option<GetStreamResponse>,
    error: Option<String>,
}

/// The `response` object of a successful engine `getstream` call.
#[derive(Debug, Deserialize)]
struct GetStreamResponse {
    playback_url: String,
    #[serde(default)]
    command_url: Option<String>,
    #[serde(default)]
    stat_url: Option<String>,
    #[serde(default)]
    playback_session_id: Option<String>,
}

#[async_trait]
impl AcestreamEngine for HttpAcestreamEngine {
    async fn start_session(
        &self,
        content_id: &str,
        format: OutputFormat,
    ) -> Result<EngineSession, AppError> {
        let url = self.getstream_url(content_id, format)?;
        // The client comes ONLY from the OutboundClient seam: tunnelled, gated
        // fail-closed, and carrying no client-identifying headers (Req 51).
        let resp = self
            .egress
            .upstream(Method::GET, &url)?
            .send()
            .await
            .map_err(|e| map_send_error(&url, e))?;

        let status = resp.status();
        if !status.is_success() {
            // Engine reachable but erroring → unavailable (Req 10.7), carrying
            // the upstream status.
            return Err(AppError::upstream_unavailable(format!(
                "Acestream engine returned HTTP {}",
                status.as_u16()
            ))
            .with_upstream_status(status.as_u16()));
        }

        let envelope: GetStreamEnvelope = resp.json().await.map_err(|e| {
            AppError::upstream_unavailable(format!(
                "failed to parse Acestream engine getstream response: {e}"
            ))
        })?;

        // The engine reports content-level failures in the `error` field.
        if let Some(err) = envelope.error.filter(|e| !e.is_empty()) {
            return Err(AppError::upstream_unavailable(format!(
                "Acestream engine error: {err}"
            )));
        }
        let response = envelope.response.ok_or_else(|| {
            AppError::upstream_unavailable(
                "Acestream engine getstream response missing playback details",
            )
        })?;

        Ok(EngineSession {
            playback_url: response.playback_url,
            command_url: response.command_url,
            stat_url: response.stat_url,
            session_id: response.playback_session_id,
        })
    }

    async fn stop_session(&self, session: &EngineSession) -> Result<(), AppError> {
        // No control URL → nothing to stop upstream (the local bookkeeping is
        // released by the caller regardless).
        let Some(command_url) = session.command_url.as_deref() else {
            return Ok(());
        };
        let mut url = Url::parse(command_url).map_err(|e| {
            AppError::upstream_unavailable(format!(
                "invalid Acestream engine command URL `{command_url}`: {e}"
            ))
        })?;
        url.query_pairs_mut().append_pair("method", "stop");

        // Best-effort: the upstream session is being torn down; a failure here
        // is logged but never blocks releasing local resources (Req 10.6).
        match self.egress.upstream(Method::GET, &url) {
            Ok(builder) => {
                if let Err(e) = builder.send().await {
                    tracing::warn!(
                        target: "acestream",
                        error = %e,
                        "failed to stop upstream Acestream session (continuing teardown)",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "acestream",
                    error = %e,
                    "egress refused the Acestream stop call (continuing teardown)",
                );
            }
        }
        Ok(())
    }
}

/// The multiplexing key: a content id in a given output format (Req 10.4).
type SessionKey = (String, OutputFormat);

/// One reference-counted upstream session shared by all clients of a content
/// id (Req 10.4, 10.6).
struct SessionEntry {
    /// The number of live clients of this session. The session is stopped and
    /// dropped when this reaches zero (Req 10.6).
    clients: AtomicUsize,
    /// The engine session, initialized exactly once across concurrent
    /// first-clients (Req 10.4).
    session: OnceCell<EngineSession>,
}

impl SessionEntry {
    fn new() -> Self {
        Self {
            clients: AtomicUsize::new(0),
            session: OnceCell::new(),
        }
    }
}

/// A client's lease on a shared Acestream session.
///
/// Holding a lease keeps the session's client count incremented (so the
/// upstream session stays alive while at least one client watches). The lease
/// is **explicitly** released via [`AcestreamProxy::release`] (the streaming
/// path attaches the release to the response body so a client disconnect tears
/// the session down — Req 10.6).
pub struct SessionLease {
    /// The session this lease belongs to.
    key: SessionKey,
    /// The resolved engine playback URL, shared across all clients of the
    /// session (Req 10.4).
    playback_url: String,
    /// A handle to the shared entry, kept so the client count can be inspected.
    entry: Arc<SessionEntry>,
}

impl SessionLease {
    /// The engine playback URL for this session — identical for every client
    /// multiplexed onto the same session (Req 10.4).
    pub fn playback_url(&self) -> &str {
        &self.playback_url
    }

    /// The number of live clients currently sharing this session.
    pub fn client_count(&self) -> usize {
        self.entry.clients.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for SessionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLease")
            .field("content_id", &self.key.0)
            .field("format", &self.key.1)
            .field("playback_url", &self.playback_url)
            .field("client_count", &self.client_count())
            .finish()
    }
}

/// The Acestream P2P proxy: starts/resolves engine sessions, multiplexes a
/// single upstream session across concurrent clients, and stops the session
/// when the last client disconnects (Req 10).
///
/// Holds a long-lived [`DashMap`] of live sessions shared across all worker
/// tasks, so concurrent requests for the same content multiplex onto one
/// upstream session (Req 10.4). All upstream HTTP — engine calls and the
/// playback stream — flows through the single egress seam (Req 51.1).
pub struct AcestreamProxy {
    /// The engine seam (HTTP in production, a fake in tests).
    engine: Arc<dyn AcestreamEngine>,
    /// The single outbound seam used to proxy the playback stream (Req 51.1).
    egress: Arc<OutboundClient>,
    /// Live sessions keyed by `(content_id, output_format)` (Req 10.4).
    sessions: DashMap<SessionKey, Arc<SessionEntry>>,
}

impl AcestreamProxy {
    /// Build a proxy over an explicit engine seam (used by tests with a fake
    /// engine) and the egress client used to proxy the playback stream.
    pub fn new(engine: Arc<dyn AcestreamEngine>, egress: Arc<OutboundClient>) -> Self {
        Self {
            engine,
            egress,
            sessions: DashMap::new(),
        }
    }

    /// Build a proxy from the [`AcestreamConfig`], using the real
    /// [`HttpAcestreamEngine`] over the egress seam (Req 10.5, 51.1).
    pub fn from_config(cfg: &AcestreamConfig, egress: Arc<OutboundClient>) -> Self {
        let engine = Arc::new(HttpAcestreamEngine::from_config(cfg, egress.clone()));
        Self::new(engine, egress)
    }

    /// Acquire a lease on the session for `content_id` in `format`, starting
    /// the upstream engine session if this is its first client (Req 10.1,
    /// 10.4).
    ///
    /// Concurrent first-clients all await the *same* engine `start_session`
    /// (a single upstream session — Req 10.4); later clients reuse the resolved
    /// playback URL. If the engine cannot start the session the client count is
    /// rolled back and a typed unavailable error is returned (Req 10.7).
    pub async fn acquire(
        &self,
        content_id: &str,
        format: OutputFormat,
    ) -> Result<SessionLease, AppError> {
        let key: SessionKey = (content_id.to_string(), format);

        // Increment the client count under the DashMap shard lock so it is
        // atomic with respect to a concurrent last-client teardown (which
        // decrements + removes under the same lock). The lock is released
        // before the await below.
        let entry = {
            let slot = self
                .sessions
                .entry(key.clone())
                .or_insert_with(|| Arc::new(SessionEntry::new()));
            slot.value().clients.fetch_add(1, Ordering::SeqCst);
            slot.value().clone()
        };

        // Start the engine session exactly once across concurrent first-clients
        // (Req 10.4); other clients of the same content await this same start.
        let started = entry
            .session
            .get_or_try_init(|| self.engine.start_session(content_id, format))
            .await;

        match started {
            Ok(session) => Ok(SessionLease {
                key,
                playback_url: session.playback_url.clone(),
                entry,
            }),
            Err(err) => {
                // Roll back this client's reservation; the engine session was
                // never initialized so nothing is stopped upstream (Req 10.7).
                self.release_inner(&key).await;
                Err(err)
            }
        }
    }

    /// Release a client's [`SessionLease`]; when the last client of the session
    /// releases, stop the upstream engine session and drop its resources
    /// (Req 10.6).
    pub async fn release(&self, lease: SessionLease) {
        self.release_inner(&lease.key).await;
    }

    /// Decrement the client count for `key`; if it reaches zero, remove the
    /// entry and stop the upstream engine session (Req 10.6).
    ///
    /// The decrement + removal decision runs under the DashMap shard lock (via
    /// [`DashMap::remove_if`]), so it is atomic with respect to a concurrent
    /// [`acquire`](Self::acquire) increment — a new client arriving exactly as
    /// the last one leaves either keeps the session alive (increment wins) or
    /// starts a fresh one (removal wins), never a torn state.
    async fn release_inner(&self, key: &SessionKey) {
        let removed = self
            .sessions
            .remove_if(key, |_, entry| entry.clients.fetch_sub(1, Ordering::SeqCst) == 1);

        if let Some((_, entry)) = removed {
            // Last client gone → stop the upstream session (Req 10.6). Only an
            // initialized session has anything to stop.
            if let Some(session) = entry.session.get() {
                if let Err(e) = self.engine.stop_session(session).await {
                    tracing::warn!(
                        target: "acestream",
                        error = %e,
                        "error stopping upstream Acestream session",
                    );
                }
            }
        }
    }

    /// The number of live (multiplexed) upstream sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// The number of live clients sharing the session for `content_id` in
    /// `format` (0 when no such session exists).
    pub fn client_count(&self, content_id: &str, format: OutputFormat) -> usize {
        self.sessions
            .get(&(content_id.to_string(), format))
            .map(|e| e.value().clients.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Initiate a session for `content_id` and proxy the resulting stream to
    /// the client (Req 10.1), delivering HLS as HLS and MPEG-TS as MPEG-TS by
    /// preserving the engine's playback content type (Req 10.2, 10.3).
    ///
    /// Multiple concurrent callers for the same content multiplex one upstream
    /// session (Req 10.4); each caller's session lease is released when its
    /// response body finishes or its client disconnects, so the upstream
    /// session stops once the last client is gone (Req 10.6).
    pub async fn serve_content(
        self: &Arc<Self>,
        content_id: &str,
        format: OutputFormat,
        range: RangeSpec,
        is_head: bool,
        prebuffer: &PrebufferConfig,
    ) -> Result<HttpResponse, AppError> {
        let lease = self.acquire(content_id, format).await?;
        let key = lease.key.clone();

        let playback_url = Url::parse(lease.playback_url()).map_err(|e| {
            AppError::upstream_unavailable(format!(
                "Acestream engine returned an invalid playback URL `{}`: {e}",
                lease.playback_url()
            ))
        });
        let playback_url = match playback_url {
            Ok(url) => url,
            Err(e) => {
                // Could not use the playback URL → release the session we just
                // acquired so it does not leak (Req 10.6).
                self.release_inner(&key).await;
                return Err(e);
            }
        };

        // Proxy the playback stream through the streaming core. The source
        // obtains its client ONLY from the egress seam (Req 51.1).
        let source = DirectSource::new(self.egress.clone(), playback_url);
        let mut body = match source.open(range).await {
            Ok(body) => body,
            Err(e) => {
                self.release_inner(&key).await;
                return Err(e);
            }
        };

        // Tie the session lease to the lifetime of the response body: when the
        // body finishes streaming or the client disconnects (the stream is
        // dropped), the lease is released and — if it was the last client — the
        // upstream session is stopped (Req 10.6).
        let guard = LeaseGuard {
            proxy: self.clone(),
            key,
            active: true,
        };
        body.stream = guarded_stream(body.stream, guard);

        build_response(body, is_head, prebuffer)
    }
}

/// A drop guard that releases an Acestream [`SessionLease`] when the response
/// body it is attached to is dropped — i.e. the stream completed or the client
/// disconnected (Req 10.6).
///
/// Teardown is async (it stops the upstream engine session), so the guard
/// spawns the release onto the current runtime when one is available; when no
/// runtime is present (e.g. a bare drop in a non-async context) it falls back
/// to a synchronous client-count decrement so the local bookkeeping never
/// leaks.
struct LeaseGuard {
    proxy: Arc<AcestreamProxy>,
    key: SessionKey,
    active: bool,
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let proxy = self.proxy.clone();
        let key = self.key.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    proxy.release_inner(&key).await;
                });
            }
            Err(_) => {
                // No runtime to drive the async stop: at least keep the
                // client-count accurate so a later sweep/acquire is correct.
                proxy
                    .sessions
                    .remove_if(&key, |_, entry| entry.clients.fetch_sub(1, Ordering::SeqCst) == 1);
            }
        }
    }
}

/// Wrap an upstream byte stream so that dropping it releases the attached
/// session [`LeaseGuard`] (Req 10.6). The guard is owned by the generator's
/// state, so it is dropped exactly when the wrapping stream is dropped.
fn guarded_stream<S>(
    inner: S,
    guard: LeaseGuard,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes, AppError>> + Send>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, AppError>> + Send + 'static,
{
    use futures::StreamExt;
    Box::pin(async_stream::stream! {
        // Moved into the generator: dropped together with this stream.
        let _guard = guard;
        futures::pin_mut!(inner);
        while let Some(item) = inner.next().await {
            yield item;
        }
    })
}

/// Map a `reqwest` send error onto the canonical taxonomy: a connect/timeout/
/// reset against the Acestream engine is an `UpstreamUnavailable` indicating
/// the engine is unavailable (Req 10.7), carrying the upstream status when the
/// error surfaced one.
fn map_send_error(url: &Url, err: reqwest::Error) -> AppError {
    let host = url.host_str().unwrap_or("<unknown>");
    let app = AppError::upstream_unavailable(format!(
        "Acestream engine at {host} is unavailable: {err}"
    ));
    match err.status() {
        Some(status) => app.with_upstream_status(status.as_u16()),
        None => app,
    }
}

// ---------------------------------------------------------------------------
// actix handler
// ---------------------------------------------------------------------------

/// `GET …/proxy/acestream` — initiate (or join) an Acestream session for the
/// `id` query parameter and proxy the stream (Req 10.1–10.4).
///
/// The output format is selected by the `output` query parameter (`hls` →
/// [`OutputFormat::Hls`], anything else → [`OutputFormat::MpegTs`], the default
/// for a P2P live stream). The shared [`AcestreamProxy`] is resolved from
/// application data so concurrent requests multiplex one upstream session
/// (Req 10.4); the dual-surface router wires this handler and the shared proxy
/// instance.
pub async fn acestream_endpoint(
    req: HttpRequest,
    proxy: web::Data<Arc<AcestreamProxy>>,
) -> Result<HttpResponse, AppError> {
    let query: HashMap<String, String> =
        web::Query::<HashMap<String, String>>::from_query(req.query_string())
            .map(|q| q.into_inner())
            .unwrap_or_default();

    let content_id = query
        .get("id")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("Acestream request missing the `id` parameter"))?;

    let format = match query.get("output").map(String::as_str) {
        Some("hls") | Some("m3u8") => OutputFormat::Hls,
        _ => OutputFormat::MpegTs,
    };

    let range = RangeSpec::from_header(
        req.headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok()),
    )?;
    let is_head = req.method() == actix_web::http::Method::HEAD;

    let proxy = proxy.get_ref().clone();
    proxy
        .serve_content(content_id, format, range, is_head, &PrebufferConfig::default())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, EgressPolicy, EgressTunnelMode};
    use crate::egress::tunnel::test_support::MockReflector;
    use crate::egress::CLIENT_IDENTIFYING_HEADERS;
    use crate::errors::ErrorCategory;

    use actix_web::body::to_bytes;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A `FailOpen` egress with no tunnel: the decision is "dial untunneled",
    /// so the proxy reaches the in-process wiremock origin directly — the real
    /// open/forward path with no network dependency (mirrors the other module
    /// tests).
    fn outbound_fail_open() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailOpen,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    /// An [`OutboundClient`] with no tunnel under the fail-closed default — the
    /// seam refuses every dial with no leak.
    fn outbound_fail_closed() -> Arc<OutboundClient> {
        let cfg = EgressConfig {
            tunnel_mode: EgressTunnelMode::Disabled,
            policy: EgressPolicy::FailClosed,
            ..EgressConfig::default()
        };
        let reflector = Arc::new(MockReflector::isolated("203.0.113.7", "198.51.100.1"));
        Arc::new(OutboundClient::from_config(&cfg, reflector).expect("builds"))
    }

    // -- A controllable in-process fake engine ------------------------------

    /// A fake [`AcestreamEngine`] that counts `start_session`/`stop_session`
    /// calls so multiplexing and teardown are asserted deterministically
    /// without a live engine.
    struct FakeEngine {
        starts: AtomicUsize,
        stops: AtomicUsize,
        /// Base playback URL; the content id is appended so distinct content
        /// yields distinct URLs.
        playback_base: String,
        /// When `true`, `start_session` fails (engine unavailable, Req 10.7).
        fail: bool,
    }

    impl FakeEngine {
        fn new() -> Self {
            Self {
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                playback_base: "http://engine.local/playback".to_string(),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::new()
            }
        }

        fn starts(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }

        fn stops(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AcestreamEngine for FakeEngine {
        async fn start_session(
            &self,
            content_id: &str,
            _format: OutputFormat,
        ) -> Result<EngineSession, AppError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(AppError::upstream_unavailable("Acestream engine is unavailable"));
            }
            Ok(EngineSession {
                playback_url: format!("{}?id={content_id}", self.playback_base),
                command_url: Some("http://engine.local/cmd/token".to_string()),
                stat_url: None,
                session_id: Some("session-1".to_string()),
            })
        }

        async fn stop_session(&self, _session: &EngineSession) -> Result<(), AppError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn proxy_with(engine: Arc<FakeEngine>) -> Arc<AcestreamProxy> {
        Arc::new(AcestreamProxy::new(engine, outbound_fail_open()))
    }

    // -- Req 10.1: a content request initiates a session --------------------

    #[tokio::test]
    async fn acquire_initiates_a_single_engine_session() {
        let engine = Arc::new(FakeEngine::new());
        let proxy = proxy_with(engine.clone());

        let lease = proxy
            .acquire("CONTENT", OutputFormat::MpegTs)
            .await
            .expect("acquire starts the engine session");

        assert_eq!(engine.starts(), 1, "first client starts the engine session");
        assert_eq!(lease.playback_url(), "http://engine.local/playback?id=CONTENT");
        assert_eq!(proxy.client_count("CONTENT", OutputFormat::MpegTs), 1);
        assert_eq!(proxy.active_sessions(), 1);
    }

    // -- Req 10.4: concurrent clients multiplex ONE upstream session --------

    #[tokio::test]
    async fn concurrent_clients_multiplex_a_single_upstream_session() {
        let engine = Arc::new(FakeEngine::new());
        let proxy = proxy_with(engine.clone());

        // Two clients of the same content, acquired concurrently.
        let (l1, l2) = tokio::join!(
            proxy.acquire("LIVE", OutputFormat::MpegTs),
            proxy.acquire("LIVE", OutputFormat::MpegTs),
        );
        let l1 = l1.expect("client 1 acquires");
        let l2 = l2.expect("client 2 acquires");

        // A single upstream session was started and both share its playback URL
        // (Req 10.4).
        assert_eq!(engine.starts(), 1, "concurrent first-clients start ONE session");
        assert_eq!(l1.playback_url(), l2.playback_url());
        assert_eq!(proxy.client_count("LIVE", OutputFormat::MpegTs), 2);
        assert_eq!(proxy.active_sessions(), 1, "one multiplexed session");

        // A third, sequential client still reuses the same session.
        let l3 = proxy
            .acquire("LIVE", OutputFormat::MpegTs)
            .await
            .expect("client 3 acquires");
        assert_eq!(engine.starts(), 1, "a later client reuses the session");
        assert_eq!(l3.playback_url(), l1.playback_url());
        assert_eq!(proxy.client_count("LIVE", OutputFormat::MpegTs), 3);

        // Cleanup so the spawn-free release path runs deterministically.
        proxy.release(l1).await;
        proxy.release(l2).await;
        proxy.release(l3).await;
        assert_eq!(engine.stops(), 1);
    }

    // -- Req 10.6: last client disconnect stops the upstream session --------

    #[tokio::test]
    async fn last_client_disconnect_stops_session_and_releases_resources() {
        let engine = Arc::new(FakeEngine::new());
        let proxy = proxy_with(engine.clone());

        let l1 = proxy.acquire("CID", OutputFormat::MpegTs).await.unwrap();
        let l2 = proxy.acquire("CID", OutputFormat::MpegTs).await.unwrap();
        assert_eq!(proxy.client_count("CID", OutputFormat::MpegTs), 2);

        // First client leaves: session stays alive (still one watcher).
        proxy.release(l1).await;
        assert_eq!(engine.stops(), 0, "session must NOT stop while a client remains");
        assert_eq!(proxy.client_count("CID", OutputFormat::MpegTs), 1);
        assert_eq!(proxy.active_sessions(), 1);

        // Last client leaves: upstream session is stopped and resources freed
        // (Req 10.6).
        proxy.release(l2).await;
        assert_eq!(engine.stops(), 1, "last client disconnect stops the session");
        assert_eq!(proxy.client_count("CID", OutputFormat::MpegTs), 0);
        assert_eq!(proxy.active_sessions(), 0, "session entry removed");
    }

    // -- Distinct content / format → distinct sessions ----------------------

    #[tokio::test]
    async fn distinct_content_and_format_get_distinct_sessions() {
        let engine = Arc::new(FakeEngine::new());
        let proxy = proxy_with(engine.clone());

        let a = proxy.acquire("A", OutputFormat::MpegTs).await.unwrap();
        let b = proxy.acquire("B", OutputFormat::MpegTs).await.unwrap();
        // Same content id but a different output format is a different session.
        let a_hls = proxy.acquire("A", OutputFormat::Hls).await.unwrap();

        assert_eq!(engine.starts(), 3, "each distinct (id,format) starts its own session");
        assert_eq!(proxy.active_sessions(), 3);
        assert_ne!(a.playback_url(), b.playback_url());

        proxy.release(a).await;
        proxy.release(b).await;
        proxy.release(a_hls).await;
        assert_eq!(engine.stops(), 3);
        assert_eq!(proxy.active_sessions(), 0);
    }

    // -- Req 10.7: engine unreachable → unavailable error + no leak ---------

    #[tokio::test]
    async fn engine_failure_surfaces_unavailable_and_rolls_back_refcount() {
        let engine = Arc::new(FakeEngine::failing());
        let proxy = proxy_with(engine.clone());

        let err = proxy
            .acquire("CID", OutputFormat::MpegTs)
            .await
            .expect_err("a failing engine must surface an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);

        // The reservation was rolled back: no lingering session/clients, and
        // nothing was stopped (the session never started).
        assert_eq!(proxy.active_sessions(), 0, "failed acquire must not leak a session");
        assert_eq!(proxy.client_count("CID", OutputFormat::MpegTs), 0);
        assert_eq!(engine.stops(), 0);
    }

    // -- Req 10.7 (HTTP engine): unreachable engine → unavailable -----------

    #[tokio::test]
    async fn http_engine_unreachable_is_unavailable() {
        // Bind then drop a listener to obtain a definitely-closed local port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let engine = HttpAcestreamEngine::new(
            outbound_fail_open(),
            format!("http://127.0.0.1:{port}"),
            None,
        );
        let err = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect_err("a closed engine port must surface an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(
            err.message.contains("unavailable"),
            "the error must indicate the engine is unavailable, got: {err}",
        );
    }

    #[tokio::test]
    async fn http_engine_error_status_is_unavailable_with_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(outbound_fail_open(), server.uri(), None);
        let err = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect_err("a 503 engine must surface an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.upstream_status, Some(503));
    }

    #[tokio::test]
    async fn http_engine_error_field_is_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"response":null,"error":"unknown content id"}"#.as_bytes().to_vec(), "application/json"),
            )
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(outbound_fail_open(), server.uri(), None);
        let err = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect_err("an engine error field must surface an error");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("unknown content id"));
    }

    // -- Req 10.5: configured access token is included in engine calls ------

    #[tokio::test]
    async fn http_engine_includes_access_token_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .and(query_param("id", "CID"))
            .and(query_param("access_token", "secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(r#"{{"response":{{"playback_url":"{}/play"}},"error":null}}"#, server.uri())
                    .into_bytes(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(
            outbound_fail_open(),
            server.uri(),
            Some("secret-token".to_string()),
        );
        let session = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect("the access_token query param must match the mock");
        assert_eq!(session.playback_url, format!("{}/play", server.uri()));
    }

    #[tokio::test]
    async fn http_engine_omits_access_token_when_not_configured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .and(query_param_is_missing("access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                br#"{"response":{"playback_url":"http://engine/play"},"error":null}"#.to_vec(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(outbound_fail_open(), server.uri(), None);
        let session = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect("with no token configured, no access_token param is sent");
        assert_eq!(session.playback_url, "http://engine/play");
    }

    // -- Req 10.5: HLS uses the manifest endpoint ---------------------------

    #[tokio::test]
    async fn http_engine_hls_uses_manifest_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ace/manifest.m3u8"))
            .and(query_param("id", "CID"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                br#"{"response":{"playback_url":"http://engine/hls.m3u8"},"error":null}"#.to_vec(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(outbound_fail_open(), server.uri(), None);
        let session = engine
            .start_session("CID", OutputFormat::Hls)
            .await
            .expect("HLS uses the manifest endpoint");
        assert_eq!(session.playback_url, "http://engine/hls.m3u8");
    }

    // -- Req 10.1 + 10.3: MPEG-TS content proxied as MPEG-TS ----------------

    #[tokio::test]
    async fn serve_content_delivers_mpegts_as_mpegts() {
        let server = MockServer::start().await;
        let ts_bytes = b"MPEG-TS-PACKET-BYTES".to_vec();
        // Engine getstream → JSON pointing at the playback endpoint.
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(r#"{{"response":{{"playback_url":"{}/playback/ts","command_url":"{}/ace/cmd"}},"error":null}}"#, server.uri(), server.uri())
                    .into_bytes(),
                "application/json",
            ))
            .mount(&server)
            .await;
        // Engine playback stream → MPEG-TS bytes.
        Mock::given(method("GET"))
            .and(path("/playback/ts"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "video/mp2t")
                    .set_body_bytes(ts_bytes.clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ace/cmd"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let proxy = Arc::new(AcestreamProxy::from_config_engine(server.uri()));
        let resp = proxy
            .serve_content("CID", OutputFormat::MpegTs, RangeSpec::Full, false, &PrebufferConfig::default())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap(),
            "video/mp2t",
            "MPEG-TS output delivered as MPEG-TS (Req 10.3)",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], &ts_bytes[..]);
    }

    // -- Req 10.1 + 10.2: HLS content proxied as HLS ------------------------

    #[tokio::test]
    async fn serve_content_delivers_hls_as_hls() {
        let server = MockServer::start().await;
        let manifest = "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:6.0,\nseg0.ts\n";
        Mock::given(method("GET"))
            .and(path("/ace/manifest.m3u8"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(r#"{{"response":{{"playback_url":"{}/playback/hls.m3u8","command_url":"{}/ace/cmd"}},"error":null}}"#, server.uri(), server.uri())
                    .into_bytes(),
                "application/json",
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/playback/hls.m3u8"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(manifest.as_bytes().to_vec(), "application/vnd.apple.mpegurl"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ace/cmd"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let proxy = Arc::new(AcestreamProxy::from_config_engine(server.uri()));
        let resp = proxy
            .serve_content("CID", OutputFormat::Hls, RangeSpec::Full, false, &PrebufferConfig::default())
            .await
            .expect("serve ok");

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/vnd.apple.mpegurl",
            "HLS output delivered as HLS (Req 10.2)",
        );
        let bytes = to_bytes(resp.into_body()).await.expect("body");
        assert_eq!(&bytes[..], manifest.as_bytes());
    }

    // -- Req 51.1: the engine call is gated by the egress seam --------------

    #[tokio::test]
    async fn engine_call_is_gated_by_fail_closed_egress() {
        let engine = HttpAcestreamEngine::new(outbound_fail_closed(), "http://engine.local:6878", None);
        let err = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect_err("fail-closed egress must refuse the engine dial");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert!(err.message.contains("egress tunnel"));
    }

    // -- Req 51.2/51.3: engine calls carry no client-identifying headers ----

    #[tokio::test]
    async fn engine_call_carries_no_client_identifying_headers() {
        let server = MockServer::start().await;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        Mock::given(method("GET"))
            .and(path("/ace/getstream"))
            .respond_with(move |req: &wiremock::Request| {
                let mut names = seen_clone.lock().unwrap();
                for h in req.headers.iter() {
                    names.push(h.0.as_str().to_ascii_lowercase());
                }
                ResponseTemplate::new(200).set_body_raw(
                    br#"{"response":{"playback_url":"http://engine/play"},"error":null}"#.to_vec(),
                    "application/json",
                )
            })
            .mount(&server)
            .await;

        let engine = HttpAcestreamEngine::new(outbound_fail_open(), server.uri(), None);
        let _ = engine
            .start_session("CID", OutputFormat::MpegTs)
            .await
            .expect("engine call succeeds");

        let names = seen.lock().unwrap();
        for forbidden in CLIENT_IDENTIFYING_HEADERS {
            assert!(
                !names.iter().any(|n| n == forbidden),
                "engine request must not carry client-identifying header {forbidden}; saw {names:?}",
            );
        }
    }

    // -- from_config builds an HTTP engine ----------------------------------

    #[test]
    fn from_config_builds_proxy_over_http_engine() {
        let cfg = AcestreamConfig {
            host: "127.0.0.1".to_string(),
            port: 6878,
            buffer_size: 4 * 1024 * 1024,
            access_token: Some("tok".to_string()),
        };
        let proxy = AcestreamProxy::from_config(&cfg, outbound_fail_open());
        assert_eq!(proxy.active_sessions(), 0);
    }

    /// Test helper: an [`AcestreamProxy`] whose HTTP engine points at the given
    /// `base` (a wiremock server), sharing one egress for engine + playback.
    impl AcestreamProxy {
        fn from_config_engine(base: String) -> Self {
            let egress = outbound_fail_open();
            let engine = Arc::new(HttpAcestreamEngine::new(egress.clone(), base, None));
            AcestreamProxy::new(engine, egress)
        }
    }
}
