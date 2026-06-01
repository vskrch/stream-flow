//! Server-Sent Events (`sse`) — Req 41.
//!
//! Exposes `/v0/events` as an SSE stream that pushes real-time status updates
//! to authenticated clients (Req 41.1). The design specifies a
//! `tokio::sync::broadcast` channel fanned out per subscription:
//!
//! * [`SseRegistry`] — the process-wide registry that holds one broadcast
//!   sender per user. Callers publish events via [`SseRegistry::publish`] and
//!   the registry fans them out to every subscriber for that user.
//! * [`sse_events_endpoint`] — the actix-web handler for `GET /v0/events`.
//!   It authenticates the request (Proxy_Auth, Req 28.2), subscribes to the
//!   user's broadcast channel, and streams SSE-formatted bytes to the client.
//!   When the client disconnects the subscription is dropped and the channel
//!   is cleaned up (Req 41.5).
//!
//! ## Event types (Req 41.2, 41.3)
//!
//! | [`SseEventKind`]          | Emitted when                                      |
//! |---------------------------|---------------------------------------------------|
//! | `MagnetStatus`            | A magnet transitions between `Magnet_Status` states (Req 41.2) |
//! | `StoreError`              | A store operation fails with a typed error (Req 41.2) |
//! | `LinkGenResult`           | A link-generation attempt completes (Req 41.3)    |
//! | `ResolutionProgress`      | A stream-resolution phase changes (Req 41.3)      |
//! | `Heartbeat`               | Keepalive comment sent on a configurable interval  |
//!
//! ## Per-user filtering (Req 41.4)
//!
//! Each subscriber receives **only** events whose `user_id` matches their own.
//! The broadcast channel is keyed by `UserId`, so events for user A are never
//! delivered to a subscriber for user B.
//!
//! ## Disconnect cleanup (Req 41.5)
//!
//! The SSE stream is an `async-stream` generator that holds a
//! `broadcast::Receiver`. When the client disconnects, actix drops the
//! response body future, which drops the generator, which drops the receiver.
//! The registry's `DashMap` entry is cleaned up lazily: when the sender detects
//! zero receivers (via `receiver_count() == 0`) it removes the entry.
//!
//! ## Polling fallback (Req 41.6)
//!
//! The existing GET endpoints (`/v0/store/magnets/check`, etc.) remain
//! available as polling fallbacks; this module does not remove them.

use std::sync::Arc;
use std::time::Duration;

use actix_web::web::{self, Bytes};
use actix_web::{HttpRequest, HttpResponse};
use async_stream::stream;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::time::interval;

use crate::app::AppState;
use crate::auth::middleware::verify_proxy_auth_req;
use crate::errors::AppError;

/// Capacity of each per-user broadcast channel (number of buffered events
/// before the oldest is dropped for a slow subscriber).
const CHANNEL_CAPACITY: usize = 64;

/// Interval between SSE keepalive heartbeat comments (Req 41.1 — the
/// connection must stay alive for long-lived clients).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// The kind of a real-time SSE event (Req 41.2, 41.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SseEventKind {
    /// A magnet transitioned between `Magnet_Status` states (Req 41.2).
    MagnetStatus,
    /// A store operation failed with a typed error (Req 41.2).
    StoreError,
    /// A link-generation attempt completed (success or failure) (Req 41.3).
    LinkGenResult,
    /// A stream-resolution phase changed (Req 41.3).
    ResolutionProgress,
    /// Keepalive heartbeat (sent as an SSE comment, not a data event).
    Heartbeat,
}

impl SseEventKind {
    /// The SSE `event:` field name for this kind.
    pub fn event_name(&self) -> &'static str {
        match self {
            SseEventKind::MagnetStatus => "magnet_status",
            SseEventKind::StoreError => "store_error",
            SseEventKind::LinkGenResult => "link_gen_result",
            SseEventKind::ResolutionProgress => "resolution_progress",
            SseEventKind::Heartbeat => "heartbeat",
        }
    }
}

/// A single SSE event published to the registry (Req 41.2, 41.3).
///
/// The `user_id` field drives per-user filtering (Req 41.4): the registry
/// routes this event only to subscribers whose `UserId` matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseEvent {
    /// The user this event belongs to (Req 41.4).
    pub user_id: String,
    /// The event kind.
    pub kind: SseEventKind,
    /// The JSON-serializable payload.
    pub data: serde_json::Value,
}

impl SseEvent {
    /// Build a new event for `user_id`.
    pub fn new(user_id: impl Into<String>, kind: SseEventKind, data: serde_json::Value) -> Self {
        Self {
            user_id: user_id.into(),
            kind,
            data,
        }
    }

    /// Serialize this event into the SSE wire format:
    ///
    /// ```text
    /// event: <kind>\n
    /// data: <json>\n
    /// \n
    /// ```
    pub fn to_sse_bytes(&self) -> Bytes {
        let data_str = serde_json::to_string(&self.data).unwrap_or_else(|_| "{}".to_string());
        let frame = format!("event: {}\ndata: {}\n\n", self.kind.event_name(), data_str);
        Bytes::from(frame)
    }
}

// ---------------------------------------------------------------------------
// SseRegistry
// ---------------------------------------------------------------------------

/// The process-wide SSE registry: one `tokio::sync::broadcast` sender per
/// user, keyed by `UserId` (design: Components → SSE; Req 41.1, 41.4).
///
/// Callers publish events via [`SseRegistry::publish`]; the registry fans them
/// out to every active subscriber for that user. Subscribers are created by
/// [`SseRegistry::subscribe`] and are dropped when the client disconnects
/// (Req 41.5).
///
/// The registry is cheap to clone (backed by an `Arc`) and is registered as
/// `web::Data<SseRegistry>` on `AppState` so every handler reaches the same
/// instance.
#[derive(Clone, Default)]
pub struct SseRegistry {
    inner: Arc<SseRegistryInner>,
}

#[derive(Default)]
struct SseRegistryInner {
    /// Per-user broadcast senders. The key is the `UserId` string.
    channels: DashMap<String, broadcast::Sender<SseEvent>>,
}

impl SseRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `event` to all active subscribers for `event.user_id`
    /// (Req 41.4).
    ///
    /// If no subscribers exist for the user the event is silently dropped
    /// (the channel is not created just to hold an unread event). If the
    /// channel exists but all receivers have been dropped (client disconnected)
    /// the entry is removed lazily.
    pub fn publish(&self, event: SseEvent) {
        let user_key = event.user_id.clone();
        if let Some(entry) = self.inner.channels.get(&user_key) {
            let sender = entry.value();
            // `send` fails only when there are no receivers; clean up the
            // entry so the map does not grow unboundedly (Req 41.5).
            if sender.send(event).is_err() {
                drop(entry);
                self.inner.channels.remove(&user_key);
            }
        }
        // No entry → no subscribers → drop silently.
    }

    /// Subscribe to events for `user_id`, creating the broadcast channel if
    /// it does not yet exist.
    ///
    /// Returns a `broadcast::Receiver` that yields every [`SseEvent`]
    /// published for this user while the receiver is alive. Dropping the
    /// receiver unsubscribes the client (Req 41.5).
    pub fn subscribe(&self, user_id: &str) -> broadcast::Receiver<SseEvent> {
        // `entry().or_insert_with` is atomic under DashMap's per-shard lock.
        let sender = self
            .inner
            .channels
            .entry(user_id.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
                tx
            });
        sender.subscribe()
    }

    /// Return the number of active subscribers for `user_id`.
    ///
    /// Used in tests to assert that a subscription was created and cleaned up.
    pub fn subscriber_count(&self, user_id: &str) -> usize {
        self.inner
            .channels
            .get(user_id)
            .map(|entry| entry.receiver_count())
            .unwrap_or(0)
    }

    /// Return the number of distinct users that currently have at least one
    /// active subscriber.
    pub fn active_user_count(&self) -> usize {
        self.inner.channels.len()
    }
}

// ---------------------------------------------------------------------------
// SSE handler
// ---------------------------------------------------------------------------

/// `GET /v0/events` — stream real-time SSE events to an authenticated client
/// (Req 41.1).
///
/// Authentication: `X-StremThru-Authorization` HTTP Basic (Req 28.2). A
/// missing or invalid credential yields `403 Forbidden`.
///
/// The response is `Content-Type: text/event-stream` with `Cache-Control:
/// no-cache` and `Connection: keep-alive`. The body is an infinite stream of
/// SSE frames interleaved with periodic heartbeat comments (`:heartbeat\n\n`)
/// to keep the connection alive through proxies and load balancers.
///
/// When the client disconnects actix drops the response body future, which
/// drops the `async-stream` generator, which drops the `broadcast::Receiver`,
/// which decrements the sender's receiver count. The registry cleans up the
/// channel entry lazily on the next publish attempt (Req 41.5).
pub async fn sse_events_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
    registry: web::Data<SseRegistry>,
) -> Result<HttpResponse, AppError> {
    // Authenticate: Proxy_Auth (Req 28.2).
    let auth = crate::auth::Auth::from_config(&state.config().auth);
    let user = verify_proxy_auth_req(&auth, &req)?;

    let user_id = user.0.clone();
    let mut rx = registry.subscribe(&user_id);

    // Build the SSE byte stream.
    let event_stream = stream! {
        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        // Consume the first tick (fires immediately).
        heartbeat.tick().await;

        loop {
            tokio::select! {
                // Heartbeat keepalive comment (Req 41.1 — connection must stay alive).
                _ = heartbeat.tick() => {
                    yield Ok::<Bytes, actix_web::Error>(Bytes::from(":heartbeat\n\n"));
                }
                // Incoming event from the broadcast channel.
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            yield Ok::<Bytes, actix_web::Error>(event.to_sse_bytes());
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Subscriber fell behind; emit a synthetic lag notice and continue.
                            let lag_frame = format!(
                                "event: lag\ndata: {{\"skipped\":{}}}\n\n",
                                n
                            );
                            yield Ok::<Bytes, actix_web::Error>(Bytes::from(lag_frame));
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Channel closed (no more senders); end the stream.
                            break;
                        }
                    }
                }
            }
        }
    };

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(event_stream))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use serde_json::json;

    // -----------------------------------------------------------------------
    // SseRegistry unit tests
    // -----------------------------------------------------------------------

    /// Publishing to a user with no subscribers is a no-op (does not panic,
    /// does not create a channel entry).
    #[tokio::test]
    async fn publish_with_no_subscribers_is_silent() {
        let registry = SseRegistry::new();
        let event = SseEvent::new(
            "alice",
            SseEventKind::MagnetStatus,
            json!({"status": "cached"}),
        );
        registry.publish(event); // must not panic
        assert_eq!(registry.active_user_count(), 0);
    }

    /// A subscriber receives events published for their user (Req 41.4).
    #[tokio::test]
    async fn subscriber_receives_own_events() {
        let registry = SseRegistry::new();
        let mut rx = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::MagnetStatus,
            json!({"status": "cached"}),
        );
        registry.publish(event.clone());

        let received = rx.recv().await.unwrap();
        assert_eq!(received.user_id, "alice");
        assert_eq!(received.kind, SseEventKind::MagnetStatus);
    }

    /// A subscriber does NOT receive events published for a different user
    /// (Req 41.4 — per-user filtering).
    #[tokio::test]
    async fn subscriber_does_not_receive_other_users_events() {
        let registry = SseRegistry::new();
        let mut rx_alice = registry.subscribe("alice");
        let _rx_bob = registry.subscribe("bob");

        // Publish only to bob.
        let bob_event = SseEvent::new("bob", SseEventKind::StoreError, json!({"error": "timeout"}));
        registry.publish(bob_event);

        // Alice's channel should have nothing.
        assert!(rx_alice.try_recv().is_err());
    }

    /// Multiple subscribers for the same user all receive the event (fan-out).
    #[tokio::test]
    async fn multiple_subscribers_for_same_user_all_receive_event() {
        let registry = SseRegistry::new();
        let mut rx1 = registry.subscribe("alice");
        let mut rx2 = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::LinkGenResult,
            json!({"url": "https://example.com/file.mkv"}),
        );
        registry.publish(event);

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    /// Dropping all receivers cleans up the channel on the next publish
    /// (Req 41.5 — disconnect cleans up subscription).
    #[tokio::test]
    async fn dropping_receiver_cleans_up_on_next_publish() {
        let registry = SseRegistry::new();
        {
            let _rx = registry.subscribe("alice");
            assert_eq!(registry.subscriber_count("alice"), 1);
        }
        // Receiver dropped; channel entry still exists until next publish attempt.
        // Publish triggers cleanup.
        let event = SseEvent::new("alice", SseEventKind::Heartbeat, json!({}));
        registry.publish(event);
        assert_eq!(registry.subscriber_count("alice"), 0);
    }

    /// `subscriber_count` reflects the live receiver count.
    #[tokio::test]
    async fn subscriber_count_reflects_live_receivers() {
        let registry = SseRegistry::new();
        assert_eq!(registry.subscriber_count("alice"), 0);

        let rx1 = registry.subscribe("alice");
        assert_eq!(registry.subscriber_count("alice"), 1);

        let rx2 = registry.subscribe("alice");
        assert_eq!(registry.subscriber_count("alice"), 2);

        drop(rx1);
        assert_eq!(registry.subscriber_count("alice"), 1);

        drop(rx2);
        assert_eq!(registry.subscriber_count("alice"), 0);
    }

    // -----------------------------------------------------------------------
    // SseEvent serialization tests
    // -----------------------------------------------------------------------

    /// `to_sse_bytes` produces a valid SSE frame with `event:` and `data:` lines
    /// followed by a blank line.
    #[tokio::test]
    async fn sse_event_serializes_to_correct_wire_format() {
        let event = SseEvent::new(
            "alice",
            SseEventKind::MagnetStatus,
            json!({"status": "cached", "hash": "abc123"}),
        );
        let bytes = event.to_sse_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();

        assert!(
            text.starts_with("event: magnet_status\n"),
            "must start with event: line"
        );
        assert!(text.contains("data: "), "must contain data: line");
        assert!(text.ends_with("\n\n"), "must end with blank line");
    }

    /// All event kinds produce the correct `event:` field name.
    #[tokio::test]
    async fn all_event_kinds_have_correct_event_names() {
        assert_eq!(SseEventKind::MagnetStatus.event_name(), "magnet_status");
        assert_eq!(SseEventKind::StoreError.event_name(), "store_error");
        assert_eq!(SseEventKind::LinkGenResult.event_name(), "link_gen_result");
        assert_eq!(
            SseEventKind::ResolutionProgress.event_name(),
            "resolution_progress"
        );
        assert_eq!(SseEventKind::Heartbeat.event_name(), "heartbeat");
    }

    // -----------------------------------------------------------------------
    // HTTP endpoint tests
    // -----------------------------------------------------------------------

    /// `GET /v0/events` without auth returns `403 Forbidden` (Req 28.2).
    #[actix_web::test]
    async fn sse_endpoint_requires_auth() {
        use crate::config::Config;

        let state = AppState::new(Config::default());
        let registry = SseRegistry::new();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(registry))
                .route("/v0/events", web::get().to(sse_events_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/v0/events").to_request();
        let resp = test::call_service(&app, req).await;
        // No auth header → 403 Forbidden (Proxy_Auth challenge, Req 28.3).
        assert_eq!(resp.status(), 403);
    }

    /// `GET /v0/events` with valid Proxy_Auth returns `200 OK` with
    /// `Content-Type: text/event-stream` (Req 41.1).
    #[actix_web::test]
    async fn sse_endpoint_with_valid_auth_returns_text_event_stream() {
        use crate::config::{AuthConfig, Config};

        let config = Config {
            auth: AuthConfig {
                api_password: None,
                metrics_password: None,
                proxy_auth: vec!["alice:wonderland".to_string()],
                per_user_store: vec![],
                admins: vec![],
            },
            ..Config::default()
        };

        let state = AppState::new(config);
        let registry = SseRegistry::new();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(registry))
                .route("/v0/events", web::get().to(sse_events_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v0/events")
            .insert_header(("X-StremThru-Authorization", "alice:wonderland"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 200);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/event-stream"),
            "Content-Type must be text/event-stream, got: {content_type}"
        );
    }

    /// `GET /v0/events` with wrong credentials returns `403 Forbidden`.
    #[actix_web::test]
    async fn sse_endpoint_with_wrong_auth_returns_403() {
        use crate::config::{AuthConfig, Config};

        let config = Config {
            auth: AuthConfig {
                api_password: None,
                metrics_password: None,
                proxy_auth: vec!["alice:wonderland".to_string()],
                per_user_store: vec![],
                admins: vec![],
            },
            ..Config::default()
        };

        let state = AppState::new(config);
        let registry = SseRegistry::new();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(registry))
                .route("/v0/events", web::get().to(sse_events_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/v0/events")
            .insert_header(("X-StremThru-Authorization", "alice:wrong"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
    }

    // -----------------------------------------------------------------------
    // Event type coverage tests (Req 41.2, 41.3)
    // -----------------------------------------------------------------------

    /// Magnet status update events can be published and received (Req 41.2).
    #[tokio::test]
    async fn magnet_status_event_published_and_received() {
        let registry = SseRegistry::new();
        let mut rx = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::MagnetStatus,
            json!({
                "hash": "abc123def456",
                "status": "downloading",
                "progress": 42
            }),
        );
        registry.publish(event);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind, SseEventKind::MagnetStatus);
        assert_eq!(received.data["status"], "downloading");
    }

    /// Store error events can be published and received (Req 41.2).
    #[tokio::test]
    async fn store_error_event_published_and_received() {
        let registry = SseRegistry::new();
        let mut rx = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::StoreError,
            json!({
                "store": "realdebrid",
                "error": "upstream-unavailable",
                "message": "RealDebrid unreachable"
            }),
        );
        registry.publish(event);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind, SseEventKind::StoreError);
        assert_eq!(received.data["store"], "realdebrid");
    }

    /// Link generation result events can be published and received (Req 41.3).
    #[tokio::test]
    async fn link_gen_result_event_published_and_received() {
        let registry = SseRegistry::new();
        let mut rx = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::LinkGenResult,
            json!({
                "store": "torbox",
                "success": true,
                "url": "https://cdn.torbox.app/file.mkv"
            }),
        );
        registry.publish(event);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind, SseEventKind::LinkGenResult);
        assert_eq!(received.data["success"], true);
    }

    /// Resolution progress events can be published and received (Req 41.3).
    #[tokio::test]
    async fn resolution_progress_event_published_and_received() {
        let registry = SseRegistry::new();
        let mut rx = registry.subscribe("alice");

        let event = SseEvent::new(
            "alice",
            SseEventKind::ResolutionProgress,
            json!({
                "phase": "link_generation",
                "store": "realdebrid"
            }),
        );
        registry.publish(event);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind, SseEventKind::ResolutionProgress);
        assert_eq!(received.data["phase"], "link_generation");
    }

    // -----------------------------------------------------------------------
    // Per-user filtering property test (Property 41, Req 41.4)
    // -----------------------------------------------------------------------

    /// **Property 41: SSE per-user event filtering**
    ///
    /// *For any* emitted event and any set of subscribers, a subscriber
    /// receives the event if and only if the event belongs to their user.
    ///
    /// **Validates: Requirements 41.4**
    #[tokio::test]
    async fn property_41_per_user_filtering() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config as PtConfig, TestRunner};

        let mut runner = TestRunner::new(PtConfig {
            cases: 100,
            ..Default::default()
        });

        runner
            .run(
                &(
                    // user_a: non-empty alphanumeric string
                    "[a-z]{3,8}",
                    // user_b: different non-empty alphanumeric string
                    "[a-z]{3,8}",
                    // event kind index 0..5
                    0usize..5,
                ),
                |(user_a, user_b, kind_idx)| {
                    // Skip when the two users happen to be the same string.
                    prop_assume!(user_a != user_b);

                    let registry = SseRegistry::new();

                    let kinds = [
                        SseEventKind::MagnetStatus,
                        SseEventKind::StoreError,
                        SseEventKind::LinkGenResult,
                        SseEventKind::ResolutionProgress,
                        SseEventKind::Heartbeat,
                    ];
                    let kind = kinds[kind_idx % kinds.len()].clone();

                    let mut rx_a = registry.subscribe(&user_a);
                    let mut rx_b = registry.subscribe(&user_b);

                    // Publish an event for user_a only.
                    let event = SseEvent::new(user_a.clone(), kind, json!({"test": true}));
                    registry.publish(event);

                    // user_a must receive it (try_recv is sync — no runtime needed).
                    prop_assert!(
                        rx_a.try_recv().is_ok(),
                        "user_a must receive their own event"
                    );
                    // user_b must NOT receive it.
                    prop_assert!(
                        rx_b.try_recv().is_err(),
                        "user_b must not receive user_a's event"
                    );

                    Ok(())
                },
            )
            .unwrap();
    }
}
