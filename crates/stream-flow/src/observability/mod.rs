//! Observability (`observability`) — Req 32, 50.14.
//!
//! This module is the system's monitoring seam (design: Components →
//! Observability). It bundles three concerns:
//!
//! * [`Metrics`] — a [`prometheus`] registry of counters and latency histograms
//!   for proxied requests, store operations, cache hit/miss, and upstream
//!   failures (Req 32.5), plus a dedicated counter for **every self-healing
//!   action** (retries, circuit-breaker transitions, store fallbacks, task
//!   restarts, Redis reattach, reclaimed resources) so operators can see the
//!   system healing itself (Req 50.14). Rendered at `/metrics` in Prometheus
//!   text exposition format (Req 32.1).
//! * [`Redactor`] — the single secret-scrubbing primitive that guarantees no
//!   API password, store token, Vault secret, or encrypted `d`/token proxy
//!   material is ever emitted verbatim into a log (Req 32.6, 46.7).
//! * The structured-logging stack ([`init_logging`] / [`RedactingMakeWriter`])
//!   — a `tracing-subscriber` `fmt` subscriber whose writer runs every rendered
//!   record through the [`Redactor`] centrally, so redaction can't be forgotten
//!   at a call site (Req 32.3, 32.6).
//!
//! The [`metrics_endpoint`] handler renders [`Metrics`] behind the metrics
//! password (Req 32.1, 32.2) and is wired into the shared surface of the
//! dual-surface router (task 11.2's `/metrics` placeholder is replaced here).
//!
//! ## Wiring self-healing counters (Req 50.14)
//!
//! The recorders ([`Metrics::record_retry`], [`Metrics::record_breaker_open`],
//! …) are the observation points the resilience primitives (retry policy,
//! circuit breaker), the cache failover loop, the task supervisor, and the
//! reaper call when they perform a healing action. They share the one registry
//! threaded through [`AppState`](crate::app::AppState), so the `/metrics`
//! exposition reflects every healing event regardless of which subsystem
//! produced it.

mod endpoint;
mod metrics;
mod redaction;
mod subscriber;

pub use endpoint::{metrics_endpoint, METRICS_PASSWORD_HEADER, METRICS_PASSWORD_QUERY};
pub use metrics::Metrics;
pub use redaction::{Redactor, REDACTED};
pub use subscriber::{init_logging, RedactingMakeWriter, RedactingWriter};
