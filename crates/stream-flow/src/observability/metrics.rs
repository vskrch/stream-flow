//! Prometheus metrics registry (`observability::metrics`) — Req 32.1, 32.5, 50.14.
//!
//! [`Metrics`] owns a private [`prometheus::Registry`] plus the full set of
//! counters and latency histograms the design calls for: proxied requests,
//! store operations, cache hit/miss, and upstream failures (Req 32.5), together
//! with a dedicated counter for **every self-healing action** — retries,
//! circuit-breaker open/close transitions, store fallbacks, supervised task
//! restarts, Redis reattach, and reclaimed resources — so an operator can watch
//! the system heal itself on a dashboard (Req 50.14).
//!
//! The registry is created once and shared via [`AppState`](crate::app::AppState)
//! (it is cheap to clone — an [`Arc`] bump — and every clone records into the
//! same underlying series, which is exactly what the actix workers and the
//! resilience primitives at every call site need). [`Metrics::gather`] renders
//! the current values in Prometheus text exposition format for the `/metrics`
//! endpoint (Req 32.1).

use std::sync::Arc;
use std::time::Duration;

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
    TextEncoder,
};

/// Metric/series name prefix so every series is grouped under one namespace in
/// the exposition (and never collides with sidecar exporters).
const NS: &str = "stream_flow";

/// The process-wide Prometheus metrics registry (Req 32.1, 32.5, 50.14).
///
/// Cheap to clone (an [`Arc`] bump); all clones share one set of series.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

/// The owned registry + metric handles behind [`Metrics`]'s [`Arc`].
struct MetricsInner {
    registry: Registry,

    // -- Req 32.5: proxied requests / store ops / cache / upstream failures --
    /// Proxied requests by outcome (`success` / `error` / `client_abort` / …).
    proxied_requests: IntCounterVec,
    /// End-to-end proxied-request latency.
    proxied_request_duration: Histogram,
    /// Store operations by `(store, outcome)`.
    store_operations: IntCounterVec,
    /// Store-operation latency by store.
    store_operation_duration: HistogramVec,
    /// Cache hits.
    cache_hits: IntCounter,
    /// Cache misses.
    cache_misses: IntCounter,
    /// Upstream failures by kind (`timeout` / `reset` / `status_5xx` / …).
    upstream_failures: IntCounterVec,

    // -- Req 50.14: self-healing actions -------------------------------------
    /// Retry attempts performed by the unified retry policy.
    retries: IntCounter,
    /// Circuit-breaker transitions by `(origin, transition)` where transition
    /// is `open` or `close`.
    breaker_transitions: IntCounterVec,
    /// Store fallbacks (routing a request to the next healthy store, Req 50.3).
    store_fallbacks: IntCounter,
    /// Supervised background-task restarts by task name (Req 50.7).
    task_restarts: IntCounterVec,
    /// Successful Redis reattachments after a failover episode (Req 50.5).
    redis_reattach: IntCounter,
    /// Leaked/idle resources reclaimed by the reaper, by kind (Req 50.12).
    resources_reclaimed: IntCounterVec,
}

impl Metrics {
    /// Build a fresh registry with every series registered.
    ///
    /// Registering the zero-valued series up front means the exposition always
    /// advertises the full schema (`# HELP`/`# TYPE` lines) even before any
    /// traffic, which keeps dashboards/alerts stable across restarts.
    pub fn new() -> Self {
        let registry = Registry::new();

        let proxied_requests = IntCounterVec::new(
            Opts::new(
                format!("{NS}_proxied_requests_total"),
                "Total proxied requests, by outcome.",
            ),
            &["outcome"],
        )
        .expect("valid metric opts");

        let proxied_request_duration = Histogram::with_opts(HistogramOpts::new(
            format!("{NS}_proxied_request_duration_seconds"),
            "Proxied-request latency in seconds.",
        ))
        .expect("valid histogram opts");

        let store_operations = IntCounterVec::new(
            Opts::new(
                format!("{NS}_store_operations_total"),
                "Total debrid-store operations, by store and outcome.",
            ),
            &["store", "outcome"],
        )
        .expect("valid metric opts");

        let store_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                format!("{NS}_store_operation_duration_seconds"),
                "Debrid-store operation latency in seconds, by store.",
            ),
            &["store"],
        )
        .expect("valid histogram opts");

        let cache_hits = IntCounter::new(format!("{NS}_cache_hits_total"), "Total cache hits.")
            .expect("valid metric opts");

        let cache_misses =
            IntCounter::new(format!("{NS}_cache_misses_total"), "Total cache misses.")
                .expect("valid metric opts");

        let upstream_failures = IntCounterVec::new(
            Opts::new(
                format!("{NS}_upstream_failures_total"),
                "Total upstream failures, by kind.",
            ),
            &["kind"],
        )
        .expect("valid metric opts");

        let retries = IntCounter::new(
            format!("{NS}_retries_total"),
            "Total retry attempts performed by the retry policy (self-healing).",
        )
        .expect("valid metric opts");

        let breaker_transitions = IntCounterVec::new(
            Opts::new(
                format!("{NS}_circuit_breaker_transitions_total"),
                "Circuit-breaker state transitions, by origin and transition (open/close).",
            ),
            &["origin", "transition"],
        )
        .expect("valid metric opts");

        let store_fallbacks = IntCounter::new(
            format!("{NS}_store_fallbacks_total"),
            "Total store fallbacks to the next healthy store (self-healing).",
        )
        .expect("valid metric opts");

        let task_restarts = IntCounterVec::new(
            Opts::new(
                format!("{NS}_task_restarts_total"),
                "Total supervised background-task restarts, by task (self-healing).",
            ),
            &["task"],
        )
        .expect("valid metric opts");

        let redis_reattach = IntCounter::new(
            format!("{NS}_redis_reattach_total"),
            "Total successful Redis reattachments after a failover (self-healing).",
        )
        .expect("valid metric opts");

        let resources_reclaimed = IntCounterVec::new(
            Opts::new(
                format!("{NS}_resources_reclaimed_total"),
                "Total leaked/idle resources reclaimed by the reaper, by kind (self-healing).",
            ),
            &["kind"],
        )
        .expect("valid metric opts");

        // Register everything; a duplicate registration is a programmer error.
        for collector in [
            Box::new(proxied_requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(proxied_request_duration.clone()),
            Box::new(store_operations.clone()),
            Box::new(store_operation_duration.clone()),
            Box::new(cache_hits.clone()),
            Box::new(cache_misses.clone()),
            Box::new(upstream_failures.clone()),
            Box::new(retries.clone()),
            Box::new(breaker_transitions.clone()),
            Box::new(store_fallbacks.clone()),
            Box::new(task_restarts.clone()),
            Box::new(redis_reattach.clone()),
            Box::new(resources_reclaimed.clone()),
        ] {
            registry
                .register(collector)
                .expect("metric registered exactly once");
        }

        Self {
            inner: Arc::new(MetricsInner {
                registry,
                proxied_requests,
                proxied_request_duration,
                store_operations,
                store_operation_duration,
                cache_hits,
                cache_misses,
                upstream_failures,
                retries,
                breaker_transitions,
                store_fallbacks,
                task_restarts,
                redis_reattach,
                resources_reclaimed,
            }),
        }
    }

    // -- Req 32.5 recorders --------------------------------------------------

    /// Record one proxied request: bump the by-outcome counter and observe its
    /// end-to-end latency.
    pub fn record_proxied_request(&self, outcome: &str, duration: Duration) {
        self.inner
            .proxied_requests
            .with_label_values(&[outcome])
            .inc();
        self.inner
            .proxied_request_duration
            .observe(duration.as_secs_f64());
    }

    /// Record one debrid-store operation: bump the by-`(store, outcome)`
    /// counter and observe its latency.
    pub fn record_store_op(&self, store: &str, outcome: &str, duration: Duration) {
        self.inner
            .store_operations
            .with_label_values(&[store, outcome])
            .inc();
        self.inner
            .store_operation_duration
            .with_label_values(&[store])
            .observe(duration.as_secs_f64());
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.inner.cache_hits.inc();
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&self) {
        self.inner.cache_misses.inc();
    }

    /// Record an upstream failure of the given kind.
    pub fn record_upstream_failure(&self, kind: &str) {
        self.inner
            .upstream_failures
            .with_label_values(&[kind])
            .inc();
    }

    // -- Req 50.14 self-healing recorders ------------------------------------

    /// Record a retry attempt (Req 50.1).
    pub fn record_retry(&self) {
        self.inner.retries.inc();
    }

    /// Record a circuit breaker opening for `origin` (Req 50.2).
    pub fn record_breaker_open(&self, origin: &str) {
        self.inner
            .breaker_transitions
            .with_label_values(&[origin, "open"])
            .inc();
    }

    /// Record a circuit breaker closing for `origin` (Req 50.2, 50.4).
    pub fn record_breaker_close(&self, origin: &str) {
        self.inner
            .breaker_transitions
            .with_label_values(&[origin, "close"])
            .inc();
    }

    /// Record a fallback to the next healthy store (Req 50.3).
    pub fn record_store_fallback(&self) {
        self.inner.store_fallbacks.inc();
    }

    /// Record a supervised background-task restart (Req 50.7).
    pub fn record_task_restart(&self, task: &str) {
        self.inner.task_restarts.with_label_values(&[task]).inc();
    }

    /// Record a successful Redis reattachment after failover (Req 50.5).
    pub fn record_redis_reattach(&self) {
        self.inner.redis_reattach.inc();
    }

    /// Record a reclaimed leaked/idle resource of the given kind (Req 50.12).
    pub fn record_resource_reclaimed(&self, kind: &str) {
        self.inner
            .resources_reclaimed
            .with_label_values(&[kind])
            .inc();
    }

    // -- Exposition ----------------------------------------------------------

    /// Render the current metrics in Prometheus text exposition format
    /// (Req 32.1).
    pub fn gather(&self) -> String {
        let metric_families = self.inner.registry.gather();
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("prometheus text encoding never fails for in-memory buffer");
        String::from_utf8(buffer).expect("prometheus text exposition is valid UTF-8")
    }

    /// The HTTP `Content-Type` for the exposition format (Req 32.1).
    pub fn content_type(&self) -> &'static str {
        // The text exposition content type is a fixed, well-known string.
        "text/plain; version=0.0.4; charset=utf-8"
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_registry_advertises_schema_even_at_zero() {
        let m = Metrics::new();
        let text = m.gather();
        // Non-vec series advertise HELP/TYPE even before any observation.
        assert!(text.contains("# HELP"));
        assert!(text.contains("# TYPE"));
        assert!(text.contains("stream_flow_cache_hits_total"));
    }

    #[test]
    fn proxied_request_counter_and_histogram_increment() {
        let m = Metrics::new();
        m.record_proxied_request("success", Duration::from_millis(5));
        m.record_proxied_request("success", Duration::from_millis(7));
        m.record_proxied_request("error", Duration::from_millis(1));

        let text = m.gather();
        assert!(text.contains("stream_flow_proxied_requests_total{outcome=\"success\"} 2"));
        assert!(text.contains("stream_flow_proxied_requests_total{outcome=\"error\"} 1"));
        assert!(text.contains("stream_flow_proxied_request_duration_seconds_count 3"));
    }

    #[test]
    fn store_op_records_per_store_and_outcome() {
        let m = Metrics::new();
        m.record_store_op("realdebrid", "success", Duration::from_millis(10));
        m.record_store_op("realdebrid", "error", Duration::from_millis(20));
        m.record_store_op("alldebrid", "success", Duration::from_millis(30));

        let text = m.gather();
        assert!(text.contains(
            "stream_flow_store_operations_total{outcome=\"success\",store=\"realdebrid\"} 1"
        ));
        assert!(text.contains(
            "stream_flow_store_operations_total{outcome=\"error\",store=\"realdebrid\"} 1"
        ));
        assert!(text.contains(
            "stream_flow_store_operations_total{outcome=\"success\",store=\"alldebrid\"} 1"
        ));
    }

    #[test]
    fn cache_and_upstream_counters() {
        let m = Metrics::new();
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_cache_miss();
        m.record_upstream_failure("timeout");

        let text = m.gather();
        assert!(text.contains("stream_flow_cache_hits_total 2"));
        assert!(text.contains("stream_flow_cache_misses_total 1"));
        assert!(text.contains("stream_flow_upstream_failures_total{kind=\"timeout\"} 1"));
    }

    #[test]
    fn self_healing_counters_are_observable() {
        let m = Metrics::new();
        m.record_retry();
        m.record_breaker_open("realdebrid");
        m.record_breaker_close("realdebrid");
        m.record_store_fallback();
        m.record_task_restart("prefetcher");
        m.record_redis_reattach();
        m.record_resource_reclaimed("sse_subscription");

        let text = m.gather();
        assert!(text.contains("stream_flow_retries_total 1"));
        assert!(text.contains(
            "stream_flow_circuit_breaker_transitions_total{origin=\"realdebrid\",transition=\"open\"} 1"
        ));
        assert!(text.contains(
            "stream_flow_circuit_breaker_transitions_total{origin=\"realdebrid\",transition=\"close\"} 1"
        ));
        assert!(text.contains("stream_flow_store_fallbacks_total 1"));
        assert!(text.contains("stream_flow_task_restarts_total{task=\"prefetcher\"} 1"));
        assert!(text.contains("stream_flow_redis_reattach_total 1"));
        assert!(text.contains("stream_flow_resources_reclaimed_total{kind=\"sse_subscription\"} 1"));
    }

    #[test]
    fn clones_share_the_same_series() {
        let m = Metrics::new();
        let clone = m.clone();
        m.record_cache_hit();
        clone.record_cache_hit();
        // Both increments land on the one shared counter.
        assert!(clone.gather().contains("stream_flow_cache_hits_total 2"));
    }
}
