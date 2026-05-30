//! Resilience primitives (`resilience`) — Req 50.
//!
//! These are small, allocation-light, pure-logic state machines wrapping the
//! canonical [`AppError`](crate::errors::AppError) taxonomy. They are the
//! backbone of Req 50 and are designed to be unit/property-testable offline
//! (design: Technology Choices — "in-house" resilience rationale; Resilience
//! patterns).
//!
//! * [`retry`] — the [`RetryPolicy`](retry::RetryPolicy): transient/permanent
//!   classification plus a bounded, full-jitter, seedable exponential backoff
//!   and a standalone retry-run loop (task 6.1; Req 50.1, 35.4).
//! * [`breaker`] — the [`CircuitBreaker`](breaker::CircuitBreaker),
//!   `BreakerKey`/`BreakerState`, and the `guarded` adapter (task 6.2;
//!   Req 50.2, 50.3, 50.4).
//! * [`deadline`] — the [`Deadline`](deadline::Deadline)/`TimeoutBudget` and
//!   `with_deadline` (task 6.3; Req 50.9, 35.4).
//! * [`bulkhead`] — the [`Bulkhead`](bulkhead::Bulkhead) and `BulkheadRegistry`
//!   per-dependency concurrency pools (task 6.4; Req 35.3, 20.3, 50.9).
//! * [`hedge`] — the `hedged` speculative-request combinator (task 6.5;
//!   Req 37.1, 37.7, 20.2, 50.9).

pub mod breaker;
pub mod bulkhead;
pub mod deadline;
pub mod hedge;
pub mod retry;

pub use breaker::{
    guarded, with_retry, with_retry_seeded, with_retry_with_rng, BreakerConfig, BreakerKey,
    BreakerPermit, BreakerState, CircuitBreaker,
};
pub use deadline::{with_deadline, with_timeout, Deadline, TimeoutBudget};
pub use hedge::{hedged, Candidate, CandidateId, HedgeConfig};
pub use retry::{RetryPolicy, Retryability};
