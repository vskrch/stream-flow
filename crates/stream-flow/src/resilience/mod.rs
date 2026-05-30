//! Resilience primitives (`resilience`) — Req 50.
//!
//! These are small, allocation-light, pure-logic state machines wrapping the
//! canonical [`AppError`](crate::errors::AppError) taxonomy. They are the
//! backbone of Req 50 and are designed to be unit/property-testable offline
//! (design: Technology Choices — "in-house" resilience rationale; Resilience
//! patterns).
//!
//! Task 6.1 lands the [`retry`] module: the [`RetryPolicy`](retry::RetryPolicy)
//! — transient/permanent classification plus a bounded, full-jitter,
//! seedable exponential backoff and a standalone retry-run loop (design:
//! Resilience → Pattern 2 "Unified Retry Policy"; Components → `RetryPolicy`;
//! Req 50.1, 35.4).
//!
//! The `CircuitBreaker` (task 6.2), `Deadline`/`TimeoutBudget` (task 6.3),
//! `Bulkhead` (task 6.4), and `hedged` combinator (task 6.5) land in later
//! waves, alongside the full `with_retry(policy, breaker, deadline, op)`
//! composition wrapper that wires retry → breaker → deadline together.

pub mod retry;

pub use retry::{RetryPolicy, Retryability};
