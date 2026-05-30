//! HTTP edge: middleware and (in later tasks) the dual-surface router.
//!
//! Task 2.2 lands the [`panic_boundary`] middleware (the top-level panic →
//! `500` boundary, Req 47.3 / 50.8). The client-IP resolver, dual-surface
//! router skeleton, and the degradation guard arrive in task 11 (design:
//! Components → HTTP edge).

pub mod panic_boundary;

pub use panic_boundary::PanicBoundary;
