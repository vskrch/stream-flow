//! HTTP edge: middleware and the dual-surface router.
//!
//! Task 2.2 lands the [`panic_boundary`] middleware (the top-level panic →
//! `500` boundary, Req 47.3 / 50.8). Task 11.1 adds the [`client_ip`] resolver
//! (Req 28.7, 51.2). Task 11.2 lands the dual-surface [`router`] skeleton (the
//! two disjoint path namespaces + shared routes onto one handler set, Req 36.1
//! / 36.2). The degradation guard arrives in the rest of task 11 (design:
//! Components → HTTP edge).

pub mod client_ip;
pub mod panic_boundary;
pub mod router;

pub use client_ip::{client_ip, resolve_client_ip};
pub use panic_boundary::PanicBoundary;
