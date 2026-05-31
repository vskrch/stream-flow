//! Stremio addons + protocol types (`stremio`) — Req 23, 24, 25, 26.
//!
//! This module hosts the Stremio addon protocol surface: the serde-compatible
//! wire [`types`] (Req 26) plus, in later tasks, the Store / Wrap / Sidekick /
//! Torz addons that produce and consume them (Req 23, 24, 25).
//!
//! The protocol [`types`] are a faithful Rust port of stremthru's Go `stremio`
//! package — same JSON field names and the same `omitempty` semantics — so the
//! addons stay drop-in compatible with every Stremio client (design: Data
//! Models -> Stremio Protocol Types; Req 26.1). Serializing then deserializing
//! any produced object recovers an equivalent value (Req 26.2), including the
//! string-or-object [`Resource`](types::Resource) form and the coerced
//! [`CatalogExtraOptions`](types::CatalogExtraOptions) form. A request for a
//! resource an addon's [`Manifest`](types::Manifest) does not declare maps onto
//! a Stremio not-found ([`AppError::not_found`](crate::errors::AppError::not_found),
//! `404`; Req 26.3), and each manifest declares every supported content type
//! and id prefix (Req 26.4).

pub mod types;
