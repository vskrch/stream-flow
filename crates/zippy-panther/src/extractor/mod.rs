//! Video extractors (`extractor`) — Req 12.
//!
//! Resolves a streaming *page* URL on one of the 24 supported video hosts
//! (Req 12.1) into a direct, playable media URL plus the request headers
//! required to play it (Req 12.2); the HTTP edge then wraps that into a
//! `ZippyPanther` proxy URL with the headers attached (Req 12.3). All upstream
//! page I/O goes through the single egress seam
//! ([`OutboundClient`](crate::egress::OutboundClient)) so every fetch is
//! tunnelled and client-IP-stripped (Req 51.1–51.3).
//!
//! ## Layout (design: Components → Extractor (+Byparr))
//!
//! * [`base`] — the [`Extractor`] trait, the [`ExtraParams`]/[`ExtractorResult`]
//!   request/result types, the module-local [`ExtractorError`] taxonomy (mapped
//!   back onto the canonical [`AppError`](crate::errors::AppError)), and the
//!   [`ClientPool`] selector (Req 12.4, 12.5).
//! * [`http`] — [`ExtractorHttp`], the shared page-fetching layer that selects
//!   the per-host client pool (default rustls / `wreq` impersonation / Byparr)
//!   over the egress seam.
//! * [`byparr`] — the [`Byparr`] FlareSolverr-style challenge-bypass client
//!   (Req 12.5).
//! * [`factory`] — [`ExtractorFactory`], the case-insensitive registry over all
//!   24 hosts (Req 12.1, 12.6).
//! * [`hosts`] — the concrete host extractors plus the structured stub.
//!
//! ## Host coverage
//!
//! Two hosts have **full** parsing logic — `vidoza` (DOM via `scraper`) and
//! `streamtape` (regex / inline-JS, impersonation pool) — and the remaining 22
//! supported hosts are registered with a structured
//! [`StubExtractor`](hosts::stub::StubExtractor) returning a typed
//! [`NotImplemented`](base::ExtractorError::NotImplemented) error, so the
//! factory/registry contract (case-insensitive host matching, header
//! propagation, client-pool selection) is complete and tested for all 24.

pub mod base;
pub mod byparr;
pub mod factory;
pub mod hosts;
pub mod http;

pub use base::{ClientPool, ExtraParams, Extractor, ExtractorError, ExtractorResult};
pub use byparr::Byparr;
pub use factory::{ExtractorFactory, SUPPORTED_HOSTS};
pub use http::ExtractorHttp;
