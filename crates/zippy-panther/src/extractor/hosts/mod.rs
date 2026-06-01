//! Concrete host extractors (`extractor::hosts`) — Req 12.
//!
//! Each supported host (Req 12.1) is either a concrete extractor with real
//! parsing logic or a structured [`stub::StubExtractor`] that returns a clear
//! [`NotImplemented`](crate::extractor::base::ExtractorError::NotImplemented)
//! error until its scraping logic lands. Two representative concrete
//! extractors are implemented:
//!
//! * [`vidoza::VidozaExtractor`] — DOM-based ([`scraper`](https://docs.rs/scraper)),
//!   default client pool;
//! * [`streamtape::StreamtapeExtractor`] — regex / inline-JS, browser-TLS
//!   impersonation pool (Req 12.4).
//!
//! The [`ExtractorFactory`](crate::extractor::ExtractorFactory) registers every
//! host so the case-insensitive host match + client-pool selection contract is
//! exercised for all 24 (Req 12.1), regardless of whether the host is
//! concrete or a stub.

pub mod streamtape;
pub mod stub;
pub mod vidoza;
