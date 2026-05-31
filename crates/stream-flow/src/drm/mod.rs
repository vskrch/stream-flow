//! ClearKey DRM (`drm`) — Req 4.
//!
//! On-the-fly ClearKey decryption of CENC-protected MP4 (DASH) media. The
//! module is split so each concern is pure and independently testable
//! (design: Components → DRM):
//!
//! * [`mp4_atom`] — the MP4 sample-encryption **box parser**: walks the
//!   `moov/trak/.../stsd/<enc*>/sinf/schi/tenc` and `moof/traf/senc|saiz|saio`
//!   hierarchy and decodes the four sample-encryption boxes into typed
//!   per-sample IVs, subsample ranges, and track-level encryption parameters
//!   (KID, IV size, crypt/skip pattern, constant IV) — Req 4.9.
//! * [`clearkey`] — the [`ClearKeyStore`](clearkey::ClearKeyStore): resolves a
//!   decryption key by KID against the configured key set (Req 4.6), caches
//!   resolved keys for the key-cache TTL (Req 4.7), and fails with a
//!   KID-naming error when no key matches (Req 4.8).
//!
//! * [`cenc`] — the per-scheme sample decryptor: dispatches over the four CENC
//!   schemes (`cenc`/`cens`/`cbc1`/`cbcs`), consuming the typed metadata
//!   produced by [`mp4_atom`] and the keys resolved by [`clearkey`] to decrypt
//!   one MP4 sample under AES-128 CTR/CBC (incl. the correct `cens`/`cbcs`
//!   crypt/skip pattern) — Req 4.1–4.5.

pub mod cenc;
pub mod clearkey;
pub mod mp4_atom;
