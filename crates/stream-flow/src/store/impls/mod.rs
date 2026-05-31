//! Per-store `Store` trait implementations (`store/impls/`) — Req 16.1, 16.14,
//! 17.11, 17.12, 17.14, 51.1.
//!
//! Each file implements the [`Store`](super::Store) trait for one of the nine
//! debrid services. Every impl:
//!
//! * Obtains its HTTP client **only** from
//!   [`OutboundClient`](crate::egress::OutboundClient) (Req 51.1).
//! * Normalizes native status strings via
//!   [`MagnetStatus::from_native`](super::MagnetStatus::from_native) (Req 16.5, 16.14).
//! * Applies per-store quirks:
//!   - **Offcloud:** cached status with empty file list is valid (Req 17.11);
//!     file idx/size `-1` when unknown (Req 17.12).
//!   - **TorBox:** drop trailing quirk item from list results (Req 17.14).
//!   - **RealDebrid / TorBox:** forward Egress_IP on link-gen (Req 18.3).
//!   - **AllDebrid / Offcloud:** omit IP and don't fail (Req 18.4).
//! * Maps native errors via `map_error` into the canonical [`AppError`]
//!   taxonomy (Req 16.10).

pub mod alldebrid;
pub mod debrider;
pub mod debridlink;
pub mod easydebrid;
pub mod offcloud;
pub mod pikpak;
pub mod premiumize;
pub mod realdebrid;
pub mod torbox;

pub use alldebrid::AllDebridStore;
pub use debrider::DebriderStore;
pub use debridlink::DebridLinkStore;
pub use easydebrid::EasyDebridStore;
pub use offcloud::OffcloudStore;
pub use pikpak::PikPakStore;
pub use premiumize::PremiumizeStore;
pub use realdebrid::RealDebridStore;
pub use torbox::TorBoxStore;
