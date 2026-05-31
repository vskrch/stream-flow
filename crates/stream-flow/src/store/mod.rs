//! Unified debrid `Store` abstraction (`store`) — Req 16, 17, 18, 20.
//!
//! The canonical Rust port of stremthru's `Store` interface (design:
//! Components -> Store; Data Models -> Store Abstraction). One [`Store`] trait
//! is implemented for each of the nine [`Debrid_Service`s](StoreName) so a
//! caller manages magnets and links over a single uniform API, never reaching
//! for service-specific code (Req 16.1).
//!
//! ## What lives here (task 22.1 — the foundation)
//!
//! * [`StoreName`] — the nine debrid services, and [`StoreCode`] — their
//!   two-letter codes, with a **bijection** between them: `name ↔ code` round
//!   trips are the identity (Req 16.3, 16.6; Property 19). [`StoreName`] also
//!   parses from / renders to its canonical lowercase service slug
//!   (`"realdebrid"`, `"alldebrid"`, …), and an unknown name **or** code maps
//!   to an [`invalid-store-name`](AppError::invalid_store_name) error
//!   (Req 16.7).
//! * The object-safe, async [`Store`] trait exposing the common operations —
//!   `get_name` / `get_user` / `check_magnet` / `add_magnet` / `get_magnet` /
//!   `list_magnets` / `remove_magnet` / `generate_link` (Req 16.2) — returning
//!   the normalized value types from [`types`] and the canonical [`AppError`]
//!   taxonomy on failure (Req 16.8, 16.9, 16.10).
//!
//! The value/parameter types are defined in [`types`]. The per-store canonical
//! **error mapping** (`map_error`) lands in task 22.2 (`store::error`), and the
//! nine concrete impls in task 22.3 — each obtaining its HTTP client **only**
//! through [`egress::OutboundClient`](crate::egress::OutboundClient) (Req 51.1)
//! and normalizing per-store quirks before returning these types. The trait and
//! types here are deliberately shaped to be extended by those tasks without a
//! signature change.

// TODO: content_proxy module is WIP from another task, temporarily disabled
// pub mod content_proxy;
pub mod endpoints;
pub mod error;
pub mod fallback;
pub mod link;
pub mod types;
pub mod impls;

pub use error::map_store_error;
pub use types::{
    AddMagnetData, AddMagnetParams, CheckMagnetData, CheckMagnetItem, CheckMagnetParams, Ctx,
    GenerateLinkData, GenerateLinkParams, GetMagnetData, GetMagnetParams, GetUserParams,
    ListMagnetItem, ListMagnetsData, ListMagnetsParams, MagnetFile, MagnetStatus, RemoveMagnetData,
    RemoveMagnetParams, SubscriptionStatus, User,
};

use async_trait::async_trait;

use crate::errors::AppError;

/// One of the nine supported [`Debrid_Service`s](https://) (Req 16.1).
///
/// Each name has a stable two-letter [`StoreCode`] (Req 16.6) and a canonical
/// lowercase service slug (its [`as_str`](StoreName::as_str)) used as the
/// `store` marker on store-identifying [`AppError`]s (Req 16.8, 16.9, 16.13)
/// and as the breaker/bulkhead key.
///
/// Serializes via serde using the default (PascalCase variant) representation;
/// the wire-facing slug / code conversions are the explicit
/// [`as_str`](StoreName::as_str) / [`code`](StoreName::code) methods.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum StoreName {
    /// AllDebrid (`ad`).
    AllDebrid,
    /// Debrider (`dr`).
    Debrider,
    /// Debrid-Link (`dl`).
    DebridLink,
    /// EasyDebrid (`ed`).
    EasyDebrid,
    /// Offcloud (`oc`).
    Offcloud,
    /// PikPak (`pp`).
    PikPak,
    /// Premiumize (`pm`).
    Premiumize,
    /// RealDebrid (`rd`).
    RealDebrid,
    /// TorBox (`tb`).
    TorBox,
}

/// The two-letter code identifying a store (Req 16.6): `ad`, `dr`, `dl`, `ed`,
/// `oc`, `pp`, `pm`, `rd`, `tb`.
///
/// In bijection with [`StoreName`]: [`name`](StoreCode::name) and
/// [`StoreName::code`] are mutual inverses (Property 19).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StoreCode {
    /// AllDebrid — `ad`.
    Ad,
    /// Debrider — `dr`.
    Dr,
    /// Debrid-Link — `dl`.
    Dl,
    /// EasyDebrid — `ed`.
    Ed,
    /// Offcloud — `oc`.
    Oc,
    /// PikPak — `pp`.
    Pp,
    /// Premiumize — `pm`.
    Pm,
    /// RealDebrid — `rd`.
    Rd,
    /// TorBox — `tb`.
    Tb,
}

impl StoreName {
    /// Every store, in declaration order — the totality anchor for the
    /// bijection property (Property 19).
    pub const ALL: [StoreName; 9] = [
        StoreName::AllDebrid,
        StoreName::Debrider,
        StoreName::DebridLink,
        StoreName::EasyDebrid,
        StoreName::Offcloud,
        StoreName::PikPak,
        StoreName::Premiumize,
        StoreName::RealDebrid,
        StoreName::TorBox,
    ];

    /// This store's two-letter [`StoreCode`] (Req 16.3, 16.6).
    pub fn code(self) -> StoreCode {
        match self {
            StoreName::AllDebrid => StoreCode::Ad,
            StoreName::Debrider => StoreCode::Dr,
            StoreName::DebridLink => StoreCode::Dl,
            StoreName::EasyDebrid => StoreCode::Ed,
            StoreName::Offcloud => StoreCode::Oc,
            StoreName::PikPak => StoreCode::Pp,
            StoreName::Premiumize => StoreCode::Pm,
            StoreName::RealDebrid => StoreCode::Rd,
            StoreName::TorBox => StoreCode::Tb,
        }
    }

    /// The store for a given [`StoreCode`] (Req 16.6). Total — the inverse of
    /// [`code`](StoreName::code).
    pub fn from_code(c: StoreCode) -> StoreName {
        c.name()
    }

    /// The canonical lowercase service slug (`"alldebrid"`, `"realdebrid"`, …).
    ///
    /// This is the identifier used as the `store` field on store-identifying
    /// [`AppError`]s (Req 16.8, 16.9) and as the breaker / bulkhead key, so it
    /// is part of the wire/operational contract.
    pub fn as_str(self) -> &'static str {
        match self {
            StoreName::AllDebrid => "alldebrid",
            StoreName::Debrider => "debrider",
            StoreName::DebridLink => "debridlink",
            StoreName::EasyDebrid => "easydebrid",
            StoreName::Offcloud => "offcloud",
            StoreName::PikPak => "pikpak",
            StoreName::Premiumize => "premiumize",
            StoreName::RealDebrid => "realdebrid",
            StoreName::TorBox => "torbox",
        }
    }

    /// Parse a store by its canonical slug **or** its two-letter code
    /// (case-insensitive), the inverse of [`as_str`](StoreName::as_str) over
    /// the slug forms (Req 16.6).
    ///
    /// Accepts both the slug (`"realdebrid"`) and the code (`"rd"`), plus the
    /// common hyphenated alias `"debrid-link"` for Debrid-Link. Returns `None`
    /// for any unrecognized token; use [`require`](StoreName::require) to get
    /// the canonical [`invalid-store-name`](AppError::invalid_store_name)
    /// error instead (Req 16.7).
    pub fn parse(s: &str) -> Option<StoreName> {
        let norm = s.trim().to_ascii_lowercase();
        // Two-letter code form.
        if let Some(code) = StoreCode::parse(&norm) {
            return Some(code.name());
        }
        // Canonical slug form (+ a couple of common aliases).
        match norm.as_str() {
            "alldebrid" | "all-debrid" => Some(StoreName::AllDebrid),
            "debrider" => Some(StoreName::Debrider),
            "debridlink" | "debrid-link" => Some(StoreName::DebridLink),
            "easydebrid" | "easy-debrid" => Some(StoreName::EasyDebrid),
            "offcloud" => Some(StoreName::Offcloud),
            "pikpak" => Some(StoreName::PikPak),
            "premiumize" => Some(StoreName::Premiumize),
            "realdebrid" | "real-debrid" => Some(StoreName::RealDebrid),
            "torbox" => Some(StoreName::TorBox),
            _ => None,
        }
    }

    /// Resolve a store name **or** code, returning the canonical
    /// [`invalid-store-name`](AppError::invalid_store_name) error (`400`) for an
    /// unknown token (Req 16.7).
    pub fn require(s: &str) -> Result<StoreName, AppError> {
        StoreName::parse(s).ok_or_else(|| {
            AppError::invalid_store_name(format!("unknown store name or code: `{s}`"))
        })
    }
}

impl StoreCode {
    /// Every code, in declaration order (parallel to [`StoreName::ALL`]).
    pub const ALL: [StoreCode; 9] = [
        StoreCode::Ad,
        StoreCode::Dr,
        StoreCode::Dl,
        StoreCode::Ed,
        StoreCode::Oc,
        StoreCode::Pp,
        StoreCode::Pm,
        StoreCode::Rd,
        StoreCode::Tb,
    ];

    /// The [`StoreName`] for this code (Req 16.6). Total — the inverse of
    /// [`StoreName::code`].
    pub fn name(self) -> StoreName {
        match self {
            StoreCode::Ad => StoreName::AllDebrid,
            StoreCode::Dr => StoreName::Debrider,
            StoreCode::Dl => StoreName::DebridLink,
            StoreCode::Ed => StoreName::EasyDebrid,
            StoreCode::Oc => StoreName::Offcloud,
            StoreCode::Pp => StoreName::PikPak,
            StoreCode::Pm => StoreName::Premiumize,
            StoreCode::Rd => StoreName::RealDebrid,
            StoreCode::Tb => StoreName::TorBox,
        }
    }

    /// The two-letter lowercase string for this code (its wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            StoreCode::Ad => "ad",
            StoreCode::Dr => "dr",
            StoreCode::Dl => "dl",
            StoreCode::Ed => "ed",
            StoreCode::Oc => "oc",
            StoreCode::Pp => "pp",
            StoreCode::Pm => "pm",
            StoreCode::Rd => "rd",
            StoreCode::Tb => "tb",
        }
    }

    /// Parse a two-letter code (case-insensitive). Returns `None` for any
    /// token that is not one of the nine codes (Req 16.6); the handler maps
    /// `None` onto an [`invalid-store-name`](AppError::invalid_store_name)
    /// error (Req 16.7).
    pub fn parse(s: &str) -> Option<StoreCode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ad" => Some(StoreCode::Ad),
            "dr" => Some(StoreCode::Dr),
            "dl" => Some(StoreCode::Dl),
            "ed" => Some(StoreCode::Ed),
            "oc" => Some(StoreCode::Oc),
            "pp" => Some(StoreCode::Pp),
            "pm" => Some(StoreCode::Pm),
            "rd" => Some(StoreCode::Rd),
            "tb" => Some(StoreCode::Tb),
            _ => None,
        }
    }
}

impl std::fmt::Display for StoreName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for StoreCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The unified debrid store interface (Req 16.2).
///
/// One object-safe, async trait implemented for each of the nine
/// [`Debrid_Service`s](StoreName), so the orchestration layer drives any store
/// through `Box<dyn Store>` / `Arc<dyn Store>` without service-specific code
/// (Req 16.1). Every fallible operation returns the canonical [`AppError`]
/// taxonomy: an authentication failure surfaces as an
/// [`unauthorized`](AppError::unauthorized_for) error identifying the store
/// (Req 16.8) and an unreachable/timed-out service as an
/// [`upstream-unavailable`](AppError::upstream_unavailable_for) error
/// identifying the store (Req 16.9). Concrete impls (task 22.3) obtain their
/// HTTP client **only** through
/// [`egress::OutboundClient`](crate::egress::OutboundClient) (Req 51.1) and
/// normalize per-store quirks (Req 16.5, 16.14, 17.11, 17.12, 17.14) before
/// returning the [`types`] values.
///
/// Object-safety: `get_name` is a plain `&self` method and every async method
/// is desugared by [`async_trait`] into a boxed-future `&self` method, so
/// `dyn Store` is a valid type.
#[async_trait]
pub trait Store: Send + Sync {
    /// The store's identity (Req 16.3). Its [`StoreCode`] is
    /// [`StoreName::code`].
    fn get_name(&self) -> StoreName;

    /// Fetch the authenticated user's details (Req 16.4).
    ///
    /// On an auth failure returns an [`unauthorized`](AppError::unauthorized_for)
    /// error identifying the store (Req 16.8); on an unreachable service an
    /// [`upstream-unavailable`](AppError::upstream_unavailable_for) error
    /// (Req 16.9).
    async fn get_user(&self, p: &GetUserParams) -> Result<User, AppError>;

    /// Check the cache status of 1–500 magnets (Req 17.7), returning one
    /// [`CheckMagnetItem`] per supplied magnet with a normalized
    /// [`MagnetStatus`] and (possibly empty — Req 17.11) cached file list.
    async fn check_magnet(&self, p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError>;

    /// Add a magnet to the store (Req 17.2, 17.3) and return its id, hash,
    /// name, size, normalized status, and file list.
    async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError>;

    /// Fetch one magnet's details by id (Req 17.5).
    async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError>;

    /// List magnets honoring the clamped `limit`/`offset`, returning the page
    /// plus the genuine total (Req 17.4, 17.9, 17.14).
    async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError>;

    /// Remove a magnet by id and return the removed id (Req 17.6).
    async fn remove_magnet(&self, p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError>;

    /// Resolve a store link into a time-limited direct link (Req 18.1).
    ///
    /// For IP-locked stores the link is bound to the supplied Egress_IP, never
    /// the Client_IP (Req 18.3, 51.4); non-IP-binding stores ignore it and do
    /// not fail for its absence (Req 18.4).
    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCategory;
    use time::OffsetDateTime;

    // -- StoreName <-> StoreCode bijection (Req 16.3, 16.6; Property 19) -----

    #[test]
    fn all_arrays_have_nine_entries() {
        assert_eq!(StoreName::ALL.len(), 9);
        assert_eq!(StoreCode::ALL.len(), 9);
    }

    #[test]
    fn name_to_code_to_name_is_identity_for_all_nine() {
        for name in StoreName::ALL {
            assert_eq!(
                StoreName::from_code(name.code()),
                name,
                "name -> code -> name must be the identity for {name:?}",
            );
            assert_eq!(name.code().name(), name);
        }
    }

    #[test]
    fn code_to_name_to_code_is_identity_for_all_nine() {
        for code in StoreCode::ALL {
            assert_eq!(
                code.name().code(),
                code,
                "code -> name -> code must be the identity for {code:?}",
            );
        }
    }

    #[test]
    fn each_store_maps_to_the_documented_two_letter_code() {
        let cases = [
            (StoreName::AllDebrid, "ad"),
            (StoreName::Debrider, "dr"),
            (StoreName::DebridLink, "dl"),
            (StoreName::EasyDebrid, "ed"),
            (StoreName::Offcloud, "oc"),
            (StoreName::PikPak, "pp"),
            (StoreName::Premiumize, "pm"),
            (StoreName::RealDebrid, "rd"),
            (StoreName::TorBox, "tb"),
        ];
        for (name, code) in cases {
            assert_eq!(name.code().as_str(), code, "{name:?}");
        }
    }

    #[test]
    fn codes_are_distinct_and_names_are_distinct() {
        for (i, a) in StoreCode::ALL.iter().enumerate() {
            for b in &StoreCode::ALL[i + 1..] {
                assert_ne!(a.as_str(), b.as_str(), "duplicate code");
                assert_ne!(a.name(), b.name(), "two codes share a name");
            }
        }
        for (i, a) in StoreName::ALL.iter().enumerate() {
            for b in &StoreName::ALL[i + 1..] {
                assert_ne!(a.as_str(), b.as_str(), "duplicate slug");
                assert_ne!(a.code(), b.code(), "two names share a code");
            }
        }
    }

    // -- Parsing names + codes (Req 16.6, 16.7) -----------------------------

    #[test]
    fn store_code_parse_round_trips_and_is_case_insensitive() {
        for code in StoreCode::ALL {
            assert_eq!(StoreCode::parse(code.as_str()), Some(code));
            assert_eq!(StoreCode::parse(&code.as_str().to_uppercase()), Some(code));
        }
        assert_eq!(StoreCode::parse("zz"), None);
        assert_eq!(StoreCode::parse(""), None);
    }

    #[test]
    fn store_name_parse_accepts_slug_and_code_forms() {
        for name in StoreName::ALL {
            // slug form
            assert_eq!(StoreName::parse(name.as_str()), Some(name));
            // code form
            assert_eq!(StoreName::parse(name.code().as_str()), Some(name));
            // case-insensitive slug
            assert_eq!(StoreName::parse(&name.as_str().to_uppercase()), Some(name));
        }
        // hyphenated aliases
        assert_eq!(StoreName::parse("debrid-link"), Some(StoreName::DebridLink));
        assert_eq!(StoreName::parse("real-debrid"), Some(StoreName::RealDebrid));
    }

    #[test]
    fn store_name_parse_rejects_unknown_tokens() {
        assert_eq!(StoreName::parse("netflix"), None);
        assert_eq!(StoreName::parse(""), None);
        assert_eq!(StoreName::parse("zz"), None);
    }

    #[test]
    fn require_resolves_known_and_errors_on_unknown_with_invalid_store_name() {
        assert_eq!(StoreName::require("rd").unwrap(), StoreName::RealDebrid);
        assert_eq!(
            StoreName::require("realdebrid").unwrap(),
            StoreName::RealDebrid,
        );

        let err = StoreName::require("nope").unwrap_err();
        assert_eq!(err.category, ErrorCategory::InvalidStoreName);
        assert!(err.message.contains("nope"));
    }

    #[test]
    fn store_name_display_is_the_slug_and_code_display_is_two_letters() {
        assert_eq!(StoreName::RealDebrid.to_string(), "realdebrid");
        assert_eq!(StoreCode::Rd.to_string(), "rd");
    }

    #[test]
    fn store_name_serde_round_trips() {
        for name in StoreName::ALL {
            let json = serde_json::to_string(&name).unwrap();
            let back: StoreName = serde_json::from_str(&json).unwrap();
            assert_eq!(back, name);
        }
    }

    // -- Object safety: the trait can be used as `dyn Store` ----------------

    /// Compile-time witness that [`Store`] is object-safe (Req 16.1 — the
    /// abstraction is dispatched dynamically). A function taking
    /// `&dyn Store` only type-checks if the trait is object-safe.
    #[allow(dead_code)]
    fn assert_object_safe(s: &dyn Store) -> StoreName {
        s.get_name()
    }

    // -- Store trait compiles + dispatches dynamically (Req 16.1, 16.2) ------

    /// A trivial in-memory [`Store`] used only to prove the trait is
    /// object-safe and that every operation can be dispatched through a
    /// `Box<dyn Store>` (the trait is the abstraction the orchestration layer
    /// drives — Req 16.1). The concrete debrid impls land in task 22.3.
    struct MockStore;

    #[async_trait]
    impl Store for MockStore {
        fn get_name(&self) -> StoreName {
            StoreName::RealDebrid
        }

        async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
            Ok(User {
                id: "user123".into(),
                email: "test@example.com".into(),
                subscription_status: SubscriptionStatus::Premium,
                has_usenet: false,
            })
        }

        async fn check_magnet(
            &self,
            _p: &CheckMagnetParams<'_>,
        ) -> Result<CheckMagnetData, AppError> {
            Ok(CheckMagnetData { items: vec![] })
        }

        async fn add_magnet(&self, _p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
            Ok(AddMagnetData {
                id: "m1".into(),
                hash: "abc123".into(),
                magnet: "magnet:?xt=urn:btih:abc123".into(),
                name: "test".into(),
                size: 1024,
                status: MagnetStatus::Queued,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn get_magnet(&self, _p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
            Ok(GetMagnetData {
                id: "m1".into(),
                name: "test".into(),
                hash: "abc123".into(),
                size: 1024,
                status: MagnetStatus::Cached,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn list_magnets(&self, _p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
            Ok(ListMagnetsData {
                items: vec![],
                total_items: 0,
            })
        }

        async fn remove_magnet(
            &self,
            _p: &RemoveMagnetParams,
        ) -> Result<RemoveMagnetData, AppError> {
            Ok(RemoveMagnetData { id: "m1".into() })
        }

        async fn generate_link(
            &self,
            _p: &GenerateLinkParams,
        ) -> Result<GenerateLinkData, AppError> {
            Ok(GenerateLinkData {
                link: "https://cdn.example.com/file.mkv".into(),
            })
        }
    }

    #[tokio::test]
    async fn mock_store_trait_compiles_and_dispatches_via_dyn() {
        let store: Box<dyn Store> = Box::new(MockStore);
        assert_eq!(store.get_name(), StoreName::RealDebrid);
        assert_eq!(store.get_name().code(), StoreCode::Rd);

        let ctx = Ctx {
            request_id: "req-1".into(),
            client_ip: None,
            trusted: false,
        };

        let user = store
            .get_user(&GetUserParams { ctx: ctx.clone() })
            .await
            .unwrap();
        assert_eq!(user.subscription_status, SubscriptionStatus::Premium);
        assert_eq!(user.email, "test@example.com");

        let magnets = vec!["magnet:?xt=urn:btih:abc".into()];
        let check = store
            .check_magnet(&CheckMagnetParams {
                ctx: ctx.clone(),
                magnets: &magnets,
                client_ip: None,
                sid: None,
                local_only: false,
            })
            .await
            .unwrap();
        assert!(check.items.is_empty());

        let link = store
            .generate_link(&GenerateLinkParams {
                ctx: ctx.clone(),
                link: "https://store.example.com/dl/123".into(),
                client_ip: None,
            })
            .await
            .unwrap();
        assert!(!link.link.is_empty());
    }
}
