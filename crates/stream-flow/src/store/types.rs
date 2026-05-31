//! Store data + parameter types (`store::types`) — Req 16, 17, 18.
//!
//! The Rust port of stremthru's `Store` value types (design: Data Models ->
//! Store Abstraction). These are the request/response shapes the [`Store`]
//! trait (in [`super`]) speaks in, normalized so a caller never branches on
//! which of the nine debrid services answered:
//!
//! * **Status enums** — [`MagnetStatus`] (the nine canonical magnet states,
//!   Req 16.5/16.14) and [`SubscriptionStatus`] (`premium`/`trial`/`expired`,
//!   Req 16.4). Both serialize `lowercase` to match the wire contract and the
//!   glossary, and both expose a total [`parse`](MagnetStatus::parse) /
//!   [`as_str`](MagnetStatus::as_str) pair.
//! * **Value types** — [`User`] (Req 16.4), [`MagnetFile`] with `-1`
//!   idx/size "unknown" sentinels (Req 17.12), [`CheckMagnetItem`] whose
//!   `files` may be empty for stores that report cached hashes without
//!   per-file detail (Req 17.11), and the per-operation result wrappers
//!   ([`CheckMagnetData`], [`AddMagnetData`], [`GetMagnetData`],
//!   [`ListMagnetsData`], [`RemoveMagnetData`], [`GenerateLinkData`]).
//! * **Parameter structs** — every [`Store`] method takes a `*Params` struct
//!   carrying a [`Ctx`] (request id / client ip / trusted flag, like
//!   stremthru's `Ctx`) plus the operation inputs. [`ListMagnetsParams`]
//!   owns the `limit` clamp to `[1,500]` default 100 / `offset` default 0
//!   (Req 17.4, 17.9).
//!
//! Per-store quirk normalization (Offcloud empty files, TorBox trailing item,
//! dead/errored/virus → `failed`) is performed by the individual impls
//! (task 22.3) **before** they hand back these already-normalized shapes; the
//! types here only encode the normalized contract.
//!
//! [`Store`]: super::Store

use std::net::IpAddr;

use time::OffsetDateTime;

/// Per-request context threaded through every [`Store`](super::Store) call,
/// mirroring stremthru's `Ctx` (design: Data Models -> Store Abstraction,
/// "Parameter structs carry Ctx").
///
/// It carries the correlation [`request_id`](Ctx::request_id) for structured
/// logging, the inbound [`client_ip`](Ctx::client_ip) (used only for internal
/// bookkeeping — it is **never** forwarded to a store; outbound IP binding
/// uses the Egress_IP per Req 51.4), and a [`trusted`](Ctx::trusted) flag for
/// requests originating from a configured admin / trusted caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ctx {
    /// Correlation id for logs/metrics spanning the operation.
    pub request_id: String,
    /// Inbound client IP, for internal bookkeeping only. Never sent upstream
    /// (Req 51.2, 51.4).
    pub client_ip: Option<IpAddr>,
    /// `true` when the caller is a trusted/admin principal.
    pub trusted: bool,
}

/// One canonical magnet state (Req 16.5).
///
/// Every store's native status vocabulary is normalized onto exactly one of
/// these nine values; in particular a torrent the store reports as dead,
/// errored, or virus-flagged normalizes to [`Failed`](MagnetStatus::Failed)
/// rather than `Downloading`/`Unknown` (Req 16.14). Serializes `lowercase`
/// (`"cached"`, `"queued"`, …) to match the glossary wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MagnetStatus {
    /// Already cached at the store — instantly available.
    Cached,
    /// Accepted, waiting in the store's queue.
    Queued,
    /// Actively downloading into the store.
    Downloading,
    /// Post-download processing (e.g. repacking).
    Processing,
    /// Fully downloaded and ready.
    Downloaded,
    /// Uploading to the store's CDN.
    Uploading,
    /// Dead / errored / virus-flagged torrent (Req 16.14).
    Failed,
    /// Rejected as invalid (malformed magnet / hash).
    Invalid,
    /// State could not be determined.
    Unknown,
}

impl MagnetStatus {
    /// Every variant, in declaration order — the totality anchor for the
    /// status-normalization property (Req 16.5, Property 21).
    pub const ALL: [MagnetStatus; 9] = [
        MagnetStatus::Cached,
        MagnetStatus::Queued,
        MagnetStatus::Downloading,
        MagnetStatus::Processing,
        MagnetStatus::Downloaded,
        MagnetStatus::Uploading,
        MagnetStatus::Failed,
        MagnetStatus::Invalid,
        MagnetStatus::Unknown,
    ];

    /// The canonical `lowercase` wire string for this status (its serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            MagnetStatus::Cached => "cached",
            MagnetStatus::Queued => "queued",
            MagnetStatus::Downloading => "downloading",
            MagnetStatus::Processing => "processing",
            MagnetStatus::Downloaded => "downloaded",
            MagnetStatus::Uploading => "uploading",
            MagnetStatus::Failed => "failed",
            MagnetStatus::Invalid => "invalid",
            MagnetStatus::Unknown => "unknown",
        }
    }

    /// Parse a canonical status string (case-insensitive). Returns `None` for
    /// any token outside the nine canonical states; callers that must be total
    /// map `None` onto [`Unknown`](MagnetStatus::Unknown).
    pub fn parse(s: &str) -> Option<MagnetStatus> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cached" => Some(MagnetStatus::Cached),
            "queued" => Some(MagnetStatus::Queued),
            "downloading" => Some(MagnetStatus::Downloading),
            "processing" => Some(MagnetStatus::Processing),
            "downloaded" => Some(MagnetStatus::Downloaded),
            "uploading" => Some(MagnetStatus::Uploading),
            "failed" => Some(MagnetStatus::Failed),
            "invalid" => Some(MagnetStatus::Invalid),
            "unknown" => Some(MagnetStatus::Unknown),
            _ => None,
        }
    }

    /// Normalize a **native** store status string into a canonical
    /// [`MagnetStatus`] (Req 16.5, 16.14).
    ///
    /// Each debrid service reports magnet state using its own vocabulary
    /// (e.g. "ready", "seeding", "active", "dead", "virus"). This function
    /// maps every known native string onto exactly one canonical status,
    /// case-insensitively. Unrecognized strings map to [`Unknown`](MagnetStatus::Unknown).
    ///
    /// Critically, `dead`/`errored`/`virus` map to [`Failed`](MagnetStatus::Failed)
    /// rather than `Downloading` or `Unknown` (Req 16.14).
    pub fn from_native(s: &str) -> MagnetStatus {
        match s.trim().to_ascii_lowercase().as_str() {
            // Cached variants (Req 16.5)
            "cached" | "ready" | "finished" | "seeding" | "completed" => MagnetStatus::Cached,
            // Queued variants
            "queued" | "waiting" | "pending" | "magnet_conversion" | "waiting_files_selection" => {
                MagnetStatus::Queued
            }
            // Downloading variants
            "downloading" | "active" => MagnetStatus::Downloading,
            // Downloaded
            "downloaded" => MagnetStatus::Downloaded,
            // Processing variants
            "processing" | "compressing" | "uploading_to_remote" | "converting" => {
                MagnetStatus::Processing
            }
            // Uploading
            "uploading" => MagnetStatus::Uploading,
            // Failed variants (Req 16.14: dead/errored/virus -> Failed)
            "failed"
            | "error"
            | "dead"
            | "virus"
            | "magnet_error"
            | "banned"
            | "file_hosters_are_not_available"
            | "internal_error"
            | "download_error"
            | "not_downloaded"
            | "timed_out" => MagnetStatus::Failed,
            // Invalid variants
            "invalid" | "wrong_password" | "bad_token" => MagnetStatus::Invalid,
            // Anything else -> Unknown
            _ => MagnetStatus::Unknown,
        }
    }
}

/// A store user's plan state (Req 16.4). Serializes `lowercase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    /// Active paid plan.
    Premium,
    /// Trial plan.
    Trial,
    /// Lapsed / expired plan.
    Expired,
}

impl SubscriptionStatus {
    /// Every variant, in declaration order.
    pub const ALL: [SubscriptionStatus; 3] = [
        SubscriptionStatus::Premium,
        SubscriptionStatus::Trial,
        SubscriptionStatus::Expired,
    ];

    /// The canonical `lowercase` wire string (its serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionStatus::Premium => "premium",
            SubscriptionStatus::Trial => "trial",
            SubscriptionStatus::Expired => "expired",
        }
    }

    /// Parse a canonical subscription-status string (case-insensitive).
    pub fn parse(s: &str) -> Option<SubscriptionStatus> {
        match s.trim().to_ascii_lowercase().as_str() {
            "premium" => Some(SubscriptionStatus::Premium),
            "trial" => Some(SubscriptionStatus::Trial),
            "expired" => Some(SubscriptionStatus::Expired),
            _ => None,
        }
    }
}

/// The store user details returned by [`Store::get_user`](super::Store::get_user)
/// (Req 16.4).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct User {
    /// Store-side user identifier.
    pub id: String,
    /// Account email.
    pub email: String,
    /// Plan state (Req 16.4).
    pub subscription_status: SubscriptionStatus,
    /// Whether the account has Usenet access (a per-store capability flag).
    pub has_usenet: bool,
}

/// One file within a magnet (Req 17.12).
///
/// `index` is `-1` and `size` is `-1` when the store does not report a usable
/// value; consumers then rely on [`name`](MagnetFile::name) (Req 17.12). The
/// optional [`link`](MagnetFile::link) and [`video_hash`](MagnetFile::video_hash)
/// are omitted from the serialized form when absent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MagnetFile {
    /// File index within the magnet, or `-1` when unknown (Req 17.12).
    pub index: i32,
    /// Direct/store link to this file, when the store provides one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// File path within the torrent.
    pub path: String,
    /// File name.
    pub name: String,
    /// File size in bytes, or `-1` when unknown (Req 17.12).
    pub size: i64,
    /// Stremio video info-hash for this file, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video_hash: Option<String>,
}

impl MagnetFile {
    /// The sentinel for an unknown file index / size (Req 17.12).
    pub const UNKNOWN: i64 = -1;
}

/// One entry in a [`CheckMagnetData`] result (Req 17.7).
///
/// `files` MAY be empty: a store that reports a cached hash without per-file
/// detail (e.g. Offcloud) yields `status = Cached` with an empty file list
/// rather than failing (Req 17.11).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckMagnetItem {
    /// Torrent info-hash.
    pub hash: String,
    /// The supplied magnet URI.
    pub magnet: String,
    /// Normalized cache status (Req 16.5).
    pub status: MagnetStatus,
    /// Cached files (possibly empty — Req 17.11).
    pub files: Vec<MagnetFile>,
}

/// Result of [`Store::check_magnet`](super::Store::check_magnet) — one item per
/// supplied magnet (Req 17.7).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckMagnetData {
    /// One [`CheckMagnetItem`] per supplied magnet, in input order.
    pub items: Vec<CheckMagnetItem>,
}

/// Result of [`Store::add_magnet`](super::Store::add_magnet) (Req 17.2, 17.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddMagnetData {
    /// Store-assigned magnet id.
    pub id: String,
    /// Torrent info-hash.
    pub hash: String,
    /// The magnet URI (derived from a torrent file when one was supplied).
    pub magnet: String,
    /// Display name.
    pub name: String,
    /// Total size in bytes, or `-1` when unknown.
    pub size: i64,
    /// Normalized status (Req 16.5).
    pub status: MagnetStatus,
    /// Files in the magnet.
    pub files: Vec<MagnetFile>,
    /// Whether the magnet is private to this account.
    pub private: bool,
    /// When the magnet was added to the store.
    pub added_at: OffsetDateTime,
}

/// Result of [`Store::get_magnet`](super::Store::get_magnet) (Req 17.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMagnetData {
    /// Store-assigned magnet id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Torrent info-hash.
    pub hash: String,
    /// Total size in bytes, or `-1` when unknown.
    pub size: i64,
    /// Normalized status (Req 16.5).
    pub status: MagnetStatus,
    /// Files in the magnet.
    pub files: Vec<MagnetFile>,
    /// Whether the magnet is private to this account.
    pub private: bool,
    /// When the magnet was added to the store.
    pub added_at: OffsetDateTime,
}

/// One entry in a [`ListMagnetsData`] result (Req 17.4). Listings carry the
/// magnet summary without the per-file detail returned by
/// [`GetMagnetData`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListMagnetItem {
    /// Store-assigned magnet id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Torrent info-hash.
    pub hash: String,
    /// Total size in bytes, or `-1` when unknown.
    pub size: i64,
    /// Normalized status (Req 16.5).
    pub status: MagnetStatus,
}

/// Result of [`Store::list_magnets`](super::Store::list_magnets) (Req 17.4).
///
/// Per-store trailing-item quirks (e.g. TorBox) are normalized away by the
/// impl before this is built, so `items` contains only genuine magnets
/// (Req 17.14) and `total_items` reflects the genuine total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListMagnetsData {
    /// The page of magnets.
    pub items: Vec<ListMagnetItem>,
    /// Total magnets available (across all pages).
    pub total_items: i64,
}

/// Result of [`Store::remove_magnet`](super::Store::remove_magnet) (Req 17.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveMagnetData {
    /// The id of the removed magnet.
    pub id: String,
}

/// Result of [`Store::generate_link`](super::Store::generate_link) (Req 18.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateLinkData {
    /// The generated direct link (valid 12h — Req 18.2).
    pub link: String,
}

/// Parameters for [`Store::get_user`](super::Store::get_user) (Req 16.4).
#[derive(Clone, Debug, Default)]
pub struct GetUserParams {
    /// Per-request context.
    pub ctx: Ctx,
}

/// Parameters for [`Store::check_magnet`](super::Store::check_magnet)
/// (Req 17.7, 17.8, 17.13).
///
/// `magnets` is a borrowed slice (the handler owns the parsed list);
/// `sid` is the optional stream identifier associated with the check — a
/// malformed `sid` is ignored by the handler rather than rejected (Req 17.13).
pub struct CheckMagnetParams<'a> {
    /// Per-request context.
    pub ctx: Ctx,
    /// The 1–500 magnets to check (Req 17.7); cardinality is validated by the
    /// handler (Req 17.10).
    pub magnets: &'a [String],
    /// The Egress_IP to consult cache against / bind to, when relevant. Never
    /// the Client_IP (Req 51.4).
    pub client_ip: Option<IpAddr>,
    /// Associated stream id (Req 17.8); already validated/ignored upstream
    /// (Req 17.13).
    pub sid: Option<String>,
    /// When `true`, only consult locally-known cache, skipping the upstream
    /// check.
    pub local_only: bool,
}

/// Parameters for [`Store::add_magnet`](super::Store::add_magnet)
/// (Req 17.2, 17.3).
///
/// `magnet` is the magnet URI; when the request supplied a torrent file the
/// handler derives the magnet URI first and passes it here.
#[derive(Clone, Debug, Default)]
pub struct AddMagnetParams {
    /// Per-request context.
    pub ctx: Ctx,
    /// The magnet URI to add.
    pub magnet: String,
}

/// Parameters for [`Store::get_magnet`](super::Store::get_magnet) (Req 17.5).
#[derive(Clone, Debug, Default)]
pub struct GetMagnetParams {
    /// Per-request context.
    pub ctx: Ctx,
    /// The store-assigned magnet id.
    pub id: String,
}

/// Parameters for [`Store::list_magnets`](super::Store::list_magnets)
/// (Req 17.4, 17.9).
///
/// Construct with [`ListMagnetsParams::new`] to apply the canonical clamp:
/// `limit` is constrained to `[1,500]` (default [`LIMIT_DEFAULT`]) and `offset`
/// defaults to `0`.
///
/// [`LIMIT_DEFAULT`]: ListMagnetsParams::LIMIT_DEFAULT
#[derive(Clone, Debug)]
pub struct ListMagnetsParams {
    /// Per-request context.
    pub ctx: Ctx,
    /// Page size, already clamped to `[LIMIT_MIN, LIMIT_MAX]`.
    pub limit: u32,
    /// Page offset (default 0).
    pub offset: u32,
}

impl ListMagnetsParams {
    /// Minimum permitted `limit` (Req 17.4, 17.9).
    pub const LIMIT_MIN: u32 = 1;
    /// Maximum permitted `limit` (Req 17.4, 17.9).
    pub const LIMIT_MAX: u32 = 500;
    /// Default `limit` applied when none is supplied (Req 17.4).
    pub const LIMIT_DEFAULT: u32 = 100;

    /// Build params, applying the canonical clamp (Req 17.4, 17.9).
    ///
    /// A `None` limit becomes [`LIMIT_DEFAULT`](Self::LIMIT_DEFAULT); any
    /// supplied value is clamped to the nearest bound in
    /// `[LIMIT_MIN, LIMIT_MAX]` (Req 17.9). A `None` offset becomes `0`.
    pub fn new(ctx: Ctx, limit: Option<u32>, offset: Option<u32>) -> Self {
        Self {
            ctx,
            limit: Self::clamp_limit(limit.unwrap_or(Self::LIMIT_DEFAULT)),
            offset: offset.unwrap_or(0),
        }
    }

    /// Clamp a requested `limit` to the nearest bound in
    /// `[LIMIT_MIN, LIMIT_MAX]` (Req 17.9).
    pub fn clamp_limit(limit: u32) -> u32 {
        limit.clamp(Self::LIMIT_MIN, Self::LIMIT_MAX)
    }
}

/// Parameters for [`Store::remove_magnet`](super::Store::remove_magnet)
/// (Req 17.6).
#[derive(Clone, Debug, Default)]
pub struct RemoveMagnetParams {
    /// Per-request context.
    pub ctx: Ctx,
    /// The store-assigned magnet id to remove.
    pub id: String,
}

/// Parameters for [`Store::generate_link`](super::Store::generate_link)
/// (Req 18.1, 18.3, 51.4).
///
/// `client_ip` here is the **Egress_IP** to bind the link to for IP-locked
/// stores (never the user's Client_IP — Req 18.3, 51.4); non-IP-binding stores
/// ignore it (Req 18.4).
#[derive(Clone, Debug, Default)]
pub struct GenerateLinkParams {
    /// Per-request context.
    pub ctx: Ctx,
    /// The store link to resolve into a direct link.
    pub link: String,
    /// The Egress_IP to bind the link to, for IP-locked stores (Req 18.3,
    /// 51.4).
    pub client_ip: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- MagnetStatus -------------------------------------------------------

    #[test]
    fn magnet_status_serializes_lowercase() {
        let cases = [
            (MagnetStatus::Cached, "cached"),
            (MagnetStatus::Queued, "queued"),
            (MagnetStatus::Downloading, "downloading"),
            (MagnetStatus::Processing, "processing"),
            (MagnetStatus::Downloaded, "downloaded"),
            (MagnetStatus::Uploading, "uploading"),
            (MagnetStatus::Failed, "failed"),
            (MagnetStatus::Invalid, "invalid"),
            (MagnetStatus::Unknown, "unknown"),
        ];
        for (status, expected) in cases {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{expected}\""), "{status:?}");
            // as_str matches the serde form.
            assert_eq!(status.as_str(), expected);
        }
    }

    #[test]
    fn magnet_status_round_trips_through_json_for_every_variant() {
        for status in MagnetStatus::ALL {
            let json = serde_json::to_string(&status).unwrap();
            let back: MagnetStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn magnet_status_parse_is_case_insensitive_and_total() {
        for status in MagnetStatus::ALL {
            assert_eq!(MagnetStatus::parse(status.as_str()), Some(status));
            assert_eq!(
                MagnetStatus::parse(&status.as_str().to_uppercase()),
                Some(status),
            );
            assert_eq!(
                MagnetStatus::parse(&format!("  {}  ", status.as_str())),
                Some(status),
            );
        }
        assert_eq!(MagnetStatus::parse("seeding"), None);
        assert_eq!(MagnetStatus::parse(""), None);
    }

    #[test]
    fn magnet_status_all_has_nine_unique_variants() {
        assert_eq!(MagnetStatus::ALL.len(), 9);
        for (i, a) in MagnetStatus::ALL.iter().enumerate() {
            for b in &MagnetStatus::ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    // -- SubscriptionStatus -------------------------------------------------

    #[test]
    fn subscription_status_serializes_lowercase_and_round_trips() {
        let cases = [
            (SubscriptionStatus::Premium, "premium"),
            (SubscriptionStatus::Trial, "trial"),
            (SubscriptionStatus::Expired, "expired"),
        ];
        for (status, expected) in cases {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
            assert_eq!(status.as_str(), expected);
            let back: SubscriptionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
            assert_eq!(SubscriptionStatus::parse(expected), Some(status));
            assert_eq!(
                SubscriptionStatus::parse(&expected.to_uppercase()),
                Some(status),
            );
        }
        assert_eq!(SubscriptionStatus::parse("free"), None);
    }

    // -- User ---------------------------------------------------------------

    #[test]
    fn user_serializes_with_subscription_status_lowercase() {
        let user = User {
            id: "u123".into(),
            email: "a@b.c".into(),
            subscription_status: SubscriptionStatus::Premium,
            has_usenet: true,
        };
        let value = serde_json::to_value(&user).unwrap();
        assert_eq!(value["id"], "u123");
        assert_eq!(value["email"], "a@b.c");
        assert_eq!(value["subscription_status"], "premium");
        assert_eq!(value["has_usenet"], true);

        let back: User = serde_json::from_value(value).unwrap();
        assert_eq!(back, user);
    }

    // -- MagnetFile (idx/size -1 semantics, omit-if-none) -------------------

    #[test]
    fn magnet_file_unknown_index_and_size_are_minus_one() {
        let file = MagnetFile {
            index: MagnetFile::UNKNOWN as i32,
            link: None,
            path: "folder/movie.mkv".into(),
            name: "movie.mkv".into(),
            size: MagnetFile::UNKNOWN,
            video_hash: None,
        };
        assert_eq!(file.index, -1);
        assert_eq!(file.size, -1);

        let value = serde_json::to_value(&file).unwrap();
        let obj = value.as_object().unwrap();
        // index/size always present (the -1 sentinel is meaningful).
        assert_eq!(obj["index"], -1);
        assert_eq!(obj["size"], -1);
        // link/video_hash omitted when None.
        assert!(!obj.contains_key("link"), "link omitted when None");
        assert!(
            !obj.contains_key("video_hash"),
            "video_hash omitted when None",
        );
    }

    #[test]
    fn magnet_file_includes_link_and_video_hash_when_present_and_round_trips() {
        let file = MagnetFile {
            index: 2,
            link: Some("https://dl.example/file".into()),
            path: "a/b.mkv".into(),
            name: "b.mkv".into(),
            size: 123,
            video_hash: Some("deadbeef".into()),
        };
        let value = serde_json::to_value(&file).unwrap();
        assert_eq!(value["link"], "https://dl.example/file");
        assert_eq!(value["video_hash"], "deadbeef");

        let back: MagnetFile = serde_json::from_value(value).unwrap();
        assert_eq!(back, file);
    }

    // -- CheckMagnetItem (empty files allowed — Offcloud) -------------------

    #[test]
    fn check_magnet_item_allows_empty_files_for_cached_status() {
        let item = CheckMagnetItem {
            hash: "abc".into(),
            magnet: "magnet:?xt=urn:btih:abc".into(),
            status: MagnetStatus::Cached,
            files: vec![],
        };
        let value = serde_json::to_value(&item).unwrap();
        assert_eq!(value["status"], "cached");
        assert_eq!(value["files"].as_array().unwrap().len(), 0);

        let back: CheckMagnetItem = serde_json::from_value(value).unwrap();
        assert_eq!(back, item);
    }

    // -- ListMagnetsParams clamp (Req 17.4, 17.9) ---------------------------

    #[test]
    fn list_magnets_params_apply_default_limit_and_zero_offset() {
        let p = ListMagnetsParams::new(Ctx::default(), None, None);
        assert_eq!(p.limit, ListMagnetsParams::LIMIT_DEFAULT);
        assert_eq!(p.limit, 100);
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn list_magnets_params_clamp_limit_to_nearest_bound() {
        assert_eq!(ListMagnetsParams::clamp_limit(0), 1);
        assert_eq!(ListMagnetsParams::clamp_limit(1), 1);
        assert_eq!(ListMagnetsParams::clamp_limit(250), 250);
        assert_eq!(ListMagnetsParams::clamp_limit(500), 500);
        assert_eq!(ListMagnetsParams::clamp_limit(501), 500);
        assert_eq!(ListMagnetsParams::clamp_limit(u32::MAX), 500);

        let low = ListMagnetsParams::new(Ctx::default(), Some(0), Some(7));
        assert_eq!(low.limit, 1);
        assert_eq!(low.offset, 7);

        let high = ListMagnetsParams::new(Ctx::default(), Some(99999), None);
        assert_eq!(high.limit, 500);
    }
}
