//! Persistence row models (`persistence::models`) — design: Data Models ->
//! Persistence Models; Req 29.
//!
//! One `struct` per durable SQLite table (design: Database -> Schema). These
//! are the **at-rest** shapes the repositories ([`super::repo`]) read and write
//! verbatim: a `*_enc: Vec<u8>` field holds the **Vault-encrypted** ciphertext
//! exactly as it lives in its `BLOB` column (design comment "Vault-encrypted
//! (Req 29.5)"). Production callers encrypt a plaintext secret with
//! [`Vault::encrypt`](super::vault::Vault::encrypt) before constructing the
//! row and decrypt `*_enc` with [`Vault::decrypt`](super::vault::Vault::decrypt)
//! after fetching it, keeping the repository a pure CRUD layer and the codec a
//! pure transform — each independently testable.
//!
//! `OffsetDateTime` time fields are persisted as unix-**second** `INTEGER`s
//! (the schema's `unix secs` columns), so a round-tripped value is truncated to
//! whole-second precision.
//!
//! The design's models name the encrypted-store column type as `StoreName` and
//! the magnet status as `MagnetStatus`; those enums land with the store/magnet
//! tasks, so the columns are modelled here as `String` (matching their `TEXT`
//! storage) and will be narrowed to the typed enums when those are introduced.

use time::OffsetDateTime;

/// `store_userdata` row — a user's credential for one store (Req 28.4, 29.5).
///
/// `token_enc` is the store token encrypted at rest with `Vault_Secret`
/// (AES-GCM) when a vault is configured, or the plaintext token bytes when it
/// is not (design: Schema "AES-GCM(Vault_Secret) or plaintext if no vault").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreUserData {
    /// Owning username (part of the composite primary key).
    pub username: String,
    /// Store identifier (`StoreName` once that enum lands) — the other half of
    /// the primary key.
    pub store: String,
    /// Vault-encrypted store token (Req 29.5).
    pub token_enc: Vec<u8>,
    /// When the credential was first stored. Persisted as a unix-second
    /// `INTEGER` (schema column `created_at`).
    pub created_at: OffsetDateTime,
}

/// `health_history` row — per-(torrent, store) success/failure tallies used by
/// the health-score model (Req 42.2-42.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthHistory {
    /// Torrent info-hash (primary-key part).
    pub info_hash: String,
    /// Store identifier (primary-key part).
    pub store: String,
    /// Count of successful resolutions.
    pub success: u32,
    /// Count of failed resolutions.
    pub failure: u32,
    /// Optional last-observed seed count (`NULL` when unknown).
    pub seed_count: Option<u32>,
    /// Last time this pair was observed; rows older than the window are
    /// decayed/pruned by it. Persisted as a unix-second `INTEGER`.
    pub last_seen: OffsetDateTime,
}

/// `magnet_cache` row — a cached Magnet/CheckMagnet result (Req 17, 30).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetCacheRow {
    /// Store identifier (primary-key part).
    pub store: String,
    /// Torrent hash (primary-key part).
    pub hash: String,
    /// Magnet status (`MagnetStatus` once that enum lands) — stored as `TEXT`.
    pub status: String,
    /// Serialized `Vec<MagnetFile>` JSON.
    pub files_json: String,
    /// Cache expiry. Persisted as a unix-second `INTEGER`.
    pub expires_at: OffsetDateTime,
}

/// `id_map` row — a cached cross-namespace media-ID mapping (Req 22.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapRow {
    /// ID namespace (`imdb|tmdb|tvdb|trakt`) — primary-key part.
    pub id_type: String,
    /// The ID value within that namespace — primary-key part.
    pub id: String,
    /// Serialized mapping JSON.
    pub map_json: String,
    /// Cache expiry. Persisted as a unix-second `INTEGER`.
    pub expires_at: OffsetDateTime,
}

/// `integration_list` row — a third-party list snapshot with last-good
/// fallback (Req 27.3-27.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationListRow {
    /// Integration source (`anilist|github|mdblist|tmdb|trakt|tvdb|letterboxd`)
    /// — primary-key part.
    pub source: String,
    /// List key within that source — primary-key part.
    pub key: String,
    /// Serialized list-data JSON.
    pub data_json: String,
    /// When the snapshot was fetched. Persisted as a unix-second `INTEGER`.
    pub fetched_at: OffsetDateTime,
    /// When the snapshot becomes stale. Persisted as a unix-second `INTEGER`.
    pub stale_at: OffsetDateTime,
}

/// `trakt_token` row — a user's Trakt OAuth tokens, encrypted at rest
/// (Req 27.2, 29.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraktTokenRow {
    /// Owning username (primary key).
    pub username: String,
    /// Vault-encrypted access token (Req 29.5).
    pub access_enc: Vec<u8>,
    /// Vault-encrypted refresh token (Req 29.5).
    pub refresh_enc: Vec<u8>,
    /// Access-token expiry. Persisted as a unix-second `INTEGER`.
    pub expires_at: OffsetDateTime,
}

/// `peer` row — a configured peer instance (Req 29.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    /// Peer base URL (primary key).
    pub url: String,
    /// Vault-encrypted peer token (Req 29.5).
    pub token_enc: Vec<u8>,
    /// Whether this peer is enabled. Persisted as a `0`/`1` `INTEGER`.
    pub enabled: bool,
}
