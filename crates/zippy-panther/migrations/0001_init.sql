-- stream-flow initial schema (migration 0001_init) — Req 29.2, design: Database -> Schema.
--
-- Embedded SQLite only (no external DB server — Req 29.1). This migration is
-- embedded into the binary at compile time via `sqlx::migrate!()` and applied
-- at startup, before serving requests (Req 29.2). It runs inside a transaction
-- so a failure rolls back, leaving the database at its last consistent state
-- (Req 29.4). Tables/columns mirror the design's Database -> Schema section.

-- Store credentials / user data. `token_enc` holds an AES-GCM(Vault_Secret)
-- ciphertext when a vault is configured, or plaintext bytes otherwise
-- (Req 28.4, 29.5).
CREATE TABLE store_userdata (
    username   TEXT NOT NULL,
    store      TEXT NOT NULL,         -- StoreName
    token_enc  BLOB NOT NULL,         -- AES-GCM(Vault_Secret) or plaintext if no vault
    created_at INTEGER NOT NULL,
    PRIMARY KEY (username, store)
);

-- Torrent health-score history with decay (Req 42.2-42.5). Rows older than the
-- configured window are decayed/pruned by `last_seen`.
CREATE TABLE health_history (
    info_hash  TEXT NOT NULL,
    store      TEXT NOT NULL,
    success    INTEGER NOT NULL DEFAULT 0,
    failure    INTEGER NOT NULL DEFAULT 0,
    seed_count INTEGER,
    last_seen  INTEGER NOT NULL,      -- unix secs; rows older than window are decayed/pruned
    PRIMARY KEY (info_hash, store)
);
CREATE INDEX idx_health_last_seen ON health_history(last_seen);

-- Magnet/CheckMagnet cache (status + files), TTL via `expires_at` (Req 17, 30).
CREATE TABLE magnet_cache (
    store      TEXT NOT NULL,
    hash       TEXT NOT NULL,
    status     TEXT NOT NULL,         -- MagnetStatus
    files_json TEXT NOT NULL,         -- serialized Vec<MagnetFile>
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (store, hash)
);
CREATE INDEX idx_magnet_cache_exp ON magnet_cache(expires_at);

-- Meta / ID-map cache (Req 22.5).
CREATE TABLE id_map (
    id_type    TEXT NOT NULL,         -- imdb|tmdb|tvdb|trakt
    id         TEXT NOT NULL,
    map_json   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (id_type, id)
);

-- Third-party integration list cache, with last-good fallback (Req 27.3-27.5).
CREATE TABLE integration_list (
    source     TEXT NOT NULL,         -- anilist|github|mdblist|tmdb|trakt|tvdb|letterboxd
    key        TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    stale_at   INTEGER NOT NULL,
    PRIMARY KEY (source, key)
);

-- Trakt OAuth tokens (encrypted) (Req 27.2, 29.5).
CREATE TABLE trakt_token (
    username    TEXT PRIMARY KEY,
    access_enc  BLOB NOT NULL,
    refresh_enc BLOB NOT NULL,
    expires_at  INTEGER NOT NULL
);

-- Warmup pool persistence (opt-in) (Req 45).
CREATE TABLE warmup_entry (
    content_key   TEXT PRIMARY KEY,
    store         TEXT NOT NULL,
    direct_link   TEXT NOT NULL,
    link_expires  INTEGER NOT NULL,
    access_count  INTEGER NOT NULL DEFAULT 0,
    last_access   INTEGER NOT NULL,
    last_refresh  INTEGER NOT NULL
);

-- Peer instances (Req 29.7).
CREATE TABLE peer (
    url       TEXT PRIMARY KEY,
    token_enc BLOB NOT NULL,
    enabled   INTEGER NOT NULL DEFAULT 1
);
