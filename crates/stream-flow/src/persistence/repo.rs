//! Repositories (`persistence::repo`) — design: Data Models -> Persistence
//! Models; Database -> Schema; Req 29, 50.6.
//!
//! [`Repos`] is the typed CRUD layer over the durable SQLite tables. Each
//! method reads/writes one of the [`models`](super::models) row structs through
//! the shared [`SqlitePool`], using runtime `sqlx` queries (the schema is owned
//! by the migrations, so no compile-time-checked macros are used here).
//!
//! ## Vault boundary (Req 29.5)
//!
//! A `*_enc` column carries the **already-encrypted** field bytes (design:
//! Schema "AES-GCM(Vault_Secret) or plaintext if no vault"). Repositories store
//! and return those bytes **verbatim** — the [`Vault`](super::vault::Vault)
//! codec is applied by callers around the repository boundary
//! (`vault.encrypt(token)` before an upsert, `vault.decrypt(row.token_enc)`
//! after a fetch). Keeping the codec out of the repository makes each piece
//! independently testable and lets the disabled-vault plaintext passthrough
//! work with no special-casing.
//!
//! ## Busy/locked retry within the busy timeout (Req 50.6)
//!
//! SQLite serializes writers; under contention a write can return
//! `SQLITE_BUSY`/`SQLITE_LOCKED`. Two layers cover this (Req 50.6 — "retry the
//! operation within the configured busy timeout before surfacing an error, and
//! never corrupt persisted state"):
//!
//! 1. The connection's `busy_timeout` (set by [`connect_options`] from
//!    [`DbConfig`]) makes SQLite itself wait for a lock before returning busy.
//! 2. On top of that, every repository operation runs through a
//!    [`RetryPolicy`]: a busy/locked failure is classified **transient**
//!    ([`classify_sqlx_error`]) so the policy retries it with bounded
//!    full-jitter backoff, while any other SQL error is classified
//!    **permanent** and surfaces immediately. Because each statement is atomic
//!    (single-statement upsert / select), a retried write never leaves a
//!    partially-applied row — persisted state stays consistent.
//!
//! [`connect_options`]: super::connect_options
//! [`DbConfig`]: crate::config::DbConfig

use std::future::Future;
use std::time::Duration;

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;

use crate::errors::AppError;
use crate::resilience::RetryPolicy;

use super::models::{
    HealthHistory, IdMapRow, IntegrationListRow, MagnetCacheRow, PeerRow, StoreUserData,
    TraktTokenRow,
};

/// Typed CRUD repositories over the durable SQLite schema (Req 29).
///
/// Cheaply cloneable: the [`SqlitePool`] is an `Arc` internally and the
/// [`RetryPolicy`] is small. Share one [`Repos`] across worker tasks.
#[derive(Clone)]
pub struct Repos {
    /// The shared embedded-SQLite pool (built by [`build_pool`](super::build_pool)).
    pool: SqlitePool,
    /// The busy/locked retry policy applied to every operation (Req 50.6).
    retry: RetryPolicy,
}

impl Repos {
    /// Build repositories over `pool` with a busy-timeout-derived retry policy.
    ///
    /// `busy_timeout_secs` should be [`DbConfig::busy_timeout_secs`] so the
    /// retry window tracks the configured busy timeout (Req 50.6); see
    /// [`busy_retry_policy`].
    ///
    /// [`DbConfig::busy_timeout_secs`]: crate::config::DbConfig::busy_timeout_secs
    pub fn new(pool: SqlitePool, busy_timeout_secs: u64) -> Self {
        Self {
            pool,
            retry: busy_retry_policy(busy_timeout_secs),
        }
    }

    /// Build repositories with an explicit retry policy (used by tests that
    /// pin a deterministic / fast policy).
    pub fn with_retry(pool: SqlitePool, retry: RetryPolicy) -> Self {
        Self { pool, retry }
    }

    /// Borrow the underlying pool (e.g. for callers that need an ad-hoc query
    /// or a transaction outside the typed repositories).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run a single-statement SQLite `op`, retrying only transient busy/locked
    /// failures within the configured budget (Req 50.6).
    ///
    /// `op` is invoked by the [`RetryPolicy`]; its `sqlx::Error` is mapped onto
    /// the canonical taxonomy by [`classify_sqlx_error`] so busy/locked retries
    /// and everything else surfaces immediately.
    async fn run_busy<T, F, Fut>(&self, op: F) -> Result<T, AppError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, sqlx::Error>>,
    {
        self.retry
            .run(|| async { op().await.map_err(classify_sqlx_error) })
            .await
    }

    // -- store_userdata -----------------------------------------------------

    /// Insert or replace a [`StoreUserData`] row (composite key
    /// `username`+`store`). `token_enc` is stored verbatim (Req 29.5).
    pub async fn upsert_store_userdata(&self, row: &StoreUserData) -> Result<(), AppError> {
        let created_at = row.created_at.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO store_userdata (username, store, token_enc, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&row.username)
            .bind(&row.store)
            .bind(row.token_enc.as_slice())
            .bind(created_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`StoreUserData`] for `username`+`store`, or `None`.
    pub async fn get_store_userdata(
        &self,
        username: &str,
        store: &str,
    ) -> Result<Option<StoreUserData>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT username, store, token_enc, created_at FROM store_userdata \
                     WHERE username = ?1 AND store = ?2",
                )
                .bind(username)
                .bind(store)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(StoreUserData {
                username: r.get("username"),
                store: r.get("store"),
                token_enc: r.get("token_enc"),
                created_at: unix_to_odt(r.get::<i64, _>("created_at"))?,
            })),
        }
    }

    // -- health_history -----------------------------------------------------

    /// Insert or replace a [`HealthHistory`] row (key `info_hash`+`store`).
    pub async fn upsert_health_history(&self, row: &HealthHistory) -> Result<(), AppError> {
        let success = row.success as i64;
        let failure = row.failure as i64;
        let seed_count = row.seed_count.map(|v| v as i64);
        let last_seen = row.last_seen.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO health_history \
                 (info_hash, store, success, failure, seed_count, last_seen) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&row.info_hash)
            .bind(&row.store)
            .bind(success)
            .bind(failure)
            .bind(seed_count)
            .bind(last_seen)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`HealthHistory`] for `info_hash`+`store`, or `None`.
    pub async fn get_health_history(
        &self,
        info_hash: &str,
        store: &str,
    ) -> Result<Option<HealthHistory>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT info_hash, store, success, failure, seed_count, last_seen \
                     FROM health_history WHERE info_hash = ?1 AND store = ?2",
                )
                .bind(info_hash)
                .bind(store)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(HealthHistory {
                info_hash: r.get("info_hash"),
                store: r.get("store"),
                success: r.get::<i64, _>("success") as u32,
                failure: r.get::<i64, _>("failure") as u32,
                seed_count: r.get::<Option<i64>, _>("seed_count").map(|v| v as u32),
                last_seen: unix_to_odt(r.get::<i64, _>("last_seen"))?,
            })),
        }
    }

    // -- magnet_cache -------------------------------------------------------

    /// Insert or replace a [`MagnetCacheRow`] (key `store`+`hash`).
    pub async fn upsert_magnet_cache(&self, row: &MagnetCacheRow) -> Result<(), AppError> {
        let expires_at = row.expires_at.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO magnet_cache (store, hash, status, files_json, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&row.store)
            .bind(&row.hash)
            .bind(&row.status)
            .bind(&row.files_json)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`MagnetCacheRow`] for `store`+`hash`, or `None`.
    pub async fn get_magnet_cache(
        &self,
        store: &str,
        hash: &str,
    ) -> Result<Option<MagnetCacheRow>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT store, hash, status, files_json, expires_at FROM magnet_cache \
                     WHERE store = ?1 AND hash = ?2",
                )
                .bind(store)
                .bind(hash)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(MagnetCacheRow {
                store: r.get("store"),
                hash: r.get("hash"),
                status: r.get("status"),
                files_json: r.get("files_json"),
                expires_at: unix_to_odt(r.get::<i64, _>("expires_at"))?,
            })),
        }
    }

    // -- id_map -------------------------------------------------------------

    /// Insert or replace an [`IdMapRow`] (key `id_type`+`id`).
    pub async fn upsert_id_map(&self, row: &IdMapRow) -> Result<(), AppError> {
        let expires_at = row.expires_at.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO id_map (id_type, id, map_json, expires_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&row.id_type)
            .bind(&row.id)
            .bind(&row.map_json)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`IdMapRow`] for `id_type`+`id`, or `None`.
    pub async fn get_id_map(&self, id_type: &str, id: &str) -> Result<Option<IdMapRow>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT id_type, id, map_json, expires_at FROM id_map \
                     WHERE id_type = ?1 AND id = ?2",
                )
                .bind(id_type)
                .bind(id)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(IdMapRow {
                id_type: r.get("id_type"),
                id: r.get("id"),
                map_json: r.get("map_json"),
                expires_at: unix_to_odt(r.get::<i64, _>("expires_at"))?,
            })),
        }
    }

    // -- integration_list ---------------------------------------------------

    /// Insert or replace an [`IntegrationListRow`] (key `source`+`key`).
    pub async fn upsert_integration_list(&self, row: &IntegrationListRow) -> Result<(), AppError> {
        let fetched_at = row.fetched_at.unix_timestamp();
        let stale_at = row.stale_at.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO integration_list \
                 (source, key, data_json, fetched_at, stale_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&row.source)
            .bind(&row.key)
            .bind(&row.data_json)
            .bind(fetched_at)
            .bind(stale_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`IntegrationListRow`] for `source`+`key`, or `None`.
    pub async fn get_integration_list(
        &self,
        source: &str,
        key: &str,
    ) -> Result<Option<IntegrationListRow>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT source, key, data_json, fetched_at, stale_at FROM integration_list \
                     WHERE source = ?1 AND key = ?2",
                )
                .bind(source)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(IntegrationListRow {
                source: r.get("source"),
                key: r.get("key"),
                data_json: r.get("data_json"),
                fetched_at: unix_to_odt(r.get::<i64, _>("fetched_at"))?,
                stale_at: unix_to_odt(r.get::<i64, _>("stale_at"))?,
            })),
        }
    }

    // -- trakt_token --------------------------------------------------------

    /// Insert or replace a [`TraktTokenRow`] (key `username`). `access_enc` and
    /// `refresh_enc` are stored verbatim (Req 29.5).
    pub async fn upsert_trakt_token(&self, row: &TraktTokenRow) -> Result<(), AppError> {
        let expires_at = row.expires_at.unix_timestamp();
        self.run_busy(|| async {
            sqlx::query(
                "INSERT OR REPLACE INTO trakt_token (username, access_enc, refresh_enc, expires_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&row.username)
            .bind(row.access_enc.as_slice())
            .bind(row.refresh_enc.as_slice())
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
        })
        .await
    }

    /// Fetch the [`TraktTokenRow`] for `username`, or `None`.
    pub async fn get_trakt_token(&self, username: &str) -> Result<Option<TraktTokenRow>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT username, access_enc, refresh_enc, expires_at FROM trakt_token \
                     WHERE username = ?1",
                )
                .bind(username)
                .fetch_optional(&self.pool)
                .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(TraktTokenRow {
                username: r.get("username"),
                access_enc: r.get("access_enc"),
                refresh_enc: r.get("refresh_enc"),
                expires_at: unix_to_odt(r.get::<i64, _>("expires_at"))?,
            })),
        }
    }

    // -- peer ---------------------------------------------------------------

    /// Insert or replace a [`PeerRow`] (key `url`). `token_enc` is stored
    /// verbatim (Req 29.5, 29.7).
    pub async fn upsert_peer(&self, row: &PeerRow) -> Result<(), AppError> {
        let enabled = i64::from(row.enabled);
        self.run_busy(|| async {
            sqlx::query("INSERT OR REPLACE INTO peer (url, token_enc, enabled) VALUES (?1, ?2, ?3)")
                .bind(&row.url)
                .bind(row.token_enc.as_slice())
                .bind(enabled)
                .execute(&self.pool)
                .await
                .map(|_| ())
        })
        .await
    }

    /// Fetch the [`PeerRow`] for `url`, or `None`.
    pub async fn get_peer(&self, url: &str) -> Result<Option<PeerRow>, AppError> {
        let row = self
            .run_busy(|| async {
                sqlx::query("SELECT url, token_enc, enabled FROM peer WHERE url = ?1")
                    .bind(url)
                    .fetch_optional(&self.pool)
                    .await
            })
            .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(PeerRow {
                url: r.get("url"),
                token_enc: r.get("token_enc"),
                enabled: r.get::<i64, _>("enabled") != 0,
            })),
        }
    }

    /// List every enabled [`PeerRow`], ordered by `url` (Req 29.7).
    pub async fn list_enabled_peers(&self) -> Result<Vec<PeerRow>, AppError> {
        let rows = self
            .run_busy(|| async {
                sqlx::query(
                    "SELECT url, token_enc, enabled FROM peer WHERE enabled = 1 ORDER BY url",
                )
                .fetch_all(&self.pool)
                .await
            })
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| PeerRow {
                url: r.get("url"),
                token_enc: r.get("token_enc"),
                enabled: r.get::<i64, _>("enabled") != 0,
            })
            .collect())
    }
}

/// A busy/locked retry policy whose window tracks the configured busy timeout
/// (Req 50.6).
///
/// Full-jitter backoff from a 25 ms base capped at 250 ms per attempt, with the
/// attempt count scaled so the (pre-jitter) worst-case total stays in the
/// neighbourhood of the busy timeout. The connection's own `busy_timeout` is
/// the first line of defence; this policy adds bounded application-level
/// retries on top so a brief lock never surfaces as an error.
pub fn busy_retry_policy(busy_timeout_secs: u64) -> RetryPolicy {
    let base = Duration::from_millis(25);
    let cap = Duration::from_millis(250);
    // Roughly cover the busy-timeout window with capped attempts, clamped to a
    // sane [3, 64] range so a 0s or huge timeout still yields a usable policy.
    let budget_ms = busy_timeout_secs.saturating_mul(1000).max(1);
    let attempts = (budget_ms / cap.as_millis() as u64).clamp(3, 64) as u32;
    RetryPolicy::new(attempts, base, cap, 2.0)
}

/// Map a `sqlx::Error` onto the canonical taxonomy, classifying SQLite
/// busy/locked as **transient** so the [`RetryPolicy`] retries it (Req 50.6).
///
/// A transient busy/locked failure becomes an `UpstreamUnavailable`
/// (`is_retryable() == true`), so the retry loop backs off and tries again
/// within the busy-timeout budget. Every other SQL error is `Unknown`
/// (permanent) and surfaces immediately without retrying.
pub fn classify_sqlx_error(err: sqlx::Error) -> AppError {
    if is_busy_or_locked(&err) {
        AppError::upstream_unavailable(format!("sqlite busy/locked, retrying: {err}"))
    } else {
        AppError::unknown(format!("sqlite error: {err}"))
    }
}

/// Is this a transient SQLite busy/locked error (`SQLITE_BUSY` /
/// `SQLITE_LOCKED`)?
///
/// Checks the driver result code (`5` = busy, `6` = locked, plus their extended
/// `5xx`/`6xx` forms) and, defensively, the message text ("database is locked"
/// / "database table is locked") so the classification is robust across SQLite
/// versions.
fn is_busy_or_locked(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db) = err {
        if let Some(code) = db.code() {
            let code = code.as_ref();
            // Primary codes 5/6 and their extended forms (e.g. 517 BUSY_SNAPSHOT).
            if code == "5" || code == "6" || code.starts_with("51") || code.starts_with("61") {
                return true;
            }
        }
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("locked") || msg.contains("database is busy") || msg.contains("(5)")
}

/// Convert a stored unix-second timestamp into an [`OffsetDateTime`], mapping a
/// nonsensical value onto a typed [`AppError`] rather than panicking.
fn unix_to_odt(secs: i64) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::from_unix_timestamp(secs).map_err(|e| {
        AppError::unknown(format!("persistence: invalid stored timestamp {secs}: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DbConfig;
    use crate::persistence::vault::Vault;
    use crate::persistence::{build_pool, run_migrations};
    use tempfile::TempDir;
    use time::OffsetDateTime;

    /// A migrated pool over a fresh on-disk temp DB (WAL needs a real file).
    /// The `TempDir` guard must outlive the pool.
    async fn migrated_repos(busy_timeout_secs: u64) -> (TempDir, DbConfig, Repos) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("repo-test.db");
        let cfg = DbConfig {
            path: path.to_string_lossy().into_owned(),
            busy_timeout_secs,
            max_connections: 5,
        };
        let pool = build_pool(&cfg).await.expect("pool");
        run_migrations(&pool).await.expect("migrate");
        let repos = Repos::new(pool, busy_timeout_secs);
        (dir, cfg, repos)
    }

    /// Whole-second "now" so a stored→loaded `OffsetDateTime` (truncated to
    /// unix seconds) compares equal.
    fn now_secs() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
    }

    // -- store_userdata + vault round trip ----------------------------------

    /// Req 29.5: a store token encrypted with the vault round-trips through the
    /// `store_userdata` repository — write the ciphertext, read it back,
    /// decrypt, and recover the original plaintext token.
    #[tokio::test]
    async fn store_userdata_round_trips_with_vault() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let vault = Vault::enabled_from_bytes(b"vault-secret");

        let token = b"realdebrid-token-123";
        let row = StoreUserData {
            username: "alice".into(),
            store: "realdebrid".into(),
            token_enc: vault.encrypt(token).expect("encrypt"),
            created_at: now_secs(),
        };
        repos.upsert_store_userdata(&row).await.expect("upsert");

        let fetched = repos
            .get_store_userdata("alice", "realdebrid")
            .await
            .expect("get")
            .expect("row present");
        assert_eq!(fetched, row, "row must round-trip verbatim");

        let recovered = vault.decrypt(&fetched.token_enc).expect("decrypt");
        assert_eq!(recovered, token, "decrypted token must equal the original");
    }

    /// A missing key returns `None`.
    #[tokio::test]
    async fn get_store_userdata_absent_is_none() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        assert!(repos
            .get_store_userdata("nobody", "realdebrid")
            .await
            .expect("get")
            .is_none());
    }

    /// `INSERT OR REPLACE` overwrites on the composite key.
    #[tokio::test]
    async fn upsert_store_userdata_overwrites_existing() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let mut row = StoreUserData {
            username: "bob".into(),
            store: "premiumize".into(),
            token_enc: b"first".to_vec(),
            created_at: now_secs(),
        };
        repos.upsert_store_userdata(&row).await.expect("first");
        row.token_enc = b"second".to_vec();
        repos.upsert_store_userdata(&row).await.expect("second");

        let fetched = repos
            .get_store_userdata("bob", "premiumize")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched.token_enc, b"second".to_vec());
    }

    // -- the remaining repositories round-trip ------------------------------

    #[tokio::test]
    async fn health_history_round_trips() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let row = HealthHistory {
            info_hash: "abcd".into(),
            store: "torbox".into(),
            success: 7,
            failure: 2,
            seed_count: Some(42),
            last_seen: now_secs(),
        };
        repos.upsert_health_history(&row).await.expect("upsert");
        let fetched = repos
            .get_health_history("abcd", "torbox")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
    }

    /// `seed_count` `NULL` round-trips as `None`.
    #[tokio::test]
    async fn health_history_null_seed_count_round_trips() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let row = HealthHistory {
            info_hash: "ef01".into(),
            store: "realdebrid".into(),
            success: 0,
            failure: 0,
            seed_count: None,
            last_seen: now_secs(),
        };
        repos.upsert_health_history(&row).await.expect("upsert");
        let fetched = repos
            .get_health_history("ef01", "realdebrid")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched.seed_count, None);
    }

    #[tokio::test]
    async fn magnet_cache_round_trips() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let row = MagnetCacheRow {
            store: "realdebrid".into(),
            hash: "deadbeef".into(),
            status: "cached".into(),
            files_json: r#"[{"name":"a.mkv","size":1}]"#.into(),
            expires_at: now_secs(),
        };
        repos.upsert_magnet_cache(&row).await.expect("upsert");
        let fetched = repos
            .get_magnet_cache("realdebrid", "deadbeef")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
    }

    #[tokio::test]
    async fn id_map_round_trips() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let row = IdMapRow {
            id_type: "imdb".into(),
            id: "tt0111161".into(),
            map_json: r#"{"tmdb":"278"}"#.into(),
            expires_at: now_secs(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");
        let fetched = repos
            .get_id_map("imdb", "tt0111161")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
    }

    #[tokio::test]
    async fn integration_list_round_trips() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let row = IntegrationListRow {
            source: "mdblist".into(),
            key: "top-movies".into(),
            data_json: r#"["tt1","tt2"]"#.into(),
            fetched_at: now_secs(),
            stale_at: now_secs(),
        };
        repos.upsert_integration_list(&row).await.expect("upsert");
        let fetched = repos
            .get_integration_list("mdblist", "top-movies")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
    }

    #[tokio::test]
    async fn trakt_token_round_trips_with_vault() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let vault = Vault::enabled_from_bytes(b"vault-secret");
        let (access, refresh) = (b"access-tok".as_slice(), b"refresh-tok".as_slice());
        let row = TraktTokenRow {
            username: "carol".into(),
            access_enc: vault.encrypt(access).expect("enc access"),
            refresh_enc: vault.encrypt(refresh).expect("enc refresh"),
            expires_at: now_secs(),
        };
        repos.upsert_trakt_token(&row).await.expect("upsert");
        let fetched = repos
            .get_trakt_token("carol")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
        assert_eq!(vault.decrypt(&fetched.access_enc).expect("dec"), access);
        assert_eq!(vault.decrypt(&fetched.refresh_enc).expect("dec"), refresh);
    }

    #[tokio::test]
    async fn peer_round_trips_and_lists_only_enabled() {
        let (_dir, _cfg, repos) = migrated_repos(5).await;
        let enabled = PeerRow {
            url: "https://peer-a.example".into(),
            token_enc: b"tok-a".to_vec(),
            enabled: true,
        };
        let disabled = PeerRow {
            url: "https://peer-b.example".into(),
            token_enc: b"tok-b".to_vec(),
            enabled: false,
        };
        repos.upsert_peer(&enabled).await.expect("upsert a");
        repos.upsert_peer(&disabled).await.expect("upsert b");

        assert_eq!(
            repos
                .get_peer("https://peer-a.example")
                .await
                .expect("get")
                .unwrap(),
            enabled,
        );

        let listed = repos.list_enabled_peers().await.expect("list");
        assert_eq!(listed, vec![enabled], "only the enabled peer is listed");
    }

    // -- Req 50.6: busy/locked classification + retry within the timeout ----

    /// A genuine `SQLITE_BUSY` (a concurrent writer holding the lock while this
    /// connection's `busy_timeout` is 0) is classified **transient** so the
    /// retry policy will retry it (Req 50.6).
    #[tokio::test]
    async fn sqlite_busy_is_classified_transient() {
        // Two pools over the same file. The holder keeps a write lock; the
        // prober has busy_timeout=0 so it sees SQLITE_BUSY immediately.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("busy.db").to_string_lossy().into_owned();

        let holder_pool = build_pool(&DbConfig {
            path: path.clone(),
            busy_timeout_secs: 5,
            max_connections: 1,
        })
        .await
        .expect("holder pool");
        run_migrations(&holder_pool).await.expect("migrate");

        let prober_pool = build_pool(&DbConfig {
            path,
            busy_timeout_secs: 0,
            max_connections: 1,
        })
        .await
        .expect("prober pool");

        // Hold a write lock on the holder connection.
        let mut held = holder_pool.acquire().await.expect("acquire holder");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *held)
            .await
            .expect("begin immediate");

        // The prober's write fails immediately with busy/locked.
        let err = sqlx::query("INSERT INTO peer (url, token_enc, enabled) VALUES ('x', X'00', 1)")
            .execute(&prober_pool)
            .await
            .expect_err("write must hit SQLITE_BUSY while the lock is held");

        let app_err = classify_sqlx_error(err);
        assert!(
            app_err.category.is_retryable(),
            "busy/locked must classify as transient/retryable, got {:?}",
            app_err.category,
        );

        sqlx::query("COMMIT")
            .execute(&mut *held)
            .await
            .expect("commit");
    }

    /// Req 50.6: a write that initially hits a held lock is **retried within
    /// the busy timeout** and ultimately succeeds once the lock is released —
    /// without corrupting state (the row lands exactly once).
    #[tokio::test]
    async fn busy_write_is_retried_until_lock_released() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("retry.db").to_string_lossy().into_owned();

        // Prober pool with busy_timeout=0 so SQLite returns busy immediately and
        // our RetryPolicy is the mechanism that rides out the lock.
        let prober_pool = build_pool(&DbConfig {
            path: path.clone(),
            busy_timeout_secs: 0,
            max_connections: 1,
        })
        .await
        .expect("prober pool");
        run_migrations(&prober_pool).await.expect("migrate");

        // A generous, bounded busy-retry policy (well over the lock hold time).
        let retry = RetryPolicy::new(80, Duration::from_millis(5), Duration::from_millis(30), 2.0);
        let repos = Repos::with_retry(prober_pool, retry);

        // Holder pool acquires a write lock, signals, holds ~40ms, then commits.
        let holder_pool = build_pool(&DbConfig {
            path,
            busy_timeout_secs: 5,
            max_connections: 1,
        })
        .await
        .expect("holder pool");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let mut conn = holder_pool.acquire().await.expect("acquire holder");
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *conn)
                .await
                .expect("begin immediate");
            tx.send(()).expect("signal lock held");
            tokio::time::sleep(Duration::from_millis(40)).await;
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .expect("commit");
        });

        // Wait until the lock is actually held, then issue the contended write.
        rx.await.expect("lock-held signal");
        let row = PeerRow {
            url: "https://contended.example".into(),
            token_enc: b"tok".to_vec(),
            enabled: true,
        };
        repos
            .upsert_peer(&row)
            .await
            .expect("write must succeed after retrying past the held lock");

        holder.await.expect("holder task");

        // State is consistent: exactly one row, with the written value.
        let fetched = repos
            .get_peer("https://contended.example")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(fetched, row);
    }
}
