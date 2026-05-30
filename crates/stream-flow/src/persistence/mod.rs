//! Persistence (`persistence`) — embedded SQLite via `sqlx` (Req 29).
//!
//! `stream-flow` persists all application data to an **embedded SQLite**
//! database (no external DB server — Req 29.1), accessed through a
//! [`sqlx::SqlitePool`]. This module owns the pool builder: it translates a
//! [`DbConfig`] into the [`SqliteConnectOptions`] the design mandates and
//! hands back a ready connection pool (design: Database -> Connection
//! configuration).
//!
//! ## Connection configuration (Req 29.1, 29.6)
//!
//! Every connection in the pool is opened with:
//!
//! * **`journal_mode = WAL`** (Req 29.1, 29.6) — Write-Ahead Logging so
//!   concurrent readers never block the single writer. WAL is a durable,
//!   file-level mode (it needs a real file on disk, not `:memory:`), recorded
//!   in the database header once set.
//! * **`busy_timeout`** from [`DbConfig::busy_timeout_secs`] (default 5s —
//!   Req 29.6) — a writer waits up to this long for a lock before returning
//!   `SQLITE_BUSY`, which lets short, serialized writes ride out brief
//!   contention.
//! * **`synchronous = NORMAL`** — safe under WAL and far cheaper on `fsync`
//!   than `FULL`, the right trade-off for a cache-heavy workload on modest
//!   (512 MB-VPS) hardware (design note).
//! * **`foreign_keys = ON`** — SQLite leaves FK enforcement off by default;
//!   the schema relies on it, so we enable it per connection.
//!
//! The pool size ([`DbConfig::max_connections`], default 5) is configurable:
//! WAL keeps reads non-blocking while writes stay short and serialized by
//! SQLite, so a small pool suffices (design: Database -> Connection
//! configuration).
//!
//! Migrations (task 5.2), the at-rest vault field codec, and the
//! repositories (task 5.3) build on top of the pool this module produces and
//! land in their own later tasks.
//!
//! [`DbConfig`]: crate::config::DbConfig

use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::SqlitePool;

use crate::config::DbConfig;
use crate::errors::AppError;

/// Build the [`SqliteConnectOptions`] every pooled connection is opened with,
/// derived from `cfg` (design: Database -> Connection configuration; Req 29.1,
/// 29.6).
///
/// Pulled out of [`build_pool`] so the option construction is reusable (e.g.
/// for a one-off connection in a migration or a test) and so the WAL /
/// busy-timeout / synchronous / foreign-keys policy lives in exactly one
/// place. `create_if_missing(true)` lets a fresh deployment open its database
/// file on first start; the file is created before the WAL journal mode is
/// applied.
pub fn connect_options(cfg: &DbConfig) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(&cfg.path)
        .create_if_missing(true)
        // WAL: concurrent readers don't block the writer (Req 29.1, 29.6).
        .journal_mode(SqliteJournalMode::Wal)
        // Wait up to busy_timeout for a write lock before SQLITE_BUSY (Req 29.6).
        .busy_timeout(Duration::from_secs(cfg.busy_timeout_secs))
        // NORMAL is safe under WAL and cheaper on fsync than FULL (design note).
        .synchronous(SqliteSynchronous::Normal)
        // SQLite defaults FK enforcement off; the schema requires it on.
        .foreign_keys(true)
}

/// Build the embedded-SQLite [`SqlitePool`] from `cfg`.
///
/// Opens a connection pool of up to [`DbConfig::max_connections`] connections
/// (default 5), each configured by [`connect_options`] — WAL journal mode, the
/// configured `busy_timeout`, `synchronous = NORMAL`, and `foreign_keys = ON`
/// (Req 29.1, 29.6). Establishing the first connection also creates the
/// database file when it does not yet exist.
///
/// A failure to open the pool (e.g. the parent directory is unwritable)
/// surfaces as a typed [`AppError`] rather than a panic, so startup can abort
/// cleanly (Req 47.1).
pub async fn build_pool(cfg: &DbConfig) -> Result<SqlitePool, AppError> {
    SqlitePoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect_with(connect_options(cfg))
        .await
        .map_err(|e| {
            AppError::unknown(format!(
                "failed to open SQLite pool at {}: {e}",
                cfg.path
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A `DbConfig` pointing at a fresh database file inside a fresh temp dir.
    ///
    /// WAL is a file-level journal mode, so the smoke tests must run against a
    /// real on-disk file (not `:memory:`); the returned `TempDir` guard must
    /// be kept alive for the lifetime of the pool so the file (and its `-wal`
    /// / `-shm` sidecars) outlive the test body.
    fn temp_db(busy_timeout_secs: u64, max_connections: u32) -> (tempfile::TempDir, DbConfig) {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("stream-flow-test.db");
        let cfg = DbConfig {
            path: path.to_string_lossy().into_owned(),
            busy_timeout_secs,
            max_connections,
        };
        (dir, cfg)
    }

    /// Req 29.1, 29.6: a pool built from the default-ish config opens with WAL
    /// journal mode, a 5s busy_timeout, `synchronous = NORMAL`, and
    /// `foreign_keys = ON`. We assert by querying the live PRAGMAs back through
    /// the pool, proving the connect options actually took effect.
    #[tokio::test]
    async fn pool_opens_with_wal_and_expected_pragmas() {
        let (_dir, cfg) = temp_db(5, 5);
        let pool = build_pool(&cfg).await.expect("pool should open");

        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .expect("query journal_mode");
        assert_eq!(journal_mode.to_lowercase(), "wal", "journal_mode must be WAL");

        // `PRAGMA busy_timeout` reports the timeout in milliseconds.
        let busy_timeout_ms: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&pool)
            .await
            .expect("query busy_timeout");
        assert_eq!(busy_timeout_ms, 5_000, "busy_timeout must be 5s (5000ms)");

        // `synchronous` reports the numeric level: NORMAL == 1.
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await
            .expect("query synchronous");
        assert_eq!(synchronous, 1, "synchronous must be NORMAL (1)");

        // `foreign_keys` reports 1 when enforcement is ON.
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .expect("query foreign_keys");
        assert_eq!(foreign_keys, 1, "foreign_keys must be ON (1)");

        pool.close().await;
    }

    /// Req 29.6: the busy_timeout is taken from config, not hard-coded — a
    /// non-default value flows through to the live `PRAGMA busy_timeout`.
    #[tokio::test]
    async fn busy_timeout_is_configurable() {
        let (_dir, cfg) = temp_db(7, 5);
        let pool = build_pool(&cfg).await.expect("pool should open");

        let busy_timeout_ms: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&pool)
            .await
            .expect("query busy_timeout");
        assert_eq!(busy_timeout_ms, 7_000, "busy_timeout must reflect config (7s)");

        pool.close().await;
    }

    /// Req 29.6: the pool size is configurable via `DbConfig::max_connections`.
    /// The built pool reports the configured maximum.
    #[tokio::test]
    async fn pool_size_is_configurable() {
        let (_dir, cfg) = temp_db(5, 3);
        let pool = build_pool(&cfg).await.expect("pool should open");

        assert_eq!(
            pool.options().get_max_connections(),
            3,
            "pool max_connections must reflect config",
        );

        // The pool is usable: a trivial query round-trips a value.
        let one: i64 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("trivial query");
        assert_eq!(one, 1);

        pool.close().await;
    }

    /// The database file is created on first connect when missing
    /// (`create_if_missing`), so a fresh deployment opens cleanly.
    #[tokio::test]
    async fn database_file_is_created_when_missing() {
        let (dir, cfg) = temp_db(5, 5);
        let db_path = dir.path().join("stream-flow-test.db");
        assert!(!db_path.exists(), "precondition: db file absent before build");

        let pool = build_pool(&cfg).await.expect("pool should open");
        assert!(db_path.exists(), "db file must be created on first connect");

        pool.close().await;
    }
}
