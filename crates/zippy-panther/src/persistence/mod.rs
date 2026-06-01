//! Persistence (`persistence`) — embedded SQLite via `sqlx` (Req 29).
//!
//! `ZippyPanther` persists all application data to an **embedded SQLite**
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
//! ## Migrations (Req 29.2, 29.3, 29.4)
//!
//! Versioned SQL files in `crates/zippy-panther/migrations/` are embedded into
//! the binary at compile time with [`sqlx::migrate!`] and run at startup,
//! **before serving requests**, by [`run_migrations`] (design: Database ->
//! Migration mechanism). `sqlx`'s `_sqlx_migrations` table records the applied
//! version + checksum of each migration, so an already-applied migration is
//! skipped and never re-applied (Req 29.3). Each migration applies inside a
//! transaction: on failure the transaction rolls back, the migrator returns an
//! error, [`run_migrations`] turns it into a typed [`AppError`] **naming the
//! failing version**, logs that version through `tracing`, and the caller
//! aborts startup with the database left at its last consistent state
//! (Req 29.4).
//!
//! ## At-rest vault field codec + repositories (task 5.3)
//!
//! On top of the pool + schema this module produces:
//!
//! * [`vault`] — the AES-256-GCM(`Vault_Secret`) field codec that encrypts
//!   sensitive persisted fields at rest, or passes them through verbatim when
//!   no secret is configured (Req 29.5).
//! * [`models`] — one row `struct` per durable table (design: Data Models ->
//!   Persistence Models).
//! * [`repo`] — the [`Repos`](repo::Repos) typed CRUD layer, with every
//!   operation wrapped in a busy/locked [`RetryPolicy`](crate::resilience::RetryPolicy)
//!   so a transiently locked SQLite write is retried within the configured
//!   busy timeout rather than surfacing an error (Req 50.6).
//!
//! [`DbConfig`]: crate::config::DbConfig

use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

use crate::config::DbConfig;
use crate::errors::AppError;

pub mod models;
pub mod repo;
pub mod vault;

pub use models::{
    HealthHistory, IdMapRow, IntegrationListRow, MagnetCacheRow, PeerRow, StoreUserData,
    TraktTokenRow,
};
pub use repo::{busy_retry_policy, classify_sqlx_error, Repos};
pub use vault::Vault;

/// The embedded set of versioned migrations, resolved at **compile time** from
/// `crates/zippy-panther/migrations/` (design: Database -> Migration mechanism;
/// Req 29.2).
///
/// `sqlx::migrate!()` reads the SQL files relative to `CARGO_MANIFEST_DIR`
/// (i.e. the crate root), embeds their bytes + checksums into the binary, and
/// produces a const-promotable [`Migrator`]. Embedding means the running
/// server needs no `migrations/` directory on disk and the migration set can
/// never drift from the code that ships it.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

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
        .map_err(|e| AppError::unknown(format!("failed to open SQLite pool at {}: {e}", cfg.path)))
}

/// Apply all pending migrations against `pool`, in version order, before the
/// server begins serving requests (Req 29.2; design: Database -> Migration
/// mechanism).
///
/// Runs the compile-time-embedded [`MIGRATOR`]. On a **fresh** database the
/// migrator creates its `_sqlx_migrations` bookkeeping table and applies every
/// migration in ascending version order; on a database where some versions are
/// already recorded it **skips** those and applies only the pending remainder,
/// never re-running an applied migration (Req 29.3). Each migration runs inside
/// a transaction, so a failing migration rolls back and leaves the database at
/// its last consistent state (Req 29.4).
///
/// On failure this returns a typed [`AppError`] (never a panic) whose message
/// **names the failing migration version** when `sqlx` reports one, and logs
/// that version through `tracing::error!` so an operator sees it in the
/// structured log (Req 29.4). The caller is expected to abort startup on
/// `Err`.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), AppError> {
    run_with(&MIGRATOR, pool).await
}

/// Run a specific `migrator` against `pool`, mapping a [`MigrateError`] onto a
/// typed [`AppError`] that names + logs the failing version (Req 29.4).
///
/// [`run_migrations`] calls this with the compile-time-embedded [`MIGRATOR`];
/// it is split out so the error-mapping / logging path can be exercised in
/// tests against a runtime [`Migrator`] built from a deliberately broken
/// migration directory (the embedded set is always valid). The applying,
/// skipping, and transactional rollback are all `sqlx`'s `Migrator::run`
/// behavior — this wrapper only owns the typed-error translation.
async fn run_with(migrator: &Migrator, pool: &SqlitePool) -> Result<(), AppError> {
    migrator
        .run(pool)
        .await
        .map_err(|e| match failing_migration_version(&e) {
            Some(version) => {
                tracing::error!(
                    migration_version = version,
                    error = %e,
                    "migration failed; aborting startup at last consistent state",
                );
                AppError::unknown(format!("migration {version} failed to apply: {e}"))
            }
            None => {
                tracing::error!(error = %e, "migration run failed; aborting startup");
                AppError::unknown(format!("migrations failed to apply: {e}"))
            }
        })
}

/// Extract the migration **version** a [`MigrateError`] is about, when the
/// variant carries one (Req 29.4 — the failing version must be reported).
///
/// `sqlx`'s `MigrateError` is `#[non_exhaustive]`; the variants that pin a
/// specific migration each carry its `i64` version as their first numeric
/// field. Variants with no associated version (e.g. a connection-level
/// `Execute` error or a source-resolution error) yield `None`, in which case
/// the caller falls back to a version-less message.
fn failing_migration_version(err: &MigrateError) -> Option<i64> {
    match err {
        MigrateError::ExecuteMigration(_, version)
        | MigrateError::VersionMissing(version)
        | MigrateError::VersionMismatch(version)
        | MigrateError::VersionNotPresent(version)
        | MigrateError::VersionTooOld(version, _)
        | MigrateError::VersionTooNew(version, _)
        | MigrateError::Dirty(version) => Some(*version),
        _ => None,
    }
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
        let path = dir.path().join("ZippyPanther-test.db");
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
        assert_eq!(
            journal_mode.to_lowercase(),
            "wal",
            "journal_mode must be WAL"
        );

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
        assert_eq!(
            busy_timeout_ms, 7_000,
            "busy_timeout must reflect config (7s)"
        );

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
        let db_path = dir.path().join("ZippyPanther-test.db");
        assert!(
            !db_path.exists(),
            "precondition: db file absent before build"
        );

        let pool = build_pool(&cfg).await.expect("pool should open");
        assert!(db_path.exists(), "db file must be created on first connect");

        pool.close().await;
    }
}

#[cfg(test)]
mod migration_tests {
    //! Tests for the startup migrator (task 5.2): migrations apply on a fresh
    //! DB before serving, already-applied migrations are skipped on re-run, and
    //! a failing migration aborts with a typed error naming the version while
    //! leaving the database at its last consistent state (Req 29.2, 29.3,
    //! 29.4; design: Database -> Migration mechanism + Schema).

    use super::*;
    use sqlx::migrate::Migrator;
    use std::path::Path;
    use tempfile::tempdir;

    /// The seven schema tables the design's Database -> Schema section
    /// mandates for `0001_init` (plus `warmup_entry`, also created there). The
    /// task names these explicitly: store_userdata, health_history,
    /// magnet_cache, id_map, integration_list, trakt_token, peer.
    const EXPECTED_TABLES: &[&str] = &[
        "store_userdata",
        "health_history",
        "magnet_cache",
        "id_map",
        "integration_list",
        "trakt_token",
        "warmup_entry",
        "peer",
    ];

    /// Open a fresh pool over a real on-disk temp DB file. Migrations (like WAL)
    /// need a real file, not `:memory:`, and the returned `TempDir` guard must
    /// outlive the pool.
    async fn fresh_pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("migrate-test.db");
        let cfg = DbConfig {
            path: path.to_string_lossy().into_owned(),
            busy_timeout_secs: 5,
            max_connections: 5,
        };
        let pool = build_pool(&cfg).await.expect("pool should open");
        (dir, pool)
    }

    /// Does a table exist in the connected SQLite database?
    async fn table_exists(pool: &SqlitePool, name: &str) -> bool {
        let found: Option<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
                .bind(name)
                .fetch_optional(pool)
                .await
                .expect("query sqlite_master");
        found.is_some()
    }

    /// Req 29.2: applying migrations to a fresh database creates the full
    /// schema (every table from the design's Schema section) and records the
    /// `_sqlx_migrations` bookkeeping table so applied versions are tracked.
    #[tokio::test]
    async fn migrations_apply_on_fresh_db() {
        let (_dir, pool) = fresh_pool().await;

        // Precondition: a fresh DB has none of the schema tables yet.
        for table in EXPECTED_TABLES {
            assert!(
                !table_exists(&pool, table).await,
                "precondition: {table} must be absent on a fresh DB",
            );
        }

        run_migrations(&pool)
            .await
            .expect("migrations should apply on a fresh DB");

        // Every schema table now exists.
        for table in EXPECTED_TABLES {
            assert!(
                table_exists(&pool, table).await,
                "{table} must exist after migrations apply",
            );
        }

        // sqlx records applied versions in `_sqlx_migrations`; 0001 is present.
        let applied: i64 =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("query _sqlx_migrations");
        assert_eq!(
            applied, 1,
            "migration version 1 (0001_init) must be recorded"
        );

        pool.close().await;
    }

    /// Req 29.3: running the migrator a second time is a no-op — already-applied
    /// migrations are skipped (never re-applied), the recorded version set is
    /// unchanged, and the schema is identical.
    #[tokio::test]
    async fn already_applied_migrations_are_skipped_on_rerun() {
        let (_dir, pool) = fresh_pool().await;

        run_migrations(&pool)
            .await
            .expect("first run applies migrations");

        let count_after_first: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .expect("count applied migrations");

        // A second run must succeed without error and without re-applying
        // (which would otherwise fail on `CREATE TABLE ... ` for existing
        // tables — proof the migrations were skipped, not re-executed).
        run_migrations(&pool)
            .await
            .expect("re-run must succeed and skip already-applied migrations");

        let count_after_second: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .expect("count applied migrations");

        assert_eq!(
            count_after_first, count_after_second,
            "re-running must not record any additional applied migrations",
        );

        // Schema is still intact and complete.
        for table in EXPECTED_TABLES {
            assert!(
                table_exists(&pool, table).await,
                "{table} must still exist after an idempotent re-run",
            );
        }

        pool.close().await;
    }

    /// Req 29.4: a migration that fails to apply aborts with a typed `AppError`
    /// that **names the failing version**, and leaves the database at its last
    /// consistent state — the earlier valid migration's table survives while
    /// the broken migration's effects are rolled back.
    ///
    /// Built from a runtime `Migrator` over a temp directory: `0001` is valid,
    /// `0002` contains invalid SQL. (The compile-time-embedded set is always
    /// valid, so the failure path is exercised against a deliberately broken
    /// source through the shared `run_with` mapper.)
    #[tokio::test]
    async fn failing_migration_aborts_naming_version_and_keeps_consistent_state() {
        let mig_dir = tempdir().expect("create migrations dir");

        // 0001: a valid migration that creates a sentinel table.
        std::fs::write(
            mig_dir.path().join("0001_ok.sql"),
            "CREATE TABLE ok_marker (id INTEGER PRIMARY KEY);",
        )
        .expect("write 0001");

        // 0002: invalid SQL — applying it must fail.
        std::fs::write(
            mig_dir.path().join("0002_broken.sql"),
            "CREATE TABLE broken (id INTEGER PRIMARY KEY);\nTHIS IS NOT VALID SQL;",
        )
        .expect("write 0002");

        let migrator = Migrator::new(Path::new(mig_dir.path()))
            .await
            .expect("resolve runtime migrator");

        let (_dir, pool) = fresh_pool().await;

        let err = run_with(&migrator, &pool)
            .await
            .expect_err("a broken migration must abort with an error");

        // The error is typed (AppError) and names the failing version (2).
        assert!(
            err.message.contains("migration 2"),
            "error must name the failing migration version 2, got: {}",
            err.message,
        );

        // Last consistent state: the valid 0001 table survives (it committed in
        // its own transaction), while the broken 0002 table was rolled back.
        assert!(
            table_exists(&pool, "ok_marker").await,
            "the successfully-applied 0001 table must persist (last consistent state)",
        );
        assert!(
            !table_exists(&pool, "broken").await,
            "the failed 0002 migration must be rolled back, leaving no partial table",
        );

        pool.close().await;
    }
}
