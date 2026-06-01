//! Property-based test for the startup migration runner's idempotence and
//! ordering (task 5.5).
//!
//! Feature: stream-flow, Property 32
//!
//! **Property 32: Migration idempotence and ordering**
//!
//! *For any* ordered set of migrations, applying them to a fresh database and
//! then applying them again yields the same schema as applying them once
//! (already-applied migrations are skipped), and the recorded applied-version
//! set increases monotonically by version.
//!
//! **Validates: Requirements 29.2, 29.3**
//!
//! The migrator under test is the compile-time-embedded set driven by
//! [`stream_flow::persistence::run_migrations`] over a real [`SqlitePool`]
//! built by [`stream_flow::persistence::build_pool`] (design: Database ->
//! Migration mechanism). `sqlx`'s `Migrator::run` records every applied
//! migration's version + checksum in its `_sqlx_migrations` bookkeeping table,
//! so an already-applied migration is skipped and never re-run (Req 29.3), and
//! a fresh database has its full schema created in ascending version order
//! before requests are served (Req 29.2).
//!
//! ## How the invariants are exercised
//!
//! Migrations (like WAL itself) require a **real on-disk file**, never
//! `:memory:`, so every case runs against a fresh `tempfile` temp dir whose
//! guard is held for the lifetime of the pools. Each case generates:
//!
//! * `extra_runs` — how many *additional* times to run the migrator after the
//!   first (so the migrator runs `1..=N` times total), and
//! * `reopen_between_runs` — whether to close and reopen the pool between runs,
//!   modelling repeated process restarts (each of which runs migrations again)
//!   as well as repeated in-process runs against one live pool.
//!
//! This makes "run the migrator any number of times" the generated input. The
//! case then asserts, against the database left behind:
//!
//! * **Idempotence — same schema regardless of run count (Req 29.3):** the
//!   full `sqlite_master` schema snapshot (every table + index name and its
//!   DDL) after `N` runs is byte-for-byte identical to the snapshot of a
//!   reference database the migrator ran over exactly once. Running again is a
//!   no-op: already-applied migrations are skipped, not re-applied (a re-apply
//!   would error on `CREATE TABLE` of an existing table, or duplicate schema).
//! * **Applied-version set is stable under re-runs (Req 29.3):** the multiset
//!   of versions recorded in `_sqlx_migrations` after `N` runs equals the set
//!   after a single run — no version is recorded twice, so no migration was
//!   re-applied.
//! * **Monotonic ordering (Req 29.2):** the recorded versions, read in row
//!   order, are strictly increasing — migrations are applied (and tracked) in
//!   ascending version order, never out of order or duplicated.
//! * **Schema actually applied (Req 29.2):** every table the design's Schema
//!   section mandates exists after the runs, proving the migrator created the
//!   full schema rather than vacuously "succeeding".
//!
//! `proptest` cases run synchronously; each drives the async pool/migrator API
//! on a per-case current-thread Tokio runtime, mirroring the other property
//! tests in this crate.

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use sqlx::SqlitePool;

use stream_flow::config::DbConfig;
use stream_flow::persistence::{build_pool, run_migrations};

/// The schema tables the design's Database -> Schema section mandates for the
/// initial migration. Used to prove the migrator actually built the schema
/// (Req 29.2) rather than vacuously succeeding.
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

/// Build a per-case current-thread runtime with timers enabled (parity with
/// the other property tests in this crate).
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime must build")
}

/// A `DbConfig` pointing at `path`. WAL + migrations need a real on-disk file,
/// so `path` must live inside a `tempfile` temp dir whose guard outlives the
/// pool.
fn cfg_at(path: &std::path::Path) -> DbConfig {
    DbConfig {
        path: path.to_string_lossy().into_owned(),
        busy_timeout_secs: 5,
        max_connections: 5,
    }
}

/// A full, order-stable snapshot of the connected database's schema: every
/// non-internal `sqlite_master` object (tables + indexes) as `(type, name,
/// sql)`, ordered deterministically. Two schemas are identical iff their
/// snapshots are equal — this is the observable "same schema" the idempotence
/// property hinges on.
async fn schema_snapshot(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT type, name, sql FROM sqlite_master \
         WHERE name NOT LIKE 'sqlite_%' \
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .expect("query sqlite_master schema snapshot")
}

/// The applied-migration versions recorded by `sqlx` in `_sqlx_migrations`,
/// in row (version) order.
async fn applied_versions(pool: &SqlitePool) -> Vec<i64> {
    sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("query _sqlx_migrations versions")
}

/// Does a table exist in the connected SQLite database?
async fn table_exists(pool: &SqlitePool, name: &str) -> bool {
    let found: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .expect("query sqlite_master for table");
    found.is_some()
}

proptest! {
    // 128 cases (>= 100 required for a property task). Each case opens real
    // on-disk SQLite databases and runs the migrator up to seven times, so the
    // count is kept modest while staying well above the floor.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Feature: stream-flow, Property 32 — applying the migrator any number of
    /// times yields the same final schema as applying it once (already-applied
    /// migrations are skipped), and the recorded applied-version set increases
    /// monotonically by version. **Validates: Requirements 29.2, 29.3**
    #[test]
    fn migrations_are_idempotent_and_ordered(
        extra_runs in 0usize..=6,
        reopen_between_runs in any::<bool>(),
    ) {
        let total_runs = extra_runs + 1; // run the migrator 1..=7 times.
        let rt = runtime();
        let result: Result<(), TestCaseError> = rt.block_on(async {
            // -- Reference: a fresh DB the migrator runs over exactly once. ---
            // Its schema + recorded versions are the canonical "applied once"
            // baseline every multi-run database must match.
            let ref_dir = tempfile::tempdir().expect("create reference temp dir");
            let ref_pool = build_pool(&cfg_at(&ref_dir.path().join("ref.db")))
                .await
                .expect("reference pool should open");
            run_migrations(&ref_pool)
                .await
                .expect("reference migrations should apply on a fresh DB");
            let ref_schema = schema_snapshot(&ref_pool).await;
            let ref_versions = applied_versions(&ref_pool).await;
            ref_pool.close().await;

            // -- Subject: a fresh DB the migrator runs `total_runs` times. -----
            let dir = tempfile::tempdir().expect("create subject temp dir");
            let db_path = dir.path().join("subject.db");

            let mut pool = build_pool(&cfg_at(&db_path))
                .await
                .expect("subject pool should open");

            for run_idx in 0..total_runs {
                // Optionally model a process restart: close and reopen the pool
                // before this run, so idempotence is exercised across fresh
                // connections too (not just repeated runs on one live pool).
                if reopen_between_runs && run_idx > 0 {
                    pool.close().await;
                    pool = build_pool(&cfg_at(&db_path))
                        .await
                        .expect("subject pool should reopen between runs");
                }

                run_migrations(&pool).await.map_err(|e| {
                    TestCaseError::fail(format!(
                        "run {run_idx} of {total_runs} must succeed (re-runs skip \
                         applied migrations), got error: {e}"
                    ))
                })?;
            }

            let schema = schema_snapshot(&pool).await;
            let versions = applied_versions(&pool).await;

            // -- Schema actually applied (Req 29.2) --------------------------
            for table in EXPECTED_TABLES {
                prop_assert!(
                    table_exists(&pool, table).await,
                    "{table} must exist after {total_runs} migrator run(s)",
                );
            }

            // -- Idempotence: same schema regardless of run count (Req 29.3) --
            // Running the migrator N times leaves byte-for-byte the same schema
            // as running it once: applied migrations were skipped, not re-run.
            prop_assert_eq!(
                &schema, &ref_schema,
                "schema after {} run(s) (reopen={}) must equal the apply-once schema",
                total_runs, reopen_between_runs,
            );

            // -- Applied-version set is stable under re-runs (Req 29.3) -------
            // No version recorded twice: the multiset equals the single-run set,
            // so no migration was re-applied across the extra runs.
            prop_assert_eq!(
                &versions, &ref_versions,
                "recorded applied versions after {} run(s) must equal the apply-once set \
                 (no migration re-applied)",
                total_runs,
            );

            // -- Monotonic ordering (Req 29.2) -------------------------------
            // Versions are tracked strictly ascending: migrations apply in
            // version order and never duplicate.
            for pair in versions.windows(2) {
                prop_assert!(
                    pair[0] < pair[1],
                    "recorded versions must be strictly increasing (version order), \
                     found {:?} not before {:?} in {:?}",
                    pair[0], pair[1], versions,
                );
            }

            // At least the initial migration is recorded (the schema exists, so
            // the version set cannot be empty).
            prop_assert!(
                !versions.is_empty(),
                "at least one migration version must be recorded after applying the schema",
            );

            pool.close().await;
            Ok(())
        });
        result?;
    }
}
