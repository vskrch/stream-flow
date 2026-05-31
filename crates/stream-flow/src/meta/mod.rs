//! Meta / ID-map endpoint (`meta`) — Req 22.
//!
//! `GET /v0/meta/id-map/{idType}/{id}` returns an `IdMap` across IMDB/TMDB/TVDB/Trakt
//! for `movie`/`show` (Req 22.1, 22.2); unknown namespaces omitted (Req 22.3);
//! unsupported id type → bad-request (Req 22.4); resolved maps cached for the
//! stale time (Req 22.5).
//!
//! The handler queries the persistence layer ([`Repos`]) for a cached mapping.
//! If a valid (unexpired) mapping exists, it is returned directly. If no mapping
//! exists or the cached entry has expired, a 404 is returned (the upstream
//! resolution/refresh is handled by a separate integration task that populates
//! the cache — this endpoint is the read path only).

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::errors::AppError;
use crate::persistence::repo::Repos;

// ---------------------------------------------------------------------------
// Supported namespaces and id types
// ---------------------------------------------------------------------------

/// The four supported ID namespaces (Req 22.1).
const SUPPORTED_NAMESPACES: &[&str] = &["imdb", "tmdb", "tvdb", "trakt"];

/// The supported id types for the path parameter (Req 22.2).
const SUPPORTED_ID_TYPES: &[&str] = &["imdb", "tmdb", "tvdb", "trakt"];

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// The ID mapping response — only known namespaces with values are included;
/// unknown/unmapped namespaces are omitted (Req 22.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdMapResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tvdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trakt: Option<String>,
}

/// Path parameters for the id-map endpoint.
#[derive(Debug, Deserialize)]
pub struct IdMapPath {
    /// The namespace of the input ID (imdb, tmdb, tvdb, trakt).
    #[serde(rename = "idType")]
    pub id_type: String,
    /// The ID value within that namespace.
    pub id: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /v0/meta/id-map/{idType}/{id}` — returns the ID mapping across
/// IMDB/TMDB/TVDB/Trakt namespaces (Req 22.1–22.5).
///
/// - Unsupported `idType` → 400 Bad Request (Req 22.4)
/// - No cached mapping or expired → 404 Not Found
/// - Valid cached mapping → 200 with only known namespaces included (Req 22.3)
pub async fn id_map_endpoint(
    path: web::Path<IdMapPath>,
    repos: web::Data<Repos>,
) -> Result<HttpResponse, AppError> {
    let path = path.into_inner();
    let id_type = path.id_type.to_lowercase();
    let id = path.id;

    // Validate id type (Req 22.4)
    if !SUPPORTED_ID_TYPES.contains(&id_type.as_str()) {
        return Err(AppError::bad_request(format!(
            "unsupported id type: '{}'; supported types are: imdb, tmdb, tvdb, trakt",
            id_type
        )));
    }

    // Query the persistence layer for a cached mapping (Req 22.5)
    let row = repos.get_id_map(&id_type, &id).await?;

    match row {
        Some(row) => {
            // Check if the cached entry has expired
            let now = OffsetDateTime::now_utc();
            if row.expires_at <= now {
                // Expired — treat as missing
                return Err(AppError::not_found(format!(
                    "no mapping found for {id_type}:{id}"
                )));
            }

            // Parse the stored JSON map and build the response (Req 22.3)
            let map: serde_json::Value = serde_json::from_str(&row.map_json).map_err(|e| {
                AppError::unknown(format!("failed to parse cached id_map JSON: {e}"))
            })?;

            let response = build_response_from_map(&map);
            Ok(HttpResponse::Ok().json(response))
        }
        None => {
            // No mapping found → 404
            Err(AppError::not_found(format!(
                "no mapping found for {id_type}:{id}"
            )))
        }
    }
}

/// Build an [`IdMapResponse`] from the stored JSON map, omitting any namespace
/// that is not present or has a null/empty value (Req 22.3).
fn build_response_from_map(map: &serde_json::Value) -> IdMapResponse {
    let obj = map.as_object();

    let get_field = |key: &str| -> Option<String> {
        obj.and_then(|o| o.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    IdMapResponse {
        imdb: get_field("imdb"),
        tmdb: get_field("tmdb"),
        tvdb: get_field("tvdb"),
        trakt: get_field("trakt"),
    }
}

// ---------------------------------------------------------------------------
// Route configuration
// ---------------------------------------------------------------------------

/// Configure the meta/id-map route onto an actix `ServiceConfig`.
pub fn configure_meta_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/v0/meta/id-map/{idType}/{id}",
        web::get().to(id_map_endpoint),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DbConfig;
    use crate::persistence::models::IdMapRow;
    use crate::persistence::repo::Repos;
    use crate::persistence::{build_pool, run_migrations};
    use actix_web::{test as actix_test, web, App};
    use tempfile::TempDir;
    use time::OffsetDateTime;

    /// Create a migrated Repos instance for testing.
    async fn test_repos() -> (TempDir, Repos) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("meta-test.db");
        let cfg = DbConfig {
            path: path.to_string_lossy().into_owned(),
            busy_timeout_secs: 5,
            max_connections: 5,
        };
        let pool = build_pool(&cfg).await.expect("pool");
        run_migrations(&pool).await.expect("migrate");
        let repos = Repos::new(pool, 5);
        (dir, repos)
    }

    /// Helper to get a future expiry time (1 hour from now).
    fn future_expiry() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() + 3600)
            .unwrap()
    }

    /// Helper to get a past expiry time (1 hour ago).
    fn past_expiry() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() - 3600)
            .unwrap()
    }

    // -- Test: valid mapping returned (Req 22.1) ----------------------------

    #[actix_web::test]
    async fn id_map_returns_mapping_for_valid_cached_entry() {
        let (_dir, repos) = test_repos().await;

        // Seed a cached mapping
        let row = IdMapRow {
            id_type: "imdb".into(),
            id: "tt0111161".into(),
            map_json: r#"{"imdb":"tt0111161","tmdb":"278","trakt":"289"}"#.into(),
            expires_at: future_expiry(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/imdb/tt0111161")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: IdMapResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.imdb, Some("tt0111161".into()));
        assert_eq!(body.tmdb, Some("278".into()));
        assert_eq!(body.trakt, Some("289".into()));
        // tvdb not in the map → omitted (Req 22.3)
        assert_eq!(body.tvdb, None);
    }

    // -- Test: unknown namespaces omitted from response (Req 22.3) ----------

    #[actix_web::test]
    async fn id_map_omits_unknown_namespaces() {
        let (_dir, repos) = test_repos().await;

        // Seed a mapping with only imdb and tmdb
        let row = IdMapRow {
            id_type: "tmdb".into(),
            id: "278".into(),
            map_json: r#"{"imdb":"tt0111161","tmdb":"278"}"#.into(),
            expires_at: future_expiry(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/tmdb/278")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: IdMapResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.imdb, Some("tt0111161".into()));
        assert_eq!(body.tmdb, Some("278".into()));
        assert_eq!(body.tvdb, None);
        assert_eq!(body.trakt, None);
    }

    // -- Test: unsupported id type returns 400 (Req 22.4) -------------------

    #[actix_web::test]
    async fn id_map_unsupported_id_type_returns_bad_request() {
        let (_dir, repos) = test_repos().await;

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/unknown_type/12345")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // -- Test: missing mapping returns 404 ----------------------------------

    #[actix_web::test]
    async fn id_map_missing_mapping_returns_not_found() {
        let (_dir, repos) = test_repos().await;

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/imdb/tt9999999")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // -- Test: expired mapping returns 404 ----------------------------------

    #[actix_web::test]
    async fn id_map_expired_mapping_returns_not_found() {
        let (_dir, repos) = test_repos().await;

        // Seed an expired mapping
        let row = IdMapRow {
            id_type: "imdb".into(),
            id: "tt0000001".into(),
            map_json: r#"{"imdb":"tt0000001","tmdb":"999"}"#.into(),
            expires_at: past_expiry(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/imdb/tt0000001")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // -- Test: all four namespaces supported (Req 22.1, 22.2) ---------------

    #[actix_web::test]
    async fn id_map_supports_all_four_namespace_types() {
        let (_dir, repos) = test_repos().await;

        let map_json = r#"{"imdb":"tt0111161","tmdb":"278","tvdb":"70","trakt":"289"}"#;

        // Seed mappings for all four types
        for (id_type, id) in &[
            ("imdb", "tt0111161"),
            ("tmdb", "278"),
            ("tvdb", "70"),
            ("trakt", "289"),
        ] {
            let row = IdMapRow {
                id_type: id_type.to_string(),
                id: id.to_string(),
                map_json: map_json.into(),
                expires_at: future_expiry(),
            };
            repos.upsert_id_map(&row).await.expect("upsert");
        }

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        // Query each namespace type
        for (id_type, id) in &[
            ("imdb", "tt0111161"),
            ("tmdb", "278"),
            ("tvdb", "70"),
            ("trakt", "289"),
        ] {
            let uri = format!("/v0/meta/id-map/{id_type}/{id}");
            let req = actix_test::TestRequest::get().uri(&uri).to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200, "expected 200 for {id_type}/{id}");

            let body: IdMapResponse = actix_test::read_body_json(resp).await;
            assert_eq!(body.imdb, Some("tt0111161".into()));
            assert_eq!(body.tmdb, Some("278".into()));
            assert_eq!(body.tvdb, Some("70".into()));
            assert_eq!(body.trakt, Some("289".into()));
        }
    }

    // -- Test: response JSON omits null fields (Req 22.3) -------------------

    #[actix_web::test]
    async fn id_map_response_json_omits_null_fields() {
        let (_dir, repos) = test_repos().await;

        // Only imdb is mapped
        let row = IdMapRow {
            id_type: "imdb".into(),
            id: "tt5555555".into(),
            map_json: r#"{"imdb":"tt5555555"}"#.into(),
            expires_at: future_expiry(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/imdb/tt5555555")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Verify the raw JSON doesn't contain null fields
        let body_bytes = actix_test::read_body(resp).await;
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(
            !body_str.contains("tmdb"),
            "tmdb should be omitted from JSON, got: {body_str}"
        );
        assert!(
            !body_str.contains("tvdb"),
            "tvdb should be omitted from JSON, got: {body_str}"
        );
        assert!(
            !body_str.contains("trakt"),
            "trakt should be omitted from JSON, got: {body_str}"
        );
        assert!(
            body_str.contains("imdb"),
            "imdb should be present in JSON, got: {body_str}"
        );
    }

    // -- Test: id type is case-insensitive ----------------------------------

    #[actix_web::test]
    async fn id_map_id_type_is_case_insensitive() {
        let (_dir, repos) = test_repos().await;

        let row = IdMapRow {
            id_type: "imdb".into(),
            id: "tt1234567".into(),
            map_json: r#"{"imdb":"tt1234567","tmdb":"100"}"#.into(),
            expires_at: future_expiry(),
        };
        repos.upsert_id_map(&row).await.expect("upsert");

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(repos))
                .configure(configure_meta_routes),
        )
        .await;

        // Use uppercase in the path
        let req = actix_test::TestRequest::get()
            .uri("/v0/meta/id-map/IMDB/tt1234567")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: IdMapResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.imdb, Some("tt1234567".into()));
        assert_eq!(body.tmdb, Some("100".into()));
    }
}
