//! Store magnet HTTP endpoints (`store/endpoints`) — Req 17.1–17.14.
//!
//! Actix-web handlers for the stremthru-surface store magnet endpoints:
//! - `GET /v0/store/user` — fetch authenticated user details (Req 17.1)
//! - `POST /v0/store/magnets` — add a magnet (Req 17.2, 17.3)
//! - `GET /v0/store/magnets` — list magnets with clamped limit/offset (Req 17.4, 17.9)
//! - `GET /v0/store/magnets/{id}` — get a single magnet (Req 17.5)
//! - `DELETE /v0/store/magnets/{id}` — remove a magnet (Req 17.6)
//! - `GET /v0/store/magnets/check` — check 1–500 magnets (Req 17.7, 17.10)
//!
//! `sid` is accepted when it matches `tt\d+(?::\d+:\d+)?` and ignored when
//! malformed (Req 17.13). List `total_items` reflects the genuine total after
//! per-store quirk normalization (Req 17.14).

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app::AppState;
use crate::auth::{middleware::verify_proxy_auth_req, Auth};
use crate::errors::AppError;
use crate::store::{
    impls::{
        AllDebridStore, DebridLinkStore, DebriderStore, EasyDebridStore, OffcloudStore,
        PikPakStore, PremiumizeStore, RealDebridStore, TorBoxStore,
    },
    AddMagnetParams, CheckMagnetParams, Ctx, GetMagnetParams, GetUserParams, ListMagnetsParams,
    MagnetFile, MagnetStatus, RemoveMagnetParams, Store, StoreName,
};

const STORE_NAME_HEADER: &str = "X-StremThru-Store-Name";

// ---------------------------------------------------------------------------
// Shared response types (JSON wire format)
// ---------------------------------------------------------------------------

/// JSON response for GET /v0/store/user (Req 17.1).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub subscription_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_usenet: Option<bool>,
}

/// JSON response for a single magnet item in check results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckMagnetItemResponse {
    pub hash: String,
    pub magnet: String,
    pub status: MagnetStatus,
    pub files: Vec<MagnetFile>,
}

/// JSON response for GET /v0/store/magnets/check (Req 17.7).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckMagnetsResponse {
    pub items: Vec<CheckMagnetItemResponse>,
}

/// JSON response for POST /v0/store/magnets (Req 17.2).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddMagnetResponse {
    pub id: String,
    pub hash: String,
    pub magnet: String,
    pub name: String,
    pub size: i64,
    pub status: MagnetStatus,
    pub files: Vec<MagnetFile>,
}

/// JSON response for GET /v0/store/magnets/{id} (Req 17.5).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetMagnetResponse {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub size: i64,
    pub status: MagnetStatus,
    pub files: Vec<MagnetFile>,
}

/// One item in the list response.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListMagnetItemResponse {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub size: i64,
    pub status: MagnetStatus,
}

/// JSON response for GET /v0/store/magnets (Req 17.4).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListMagnetsResponse {
    pub items: Vec<ListMagnetItemResponse>,
    pub total_items: i64,
}

/// JSON response for DELETE /v0/store/magnets/{id} (Req 17.6).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveMagnetResponse {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Request types (query/body deserialization)
// ---------------------------------------------------------------------------

/// Query params for GET /v0/store/magnets/check.
#[derive(Debug, Deserialize)]
pub struct CheckMagnetsQuery {
    /// Optional store slug/code; production also accepts X-StremThru-Store-Name.
    pub store: Option<String>,
    /// Comma-separated magnet URIs (1–500, Req 17.10).
    pub magnet: Option<String>,
    /// Optional stream identifier (Req 17.8, 17.13).
    pub sid: Option<String>,
}

/// Query params for GET /v0/store/magnets.
#[derive(Debug, Deserialize)]
pub struct ListMagnetsQuery {
    /// Optional store slug/code; production also accepts X-StremThru-Store-Name.
    pub store: Option<String>,
    /// Page size, clamped to [1,500] default 100 (Req 17.9).
    pub limit: Option<u32>,
    /// Page offset, default 0.
    pub offset: Option<u32>,
}

/// Body for POST /v0/store/magnets.
#[derive(Debug, Deserialize, Serialize)]
pub struct AddMagnetBody {
    /// Optional store slug/code; production also accepts X-StremThru-Store-Name
    /// or `store` in the query string.
    pub store: Option<String>,
    /// The magnet URI to add.
    pub magnet: String,
}

/// Path param for /v0/store/magnets/{id}.
#[derive(Debug, Deserialize)]
pub struct MagnetIdPath {
    pub id: String,
}

// ---------------------------------------------------------------------------
// sid validation (Req 17.13)
// ---------------------------------------------------------------------------

/// Validate a `sid` parameter: accepted when it matches `tt\d+(?::\d+:\d+)?`,
/// ignored (returns `None`) when malformed (Req 17.13).
pub fn validate_sid(sid: Option<&str>) -> Option<String> {
    let sid = sid?.trim();
    if sid.is_empty() {
        return None;
    }
    // Must start with "tt" followed by digits, optionally ":season:episode"
    let rest = sid.strip_prefix("tt")?;
    // Split on ':' — first part must be all digits
    let mut parts = rest.splitn(3, ':');
    let id_part = parts.next()?;
    if id_part.is_empty() || !id_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // If there's a season part, it must be digits
    if let Some(season) = parts.next() {
        if season.is_empty() || !season.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        // If there's an episode part, it must be digits
        if let Some(episode) = parts.next() {
            if episode.is_empty() || !episode.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
        } else {
            // season without episode is invalid
            return None;
        }
    }
    Some(sid.to_string())
}

fn selected_store_token(req: &HttpRequest, body_store: Option<&str>) -> Option<String> {
    req.headers()
        .get(STORE_NAME_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            url::form_urlencoded::parse(req.query_string().as_bytes())
                .find(|(key, value)| key == "store" && !value.trim().is_empty())
                .map(|(_, value)| value.into_owned())
        })
        .or_else(|| {
            body_store
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn build_store(store_name: StoreName, token: String, state: &AppState) -> Arc<dyn Store> {
    let client = state.egress().clone();
    match store_name {
        StoreName::AllDebrid => Arc::new(AllDebridStore::new(client, token)),
        StoreName::Debrider => Arc::new(DebriderStore::new(client, token)),
        StoreName::DebridLink => Arc::new(DebridLinkStore::new(client, token)),
        StoreName::EasyDebrid => Arc::new(EasyDebridStore::new(client, token)),
        StoreName::Offcloud => Arc::new(OffcloudStore::new(client, token)),
        StoreName::PikPak => Arc::new(PikPakStore::new(client, token)),
        StoreName::Premiumize => Arc::new(PremiumizeStore::new(client, token)),
        StoreName::RealDebrid => Arc::new(RealDebridStore::new(client, token)),
        StoreName::TorBox => Arc::new(TorBoxStore::new(client, token)),
    }
}

fn resolve_store(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<&AppState>,
    req: &HttpRequest,
    body_store: Option<&str>,
) -> Result<Arc<dyn Store>, AppError> {
    if let Some(store) = injected_store {
        return Ok(store.get_ref().clone());
    }

    let state = state.ok_or_else(|| {
        AppError::unknown("store endpoints require AppState or an injected Store implementation")
    })?;
    let auth = Auth::from_config(&state.config().auth);
    let user = verify_proxy_auth_req(&auth, req)?;
    let store_token = selected_store_token(req, body_store).ok_or_else(|| {
        AppError::bad_request(format!(
            "missing store selection; provide {STORE_NAME_HEADER} or store query/body field"
        ))
    })?;
    let store_name = StoreName::require(&store_token)?;
    let token = auth
        .resolve_store_credential(user.as_str(), store_name.as_str())
        .ok_or_else(|| {
            AppError::unauthorized_for(
                store_name.as_str(),
                format!(
                    "missing store credential for user `{}` and store `{}`",
                    user.as_str(),
                    store_name.as_str()
                ),
            )
        })?;

    Ok(build_store(store_name, token.to_string(), state))
}

fn app_state_ref(state: &Option<web::Data<AppState>>) -> Option<&AppState> {
    state.as_ref().map(web::Data::get_ref)
}

// ---------------------------------------------------------------------------
// Handler: GET /v0/store/user (Req 17.1)
// ---------------------------------------------------------------------------

/// GET /v0/store/user — returns the authenticated store user's details.
pub async fn get_user_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let store = resolve_store(injected_store, app_state_ref(&state), &req, None)?;
    let params = GetUserParams {
        ctx: Ctx::default(),
    };
    let user = store.get_user(&params).await?;
    let resp = UserResponse {
        id: user.id,
        email: user.email,
        subscription_status: user.subscription_status.as_str().to_string(),
        has_usenet: if user.has_usenet { Some(true) } else { None },
    };
    Ok(HttpResponse::Ok().json(resp))
}

// ---------------------------------------------------------------------------
// Handler: GET /v0/store/magnets/check (Req 17.7, 17.10, 17.13)
// ---------------------------------------------------------------------------

/// GET /v0/store/magnets/check — check 1–500 magnets for cache status.
pub async fn check_magnets_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    query: web::Query<CheckMagnetsQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let store = resolve_store(
        injected_store,
        app_state_ref(&state),
        &req,
        query.store.as_deref(),
    )?;
    // Parse comma-separated magnets
    let magnets_str = query.magnet.as_deref().unwrap_or("");
    let magnets: Vec<String> = if magnets_str.is_empty() {
        vec![]
    } else {
        magnets_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Validate cardinality: 1–500 (Req 17.10)
    if magnets.is_empty() || magnets.len() > 500 {
        return Err(AppError::bad_request(format!(
            "magnet count must be between 1 and 500, got {}",
            magnets.len()
        )));
    }

    // Validate sid (Req 17.13): accepted when valid, ignored when malformed
    let sid = validate_sid(query.sid.as_deref());

    let params = CheckMagnetParams {
        ctx: Ctx::default(),
        magnets: &magnets,
        client_ip: None,
        sid,
        local_only: false,
    };

    let data = store.check_magnet(&params).await?;

    let items: Vec<CheckMagnetItemResponse> = data
        .items
        .into_iter()
        .map(|item| CheckMagnetItemResponse {
            hash: item.hash,
            magnet: item.magnet,
            status: item.status,
            files: item.files,
        })
        .collect();

    Ok(HttpResponse::Ok().json(CheckMagnetsResponse { items }))
}

// ---------------------------------------------------------------------------
// Handler: POST /v0/store/magnets (Req 17.2)
// ---------------------------------------------------------------------------

/// POST /v0/store/magnets — add a magnet to the store.
pub async fn add_magnet_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    body: web::Json<AddMagnetBody>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let body = body.into_inner();
    let store = resolve_store(
        injected_store,
        app_state_ref(&state),
        &req,
        body.store.as_deref(),
    )?;
    let params = AddMagnetParams {
        ctx: Ctx::default(),
        magnet: body.magnet,
    };

    let data = store.add_magnet(&params).await?;

    let resp = AddMagnetResponse {
        id: data.id,
        hash: data.hash,
        magnet: data.magnet,
        name: data.name,
        size: data.size,
        status: data.status,
        files: data.files,
    };

    Ok(HttpResponse::Ok().json(resp))
}

// ---------------------------------------------------------------------------
// Handler: GET /v0/store/magnets (Req 17.4, 17.9, 17.14)
// ---------------------------------------------------------------------------

/// GET /v0/store/magnets — list magnets with clamped limit/offset.
pub async fn list_magnets_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    query: web::Query<ListMagnetsQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let store = resolve_store(
        injected_store,
        app_state_ref(&state),
        &req,
        query.store.as_deref(),
    )?;
    let params = ListMagnetsParams::new(Ctx::default(), query.limit, query.offset);

    let data = store.list_magnets(&params).await?;

    let items: Vec<ListMagnetItemResponse> = data
        .items
        .into_iter()
        .map(|item| ListMagnetItemResponse {
            id: item.id,
            name: item.name,
            hash: item.hash,
            size: item.size,
            status: item.status,
        })
        .collect();

    Ok(HttpResponse::Ok().json(ListMagnetsResponse {
        items,
        total_items: data.total_items,
    }))
}

// ---------------------------------------------------------------------------
// Handler: GET /v0/store/magnets/{id} (Req 17.5)
// ---------------------------------------------------------------------------

/// GET /v0/store/magnets/{id} — get a single magnet's details.
pub async fn get_magnet_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    path: web::Path<MagnetIdPath>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let store = resolve_store(injected_store, app_state_ref(&state), &req, None)?;
    let params = GetMagnetParams {
        ctx: Ctx::default(),
        id: path.into_inner().id,
    };

    let data = store.get_magnet(&params).await?;

    let resp = GetMagnetResponse {
        id: data.id,
        name: data.name,
        hash: data.hash,
        size: data.size,
        status: data.status,
        files: data.files,
    };

    Ok(HttpResponse::Ok().json(resp))
}

// ---------------------------------------------------------------------------
// Handler: DELETE /v0/store/magnets/{id} (Req 17.6)
// ---------------------------------------------------------------------------

/// DELETE /v0/store/magnets/{id} — remove a magnet from the store.
pub async fn remove_magnet_endpoint(
    injected_store: Option<web::Data<Arc<dyn Store>>>,
    state: Option<web::Data<AppState>>,
    path: web::Path<MagnetIdPath>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let store = resolve_store(injected_store, app_state_ref(&state), &req, None)?;
    let params = RemoveMagnetParams {
        ctx: Ctx::default(),
        id: path.into_inner().id,
    };

    let data = store.remove_magnet(&params).await?;

    Ok(HttpResponse::Ok().json(RemoveMagnetResponse { id: data.id }))
}

// ---------------------------------------------------------------------------
// Route configuration
// ---------------------------------------------------------------------------

/// Configure the store magnet routes onto an actix `ServiceConfig`.
///
/// Mounts:
/// - `GET /v0/store/user`
/// - `GET /v0/store/magnets/check`
/// - `POST /v0/store/magnets`
/// - `GET /v0/store/magnets`
/// - `GET /v0/store/magnets/{id}`
/// - `DELETE /v0/store/magnets/{id}`
pub fn configure_store_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/v0/store/user", web::get().to(get_user_endpoint))
        .route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        )
        .route("/v0/store/magnets", web::post().to(add_magnet_endpoint))
        .route("/v0/store/magnets", web::get().to(list_magnets_endpoint))
        .route("/v0/store/magnets/{id}", web::get().to(get_magnet_endpoint))
        .route(
            "/v0/store/magnets/{id}",
            web::delete().to(remove_magnet_endpoint),
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::types::*;
    use crate::store::Store;
    use actix_web::{test as actix_test, web, App};
    use async_trait::async_trait;
    use std::sync::Arc;
    use time::OffsetDateTime;

    // -- Mock store for endpoint tests --------------------------------------

    struct MockStore;

    #[async_trait]
    impl Store for MockStore {
        fn get_name(&self) -> crate::store::StoreName {
            crate::store::StoreName::RealDebrid
        }

        async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
            Ok(User {
                id: "user-42".into(),
                email: "test@example.com".into(),
                subscription_status: SubscriptionStatus::Premium,
                has_usenet: false,
            })
        }

        async fn check_magnet(
            &self,
            p: &CheckMagnetParams<'_>,
        ) -> Result<CheckMagnetData, AppError> {
            let items = p
                .magnets
                .iter()
                .map(|m| {
                    let hash = m
                        .strip_prefix("magnet:?xt=urn:btih:")
                        .unwrap_or("unknown")
                        .to_string();
                    CheckMagnetItem {
                        hash: hash.clone(),
                        magnet: m.clone(),
                        status: MagnetStatus::Cached,
                        files: vec![MagnetFile {
                            index: 0,
                            link: Some(format!("https://dl.example/{hash}")),
                            path: "movie.mkv".into(),
                            name: "movie.mkv".into(),
                            size: 1_500_000_000,
                            video_hash: None,
                        }],
                    }
                })
                .collect();
            Ok(CheckMagnetData { items })
        }

        async fn add_magnet(&self, p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
            Ok(AddMagnetData {
                id: "magnet-1".into(),
                hash: "abc123def456".into(),
                magnet: p.magnet.clone(),
                name: "Test Torrent".into(),
                size: 2_000_000_000,
                status: MagnetStatus::Queued,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn get_magnet(&self, p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
            Ok(GetMagnetData {
                id: p.id.clone(),
                name: "Test Torrent".into(),
                hash: "abc123def456".into(),
                size: 2_000_000_000,
                status: MagnetStatus::Cached,
                files: vec![MagnetFile {
                    index: 0,
                    link: Some("https://dl.example/file".into()),
                    path: "movie.mkv".into(),
                    name: "movie.mkv".into(),
                    size: 2_000_000_000,
                    video_hash: None,
                }],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn list_magnets(&self, p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
            // Return items respecting limit, with a genuine total of 42
            let total = 42i64;
            let items: Vec<ListMagnetItem> = (0..p.limit.min(total as u32))
                .map(|i| ListMagnetItem {
                    id: format!("m-{}", p.offset + i),
                    name: format!("Torrent {}", p.offset + i),
                    hash: format!("hash{:03}", p.offset + i),
                    size: 1_000_000_000,
                    status: MagnetStatus::Cached,
                })
                .collect();
            Ok(ListMagnetsData {
                items,
                total_items: total,
            })
        }

        async fn remove_magnet(
            &self,
            p: &RemoveMagnetParams,
        ) -> Result<RemoveMagnetData, AppError> {
            Ok(RemoveMagnetData { id: p.id.clone() })
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

    fn mock_store() -> web::Data<Arc<dyn Store>> {
        web::Data::new(Arc::new(MockStore) as Arc<dyn Store>)
    }

    // -- Tests: sid validation (Req 17.13) ----------------------------------
    //
    // NOTE: `use actix_web::test` (above) imports actix's `test` attribute macro
    // into the macro namespace, shadowing the built-in `#[test]`. These sync unit
    // tests therefore fully-qualify the standard library test attribute so they
    // remain synchronous rather than being treated as actix async tests.

    #[::core::prelude::v1::test]
    fn sid_valid_imdb_id_accepted() {
        assert_eq!(validate_sid(Some("tt1234567")), Some("tt1234567".into()));
    }

    #[::core::prelude::v1::test]
    fn sid_valid_with_season_episode_accepted() {
        assert_eq!(
            validate_sid(Some("tt1234567:1:2")),
            Some("tt1234567:1:2".into())
        );
    }

    #[::core::prelude::v1::test]
    fn sid_malformed_ignored_not_rejected() {
        // Malformed sids are ignored (return None), not rejected (Req 17.13)
        assert_eq!(validate_sid(Some("invalid")), None);
        assert_eq!(validate_sid(Some("tt")), None);
        assert_eq!(validate_sid(Some("tt123:1")), None); // season without episode
        assert_eq!(validate_sid(Some("tt123:abc:1")), None);
        assert_eq!(validate_sid(Some("")), None);
        assert_eq!(validate_sid(None), None);
        assert_eq!(validate_sid(Some("imdb:tt123")), None);
        assert_eq!(validate_sid(Some("123456")), None);
    }

    #[::core::prelude::v1::test]
    fn sid_none_returns_none() {
        assert_eq!(validate_sid(None), None);
    }

    #[::core::prelude::v1::test]
    fn store_selection_prefers_header_then_query_then_body() {
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?store=rd")
            .insert_header((STORE_NAME_HEADER, "tb"))
            .to_http_request();
        assert_eq!(
            selected_store_token(&req, Some("pm")).as_deref(),
            Some("tb")
        );

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?store=rd")
            .to_http_request();
        assert_eq!(
            selected_store_token(&req, Some("pm")).as_deref(),
            Some("rd")
        );

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets")
            .to_http_request();
        assert_eq!(
            selected_store_token(&req, Some("pm")).as_deref(),
            Some("pm")
        );
    }

    // -- Tests: GET /v0/store/user (Req 17.1) -------------------------------

    #[actix_web::test]
    async fn get_user_returns_user_details() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/user", web::get().to(get_user_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/user")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: UserResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.id, "user-42");
        assert_eq!(body.email, "test@example.com");
        assert_eq!(body.subscription_status, "premium");
    }

    // -- Tests: GET /v0/store/magnets/check (Req 17.7, 17.10) ---------------

    #[actix_web::test]
    async fn check_magnets_returns_items_for_valid_magnets() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/check?magnet=magnet:?xt=urn:btih:abc123")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: CheckMagnetsResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 1);
        assert_eq!(body.items[0].hash, "abc123");
        assert_eq!(body.items[0].status, MagnetStatus::Cached);
        assert_eq!(body.items[0].files.len(), 1);
    }

    #[actix_web::test]
    async fn check_magnets_validates_cardinality_zero_is_bad_request() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        // No magnets supplied
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/check")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn check_magnets_validates_cardinality_over_500_is_bad_request() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        // 501 magnets
        let magnets: Vec<String> = (0..501).map(|i| format!("magnet{i}")).collect();
        let uri = format!("/v0/store/magnets/check?magnet={}", magnets.join(","));
        let req = actix_test::TestRequest::get().uri(&uri).to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn check_magnets_accepts_500_magnets() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        // Exactly 500 magnets
        let magnets: Vec<String> = (0..500)
            .map(|i| format!("magnet:?xt=urn:btih:h{i}"))
            .collect();
        let uri = format!("/v0/store/magnets/check?magnet={}", magnets.join(","));
        let req = actix_test::TestRequest::get().uri(&uri).to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: CheckMagnetsResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 500);
    }

    #[actix_web::test]
    async fn check_magnets_sid_valid_is_accepted() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/check?magnet=magnet:?xt=urn:btih:abc&sid=tt1234567:1:2")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn check_magnets_sid_malformed_is_ignored_not_rejected() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/check",
            web::get().to(check_magnets_endpoint),
        ))
        .await;

        // Malformed sid should be ignored, not cause a rejection (Req 17.13)
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/check?magnet=magnet:?xt=urn:btih:abc&sid=invalid-sid")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    // -- Tests: POST /v0/store/magnets (Req 17.2) ---------------------------

    #[actix_web::test]
    async fn add_magnet_returns_magnet_details() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::post().to(add_magnet_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::post()
            .uri("/v0/store/magnets")
            .set_json(AddMagnetBody {
                store: None,
                magnet: "magnet:?xt=urn:btih:abc123def456".into(),
            })
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: AddMagnetResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.id, "magnet-1");
        assert_eq!(body.hash, "abc123def456");
        assert_eq!(body.status, MagnetStatus::Queued);
    }

    // -- Tests: GET /v0/store/magnets (Req 17.4, 17.9, 17.14) --------------

    #[actix_web::test]
    async fn list_magnets_default_limit_and_offset() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::get().to(list_magnets_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: ListMagnetsResponse = actix_test::read_body_json(resp).await;
        // Default limit is 100, but mock only has 42 total
        assert_eq!(body.items.len(), 42);
        assert_eq!(body.total_items, 42); // Genuine total (Req 17.14)
    }

    #[actix_web::test]
    async fn list_magnets_limit_clamped_to_1_when_zero() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::get().to(list_magnets_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?limit=0")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: ListMagnetsResponse = actix_test::read_body_json(resp).await;
        // Clamped to 1 (Req 17.9)
        assert_eq!(body.items.len(), 1);
        assert_eq!(body.total_items, 42);
    }

    #[actix_web::test]
    async fn list_magnets_limit_clamped_to_500_when_over() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::get().to(list_magnets_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?limit=9999")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: ListMagnetsResponse = actix_test::read_body_json(resp).await;
        // Clamped to 500, but mock only has 42 total
        assert_eq!(body.items.len(), 42);
        assert_eq!(body.total_items, 42);
    }

    #[actix_web::test]
    async fn list_magnets_with_offset() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::get().to(list_magnets_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?limit=5&offset=10")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: ListMagnetsResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.items.len(), 5);
        assert_eq!(body.items[0].id, "m-10");
        assert_eq!(body.total_items, 42);
    }

    #[actix_web::test]
    async fn list_magnets_total_items_is_genuine_total_independent_of_page() {
        // total_items must reflect the genuine total after per-store quirk
        // normalization, regardless of how many items the requested page returns
        // (Req 17.14). Here a small page (limit=3) returns 3 items but the total
        // stays 42.
        //
        // Validates: Requirements 17.14
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets", web::get().to(list_magnets_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets?limit=3&offset=0")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: ListMagnetsResponse = actix_test::read_body_json(resp).await;
        // Page is small...
        assert_eq!(body.items.len(), 3);
        // ...but total is the genuine, page-independent total.
        assert_eq!(body.total_items, 42);
        assert!(
            body.total_items > body.items.len() as i64,
            "total_items should be the genuine total, not the page size"
        );
    }

    // -- Tests: GET /v0/store/magnets/{id} (Req 17.5) -----------------------

    #[actix_web::test]
    async fn get_magnet_returns_details() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .route("/v0/store/magnets/{id}", web::get().to(get_magnet_endpoint)),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/magnet-1")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: GetMagnetResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.id, "magnet-1");
        assert_eq!(body.name, "Test Torrent");
        assert_eq!(body.status, MagnetStatus::Cached);
        assert_eq!(body.files.len(), 1);
    }

    // -- Tests: DELETE /v0/store/magnets/{id} (Req 17.6) --------------------

    #[actix_web::test]
    async fn remove_magnet_returns_removed_id() {
        let app = actix_test::init_service(App::new().app_data(mock_store()).route(
            "/v0/store/magnets/{id}",
            web::delete().to(remove_magnet_endpoint),
        ))
        .await;

        let req = actix_test::TestRequest::delete()
            .uri("/v0/store/magnets/magnet-1")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: RemoveMagnetResponse = actix_test::read_body_json(resp).await;
        assert_eq!(body.id, "magnet-1");
    }

    // -- Tests: route configuration -----------------------------------------

    #[actix_web::test]
    async fn configure_store_routes_registers_all_endpoints() {
        let app = actix_test::init_service(
            App::new()
                .app_data(mock_store())
                .configure(configure_store_routes),
        )
        .await;

        // GET /v0/store/user
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/user")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // GET /v0/store/magnets/check (needs at least 1 magnet)
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/check?magnet=magnet:?xt=urn:btih:abc")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // POST /v0/store/magnets
        let req = actix_test::TestRequest::post()
            .uri("/v0/store/magnets")
            .set_json(AddMagnetBody {
                store: None,
                magnet: "magnet:?xt=urn:btih:test".into(),
            })
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // GET /v0/store/magnets
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // GET /v0/store/magnets/{id}
        let req = actix_test::TestRequest::get()
            .uri("/v0/store/magnets/m1")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // DELETE /v0/store/magnets/{id}
        let req = actix_test::TestRequest::delete()
            .uri("/v0/store/magnets/m1")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn production_store_routes_use_app_state_auth_instead_of_raw_store_data() {
        let mut config = crate::config::Config::default();
        config.auth.proxy_auth = vec!["alice:wonderland".into()];
        config.auth.per_user_store = vec!["alice:realdebrid:rd-token".into()];
        let state = AppState::new(config);

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_store_routes),
        )
        .await;

        let req = actix_test::TestRequest::get()
            .uri("/v0/store/user?store=rd")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;

        assert_eq!(resp.status(), 403);
    }
}
