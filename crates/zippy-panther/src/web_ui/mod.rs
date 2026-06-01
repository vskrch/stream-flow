//! Minimal built-in web UI (`web_ui`) — Req 33.
//!
//! The UI is intentionally server-rendered and dependency-free: it exposes the
//! production endpoints, builds Stremio install URLs, and gates the admin
//! dashboard using the configured admin usernames.

use actix_web::{http::header, web, HttpResponse};
use rust_embed::RustEmbed;
use serde::Deserialize;

use crate::auth::Auth;
use crate::errors::AppError;
use crate::AppState;

#[derive(RustEmbed)]
#[folder = "src/web_ui/assets/"]
struct Assets;

#[derive(Debug, Deserialize, Default)]
pub struct ConfigureQuery {
    pub base_url: Option<String>,
    pub store: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AdminQuery {
    pub user: Option<String>,
}

pub async fn index_endpoint(state: web::Data<AppState>) -> HttpResponse {
    let base = state
        .config()
        .stremio
        .base_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8080");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(index_html(base))
}

pub async fn configure_endpoint(
    query: web::Query<ConfigureQuery>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let base = query
        .base_url
        .as_deref()
        .or(state.config().stremio.base_url.as_deref())
        .unwrap_or("http://127.0.0.1:8080")
        .trim_end_matches('/')
        .to_string();
    let store = query.store.as_deref().unwrap_or("rd");
    let store_install = format!("{base}/stremio/store/{store}/manifest.json");
    let wrap_install = format!("{base}/stremio/wrap/manifest.json");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(configure_html(&base, &store_install, &wrap_install))
}

pub async fn admin_endpoint(
    query: web::Query<AdminQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let user = query.user.as_deref().unwrap_or("");
    let auth = Auth::from_config(&state.config().auth);
    if !auth.is_admin(user) {
        return Err(AppError::forbidden(
            "administrative endpoint requires an admin user",
        ));
    }
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(admin_html(state.get_ref())))
}

pub async fn asset_endpoint(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let filename = path.into_inner();
    let Some(asset) = Assets::get(&filename) else {
        return Err(AppError::not_found("web UI asset not found"));
    };
    let content_type = match filename.rsplit_once('.').map(|(_, ext)| ext) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, content_type))
        .body(asset.data.into_owned()))
}

pub fn configure_web_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(index_endpoint))
        .route("/configure", web::get().to(configure_endpoint))
        .route("/admin", web::get().to(admin_endpoint))
        .route("/assets/{filename:.*}", web::get().to(asset_endpoint));
}

fn index_html(base: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>ZippyPanther</title><link rel="stylesheet" href="/assets/style.css"></head>
<body>
<main>
<h1>ZippyPanther</h1>
<section><h2>Streaming</h2><p>Proxy streams, HLS, DASH, subtitles, Acestream, Telegram, Xtream, and EPG through one egress-controlled engine.</p></section>
<section><h2>Stremio</h2><p>Install store addons or wrap upstream addons through encrypted proxy links.</p><p><a href="/configure?base_url={base}">Configure install URLs</a></p></section>
<section><h2>Operations</h2><p><a href="/health">Health</a> · <a href="/metrics">Metrics</a> · <a href="/admin">Admin</a></p></section>
</main>
</body>
</html>"#
    )
}

fn configure_html(base: &str, store_install: &str, wrap_install: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>ZippyPanther configure</title><link rel="stylesheet" href="/assets/style.css"></head>
<body>
<main>
<h1>Configure</h1>
<form action="/configure" method="get">
<label>Public base URL <input name="base_url" value="{base}"></label>
<label>Store code <input name="store" value="rd"></label>
<button type="submit">Build URLs</button>
</form>
<section><h2>Install URLs</h2><p><code>{store_install}</code></p><p><code>{wrap_install}</code></p></section>
</main>
</body>
</html>"#
    )
}

fn admin_html(state: &AppState) -> String {
    let health = state.health().report();
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>ZippyPanther admin</title><link rel="stylesheet" href="/assets/style.css"></head>
<body>
<main>
<h1>Admin</h1>
<section><h2>Status</h2><p>Health: <strong>{:?}</strong></p><p>Load: <strong>{:?}</strong></p></section>
</main>
</body>
</html>"#,
        health.status,
        state.load_controller().load_state()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Config};
    use actix_web::{test, App};

    #[actix_web::test]
    async fn configure_page_builds_install_urls() {
        let state = AppState::new(Config::default());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_web_routes),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/configure?base_url=https://flow.example&store=tb")
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("https://flow.example/stremio/store/tb/manifest.json"));
        assert!(html.contains("https://flow.example/stremio/wrap/manifest.json"));
    }

    #[actix_web::test]
    async fn admin_requires_configured_admin() {
        let config = Config {
            auth: AuthConfig {
                admins: vec!["alice".to_string()],
                ..AuthConfig::default()
            },
            ..Config::default()
        };
        let state = AppState::new(config);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_web_routes),
        )
        .await;
        let denied = test::call_service(
            &app,
            test::TestRequest::get().uri("/admin?user=bob").to_request(),
        )
        .await;
        assert_eq!(denied.status(), 403);
        let allowed = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/admin?user=alice")
                .to_request(),
        )
        .await;
        assert!(allowed.status().is_success());
    }

    #[actix_web::test]
    async fn embedded_asset_is_served() {
        let state = AppState::new(Config::default());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .configure(configure_web_routes),
        )
        .await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/assets/style.css")
                .to_request(),
        )
        .await;
        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );
    }
}
