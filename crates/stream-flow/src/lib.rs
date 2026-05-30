//! `stream_flow` — unified Stremio streaming-proxy + debrid-orchestration
//! library crate.
//!
//! All application logic lives in this library crate. The `stream-flow-bin`
//! binary is a thin `main` that wires config + server, and the
//! `stream-flow-ffi` staticlib re-uses these same APIs across the C-ABI
//! (design: Workspace and Crate Layout; Req 49.6).
//!
//! This is the task-1.1 skeleton: it exposes a stub [`build_app`] factory so
//! that `cargo build` succeeds and so the binary and the integration-test
//! harness can construct the *identical* routing tree. The full routing tree,
//! `AppState`, and the dual-surface router land in later tasks (router
//! skeleton: task 11.2).

pub mod errors;

use actix_web::{dev::HttpServiceFactory, web, HttpResponse};

/// Build the application's routing tree.
///
/// Returns an actix [`HttpServiceFactory`] so the binary
/// (`App::new().service(build_app())`) and the test harness
/// (`test::init_service(App::new().service(build_app()))`) construct the
/// exact same service graph (Req 49.6).
///
/// This is a stub: it currently registers only a single liveness route. The
/// real dual-surface router and `AppState` threading are added in task 11.2;
/// the signature will grow a `state: AppState` parameter at that point.
pub fn build_app() -> impl HttpServiceFactory {
    web::scope("").route("/health", web::get().to(health))
}

/// Minimal liveness handler used by the skeleton `build_app` factory.
///
/// Replaced by the full health model (`health::HealthRegistry`) in task 7.3.
async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn build_app_registers_health_route() {
        let app = test::init_service(App::new().service(build_app())).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
