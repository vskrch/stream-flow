//! Mediaflow-style health view (`utils::health_view`) — Req 15.8.
//!
//! Requirement 15.8 asks the system to return a *success response indicating
//! the service is operational* for a health-check request. The orchestration-
//! grade `/health` endpoint (backed by the [`HealthRegistry`](crate::health),
//! task 7.3) already satisfies this — it answers `200 OK` with the full
//! [`HealthReport`](crate::health::HealthReport) whenever the service is
//! operational — and remains the registered `/health` route.
//!
//! This module adds the **mediaflow-proxy-light-compatible** body shape on top
//! of that registry: the Python/Rust mediaflow reference answers a health
//! probe with the minimal `{"status":"healthy"}` JSON. Exposing that view here
//! (in the utilities module that owns the mediaflow utility surface) keeps the
//! existing [`HealthRegistry`] untouched while making the drop-in body
//! available for surfaces/clients that expect the mediaflow shape (Req 36.5).
//!
//! It is a thin, dependency-free success view — it does not consult the
//! registry — so it is exactly the "the service process is up and answering"
//! signal Req 15.8 describes. Readiness/liveness/startup nuance stays the
//! responsibility of the orchestration `/health` probe.

use actix_web::HttpResponse;

/// The mediaflow-style health body: `{"status":"healthy"}` (Req 15.8, 36.5).
pub fn mediaflow_health_body() -> serde_json::Value {
    serde_json::json!({ "status": "healthy" })
}

/// A mediaflow-style health-check handler returning `200 OK` with the
/// `{"status":"healthy"}` body (Req 15.8).
///
/// Not registered on its own route by default (the orchestration `/health`
/// route already serves health checks); provided so the mediaflow-compatible
/// body is available where a surface needs the drop-in shape.
pub async fn mediaflow_health_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(mediaflow_health_body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_the_mediaflow_healthy_shape() {
        let body = mediaflow_health_body();
        assert_eq!(body["status"], "healthy");
    }

    #[actix_web::test]
    async fn endpoint_returns_success_indicating_operational() {
        use actix_web::{test, web, App};
        let app = test::init_service(
            App::new().route("/healthz", web::get().to(mediaflow_health_endpoint)),
        )
        .await;
        let req = test::TestRequest::get().uri("/healthz").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "health check must indicate operational");

        let body: serde_json::Value = {
            let req = test::TestRequest::get().uri("/healthz").to_request();
            test::call_and_read_body_json(&app, req).await
        };
        assert_eq!(body["status"], "healthy");
    }
}
