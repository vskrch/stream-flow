//! Top-level panic-boundary middleware (Req 47.3, 50.8).
//!
//! A per-request handler that panics must be isolated to that one request:
//! the panic is caught and converted into a `500` [`ErrorResponse`] while the
//! worker keeps serving every other request, with the process never
//! terminating (design: Error Handling → Panic boundary). This relies on the
//! server binary being built with `panic = "unwind"` (workspace
//! `[profile.release]`) so a panic unwinds up to this boundary instead of
//! aborting; the FFI staticlib uses `panic = "abort"` and its own
//! `catch_unwind` at every C-ABI entry point instead (design: Profile note).
//!
//! ## How the panic becomes a canonical `500`
//!
//! The boundary wraps the inner service future in
//! [`AssertUnwindSafe`](std::panic::AssertUnwindSafe) +
//! [`catch_unwind`](futures::future::FutureExt::catch_unwind). On a caught
//! panic it returns `Err(`[`AppError::unknown`]`)`. Because [`AppError`]
//! implements [`actix_web::ResponseError`] (see [`crate::errors`]), actix
//! renders that error as the canonical `500` [`ErrorResponse`] envelope — the
//! same body shape every other endpoint produces (Req 47.6) — so addons keying
//! off the error contract are unaffected. This mirrors the actix idiom where a
//! middleware surfaces failures as `Error` and the `App` renders them.
//!
//! `async fn` handler bodies do not run until first polled, so a `panic!`
//! placed anywhere in a handler (before or after an `.await`) surfaces while
//! the future is being polled — inside the guard — not while it is being
//! constructed.

use std::future::{ready, Ready};
use std::panic::AssertUnwindSafe;
use std::rc::Rc;

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::{FutureExt, LocalBoxFuture};

use crate::errors::AppError;

/// Install the panic boundary as `App::wrap(PanicBoundary)` (or
/// `Scope::wrap`).
///
/// Register it as the **outermost** layer (after everything except a logger)
/// so it also catches panics raised inside other middleware's request
/// handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicBoundary;

impl<S, B> Transform<S, ServiceRequest> for PanicBoundary
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = PanicBoundaryService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PanicBoundaryService {
            service: Rc::new(service),
        }))
    }
}

/// The instantiated panic-boundary service produced by [`PanicBoundary`].
pub struct PanicBoundaryService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for PanicBoundaryService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // `AssertUnwindSafe` is sound here: on a caught panic we discard the
        // inner future's (possibly inconsistent) state entirely and synthesize
        // a fresh typed error, so no partially-mutated state is observed across
        // the boundary.
        AssertUnwindSafe(self.service.call(req))
            .catch_unwind()
            .map(|outcome| match outcome {
                // No panic: forward the downstream result verbatim (a normal
                // `Ok` response or an already-typed `Err`).
                Ok(result) => result,
                // A panic unwound to the boundary: isolate it to this request
                // and surface it as the canonical `500` typed error so the
                // worker survives and keeps serving others (Req 47.3, 50.8).
                Err(panic) => {
                    let detail = panic_message(&panic);
                    log_panic(&detail);
                    Err(AppError::unknown(format!(
                        "internal error: a request handler panicked ({detail})"
                    ))
                    .into())
                }
            })
            .boxed_local()
    }
}

/// Extract a best-effort human-readable message from a caught panic payload.
///
/// `panic!("msg")` yields a `&'static str`; `panic!("{}", x)` yields a
/// `String`; anything else is reported generically.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Emit a breadcrumb for a caught handler panic so it is never silent.
///
/// The structured-logging stack (`tracing-subscriber` + secret redaction)
/// lands in task 12.1; this stderr line is the minimal stand-in until then
/// (Req 50.14).
fn log_panic(detail: &str) {
    eprintln!("[panic-boundary] caught handler panic, returned 500: {detail}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorResponse;
    use actix_web::body::to_bytes;
    use actix_web::{test, web, App, HttpResponse};

    async fn ok_handler() -> HttpResponse {
        HttpResponse::Ok().body("alive")
    }

    async fn panic_before_await() -> HttpResponse {
        panic!("boom: panic before first await");
    }

    async fn panic_after_await() -> HttpResponse {
        // Yield once so the panic happens later in the poll, after the future
        // has already made progress past an await point.
        tokio::task::yield_now().await;
        panic!("boom: panic after await");
    }

    /// Drive a request through the app, rendering a boundary `Err` into the
    /// HTTP response actix would send a client (via the `ResponseError` impl).
    /// Returns `(status, body_bytes)`.
    ///
    /// `test::try_call_service` surfaces the typed `Err` instead of panicking
    /// (which `test::call_service` does), so the panic path is observable.
    async fn render<B>(result: Result<ServiceResponse<B>, Error>) -> (u16, web::Bytes)
    where
        B: actix_web::body::MessageBody,
    {
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = to_bytes(resp.into_body())
                    .await
                    .unwrap_or_else(|_| web::Bytes::new());
                (status, body)
            }
            Err(err) => {
                let resp = err.error_response();
                let status = resp.status().as_u16();
                let body = to_bytes(resp.into_body())
                    .await
                    .unwrap_or_else(|_| web::Bytes::new());
                (status, body)
            }
        }
    }

    #[actix_web::test]
    async fn panicking_handler_yields_500_with_canonical_error_envelope() {
        let app = test::init_service(
            App::new()
                .wrap(PanicBoundary)
                .route("/panic", web::get().to(panic_before_await)),
        )
        .await;

        let req = test::TestRequest::get().uri("/panic").to_request();
        let (status, body) = render(test::try_call_service(&app, req).await).await;
        assert_eq!(status, 500);

        // Body is the canonical ErrorResponse envelope with the `unknown` code.
        let decoded: ErrorResponse = serde_json::from_slice(&body).expect("canonical error body");
        assert_eq!(decoded.error.code, "unknown");
        assert!(decoded.error.message.contains("panicked"));
    }

    #[actix_web::test]
    async fn panic_after_await_is_also_caught() {
        let app = test::init_service(
            App::new()
                .wrap(PanicBoundary)
                .route("/panic", web::get().to(panic_after_await)),
        )
        .await;

        let req = test::TestRequest::get().uri("/panic").to_request();
        let (status, _) = render(test::try_call_service(&app, req).await).await;
        assert_eq!(status, 500);
    }

    #[actix_web::test]
    async fn concurrent_handler_returns_200_when_another_panics() {
        // Req 50.8 / 47.3: a per-request panic is isolated — a sibling request
        // through the same wrapped app still completes normally with 200.
        let app = test::init_service(
            App::new()
                .wrap(PanicBoundary)
                .route("/panic", web::get().to(panic_before_await))
                .route("/ok", web::get().to(ok_handler)),
        )
        .await;

        // The panicking request is contained as a 500...
        let panic_req = test::TestRequest::get().uri("/panic").to_request();
        let (panic_status, _) = render(test::try_call_service(&app, panic_req).await).await;
        assert_eq!(panic_status, 500);

        // ...while a healthy request through the same app returns 200 + body.
        let ok_req = test::TestRequest::get().uri("/ok").to_request();
        let (ok_status, ok_body) = render(test::try_call_service(&app, ok_req).await).await;
        assert_eq!(ok_status, 200);
        assert_eq!(&ok_body[..], b"alive");
    }

    #[actix_web::test]
    async fn process_survives_repeated_panics() {
        // The boundary catches each unwind rather than letting it abort the
        // worker, so many panics in a row never tear the process down — if a
        // panic escaped the guard, this test binary itself would abort.
        let app = test::init_service(
            App::new()
                .wrap(PanicBoundary)
                .route("/panic", web::get().to(panic_before_await)),
        )
        .await;

        for _ in 0..25 {
            let req = test::TestRequest::get().uri("/panic").to_request();
            let (status, _) = render(test::try_call_service(&app, req).await).await;
            assert_eq!(status, 500);
        }
    }

    #[actix_web::test]
    async fn non_panicking_handler_passes_through_unchanged() {
        let app = test::init_service(
            App::new()
                .wrap(PanicBoundary)
                .route("/ok", web::get().to(ok_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/ok").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
        let body = test::read_body(resp).await;
        assert_eq!(&body[..], b"alive");
    }
}
