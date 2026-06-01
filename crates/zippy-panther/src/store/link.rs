//! Link generation with Egress-IP binding and `DebridSource` (`store::link`)
//! — Req 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 37.6, 51.4.
//!
//! This module provides:
//! * [`generate_link`] — resolves a store link into a time-limited direct link,
//!   binding IP-locked stores to the **Egress_IP** (never Client_IP) and omitting
//!   IP for non-IP-binding stores (Req 18.3, 18.4, 51.4).
//! * [`DebridSource`] — an [`UpstreamSource`] implementation wrapping a store +
//!   link + egress IP + fallback chain; its [`renew`](UpstreamSource::renew)
//!   transparently re-generates the link when it expires (Req 37.6), with
//!   one-time Egress-IP regen on IP rejection (Req 18.6) and fallback chain
//!   walking on primary failure (Req 37.7, 20.2).

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use url::Url;

use crate::egress::OutboundClient;
use crate::errors::AppError;
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{UpstreamBody, UpstreamSource};
use crate::store::fallback::StoreFallbackChain;
use crate::store::{Ctx, GenerateLinkData, GenerateLinkParams, Store, StoreName};

/// Stores that bind direct links to the requesting IP (Req 18.3).
/// These stores MUST receive the Egress_IP on link generation.
const IP_LOCKED_STORES: &[StoreName] = &[StoreName::RealDebrid, StoreName::TorBox];

/// Whether a store requires IP binding for link generation (Req 18.3, 18.4).
///
/// IP-locked stores (RealDebrid, TorBox) bind the direct link to the IP that
/// requested it; non-IP-binding stores (AllDebrid, Offcloud, etc.) ignore the
/// IP parameter entirely.
pub fn requires_ip_binding(store: StoreName) -> bool {
    IP_LOCKED_STORES.contains(&store)
}

/// Generate a direct link from a store, binding to the Egress_IP for IP-locked
/// stores and omitting IP for non-IP-binding stores (Req 18.1, 18.3, 18.4, 51.4).
///
/// The `egress_ip` parameter is the system's tunnel-observed public IP — it is
/// **never** the user's Client_IP (Req 51.4). For IP-locked stores it is passed
/// as `client_ip` in [`GenerateLinkParams`]; for non-IP-binding stores it is
/// omitted so the call does not fail due to absence of IP binding (Req 18.4).
///
/// On IP-restriction rejection (Req 18.6), the caller should retry once with a
/// refreshed Egress_IP via [`generate_link_with_retry`].
pub async fn generate_link(
    store: &dyn Store,
    link: &str,
    egress_ip: Option<IpAddr>,
    ctx: &Ctx,
) -> Result<GenerateLinkData, AppError> {
    let store_name = store.get_name();
    let client_ip = if requires_ip_binding(store_name) {
        egress_ip
    } else {
        None // Non-IP-binding stores omit IP (Req 18.4)
    };

    store
        .generate_link(&GenerateLinkParams {
            ctx: ctx.clone(),
            link: link.to_string(),
            client_ip,
        })
        .await
}

/// Generate a direct link with one-time retry on IP-restriction rejection
/// (Req 18.6).
///
/// If the store rejects the link as IP-restricted, this function calls
/// `refresh_egress_ip` to obtain the current Egress_IP and retries once.
/// If the retry also fails, or if the rejection is for a non-IP reason,
/// the error is returned mapped to the canonical taxonomy (Req 18.7).
pub async fn generate_link_with_retry<F, Fut>(
    store: &dyn Store,
    link: &str,
    egress_ip: Option<IpAddr>,
    ctx: &Ctx,
    refresh_egress_ip: F,
) -> Result<GenerateLinkData, AppError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<IpAddr>>,
{
    match generate_link(store, link, egress_ip, ctx).await {
        Ok(data) => Ok(data),
        Err(err) if err.ip_restricted => {
            // One-time Egress-IP regen on IP rejection (Req 18.6)
            let refreshed_ip = refresh_egress_ip().await;
            generate_link(store, link, refreshed_ip, ctx).await
        }
        Err(err) => {
            // Non-IP rejection → return error with store reason (Req 18.7)
            Err(err)
        }
    }
}

/// A debrid-backed [`UpstreamSource`] that wraps a store + link + egress IP +
/// fallback chain (design: Components → Streaming Core → DebridSource).
///
/// Its [`renew`](UpstreamSource::renew) transparently re-generates the link
/// when it expires (Req 37.6), with one-time Egress-IP regen on IP rejection
/// (Req 18.6) and fallback chain walking on primary failure (Req 37.7, 20.2).
/// It obtains its HTTP client exclusively from [`OutboundClient`] so all debrid
/// traffic is tunneled and client-IP-stripped (Req 51).
pub struct DebridSource {
    /// The outbound client seam (Req 51.1).
    client: Arc<OutboundClient>,
    /// The primary store to generate links from.
    store: Arc<dyn Store>,
    /// The store link to resolve (the magnet file's store-side link).
    store_link: String,
    /// The current direct link (refreshed on renew).
    current_link: RwLock<Url>,
    /// The fallback chain for multi-store failover (Req 37.7, 20.2).
    fallback_chain: Option<Arc<StoreFallbackChain>>,
    /// Per-request context for store calls.
    ctx: Ctx,
    /// Probed total size (set after first open).
    total_size: RwLock<Option<u64>>,
    /// Probed content type (set after first open).
    content_type: RwLock<Option<String>>,
    /// Whether the upstream supports range requests.
    accept_ranges: RwLock<bool>,
}

impl DebridSource {
    /// Create a new [`DebridSource`] from a store, its resolved direct link,
    /// and the store link used to generate it.
    pub fn new(
        client: Arc<OutboundClient>,
        store: Arc<dyn Store>,
        store_link: String,
        direct_link: Url,
        ctx: Ctx,
    ) -> Self {
        Self {
            client,
            store,
            store_link,
            current_link: RwLock::new(direct_link),
            fallback_chain: None,
            ctx,
            total_size: RwLock::new(None),
            content_type: RwLock::new(None),
            accept_ranges: RwLock::new(false),
        }
    }

    /// Attach a fallback chain for multi-store failover (Req 37.7, 20.2).
    pub fn with_fallback_chain(mut self, chain: Arc<StoreFallbackChain>) -> Self {
        self.fallback_chain = Some(chain);
        self
    }

    /// The current direct link URL.
    pub async fn current_link(&self) -> Url {
        self.current_link.read().await.clone()
    }

    /// The Egress_IP used for link binding (Req 18.3, 51.4).
    fn egress_ip(&self) -> Option<IpAddr> {
        self.client.egress_ip()
    }
}

#[async_trait]
impl UpstreamSource for DebridSource {
    fn total_size(&self) -> Option<u64> {
        // Use try_read to avoid blocking; return None if locked.
        self.total_size.try_read().ok().and_then(|guard| *guard)
    }

    fn content_type(&self) -> Option<&str> {
        // UpstreamSource requires &str lifetime tied to &self.
        // We cannot return a reference from RwLock, so return None here.
        // The proxy core will use the content_type from the UpstreamBody instead.
        None
    }

    fn accept_ranges(&self) -> bool {
        self.accept_ranges
            .try_read()
            .ok()
            .map(|guard| *guard)
            .unwrap_or(false)
    }

    async fn open(&self, range: RangeSpec) -> Result<UpstreamBody, AppError> {
        let url = self.current_link.read().await.clone();
        let mut builder = self.client.upstream(reqwest::Method::GET, &url)?;

        // Translate range to upstream Range header
        if let Some(value) = range_header_value(range) {
            builder = builder.header(reqwest::header::RANGE, value);
        }

        let resp = builder.send().await.map_err(|e| {
            let host = url.host_str().unwrap_or("<unknown>");
            AppError::upstream_unavailable(format!("upstream request to {host} failed: {e}"))
        })?;

        let body = UpstreamBody::from_response(resp);

        // Cache metadata from first successful open
        if let Some(size) = body.content_length {
            let mut ts = self.total_size.write().await;
            if ts.is_none() {
                *ts = Some(size);
            }
        }
        if body.accept_ranges {
            let mut ar = self.accept_ranges.write().await;
            *ar = true;
        }

        Ok(body)
    }

    /// Re-generate the link transparently (Req 37.6).
    ///
    /// On IP-restriction, regenerates bound to the current Egress_IP one time
    /// (Req 18.6). On primary store failure, walks the configured fallback
    /// chain (Req 37.7, 20.2).
    async fn renew(&self) -> Result<(), AppError> {
        let egress_ip = self.egress_ip();

        // Try primary store with one-time IP-regen retry
        let result = generate_link_with_retry(
            self.store.as_ref(),
            &self.store_link,
            egress_ip,
            &self.ctx,
            || async { self.client.egress_ip() },
        )
        .await;

        match result {
            Ok(data) => {
                let new_url = Url::parse(&data.link).map_err(|e| {
                    AppError::unknown(format!("store returned invalid link URL: {e}"))
                })?;
                *self.current_link.write().await = new_url;
                Ok(())
            }
            Err(primary_err) => {
                // Walk fallback chain on primary failure (Req 37.7, 20.2)
                if let Some(chain) = &self.fallback_chain {
                    chain.record_failure(self.store.get_name(), &primary_err);
                    match chain.next_healthy() {
                        Ok((_, fallback_store)) => {
                            let fallback_result = generate_link_with_retry(
                                fallback_store.as_ref(),
                                &self.store_link,
                                egress_ip,
                                &self.ctx,
                                || async { self.client.egress_ip() },
                            )
                            .await;
                            match fallback_result {
                                Ok(data) => {
                                    let new_url = Url::parse(&data.link).map_err(|e| {
                                        AppError::unknown(format!(
                                            "fallback store returned invalid link URL: {e}"
                                        ))
                                    })?;
                                    *self.current_link.write().await = new_url;
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(_) => Err(primary_err),
                    }
                } else {
                    Err(primary_err)
                }
            }
        }
    }
}

/// Translate a [`RangeSpec`] into the `Range` header value to forward upstream,
/// or `None` for [`RangeSpec::Full`] (no header → full body).
fn range_header_value(range: RangeSpec) -> Option<String> {
    match range {
        RangeSpec::Full => None,
        RangeSpec::FromOffset(start) => Some(format!("bytes={start}-")),
        RangeSpec::Inclusive(start, end) => Some(format!("bytes={start}-{end}")),
        RangeSpec::Suffix(n) => Some(format!("bytes=-{n}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EgressPolicy;
    use crate::errors::ErrorCategory;
    use crate::resilience::BreakerConfig;
    use crate::store::fallback::StoreBreakerSet;
    use crate::store::types::*;
    use std::collections::{HashMap, VecDeque};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;
    use time::OffsetDateTime;

    // -- Test seam helpers ---------------------------------------------------

    /// A no-tunnel, fail-open [`OutboundClient`] whose
    /// [`egress_ip`](OutboundClient::egress_ip) is `None` (no resolver
    /// attached). Building the clients performs no network I/O, matching the
    /// crate's `OutboundClient::new(...)` test-client pattern.
    fn outbound_no_egress() -> Arc<OutboundClient> {
        Arc::new(OutboundClient::new(
            reqwest::Client::new(),
            wreq::Client::new(),
            EgressPolicy::FailOpen,
            None,
            None,
            HashMap::new(),
        ))
    }

    /// A fail-open [`OutboundClient`] with a verified resolver, so
    /// [`egress_ip`](OutboundClient::egress_ip) returns `Some(egress)` — the
    /// tunnel-observed public IP, never any Client_IP (Req 51.4). Built from
    /// the crate's mock reflector so there is no network dependency.
    async fn outbound_with_egress(egress: &str, host: &str) -> Arc<OutboundClient> {
        use crate::egress::tunnel::test_support::MockReflector;
        use crate::egress::{EgressResolver, Tunnel};

        let tunnel = Tunnel::proxy(
            "http://proxy:8888",
            Arc::new(MockReflector::isolated(egress, host)),
        );
        let resolver = Arc::new(EgressResolver::new(
            Arc::new(tunnel),
            Duration::from_secs(3600),
        ));
        // Populate the lock-free cache so `egress_ip()` is `Some(egress)`.
        resolver.refresh().await;
        Arc::new(OutboundClient::new(
            reqwest::Client::new(),
            wreq::Client::new(),
            EgressPolicy::FailOpen,
            Some(resolver),
            None,
            HashMap::new(),
        ))
    }

    /// A request context that carries a Client_IP — used to prove the link-gen
    /// layer never forwards it to a store (Req 51.4).
    fn ctx() -> Ctx {
        Ctx {
            request_id: "test-req".into(),
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            trusted: false,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid IP")
    }

    /// One scripted outcome for a [`RecordingStore::generate_link`] call.
    enum Outcome {
        /// Succeed, returning this direct link.
        Link(String),
        /// Reject as IP-restricted (sets the `ip_restricted` marker, Req 18.6).
        IpRestricted,
        /// Reject for a non-IP reason carrying the store name (Req 18.7).
        Unauthorized,
        /// Reject as upstream-unavailable (drives the fallback chain, Req 37.7).
        Upstream,
    }

    /// A [`Store`] that records the `client_ip` it receives on every
    /// `generate_link` call and replays a scripted queue of outcomes. Only
    /// `generate_link` / `get_name` are exercised; the other operations are
    /// trivial stubs so the trait is fully implemented and object-safe.
    struct RecordingStore {
        name: StoreName,
        received: Mutex<Vec<Option<IpAddr>>>,
        outcomes: Mutex<VecDeque<Outcome>>,
    }

    impl RecordingStore {
        fn new(name: StoreName, outcomes: Vec<Outcome>) -> Arc<Self> {
            Arc::new(Self {
                name,
                received: Mutex::new(Vec::new()),
                outcomes: Mutex::new(VecDeque::from(outcomes)),
            })
        }

        /// The `client_ip` values passed to `generate_link`, in call order.
        fn received_ips(&self) -> Vec<Option<IpAddr>> {
            self.received.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Store for RecordingStore {
        fn get_name(&self) -> StoreName {
            self.name
        }

        async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
            Ok(User {
                id: "u1".into(),
                email: "t@t.com".into(),
                subscription_status: SubscriptionStatus::Premium,
                has_usenet: false,
            })
        }

        async fn check_magnet(
            &self,
            _p: &CheckMagnetParams<'_>,
        ) -> Result<CheckMagnetData, AppError> {
            Ok(CheckMagnetData { items: vec![] })
        }

        async fn add_magnet(&self, _p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
            Ok(AddMagnetData {
                id: "m1".into(),
                hash: "abc".into(),
                magnet: "magnet:?xt=urn:btih:abc".into(),
                name: "t".into(),
                size: 1,
                status: MagnetStatus::Queued,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn get_magnet(&self, _p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
            Ok(GetMagnetData {
                id: "m1".into(),
                name: "t".into(),
                hash: "abc".into(),
                size: 1,
                status: MagnetStatus::Cached,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn list_magnets(&self, _p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
            Ok(ListMagnetsData {
                items: vec![],
                total_items: 0,
            })
        }

        async fn remove_magnet(
            &self,
            _p: &RemoveMagnetParams,
        ) -> Result<RemoveMagnetData, AppError> {
            Ok(RemoveMagnetData { id: "m1".into() })
        }

        async fn generate_link(
            &self,
            p: &GenerateLinkParams,
        ) -> Result<GenerateLinkData, AppError> {
            // Record exactly what IP (if any) the link-gen layer bound the call
            // to — the heart of the Egress-IP-vs-omitted assertions.
            self.received.lock().unwrap().push(p.client_ip);
            match self.outcomes.lock().unwrap().pop_front() {
                Some(Outcome::Link(link)) => Ok(GenerateLinkData { link }),
                Some(Outcome::IpRestricted) => Err(AppError::ip_restricted_for(
                    self.name.as_str(),
                    "IP not allowed",
                )),
                Some(Outcome::Unauthorized) => {
                    Err(AppError::unauthorized_for(self.name.as_str(), "bad token"))
                }
                Some(Outcome::Upstream) => Err(AppError::upstream_unavailable_for(
                    self.name.as_str(),
                    "service unavailable",
                )),
                // Default when the script is exhausted: a stable success.
                None => Ok(GenerateLinkData {
                    link: "https://cdn.example/default.mkv".into(),
                }),
            }
        }
    }

    fn breaker_set() -> Arc<StoreBreakerSet> {
        Arc::new(StoreBreakerSet::new(
            BreakerConfig::new(3, Duration::from_secs(15)),
            Duration::from_secs(300),
        ))
    }

    // -- requires_ip_binding (Req 18.3, 18.4) -------------------------------

    #[test]
    fn requires_ip_binding_is_true_only_for_realdebrid_and_torbox() {
        // IP-locked stores bind the link to the requesting IP (Req 18.3).
        assert!(requires_ip_binding(StoreName::RealDebrid));
        assert!(requires_ip_binding(StoreName::TorBox));

        // Every other store omits the IP and must not fail for its absence
        // (Req 18.4).
        for name in [
            StoreName::AllDebrid,
            StoreName::Debrider,
            StoreName::DebridLink,
            StoreName::EasyDebrid,
            StoreName::Offcloud,
            StoreName::PikPak,
            StoreName::Premiumize,
        ] {
            assert!(!requires_ip_binding(name), "{name:?} must not bind IP");
        }
    }

    // -- generate_link binds Egress_IP for IP-locked stores (Req 18.3, 51.4) -

    #[tokio::test]
    async fn generate_link_passes_egress_ip_for_ip_locked_store() {
        let egress = ip("203.0.113.7");
        let store = RecordingStore::new(
            StoreName::RealDebrid,
            vec![Outcome::Link("https://cdn.example/file.mkv".into())],
        );

        let data = generate_link(store.as_ref(), "https://store/dl/1", Some(egress), &ctx())
            .await
            .expect("link gen succeeds");

        assert_eq!(data.link, "https://cdn.example/file.mkv");
        // The Egress_IP — never a Client_IP — was bound at the store (Req 51.4).
        assert_eq!(store.received_ips(), vec![Some(egress)]);
    }

    #[tokio::test]
    async fn generate_link_passes_egress_ip_for_torbox_too() {
        let egress = ip("198.51.100.42");
        let store = RecordingStore::new(StoreName::TorBox, vec![]);

        generate_link(store.as_ref(), "https://store/dl/2", Some(egress), &ctx())
            .await
            .expect("link gen succeeds");

        assert_eq!(store.received_ips(), vec![Some(egress)]);
    }

    #[tokio::test]
    async fn generate_link_never_forwards_client_ip_to_store() {
        // Even though the Ctx carries a Client_IP, only the Egress_IP is bound
        // at the store (Req 51.4). The Ctx Client_IP must never appear.
        let egress = ip("203.0.113.7");
        let store = RecordingStore::new(StoreName::RealDebrid, vec![]);
        let ctx = ctx();
        let client_ip = ctx.client_ip.unwrap();

        generate_link(store.as_ref(), "https://store/dl/c", Some(egress), &ctx)
            .await
            .expect("link gen succeeds");

        let ips = store.received_ips();
        assert_eq!(ips, vec![Some(egress)]);
        assert_ne!(
            ips[0],
            Some(client_ip),
            "Client_IP must never reach the store"
        );
    }

    // -- generate_link omits the IP for non-IP-binding stores (Req 18.4) -----

    #[tokio::test]
    async fn generate_link_omits_ip_for_non_ip_binding_store_even_when_egress_known() {
        let egress = ip("203.0.113.7");
        let store = RecordingStore::new(StoreName::AllDebrid, vec![]);

        // An Egress_IP is available, but a non-IP-binding store must still get
        // `None` so the IP is never bound (Req 18.4).
        generate_link(store.as_ref(), "https://store/dl/3", Some(egress), &ctx())
            .await
            .expect("non-IP store link gen succeeds");

        assert_eq!(store.received_ips(), vec![None]);
    }

    #[tokio::test]
    async fn generate_link_non_ip_store_does_not_fail_when_egress_ip_absent() {
        // Req 18.4: absence of IP binding must not, by itself, fail link gen.
        let store = RecordingStore::new(StoreName::Offcloud, vec![]);

        let data = generate_link(store.as_ref(), "https://store/dl/4", None, &ctx())
            .await
            .expect("must not fail solely for lack of IP binding");

        assert_eq!(data.link, "https://cdn.example/default.mkv");
        assert_eq!(store.received_ips(), vec![None]);
    }

    // -- generate_link_with_retry: success on the first attempt -------------

    #[tokio::test]
    async fn generate_link_with_retry_succeeds_without_refresh_on_first_try() {
        let store = RecordingStore::new(
            StoreName::RealDebrid,
            vec![Outcome::Link("https://cdn.example/ok.mkv".into())],
        );
        let refreshed = AtomicBool::new(false);

        let data = generate_link_with_retry(
            store.as_ref(),
            "https://store/dl/ok",
            Some(ip("203.0.113.7")),
            &ctx(),
            || async {
                refreshed.store(true, Ordering::SeqCst);
                Some(ip("203.0.113.99"))
            },
        )
        .await
        .expect("first attempt succeeds");

        assert_eq!(data.link, "https://cdn.example/ok.mkv");
        assert!(
            !refreshed.load(Ordering::SeqCst),
            "no refresh when the first try works"
        );
        assert_eq!(store.received_ips().len(), 1);
    }

    // -- generate_link_with_retry: one-time Egress-IP regen (Req 18.6) -------

    #[tokio::test]
    async fn generate_link_with_retry_regenerates_once_with_refreshed_egress_ip() {
        let first_ip = ip("203.0.113.7");
        let refreshed_ip = ip("203.0.113.99");
        // First attempt is IP-rejected; the retry (with the refreshed IP)
        // succeeds.
        let store = RecordingStore::new(
            StoreName::RealDebrid,
            vec![
                Outcome::IpRestricted,
                Outcome::Link("https://cdn.example/after-regen.mkv".into()),
            ],
        );

        let refreshed = AtomicBool::new(false);
        let data = generate_link_with_retry(
            store.as_ref(),
            "https://store/dl/5",
            Some(first_ip),
            &ctx(),
            || async {
                refreshed.store(true, Ordering::SeqCst);
                Some(refreshed_ip)
            },
        )
        .await
        .expect("retry with refreshed Egress_IP succeeds");

        assert_eq!(data.link, "https://cdn.example/after-regen.mkv");
        assert!(
            refreshed.load(Ordering::SeqCst),
            "the refresh closure ran once"
        );
        // Exactly two attempts: the original IP, then the refreshed Egress_IP.
        assert_eq!(
            store.received_ips(),
            vec![Some(first_ip), Some(refreshed_ip)]
        );
    }

    // -- generate_link_with_retry: non-IP error returns without retry (18.7) -

    #[tokio::test]
    async fn generate_link_with_retry_returns_non_ip_error_without_retrying() {
        let store = RecordingStore::new(StoreName::RealDebrid, vec![Outcome::Unauthorized]);

        let refreshed = AtomicBool::new(false);
        let err = generate_link_with_retry(
            store.as_ref(),
            "https://store/dl/6",
            Some(ip("203.0.113.7")),
            &ctx(),
            || async {
                refreshed.store(true, Ordering::SeqCst);
                Some(ip("203.0.113.99"))
            },
        )
        .await
        .expect_err("a non-IP rejection must surface as an error");

        // Mapped onto the canonical taxonomy and carries the store reason
        // (Req 18.7).
        assert_eq!(err.category, ErrorCategory::Unauthorized);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        assert!(
            !refreshed.load(Ordering::SeqCst),
            "no IP refresh on a non-IP error"
        );
        // Only the single original attempt was made (no retry).
        assert_eq!(store.received_ips().len(), 1);
    }

    // -- DebridSource trait surface (initial state) -------------------------

    #[tokio::test]
    async fn debrid_source_reports_unknown_metadata_before_first_open() {
        let client = outbound_no_egress();
        let store = RecordingStore::new(StoreName::RealDebrid, vec![]);
        let source = DebridSource::new(
            client,
            store as Arc<dyn Store>,
            "https://store/dl/meta".into(),
            Url::parse("https://cdn.example/file.mkv").unwrap(),
            ctx(),
        );

        assert_eq!(source.total_size(), None);
        assert!(!source.accept_ranges());
        // content_type is intentionally None (served from UpstreamBody instead).
        assert_eq!(source.content_type(), None);
    }

    // -- DebridSource::current_link / renew re-generates the link (Req 37.6) -

    #[tokio::test]
    async fn debrid_source_exposes_initial_link_then_renew_replaces_it() {
        let client = outbound_with_egress("203.0.113.7", "198.51.100.1").await;
        let store = RecordingStore::new(
            StoreName::RealDebrid,
            vec![Outcome::Link("https://cdn.example/fresh.mkv".into())],
        );
        let source = DebridSource::new(
            client,
            store.clone() as Arc<dyn Store>,
            "https://store/dl/7".into(),
            Url::parse("https://cdn.example/stale.mkv").unwrap(),
            ctx(),
        );

        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/stale.mkv"
        );

        source.renew().await.expect("renew re-generates the link");

        // The link was transparently regenerated (Req 37.6) …
        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/fresh.mkv"
        );
        // … bound to the verified Egress_IP for this IP-locked store (Req 18.3).
        assert_eq!(store.received_ips(), vec![Some(ip("203.0.113.7"))]);
    }

    // -- renew: one-time Egress-IP regen on IP rejection inside renew (18.6) -

    #[tokio::test]
    async fn debrid_source_renew_regenerates_on_ip_rejection_one_time() {
        let client = outbound_with_egress("203.0.113.7", "198.51.100.1").await;
        let store = RecordingStore::new(
            StoreName::RealDebrid,
            vec![
                Outcome::IpRestricted,
                Outcome::Link("https://cdn.example/regen.mkv".into()),
            ],
        );
        let source = DebridSource::new(
            client,
            store.clone() as Arc<dyn Store>,
            "https://store/dl/8".into(),
            Url::parse("https://cdn.example/stale.mkv").unwrap(),
            ctx(),
        );

        source
            .renew()
            .await
            .expect("renew retries once and succeeds");

        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/regen.mkv"
        );
        // Both attempts bound to the current Egress_IP (the one-time regen).
        assert_eq!(
            store.received_ips(),
            vec![Some(ip("203.0.113.7")), Some(ip("203.0.113.7"))]
        );
    }

    // -- renew on a non-IP-binding store omits the IP (Req 18.4) ------------

    #[tokio::test]
    async fn debrid_source_renew_omits_ip_for_non_ip_binding_store() {
        let client = outbound_with_egress("203.0.113.7", "198.51.100.1").await;
        let store = RecordingStore::new(
            StoreName::AllDebrid,
            vec![Outcome::Link("https://cdn.example/ad.mkv".into())],
        );
        let source = DebridSource::new(
            client,
            store.clone() as Arc<dyn Store>,
            "https://store/dl/ad".into(),
            Url::parse("https://cdn.example/stale.mkv").unwrap(),
            ctx(),
        );

        source
            .renew()
            .await
            .expect("renew succeeds for non-IP store");

        // Even though a verified Egress_IP exists, a non-IP-binding store gets
        // `None` (Req 18.4).
        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/ad.mkv"
        );
        assert_eq!(store.received_ips(), vec![None]);
    }

    // -- renew: walks the fallback chain on primary failure (Req 37.7, 37.6) -

    #[tokio::test]
    async fn debrid_source_renew_walks_fallback_chain_on_primary_failure() {
        let client = outbound_no_egress();

        // Primary store fails with an upstream error (not IP-restricted → no
        // retry), forcing the fallback chain to be consulted.
        let primary = RecordingStore::new(StoreName::RealDebrid, vec![Outcome::Upstream]);
        // The fallback store generates a fresh link successfully.
        let fallback = RecordingStore::new(
            StoreName::AllDebrid,
            vec![Outcome::Link("https://cdn.example/fallback.mkv".into())],
        );

        let chain = Arc::new(StoreFallbackChain::new(
            vec![(StoreName::AllDebrid, fallback.clone() as Arc<dyn Store>)],
            breaker_set(),
        ));

        let source = DebridSource::new(
            client,
            primary.clone() as Arc<dyn Store>,
            "https://store/dl/9".into(),
            Url::parse("https://cdn.example/stale.mkv").unwrap(),
            ctx(),
        )
        .with_fallback_chain(chain);

        source
            .renew()
            .await
            .expect("renew falls back to the next store");

        // The fallback store's fresh link is now current (Req 37.7).
        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/fallback.mkv"
        );
        assert_eq!(
            primary.received_ips().len(),
            1,
            "primary tried exactly once"
        );
        assert_eq!(
            fallback.received_ips().len(),
            1,
            "fallback tried exactly once"
        );
    }

    // -- renew: no fallback chain → primary failure surfaces (Req 37.6) ------

    #[tokio::test]
    async fn debrid_source_renew_without_chain_returns_primary_error() {
        let client = outbound_no_egress();
        let store = RecordingStore::new(StoreName::RealDebrid, vec![Outcome::Upstream]);
        let source = DebridSource::new(
            client,
            store.clone() as Arc<dyn Store>,
            "https://store/dl/10".into(),
            Url::parse("https://cdn.example/stale.mkv").unwrap(),
            ctx(),
        );

        let err = source
            .renew()
            .await
            .expect_err("with no fallback chain the primary error must surface");
        assert_eq!(err.category, ErrorCategory::UpstreamUnavailable);
        assert_eq!(err.store.as_deref(), Some("realdebrid"));
        // The current link is left untouched on a failed renew.
        assert_eq!(
            source.current_link().await.as_str(),
            "https://cdn.example/stale.mkv"
        );
    }
}
