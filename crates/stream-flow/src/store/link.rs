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
use crate::errors::{AppError};
use crate::proxy::range::RangeSpec;
use crate::proxy::source::{UpstreamBody, UpstreamSource};
use crate::store::fallback::StoreFallbackChain;
use crate::store::{GenerateLinkData, GenerateLinkParams, Ctx, Store, StoreName};

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
        self.total_size
            .try_read()
            .ok()
            .and_then(|guard| *guard)
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
            AppError::upstream_unavailable(
                format!("upstream request to {host} failed: {e}"),
            )
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
                                    let new_url =
                                        Url::parse(&data.link).map_err(|e| {
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
    use crate::errors::ErrorCategory;
    use crate::store::types::*;
    use crate::store::{Store, StoreName};
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;
    use time::OffsetDateTime;

    // -- Test helpers --------------------------------------------------------

    /// The Egress_IP used in tests (never a client IP).
    const EGRESS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    /// A mock store that records the `client_ip` passed to `generate_link`.
    struct RecordingStore {
        name: StoreName,
        recorded_ips: Mutex<Vec<Option<IpAddr>>>,
        call_count: AtomicU32,
        /// If set, generate_link returns this error.
        fail_with: Mutex<Option<AppError>>,
    }

    impl RecordingStore {
        fn new(name: StoreName) -> Self {
            Self {
                name,
                recorded_ips: Mutex::new(Vec::new()),
                call_count: AtomicU32::new(0),
                fail_with: Mutex::new(None),
            }
        }

        fn set_failure(&self, err: AppError) {
            *self.fail_with.lock().unwrap() = Some(err);
        }

        fn clear_failure(&self) {
            *self.fail_with.lock().unwrap() = None;
        }

        fn recorded_ips(&self) -> Vec<Option<IpAddr>> {
            self.recorded_ips.lock().unwrap().clone()
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }
