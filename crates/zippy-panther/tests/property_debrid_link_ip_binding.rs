//! Property-based test for debrid link IP-binding (`store::link`, task 24.8).
//!
//! Feature: stream-flow, Property 61
//!
//! **Property 61: Debrid link IP-binding uses the Egress_IP, never the
//! Client_IP**
//!
//! *For any* user `Client_IP` and any resolved `Egress_IP` with
//! `Client_IP ≠ Egress_IP`, the IP value supplied to a link-binding store on
//! `generate_link` equals the `Egress_IP` and is never equal to the
//! `Client_IP`; for non-IP-binding stores no IP is supplied; and in no case is
//! the `Client_IP` passed to the store.
//!
//! **Validates: Requirements 51.4, 18.3**
//!
//! Requirement 18.3: IP-locked stores (RealDebrid, TorBox) bind the generated
//! direct link to the **Egress_IP** — never the user's Client_IP.
//!
//! Requirement 18.4: stores that do not require IP binding omit the IP entirely
//! and must not fail for its absence.
//!
//! Requirement 51.4: the only IP ever bound to a store link is the
//! tunnel-observed Egress_IP; the inbound Client_IP carried on the per-request
//! [`Ctx`] is used for internal bookkeeping only and must NEVER be forwarded to
//! a store.
//!
//! The unit under test is [`stream_flow::store::link`]:
//! [`generate_link`] (the IP-binding decision) and [`requires_ip_binding`]
//! (the per-store predicate). [`generate_link`] takes `&dyn Store` directly, so
//! no [`OutboundClient`](stream_flow::egress::OutboundClient) is needed here —
//! the property is purely about which IP the link-gen layer hands to the store.
//!
//! ## How the invariants are exercised
//!
//! Each case generates:
//!
//! * an arbitrary store (any of the nine [`StoreName::ALL`]),
//! * an arbitrary resolved `Egress_IP` (IPv4 or IPv6), and
//! * an arbitrary `Ctx.client_ip` that is **distinct** from the `Egress_IP`
//!   (the property's `Client_IP ≠ Egress_IP` precondition), supplied either as
//!   `Some(client_ip)` or `None`.
//!
//! It then drives [`generate_link`] against a [`RecordingStore`] that captures
//! the `client_ip` it actually received, and asserts the three guarantees:
//!
//! 1. **IP-locked stores (Req 18.3, 51.4):** the store receives exactly the
//!    `Egress_IP`.
//! 2. **Non-IP-binding stores (Req 18.4):** the store receives `None`.
//! 3. **Client_IP never leaks (Req 51.4):** in no case does the store receive
//!    the `Ctx.client_ip`.
//!
//! The "which stores bind" decision is checked against an **independent**
//! reference set (`{RealDebrid, TorBox}`) so the assertion is an external
//! oracle rather than the same `requires_ip_binding` logic under test; the test
//! additionally asserts `requires_ip_binding` agrees with that reference.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use async_trait::async_trait;
use proptest::prelude::*;
use time::OffsetDateTime;

use stream_flow::errors::AppError;
use stream_flow::store::link::{generate_link, requires_ip_binding};
use stream_flow::store::{
    AddMagnetData, AddMagnetParams, CheckMagnetData, CheckMagnetParams, Ctx, GenerateLinkData,
    GenerateLinkParams, GetMagnetData, GetMagnetParams, GetUserParams, ListMagnetsData,
    ListMagnetsParams, MagnetStatus, RemoveMagnetData, RemoveMagnetParams, Store, StoreName,
    SubscriptionStatus, User,
};

// ---------------------------------------------------------------------------
// Independent reference: the documented IP-locked store set (Req 18.3).
// ---------------------------------------------------------------------------

/// The stores that bind direct links to the requesting IP, per Req 18.3 /
/// 51.4. This is an **independent** restatement of the spec contract (not a
/// call into the production `requires_ip_binding`) so it can serve as the
/// oracle for the property.
fn ref_requires_ip_binding(store: StoreName) -> bool {
    matches!(store, StoreName::RealDebrid | StoreName::TorBox)
}

// ---------------------------------------------------------------------------
// RecordingStore — captures the `client_ip` passed to `generate_link`.
// ---------------------------------------------------------------------------

/// A [`Store`] that records the `client_ip` it receives on every
/// `generate_link` call and otherwise returns trivial successes. Mirrors the
/// `RecordingStore` / `MockStore` pattern in `src/store/link.rs` and
/// `src/store/fallback.rs`; only `generate_link` / `get_name` are exercised,
/// the rest are stubs so the trait is fully implemented and object-safe.
struct RecordingStore {
    name: StoreName,
    received: Mutex<Vec<Option<IpAddr>>>,
}

impl RecordingStore {
    fn new(name: StoreName) -> Self {
        Self {
            name,
            received: Mutex::new(Vec::new()),
        }
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

    async fn check_magnet(&self, _p: &CheckMagnetParams<'_>) -> Result<CheckMagnetData, AppError> {
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

    async fn remove_magnet(&self, _p: &RemoveMagnetParams) -> Result<RemoveMagnetData, AppError> {
        Ok(RemoveMagnetData { id: "m1".into() })
    }

    async fn generate_link(&self, p: &GenerateLinkParams) -> Result<GenerateLinkData, AppError> {
        // Record exactly what IP (if any) the link-gen layer bound the call to
        // — the heart of the Egress-IP-vs-omitted assertions.
        self.received.lock().unwrap().push(p.client_ip);
        Ok(GenerateLinkData {
            link: "https://cdn.example/file.mkv".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// All nine stores, in declaration order.
const ALL_STORES: [StoreName; 9] = StoreName::ALL;

/// Arbitrary IP — both IPv4 and IPv6 so the Egress_IP / Client_IP comparisons
/// are exercised across the whole address space.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
        any::<u128>().prop_map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
    ]
}

/// A `(egress_ip, client_ip)` pair guaranteed **distinct** (the property's
/// `Client_IP ≠ Egress_IP` precondition).
fn arb_distinct_ips() -> impl Strategy<Value = (IpAddr, IpAddr)> {
    (arb_ip(), arb_ip()).prop_filter("Client_IP must differ from Egress_IP", |(e, c)| e != c)
}

/// A request context carrying the supplied `client_ip` (or none). The
/// `client_ip` here must never reach a store (Req 51.4).
fn ctx_with(client_ip: Option<IpAddr>) -> Ctx {
    Ctx {
        request_id: "prop-req".into(),
        client_ip,
        trusted: false,
    }
}

// ---------------------------------------------------------------------------
// Per-case current-thread runtime (proptest cases are synchronous).
// ---------------------------------------------------------------------------

/// Build a per-case current-thread Tokio runtime, mirroring the other async
/// property tests in this crate. `generate_link` is `async` but performs no
/// real I/O against the `RecordingStore`, so a single-threaded runtime fully
/// and deterministically drives the property.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime must build")
}

// ---------------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 61 — debrid link IP-binding uses the
    /// Egress_IP, never the Client_IP.
    ///
    /// **Validates: Requirements 51.4, 18.3**
    #[test]
    fn debrid_link_binds_egress_ip_never_client_ip(
        store_idx in 0usize..ALL_STORES.len(),
        (egress_ip, client_ip) in arb_distinct_ips(),
        supply_client_ip in any::<bool>(),
    ) {
        let store_name = ALL_STORES[store_idx];
        // The Ctx may or may not carry a Client_IP; either way it must never
        // be forwarded to the store (Req 51.4).
        let ctx_client_ip = if supply_client_ip { Some(client_ip) } else { None };

        let rt = runtime();
        let outcome: Result<(), TestCaseError> = rt.block_on(async {
            let store = RecordingStore::new(store_name);
            let ctx = ctx_with(ctx_client_ip);

            // Drive the link-gen layer with the *resolved* Egress_IP. This is
            // the only IP the system should ever bind — never the Client_IP.
            generate_link(&store, "https://store/dl/1", Some(egress_ip), &ctx)
                .await
                .expect("link generation succeeds for any store");

            let received = store.received_ips();
            prop_assert_eq!(
                received.len(),
                1,
                "generate_link must invoke the store exactly once",
            );
            let bound = received[0];

            // The production predicate must agree with the independent
            // reference set {RealDebrid, TorBox} (Req 18.3).
            let ref_binds = ref_requires_ip_binding(store_name);
            prop_assert_eq!(
                requires_ip_binding(store_name),
                ref_binds,
                "requires_ip_binding({:?}) must match the documented IP-locked set",
                store_name,
            );

            if ref_binds {
                // Guarantee 1 — IP-locked stores get exactly the Egress_IP
                // (Req 18.3, 51.4).
                prop_assert_eq!(
                    bound,
                    Some(egress_ip),
                    "IP-locked store {:?} must be bound to the Egress_IP",
                    store_name,
                );
            } else {
                // Guarantee 2 — non-IP-binding stores get no IP (Req 18.4).
                prop_assert_eq!(
                    bound,
                    None,
                    "non-IP-binding store {:?} must receive no IP",
                    store_name,
                );
            }

            // Guarantee 3 — the Client_IP NEVER reaches the store (Req 51.4).
            // Egress_IP and Client_IP are generated distinct, so a bound value
            // equal to the Egress_IP can never coincide with the Client_IP.
            if let Some(ctx_ip) = ctx_client_ip {
                prop_assert_ne!(
                    bound,
                    Some(ctx_ip),
                    "the Ctx Client_IP must never be forwarded to store {:?}",
                    store_name,
                );
            }

            Ok(())
        });
        outcome?;
    }
}
