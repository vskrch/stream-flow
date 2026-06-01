//! Store addon (`stremio::store_addon`) — Req 23 (task 26.2).
//!
//! The Stremio **Store addon**: a thin orchestration layer that turns a
//! configured debrid [`Store`] into a browsable Stremio addon (design:
//! Components -> Stremio Addons (Store)). It exposes
//!
//! * a [`Manifest`](StoreAddon::manifest) declaring **both** a `catalog` and a
//!   `stream` resource (Req 23.1);
//! * an **explore** catalog derived from the configured user's store contents
//!   — the magnets/torrents already held at the debrid service
//!   ([`explore_catalog`](StoreAddon::explore_catalog), Req 23.2);
//! * a **search** catalog whose entries are the explore entries filtered to
//!   those whose title matches the query
//!   ([`search_catalog`](StoreAddon::search_catalog), Req 23.3);
//! * a **stream** resource whose every [`Stream`] URL is a `ZippyPanther`
//!   **proxy link** (never a bare upstream/store URL), so playback always flows
//!   through the [`Streaming_Proxy_Engine`](crate::proxy)
//!   ([`streams`](StoreAddon::streams), Req 23.4; Property 26).
//!
//! When the store is not configured, or the store rejects the request because
//! its credentials are missing/invalid, every resource answers with a
//! [`StremioError`] indicating the store is not configured (Req 23.5) rather
//! than panicking or leaking a raw [`AppError`].
//!
//! The addon never reaches for service-specific code: it drives the store
//! exclusively through the object-safe [`Store`] trait, and it builds proxy
//! links through the shared [`ProxyCodec`] so the produced links round-trip on
//! the playback path exactly like those minted by the proxify-links endpoint.

use std::sync::Arc;

use crate::auth::encryption::ProxyPayload;
use crate::errors::{AppError, ErrorCategory};
use crate::proxylink::ProxyCodec;
use crate::store::types::{Ctx, GetMagnetParams, ListMagnetItem, ListMagnetsParams, MagnetFile};
use crate::store::{Store, StoreName};
use crate::stremio::types::{
    Catalog, CatalogExtra, ContentType, Manifest, MetaPreview, MetasResponse, Resource,
    ResourceName, Stream, StreamBehaviorHints, StreamsResponse, StremioError,
};

/// The addon's semantic version (advertised in the manifest, Req 23.1).
const ADDON_VERSION: &str = "0.1.0";

/// The single Stremio content type the store catalog/streams are offered for.
///
/// A debrid store holds arbitrary torrents, so — like stremthru — the addon
/// declares the catch-all `other` content type rather than guessing
/// `movie`/`series` per item (Req 26.4).
const STORE_CONTENT_TYPE: &str = ContentType::OTHER;

/// The Stremio **Store addon** for one configured debrid [`Store`] (Req 23).
///
/// Construct one per configured store with [`StoreAddon::new`] (a live store)
/// or [`StoreAddon::unconfigured`] (no credentials — every resource then yields
/// the Req 23.5 "not configured" [`StremioError`]). The addon is cheap to build
/// and holds:
///
/// * the [`StoreName`] it fronts (drives the manifest id, catalog id, and the
///   item-id prefix);
/// * the optional [`Store`] handle (`None` ⇒ unconfigured, Req 23.5);
/// * a [`ProxyCodec`] used to mint the proxy links every produced [`Stream`]
///   plays through (Req 23.4);
/// * the public `base_url` proxy links are rooted at.
pub struct StoreAddon {
    /// The debrid service this addon fronts.
    store_name: StoreName,
    /// The live store handle, or `None` when the store is not configured
    /// (Req 23.5).
    store: Option<Arc<dyn Store>>,
    /// The codec minting the proxy links produced streams play through
    /// (Req 23.4).
    codec: ProxyCodec,
    /// Public base URL (scheme + host, no trailing slash) proxy links root at.
    base_url: String,
}

impl StoreAddon {
    /// Build a Store addon backed by a live, configured [`Store`].
    pub fn new(store: Arc<dyn Store>, codec: ProxyCodec, base_url: impl Into<String>) -> Self {
        let store_name = store.get_name();
        Self {
            store_name,
            store: Some(store),
            codec,
            base_url: normalize_base_url(base_url.into()),
        }
    }

    /// Build a Store addon for a store whose credentials are missing/invalid
    /// (Req 23.5).
    ///
    /// The [`manifest`](StoreAddon::manifest) is still served (so a client can
    /// install the addon), but every catalog/stream request answers with the
    /// "store is not configured" [`StremioError`].
    pub fn unconfigured(
        store_name: StoreName,
        codec: ProxyCodec,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            store_name,
            store: None,
            codec,
            base_url: normalize_base_url(base_url.into()),
        }
    }

    /// The debrid service this addon fronts.
    pub fn store_name(&self) -> StoreName {
        self.store_name
    }

    /// The item-id prefix this addon stamps on every catalog entry and strips
    /// off on a stream request (e.g. `st:sf:rd:` for RealDebrid).
    ///
    /// It is the manifest's declared id prefix (Req 26.4) so a Stremio client
    /// only routes matching ids back to this addon.
    pub fn item_prefix(&self) -> String {
        format!("st:sf:{}:", self.store_name.code().as_str())
    }

    /// The addon's catalog id (stable per store).
    pub fn catalog_id(&self) -> String {
        format!("zippypanther-store-{}", self.store_name.code().as_str())
    }

    /// The addon [`Manifest`], declaring the **catalog and stream** resources
    /// the addon provides (Req 23.1).
    ///
    /// The manifest is valid in the Go sense (non-empty id/name/version,
    /// [`Manifest::is_valid`]), declares the `other` content type and the
    /// addon's id prefix (Req 26.4), and offers a single searchable catalog so
    /// both the explore (Req 23.2) and search (Req 23.3) flows resolve to it.
    pub fn manifest(&self) -> Manifest {
        let types = vec![ContentType::new(STORE_CONTENT_TYPE)];
        let id_prefixes = vec![self.item_prefix()];

        // Both the catalog and the stream resource are declared in object form
        // (carrying types + idPrefixes) so a client knows exactly which ids and
        // content types this addon serves (Req 23.1, 26.4).
        let resources = vec![
            Resource::full(ResourceName::catalog(), types.clone(), id_prefixes.clone()),
            Resource::full(ResourceName::stream(), types.clone(), id_prefixes.clone()),
        ];

        // One catalog accepting an optional `search` extra: absent ⇒ explore
        // (Req 23.2), present ⇒ title search (Req 23.3). `skip` enables paging.
        let catalogs = vec![Catalog {
            r#type: STORE_CONTENT_TYPE.to_string(),
            id: self.catalog_id(),
            name: format!("ZippyPanther Store · {}", self.store_name),
            extra: vec![
                CatalogExtra {
                    name: "search".to_string(),
                    ..Default::default()
                },
                CatalogExtra {
                    name: "skip".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }];

        Manifest {
            id: format!("st.zippypanther.store.{}", self.store_name.as_str()),
            name: format!("ZippyPanther Store: {}", self.store_name),
            description: format!(
                "Browse and search the contents of your {} debrid store, streamed through ZippyPanther.",
                self.store_name
            ),
            version: ADDON_VERSION.to_string(),
            resources,
            types,
            id_prefixes,
            catalogs,
            ..Default::default()
        }
    }

    /// Serve the **explore** catalog: catalog entries derived from the
    /// configured user's store contents (Req 23.2).
    ///
    /// Each magnet held at the store becomes one [`MetaPreview`] whose id is the
    /// addon's [`item_prefix`](StoreAddon::item_prefix) followed by the
    /// store-assigned magnet id (so a later stream request routes back here).
    /// `limit`/`offset` are forwarded to the store with its canonical clamp
    /// (Req 17.4, 17.9).
    pub async fn explore_catalog(
        &self,
        ctx: &Ctx,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<MetasResponse, StremioError> {
        let store = self.require_store()?;
        let params = ListMagnetsParams::new(ctx.clone(), limit, offset);
        let data = store
            .list_magnets(&params)
            .await
            .map_err(|e| self.map_store_error(e))?;

        let metas = data.items.iter().map(|item| self.preview(item)).collect();
        Ok(MetasResponse { metas })
    }

    /// Serve the **search** catalog: the store contents filtered to entries
    /// whose title matches `query` (Req 23.3).
    ///
    /// An empty/whitespace query degenerates to [`explore_catalog`] (every
    /// entry "matches"). Matching is case-insensitive substring containment on
    /// the magnet's display name. To search the whole store rather than a
    /// single page, the listing is fetched at the store's maximum page size
    /// before filtering.
    pub async fn search_catalog(
        &self,
        ctx: &Ctx,
        query: &str,
        offset: Option<u32>,
    ) -> Result<MetasResponse, StremioError> {
        let query = query.trim();
        if query.is_empty() {
            return self.explore_catalog(ctx, None, offset).await;
        }

        let store = self.require_store()?;
        let params =
            ListMagnetsParams::new(ctx.clone(), Some(ListMagnetsParams::LIMIT_MAX), offset);
        let data = store
            .list_magnets(&params)
            .await
            .map_err(|e| self.map_store_error(e))?;

        let metas = data
            .items
            .iter()
            .filter(|item| title_matches(&item.name, query))
            .map(|item| self.preview(item))
            .collect();
        Ok(MetasResponse { metas })
    }

    /// Serve the **stream** resource for a store item (Req 23.4).
    ///
    /// `id` is a catalog item id minted by this addon
    /// ([`item_prefix`](StoreAddon::item_prefix) + magnet id). The addon fetches
    /// that magnet's files from the store and returns one [`Stream`] per
    /// playable file, **each with a `ZippyPanther` proxy-link URL** wrapping the
    /// file's store link — so the bytes are delivered by the
    /// [`Streaming_Proxy_Engine`](crate::proxy), never fetched directly by the
    /// client (Req 23.4; Property 26). The file name and (when known) size are
    /// preserved on the stream's [`StreamBehaviorHints`].
    pub async fn streams(
        &self,
        ctx: &Ctx,
        _content_type: &str,
        id: &str,
    ) -> Result<StreamsResponse, StremioError> {
        let store = self.require_store()?;
        let magnet_id = self.magnet_id_from_item(id);

        let data = store
            .get_magnet(&GetMagnetParams {
                ctx: ctx.clone(),
                id: magnet_id.to_string(),
            })
            .await
            .map_err(|e| self.map_store_error(e))?;

        let mut streams = Vec::new();
        for file in &data.files {
            // A file is playable only if the store gave us a link to resolve.
            let Some(store_link) = file.link.as_deref() else {
                continue;
            };
            streams.push(self.stream_for_file(store_link, file)?);
        }

        Ok(StreamsResponse { streams })
    }

    // -- internals ----------------------------------------------------------

    /// The live store, or the Req 23.5 "not configured" [`StremioError`].
    fn require_store(&self) -> Result<&Arc<dyn Store>, StremioError> {
        self.store
            .as_ref()
            .ok_or_else(|| self.not_configured_error())
    }

    /// The canonical "store is not configured" Stremio error (Req 23.5).
    fn not_configured_error(&self) -> StremioError {
        StremioError::new(format!(
            "store `{}` is not configured: set valid store credentials to use this addon",
            self.store_name
        ))
    }

    /// Map a store [`AppError`] onto a [`StremioError`] (Req 23.5).
    ///
    /// An authentication/authorization/payment failure means the configured
    /// credentials are missing or invalid, so it surfaces as the same "not
    /// configured" error (Req 23.5). Any other store failure surfaces as a
    /// descriptive Stremio error so the addon always answers in Stremio shape
    /// rather than leaking a raw HTTP error.
    fn map_store_error(&self, err: AppError) -> StremioError {
        match err.category {
            ErrorCategory::Unauthorized
            | ErrorCategory::Forbidden
            | ErrorCategory::PaymentRequired => self.not_configured_error(),
            _ => StremioError::new(format!(
                "store `{}` error: {}",
                self.store_name, err.message
            )),
        }
    }

    /// Strip the addon's item-id prefix to recover the store-side magnet id.
    /// Lenient: an id without the prefix is used verbatim.
    fn magnet_id_from_item<'a>(&self, id: &'a str) -> &'a str {
        let prefix = self.item_prefix();
        id.strip_prefix(&prefix).unwrap_or(id)
    }

    /// Build a catalog preview for one listed magnet (Req 23.2).
    fn preview(&self, item: &ListMagnetItem) -> MetaPreview {
        MetaPreview {
            id: format!("{}{}", self.item_prefix(), item.id),
            r#type: ContentType::new(STORE_CONTENT_TYPE),
            name: item.name.clone(),
            // Store items have no artwork; an empty poster is the valid
            // "no poster" value (MetaPreview::poster is always present).
            poster: String::new(),
            ..Default::default()
        }
    }

    /// Build a playable [`Stream`] for one magnet file, wrapping its store link
    /// in a proxy link (Req 23.4; Property 26).
    fn stream_for_file(&self, store_link: &str, file: &MagnetFile) -> Result<Stream, StremioError> {
        let mut payload = ProxyPayload::new(store_link.to_string());
        payload.filename = Some(file.name.clone());

        let url = self
            .proxy_stream_url(&payload)
            .map_err(|e| self.map_store_error(e))?;

        let behavior_hints = StreamBehaviorHints {
            filename: Some(file.name.clone()),
            // `-1` is the "unknown size" sentinel (Req 17.12); only advertise a
            // genuine size.
            video_size: (file.size >= 0).then_some(file.size),
            ..Default::default()
        };

        Ok(Stream {
            url: Some(url),
            name: Some(format!("ZippyPanther · {}", self.store_name)),
            description: Some(file.name.clone()),
            // Only carry a genuine file index (the `-1` sentinel is "unknown").
            file_index: (file.index >= 0).then_some(file.index),
            behavior_hints: Some(behavior_hints),
            ..Default::default()
        })
    }

    /// Encode `payload` as a proxy link and root it at the public base URL,
    /// yielding the URL a Stremio client plays (Req 23.4).
    ///
    /// The stremthru-native signed `token` format is used (the Store addon is a
    /// stremthru-surface addon), matching the proxify-links playback path so
    /// the link round-trips through [`ProxyCodec`].
    fn proxy_stream_url(&self, payload: &ProxyPayload) -> Result<String, AppError> {
        let link = self.codec.encode_token(payload)?;
        Ok(format!(
            "{}/v0/proxy/stream?{}",
            self.base_url,
            link.as_query_param()
        ))
    }
}

/// Case-insensitive substring match of a search `query` against an item title
/// (Req 23.3).
fn title_matches(title: &str, query: &str) -> bool {
    title.to_lowercase().contains(&query.to_lowercase())
}

/// Normalize a configured base URL: trim trailing slashes so the
/// `/v0/proxy/stream` suffix joins cleanly.
fn normalize_base_url(mut base: String) -> String {
    while base.ends_with('/') {
        base.pop();
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::AppError;
    use crate::proxylink::ProxyLink;
    use crate::store::types::{
        AddMagnetData, AddMagnetParams, CheckMagnetData, CheckMagnetParams, GenerateLinkData,
        GenerateLinkParams, GetMagnetData, GetUserParams, ListMagnetsData, MagnetStatus,
        RemoveMagnetData, RemoveMagnetParams, SubscriptionStatus, User,
    };
    use async_trait::async_trait;
    use time::OffsetDateTime;

    const API_PASSWORD: &str = "test-api-password";
    const TOKEN_SECRET: &str = "test-token-secret";
    const BASE_URL: &str = "https://proxy.example.com";

    fn codec() -> ProxyCodec {
        ProxyCodec::from_secrets(API_PASSWORD, TOKEN_SECRET)
    }

    // -- A configurable in-memory Store seam --------------------------------

    /// A [`Store`] that replays a scripted listing + file set, or fails every
    /// operation with an `unauthorized` error (to model invalid credentials —
    /// Req 23.5). Only `list_magnets`/`get_magnet`/`get_name` are exercised;
    /// the rest are trivial stubs so the trait is object-safe.
    struct MockStore {
        name: StoreName,
        magnets: Vec<ListMagnetItem>,
        files: Vec<MagnetFile>,
        unauthorized: bool,
    }

    impl MockStore {
        fn new(name: StoreName, magnets: Vec<ListMagnetItem>, files: Vec<MagnetFile>) -> Arc<Self> {
            Arc::new(Self {
                name,
                magnets,
                files,
                unauthorized: false,
            })
        }

        fn unauthorized(name: StoreName) -> Arc<Self> {
            Arc::new(Self {
                name,
                magnets: vec![],
                files: vec![],
                unauthorized: true,
            })
        }
    }

    #[async_trait]
    impl Store for MockStore {
        fn get_name(&self) -> StoreName {
            self.name
        }

        async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
            if self.unauthorized {
                return Err(AppError::unauthorized_for(self.name.as_str(), "bad token"));
            }
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
            if self.unauthorized {
                return Err(AppError::unauthorized_for(self.name.as_str(), "bad token"));
            }
            Ok(GetMagnetData {
                id: "magnet123".into(),
                name: "The Matrix (1999)".into(),
                hash: "abc".into(),
                size: 4096,
                status: MagnetStatus::Cached,
                files: self.files.clone(),
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn list_magnets(&self, _p: &ListMagnetsParams) -> Result<ListMagnetsData, AppError> {
            if self.unauthorized {
                return Err(AppError::unauthorized_for(self.name.as_str(), "bad token"));
            }
            Ok(ListMagnetsData {
                total_items: self.magnets.len() as i64,
                items: self.magnets.clone(),
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
            _p: &GenerateLinkParams,
        ) -> Result<GenerateLinkData, AppError> {
            Ok(GenerateLinkData {
                link: "https://cdn.example/file.mkv".into(),
            })
        }
    }

    // -- test data builders --------------------------------------------------

    fn magnet(id: &str, name: &str) -> ListMagnetItem {
        ListMagnetItem {
            id: id.to_string(),
            name: name.to_string(),
            hash: "deadbeef".to_string(),
            size: 1_000,
            status: MagnetStatus::Cached,
        }
    }

    fn file(index: i32, name: &str, link: Option<&str>, size: i64) -> MagnetFile {
        MagnetFile {
            index,
            link: link.map(|s| s.to_string()),
            path: format!("/{name}"),
            name: name.to_string(),
            size,
            video_hash: None,
        }
    }

    fn ctx() -> Ctx {
        Ctx {
            request_id: "req-1".into(),
            client_ip: None,
            trusted: false,
        }
    }

    fn addon_with(store: Arc<dyn Store>) -> StoreAddon {
        StoreAddon::new(store, codec(), BASE_URL)
    }

    /// Extract and decode the proxy token embedded in a produced stream URL,
    /// recovering the wrapped [`ProxyPayload`].
    fn decode_stream_url(c: &ProxyCodec, url: &str) -> ProxyPayload {
        let token = url
            .split("token=")
            .nth(1)
            .expect("stream URL carries a token");
        c.decode(&ProxyLink::Token {
            token: token.to_string(),
        })
        .expect("token decodes")
    }

    // -- Req 23.1: manifest declares catalog + stream resources -------------

    #[test]
    fn manifest_declares_catalog_and_stream_resources() {
        let store = MockStore::new(StoreName::RealDebrid, vec![], vec![]);
        let addon = addon_with(store);
        let manifest = addon.manifest();

        assert!(manifest.is_valid(), "manifest must be valid");
        assert!(manifest.provides("catalog"), "declares catalog (Req 23.1)");
        assert!(manifest.provides("stream"), "declares stream (Req 23.1)");

        // Content type + id prefix are declared (Req 26.4).
        assert!(manifest
            .types
            .iter()
            .any(|t| t.as_str() == STORE_CONTENT_TYPE));
        assert_eq!(manifest.id_prefixes, vec![addon.item_prefix()]);

        // The catalog is searchable, so both explore and search resolve to it.
        assert_eq!(manifest.catalogs.len(), 1);
        let cat = &manifest.catalogs[0];
        assert_eq!(cat.id, addon.catalog_id());
        assert!(cat.extra.iter().any(|e| e.name == "search"));
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let store = MockStore::new(StoreName::TorBox, vec![], vec![]);
        let manifest = addon_with(store).manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    // -- Req 23.2: explore catalog derived from store contents --------------

    #[tokio::test]
    async fn explore_catalog_derives_entries_from_store_contents() {
        let store = MockStore::new(
            StoreName::RealDebrid,
            vec![
                magnet("m1", "The Matrix (1999)"),
                magnet("m2", "Inception (2010)"),
                magnet("m3", "Interstellar (2014)"),
            ],
            vec![],
        );
        let addon = addon_with(store);

        let resp = addon.explore_catalog(&ctx(), None, None).await.unwrap();

        assert_eq!(resp.metas.len(), 3, "one entry per store magnet (Req 23.2)");
        let names: Vec<&str> = resp.metas.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "The Matrix (1999)",
                "Inception (2010)",
                "Interstellar (2014)"
            ]
        );
        // Every entry id carries the addon's prefix so streams route back here.
        let prefix = addon.item_prefix();
        assert!(resp.metas.iter().all(|m| m.id.starts_with(&prefix)));
        assert_eq!(resp.metas[0].id, format!("{prefix}m1"));
        assert_eq!(resp.metas[0].r#type.as_str(), STORE_CONTENT_TYPE);
    }

    // -- Req 23.3: search filters by title match ----------------------------

    #[tokio::test]
    async fn search_catalog_returns_only_title_matches() {
        let store = MockStore::new(
            StoreName::RealDebrid,
            vec![
                magnet("m1", "The Matrix (1999)"),
                magnet("m2", "The Matrix Reloaded (2003)"),
                magnet("m3", "Inception (2010)"),
            ],
            vec![],
        );
        let addon = addon_with(store);

        let resp = addon.search_catalog(&ctx(), "matrix", None).await.unwrap();

        assert_eq!(resp.metas.len(), 2, "only the two Matrix titles match");
        assert!(resp
            .metas
            .iter()
            .all(|m| m.name.to_lowercase().contains("matrix")));
    }

    #[tokio::test]
    async fn search_is_case_insensitive_and_empty_query_lists_all() {
        let store = MockStore::new(
            StoreName::RealDebrid,
            vec![
                magnet("m1", "The Matrix (1999)"),
                magnet("m2", "Inception (2010)"),
            ],
            vec![],
        );
        let addon = addon_with(store);

        // Case-insensitive substring match.
        let resp = addon
            .search_catalog(&ctx(), "INCEPTION", None)
            .await
            .unwrap();
        assert_eq!(resp.metas.len(), 1);
        assert_eq!(resp.metas[0].name, "Inception (2010)");

        // Empty/whitespace query degenerates to explore (everything matches).
        let resp = addon.search_catalog(&ctx(), "   ", None).await.unwrap();
        assert_eq!(resp.metas.len(), 2);
    }

    // -- Req 23.4 / Property 26: streams play through proxy links -----------

    #[tokio::test]
    async fn streams_are_proxy_links_not_bare_upstream_urls() {
        let store_link_a = "https://store.example.com/dl/file-a.mkv";
        let store_link_b = "https://store.example.com/dl/file-b.mkv";
        let store = MockStore::new(
            StoreName::RealDebrid,
            vec![],
            vec![
                file(0, "The.Matrix.1999.mkv", Some(store_link_a), 4096),
                file(1, "extras.mkv", Some(store_link_b), -1),
            ],
        );
        let addon = addon_with(store);
        let item_id = format!("{}magnet123", addon.item_prefix());

        let resp = addon.streams(&ctx(), "other", &item_id).await.unwrap();

        assert_eq!(resp.streams.len(), 2, "one stream per playable file");

        let s0 = &resp.streams[0];
        let url = s0.url.as_deref().expect("stream carries a URL");

        // The URL is a ZippyPanther proxy link rooted at the proxy base, never
        // the bare upstream/store URL (Req 23.4; Property 26).
        assert!(url.starts_with(&format!("{BASE_URL}/v0/proxy/stream?")));
        assert!(url.contains("token="));
        assert_ne!(url, store_link_a);
        assert!(!url.contains("store.example.com"));

        // Decoding the proxy token recovers the wrapped store link (round trip).
        let payload = decode_stream_url(&codec(), url);
        assert_eq!(payload.url, store_link_a);
        assert_eq!(payload.filename.as_deref(), Some("The.Matrix.1999.mkv"));

        // Behavior hints carry filename + (known) size; file index preserved.
        let hints = s0.behavior_hints.as_ref().expect("behavior hints set");
        assert_eq!(hints.filename.as_deref(), Some("The.Matrix.1999.mkv"));
        assert_eq!(hints.video_size, Some(4096));
        assert_eq!(s0.file_index, Some(0));

        // The unknown-size file omits videoSize (the -1 sentinel is not leaked).
        let s1 = &resp.streams[1];
        assert_eq!(s1.behavior_hints.as_ref().and_then(|h| h.video_size), None);
    }

    #[tokio::test]
    async fn streams_skip_files_without_a_link() {
        let store = MockStore::new(
            StoreName::RealDebrid,
            vec![],
            vec![
                file(
                    0,
                    "playable.mkv",
                    Some("https://store.example.com/dl/x.mkv"),
                    10,
                ),
                file(1, "nfo.txt", None, 1),
            ],
        );
        let addon = addon_with(store);
        let item_id = format!("{}magnet123", addon.item_prefix());

        let resp = addon.streams(&ctx(), "other", &item_id).await.unwrap();
        assert_eq!(
            resp.streams.len(),
            1,
            "only the file with a link is playable"
        );
    }

    // -- Req 23.5: missing/invalid creds -> Stremio error -------------------

    #[tokio::test]
    async fn unconfigured_store_returns_stremio_error_for_every_resource() {
        let addon = StoreAddon::unconfigured(StoreName::RealDebrid, codec(), BASE_URL);

        // Manifest is still served (so the addon can be installed).
        assert!(addon.manifest().is_valid());

        let explore_err = addon.explore_catalog(&ctx(), None, None).await.unwrap_err();
        assert!(
            explore_err.err.contains("not configured"),
            "{explore_err:?}"
        );

        let search_err = addon
            .search_catalog(&ctx(), "matrix", None)
            .await
            .unwrap_err();
        assert!(search_err.err.contains("not configured"));

        let stream_err = addon
            .streams(&ctx(), "other", "st:sf:rd:magnet123")
            .await
            .unwrap_err();
        assert!(stream_err.err.contains("not configured"));
    }

    #[tokio::test]
    async fn invalid_credentials_map_to_not_configured_stremio_error() {
        let store = MockStore::unauthorized(StoreName::RealDebrid);
        let addon = addon_with(store);

        // A store auth failure (invalid creds) surfaces as the Req 23.5 error.
        let explore_err = addon.explore_catalog(&ctx(), None, None).await.unwrap_err();
        assert!(
            explore_err.err.contains("not configured"),
            "{explore_err:?}"
        );

        let stream_err = addon
            .streams(&ctx(), "other", "st:sf:rd:magnet123")
            .await
            .unwrap_err();
        assert!(stream_err.err.contains("not configured"));
    }

    #[tokio::test]
    async fn stremio_error_serializes_with_err_field() {
        let addon = StoreAddon::unconfigured(StoreName::TorBox, codec(), BASE_URL);
        let err = addon.explore_catalog(&ctx(), None, None).await.unwrap_err();
        let value = serde_json::to_value(&err).unwrap();
        assert!(
            value.get("err").is_some(),
            "Stremio error shape is {{\"err\": ..}}"
        );
    }

    // -- item-id prefix round trip ------------------------------------------

    #[test]
    fn magnet_id_strips_the_addon_prefix() {
        let store = MockStore::new(StoreName::RealDebrid, vec![], vec![]);
        let addon = addon_with(store);
        let prefix = addon.item_prefix();
        assert_eq!(
            addon.magnet_id_from_item(&format!("{prefix}abc123")),
            "abc123"
        );
        // An id without the prefix is used verbatim (lenient).
        assert_eq!(addon.magnet_id_from_item("raw-id"), "raw-id");
    }
}

// ---------------------------------------------------------------------------
// HTTP handlers — Stremio addon protocol routes (Req 23.1–23.5)
// ---------------------------------------------------------------------------
//
// Routes (registered by [`configure_store_addon_routes`]):
//
//   GET /stremio/store/{store_code}/manifest.json
//   GET /stremio/store/{store_code}/catalog/{type}/{id}.json
//   GET /stremio/store/{store_code}/stream/{type}/{id}.json
//
// Each handler:
//   1. Parses the store code from the URL path.
//   2. Resolves the store token from the configured `*` wildcard credential.
//   3. Builds the appropriate store impl via `OutboundClient`.
//   4. Builds a `StoreAddon` and serves the Stremio protocol response.
//
// The `base_url` for proxy links is taken from `StremioConfig::base_url` when
// configured, or derived from the incoming request's `Host` header.

pub mod handlers {
    use actix_web::{web, HttpRequest, HttpResponse};
    use serde::Deserialize;
    use std::sync::Arc;

    use crate::app::AppState;
    use crate::auth::Auth;
    use crate::errors::AppError;
    use crate::proxylink::ProxyCodec;
    use crate::store::impls::{
        AllDebridStore, DebridLinkStore, DebriderStore, EasyDebridStore, OffcloudStore,
        PikPakStore, PremiumizeStore, RealDebridStore, TorBoxStore,
    };
    use crate::store::{Store, StoreName};
    use crate::stremio::types::StremioError;

    use super::StoreAddon;

    // -----------------------------------------------------------------------
    // Path / query parameter types
    // -----------------------------------------------------------------------

    /// Path params for all store addon routes.
    #[derive(Debug, Deserialize)]
    pub struct StoreAddonPath {
        /// Two-letter store code (e.g. `rd`, `ad`, `tb`).
        pub store_code: String,
    }

    /// Path params for catalog routes.
    #[derive(Debug, Deserialize)]
    pub struct CatalogPath {
        pub store_code: String,
        /// Stremio content type (e.g. `other`).
        pub r#type: String,
        /// Catalog id (e.g. `zippypanther-store-rd`).
        pub id: String,
    }

    /// Path params for stream routes.
    #[derive(Debug, Deserialize)]
    pub struct StreamPath {
        pub store_code: String,
        /// Stremio content type.
        pub r#type: String,
        /// Item id (e.g. `st:sf:rd:magnet123`).
        pub id: String,
    }

    /// Query params for catalog routes (search + pagination).
    #[derive(Debug, Deserialize, Default)]
    pub struct CatalogQuery {
        /// Optional search query (Req 23.3).
        pub search: Option<String>,
        /// Pagination offset (Req 23.2).
        pub skip: Option<u32>,
    }

    // -----------------------------------------------------------------------
    // Store builder
    // -----------------------------------------------------------------------

    /// Build a [`Store`] impl for the given store code and token, using the
    /// shared egress [`OutboundClient`](crate::egress::OutboundClient) from
    /// `AppState` (Req 51.1).
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

    /// Build a [`StoreAddon`] for the given store code from the `AppState`.
    ///
    /// Resolves the store token from the configured `*` wildcard credential
    /// (Req 28.4). When no token is configured, returns an unconfigured addon
    /// that answers every resource with the "not configured" error (Req 23.5).
    fn build_addon(store_name: StoreName, state: &AppState, base_url: &str) -> StoreAddon {
        let auth = Auth::from_config(&state.config().auth);
        let codec = build_codec(state);

        // Resolve the token using the `*` wildcard user (Req 28.4).
        match auth.resolve_store_credential("*", store_name.as_str()) {
            Some(token) => {
                let store = build_store(store_name, token.to_string(), state);
                StoreAddon::new(store, codec, base_url)
            }
            None => StoreAddon::unconfigured(store_name, codec, base_url),
        }
    }

    /// Build the [`ProxyCodec`] from the `AppState` config.
    ///
    /// Uses the `api_password` as the mediaflow AES-CBC key and the first
    /// configured proxy-auth password as the stremthru token key, falling back
    /// to the API password when no proxy-auth secret is configured.
    fn build_codec(state: &AppState) -> ProxyCodec {
        let api_password = state
            .config()
            .auth
            .api_password
            .as_ref()
            .map(|s| s.expose().to_string())
            .unwrap_or_default();
        let token_secret = state
            .config()
            .auth
            .proxy_auth
            .first()
            .and_then(|entry| entry.split_once(':').map(|(_, pass)| pass))
            .unwrap_or(&api_password);
        ProxyCodec::from_secrets(&api_password, token_secret)
    }

    /// Derive the public base URL for proxy links from the request or config.
    ///
    /// Prefers `StremioConfig::base_url` when configured; falls back to
    /// `{scheme}://{host}` derived from the incoming request's `Host` header.
    fn base_url(req: &HttpRequest, state: &AppState) -> String {
        if let Some(configured) = state.config().stremio.base_url.as_deref() {
            if !configured.is_empty() {
                return configured.trim_end_matches('/').to_string();
            }
        }
        // Derive from the request.
        let scheme = if req.connection_info().scheme() == "https" {
            "https"
        } else {
            "http"
        };
        let host = req.connection_info().host().to_string();
        format!("{scheme}://{host}")
    }

    // -----------------------------------------------------------------------
    // Handler: GET /stremio/store/{store_code}/manifest.json (Req 23.1)
    // -----------------------------------------------------------------------

    /// Serve the Store addon manifest (Req 23.1).
    ///
    /// The manifest is always served — even when the store is not configured —
    /// so a Stremio client can install the addon and see the "not configured"
    /// error only when it tries to use it (Req 23.5).
    pub async fn manifest_endpoint(
        path: web::Path<StoreAddonPath>,
        req: HttpRequest,
        state: web::Data<AppState>,
    ) -> Result<HttpResponse, AppError> {
        let store_name = StoreName::require(&path.store_code)?;
        let base = base_url(&req, &state);
        let addon = build_addon(store_name, &state, &base);
        Ok(HttpResponse::Ok().json(addon.manifest()))
    }

    // -----------------------------------------------------------------------
    // Handler: GET /stremio/store/{store_code}/catalog/{type}/{id}.json (Req 23.2, 23.3)
    // -----------------------------------------------------------------------

    /// Serve the Store addon catalog (explore or search, Req 23.2, 23.3).
    ///
    /// When the `search` query parameter is present and non-empty, the catalog
    /// is filtered to entries whose title matches the query (Req 23.3).
    /// Otherwise the full explore catalog is returned (Req 23.2).
    pub async fn catalog_endpoint(
        path: web::Path<CatalogPath>,
        query: web::Query<CatalogQuery>,
        req: HttpRequest,
        state: web::Data<AppState>,
    ) -> HttpResponse {
        let store_name = match StoreName::require(&path.store_code) {
            Ok(n) => n,
            Err(e) => return stremio_error_response(StremioError::new(e.message)),
        };
        let base = base_url(&req, &state);
        let addon = build_addon(store_name, &state, &base);
        let ctx = crate::store::types::Ctx::default();

        let result = if let Some(search) = query.search.as_deref().filter(|s| !s.trim().is_empty())
        {
            addon.search_catalog(&ctx, search, query.skip).await
        } else {
            addon.explore_catalog(&ctx, None, query.skip).await
        };

        match result {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => stremio_error_response(e),
        }
    }

    // -----------------------------------------------------------------------
    // Handler: GET /stremio/store/{store_code}/stream/{type}/{id}.json (Req 23.4)
    // -----------------------------------------------------------------------

    /// Serve the Store addon stream resource (Req 23.4).
    ///
    /// Returns one [`Stream`] per playable file in the magnet, each with a
    /// proxy-link URL (Req 23.4; Property 26). Missing/invalid credentials
    /// surface as a Stremio error (Req 23.5).
    pub async fn stream_endpoint(
        path: web::Path<StreamPath>,
        req: HttpRequest,
        state: web::Data<AppState>,
    ) -> HttpResponse {
        let store_name = match StoreName::require(&path.store_code) {
            Ok(n) => n,
            Err(e) => return stremio_error_response(StremioError::new(e.message)),
        };
        let base = base_url(&req, &state);
        let addon = build_addon(store_name, &state, &base);
        let ctx = crate::store::types::Ctx::default();

        match addon.streams(&ctx, &path.r#type, &path.id).await {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => stremio_error_response(e),
        }
    }

    // -----------------------------------------------------------------------
    // Helper: convert a StremioError to an HttpResponse
    // -----------------------------------------------------------------------

    /// Convert a [`StremioError`] to an HTTP 200 response carrying the Stremio
    /// error JSON shape `{"err": "..."}`.
    ///
    /// Stremio addons return HTTP 200 with an `err` field rather than a 4xx
    /// status for application-level errors (the Stremio client reads the `err`
    /// field and surfaces it to the user). The exception is the not-found
    /// convention (HTTP 404) for undeclared resources (Req 26.3).
    fn stremio_error_response(err: StremioError) -> HttpResponse {
        // The not-found convention uses HTTP 404 (Req 26.3).
        if err.err.contains("not found") {
            return HttpResponse::NotFound().json(err);
        }
        // All other Stremio errors are returned as HTTP 200 with the error body
        // so the Stremio client can display the message.
        HttpResponse::Ok().json(err)
    }

    // -----------------------------------------------------------------------
    // Route registration
    // -----------------------------------------------------------------------

    /// Register the Store addon routes onto an actix [`ServiceConfig`].
    ///
    /// Registers:
    /// - `GET /stremio/store/{store_code}/manifest.json`
    /// - `GET /stremio/store/{store_code}/catalog/{type}/{id}.json`
    /// - `GET /stremio/store/{store_code}/stream/{type}/{id}.json`
    pub fn configure_store_addon_routes(cfg: &mut web::ServiceConfig) {
        cfg.route(
            "/stremio/store/{store_code}/manifest.json",
            web::get().to(manifest_endpoint),
        )
        .route(
            "/stremio/store/{store_code}/catalog/{type}/{id}.json",
            web::get().to(catalog_endpoint),
        )
        .route(
            "/stremio/store/{store_code}/stream/{type}/{id}.json",
            web::get().to(stream_endpoint),
        );
    }

    // -----------------------------------------------------------------------
    // Tests for the HTTP handlers
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::Config;
        use actix_web::{test as actix_test, App};

        fn test_state() -> AppState {
            AppState::new(Config::default())
        }

        #[actix_web::test]
        async fn manifest_endpoint_returns_valid_manifest_for_known_store() {
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/stremio/store/rd/manifest.json")
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            let body: serde_json::Value = actix_test::read_body_json(resp).await;
            assert_eq!(body["id"], "st.zippypanther.store.realdebrid");
            assert!(!body["name"].as_str().unwrap_or("").is_empty());
            assert!(!body["version"].as_str().unwrap_or("").is_empty());
            // Manifest declares catalog and stream resources (Req 23.1).
            let resources = body["resources"].as_array().unwrap();
            let resource_names: Vec<&str> = resources
                .iter()
                .map(|r| {
                    if let Some(s) = r.as_str() {
                        s
                    } else {
                        r["name"].as_str().unwrap_or("")
                    }
                })
                .collect();
            assert!(resource_names.contains(&"catalog"), "must declare catalog");
            assert!(resource_names.contains(&"stream"), "must declare stream");
        }

        #[actix_web::test]
        async fn manifest_endpoint_returns_400_for_unknown_store_code() {
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/stremio/store/zz/manifest.json")
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            // Unknown store code -> 400 Bad Request (invalid-store-name error).
            assert_eq!(resp.status(), 400);
        }

        #[actix_web::test]
        async fn catalog_endpoint_returns_stremio_error_when_unconfigured() {
            // No store credentials configured -> unconfigured addon -> Stremio error.
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/stremio/store/rd/catalog/other/zippypanther-store-rd.json")
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            // Stremio errors are returned as HTTP 200 with an `err` field.
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = actix_test::read_body_json(resp).await;
            assert!(
                body.get("err").is_some(),
                "Stremio error must have an `err` field"
            );
            assert!(
                body["err"]
                    .as_str()
                    .unwrap_or("")
                    .contains("not configured"),
                "error must mention 'not configured'"
            );
        }

        #[actix_web::test]
        async fn stream_endpoint_returns_stremio_error_when_unconfigured() {
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/stremio/store/rd/stream/other/st:sf:rd:magnet123.json")
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = actix_test::read_body_json(resp).await;
            assert!(body.get("err").is_some());
            assert!(body["err"]
                .as_str()
                .unwrap_or("")
                .contains("not configured"));
        }

        #[actix_web::test]
        async fn manifest_endpoint_install_url_round_trip() {
            // The manifest URL is the install URL for the Stremio addon.
            // Verify the manifest id encodes the store code so a client can
            // derive the install URL from the manifest id (Req 23.1).
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            for (code, expected_slug) in [
                ("rd", "realdebrid"),
                ("ad", "alldebrid"),
                ("tb", "torbox"),
                ("pm", "premiumize"),
            ] {
                let req = actix_test::TestRequest::get()
                    .uri(&format!("/stremio/store/{code}/manifest.json"))
                    .to_request();
                let resp = actix_test::call_service(&app, req).await;
                assert_eq!(resp.status(), 200, "store code {code}");
                let body: serde_json::Value = actix_test::read_body_json(resp).await;
                let id = body["id"].as_str().unwrap_or("");
                assert!(
                    id.contains(expected_slug),
                    "manifest id {id:?} must contain store slug {expected_slug:?}"
                );
            }
        }

        #[actix_web::test]
        async fn catalog_endpoint_search_query_param_is_forwarded() {
            // When `?search=...` is present, the search catalog is served.
            // With no credentials configured, both paths return the same
            // "not configured" error — but the route must accept the query param.
            let state = test_state();
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(state))
                    .configure(configure_store_addon_routes),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/stremio/store/rd/catalog/other/zippypanther-store-rd.json?search=matrix")
                .to_request();
            let resp = actix_test::call_service(&app, req).await;
            // Route accepted the request (200 with Stremio error body).
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = actix_test::read_body_json(resp).await;
            assert!(body.get("err").is_some());
        }
    }
}

pub use handlers::configure_store_addon_routes;
