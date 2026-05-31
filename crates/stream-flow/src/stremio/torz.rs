//! Torz addon (`stremio::torz`) — Req 25 (25.2–25.5).
//!
//! Torz is the torrent-indexer addon: its [`Manifest`] declares a single
//! `stream` resource for indexed torrents (Req 25.2), and a stream request
//! returns [`Stream`] objects for the torrents matching the requested content,
//! **resolved through the configured debrid [`Store`]** (Req 25.3).
//!
//! ## Lazy-pull (Req 25.4)
//!
//! Torz never holds the full torrent index in memory when **lazy-pull** is
//! enabled (the default): each stream request pulls only the index data for the
//! requested content via [`TorrentIndex::pull`], so the index source is queried
//! on demand rather than pre-fetched in full. With lazy-pull disabled Torz
//! instead consults the pre-fetched [`TorrentIndex::full`] snapshot and filters
//! it locally — the same observable streams, traded for a larger working set.
//!
//! ## Resolution through the store (Req 25.3, 25.5)
//!
//! The matching torrents' magnets are checked against the configured [`Store`]
//! ([`Store::check_magnet`]); the torrents the store reports as
//! [`Cached`](MagnetStatus::Cached) are surfaced as playable [`Stream`]s
//! carrying the torrent `infoHash`, the best file index, and the size/filename
//! behavior hints. When the index has **no matches** for the content — or none
//! of the matches resolve as cached through the store — Torz returns an
//! **empty** stream list (Req 25.5) rather than an error.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::config::StremioConfig;
use crate::errors::AppError;
use crate::store::{CheckMagnetParams, Ctx, MagnetStatus, Store};

use super::types::{
    ContentType, Manifest, Resource, ResourceName, Stream, StreamBehaviorHints, StreamsResponse,
    StremioError,
};

/// The default Torz addon id.
const DEFAULT_ID: &str = "st:torz";
/// The default Torz addon name (also the per-stream source label).
const DEFAULT_NAME: &str = "StremThru Torz";
/// The addon version.
const DEFAULT_VERSION: &str = "0.1.0";

/// One torrent entry returned by a [`TorrentIndex`] (Req 25.3).
///
/// The index produces these for the requested content; Torz then resolves them
/// against the configured store and turns the cached ones into [`Stream`]s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorrentEntry {
    /// Torrent info-hash (lowercase hex), the stream `infoHash`.
    pub hash: String,
    /// The magnet URI handed to the store for cache resolution.
    pub magnet: String,
    /// Human-readable torrent / release title (the stream title).
    pub title: String,
    /// Total torrent size in bytes, or `-1` when unknown.
    pub size: i64,
    /// Seed count when the index reports one (`None` otherwise).
    pub seeders: Option<u32>,
    /// The content id this torrent indexes (e.g. `tt0111161`), used to filter
    /// the pre-fetched full index when lazy-pull is disabled.
    pub content_id: String,
}

impl TorrentEntry {
    /// A convenience constructor for a minimal entry (no seed count).
    pub fn new(
        hash: impl Into<String>,
        magnet: impl Into<String>,
        title: impl Into<String>,
        size: i64,
        content_id: impl Into<String>,
    ) -> Self {
        Self {
            hash: hash.into(),
            magnet: magnet.into(),
            title: title.into(),
            size,
            seeders: None,
            content_id: content_id.into(),
        }
    }
}

/// A source of indexed torrent data (Req 25.3, 25.4).
///
/// [`pull`](TorrentIndex::pull) fetches **only** the entries for one content id
/// — the on-demand path lazy-pull uses (Req 25.4). [`full`](TorrentIndex::full)
/// returns the entire pre-fetched index, used when lazy-pull is disabled; Torz
/// filters it locally by content id.
#[async_trait]
pub trait TorrentIndex: Send + Sync {
    /// Fetch the torrent entries for one content id, on demand (Req 25.4).
    async fn pull(
        &self,
        content_type: &str,
        id: &str,
    ) -> Result<Vec<TorrentEntry>, AppError>;

    /// The entire pre-fetched index (used only when lazy-pull is disabled).
    async fn full(&self) -> Result<Vec<TorrentEntry>, AppError>;
}

/// The Stremio Torz torrent-indexer addon (Req 25.2–25.5).
///
/// Construct with [`Torz::with_defaults`] (lazy-pull on) or [`Torz::new`].
/// [`Torz::manifest`] declares the `stream` resource (Req 25.2) and
/// [`Torz::streams`] resolves the matching, store-cached torrents into
/// [`Stream`]s (Req 25.3), returning an empty list when nothing matches
/// (Req 25.5).
#[derive(Clone, Debug)]
pub struct Torz {
    id: String,
    name: String,
    description: String,
    version: String,
    types: Vec<ContentType>,
    id_prefixes: Vec<String>,
    lazy_pull: bool,
}

impl Torz {
    /// Build a Torz addon with explicit identity, supported content `types`,
    /// id prefixes, and the `lazy_pull` toggle (Req 25.2, 25.4, 26.4).
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        types: Vec<ContentType>,
        id_prefixes: Vec<String>,
        lazy_pull: bool,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            version: DEFAULT_VERSION.to_string(),
            types,
            id_prefixes,
            lazy_pull,
        }
    }

    /// Build the standard Torz addon from a [`StremioConfig`], with lazy-pull
    /// enabled (the default), supporting `movie` and `series` with the common
    /// IMDb id prefix (Req 25.2, 25.4, 26.4).
    pub fn with_defaults(config: &StremioConfig) -> Self {
        let name = config
            .addon_name
            .clone()
            .map(|n| format!("{n} Torz"))
            .unwrap_or_else(|| DEFAULT_NAME.to_string());
        Self::new(
            DEFAULT_ID,
            name,
            "Torrent indexer resolving cached torrents through your debrid store.",
            vec![ContentType::movie(), ContentType::series()],
            vec!["tt".into()],
            true,
        )
    }

    /// Whether lazy-pull is enabled (Req 25.4).
    pub fn lazy_pull(&self) -> bool {
        self.lazy_pull
    }

    /// Whether the addon declares the named resource (Req 25.2, 26.3). Torz
    /// only provides `stream`.
    pub fn provides(&self, resource: &str) -> bool {
        resource == ResourceName::STREAM
    }

    /// The Torz [`Manifest`] declaring the `stream` resource for indexed
    /// torrents (Req 25.2), over every supported content type and id prefix
    /// (Req 26.4).
    pub fn manifest(&self) -> Manifest {
        Manifest {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            version: self.version.clone(),
            resources: vec![Resource::full(
                ResourceName::stream(),
                self.types.clone(),
                self.id_prefixes.clone(),
            )],
            types: self.types.clone(),
            id_prefixes: self.id_prefixes.clone(),
            ..Manifest::default()
        }
    }

    /// Resolve the streams for a content request (Req 25.3, 25.4, 25.5).
    ///
    /// Pulls the matching torrent entries — on demand via
    /// [`TorrentIndex::pull`] when lazy-pull is enabled (Req 25.4), else from
    /// the filtered [`TorrentIndex::full`] snapshot — checks their magnets
    /// against the configured `store` ([`Store::check_magnet`]), and surfaces
    /// the [`Cached`](MagnetStatus::Cached) torrents as [`Stream`] objects in
    /// index order (Req 25.3). Returns an **empty** [`StreamsResponse`] when the
    /// index has no matches, or none of the matches are cached (Req 25.5).
    pub async fn streams(
        &self,
        index: &dyn TorrentIndex,
        store: &dyn Store,
        ctx: &Ctx,
        content_type: &str,
        id: &str,
    ) -> Result<StreamsResponse, AppError> {
        // Req 25.4: lazy-pull queries only the requested content on demand;
        // otherwise filter the pre-fetched full index locally.
        let entries: Vec<TorrentEntry> = if self.lazy_pull {
            index.pull(content_type, id).await?
        } else {
            index
                .full()
                .await?
                .into_iter()
                .filter(|e| e.content_id == id)
                .collect()
        };

        // Req 25.5: no torrents match -> empty stream list (no store call).
        if entries.is_empty() {
            return Ok(StreamsResponse::default());
        }

        // Resolve the matches through the configured store (Req 25.3).
        let magnets: Vec<String> = entries.iter().map(|e| e.magnet.clone()).collect();
        let by_hash: HashMap<&str, &TorrentEntry> =
            entries.iter().map(|e| (e.hash.as_str(), e)).collect();

        let checked = store
            .check_magnet(&CheckMagnetParams {
                ctx: ctx.clone(),
                magnets: &magnets,
                client_ip: ctx.client_ip,
                sid: Some(id.to_string()),
                local_only: false,
            })
            .await?;

        // Surface only the torrents the store resolved as cached, in input
        // order. Anything not cached (queued/downloading/failed/…) is not an
        // instantly-playable match and is dropped (Req 25.5 keeps the list
        // empty when nothing cached).
        let mut streams = Vec::new();
        for item in &checked.items {
            if item.status != MagnetStatus::Cached {
                continue;
            }
            let Some(entry) = by_hash.get(item.hash.as_str()) else {
                continue;
            };
            streams.push(build_stream(&self.name, entry, &item.files));
        }

        Ok(StreamsResponse { streams })
    }

    /// Serve a Torz resource by name, rejecting anything but `stream` with the
    /// Stremio not-found convention (Req 25.2, 26.3).
    ///
    /// This is the synchronous shape check; the actual stream payload is
    /// produced by [`Torz::streams`]. A non-`stream` resource is not declared
    /// by the manifest and maps to [`StremioError::not_found`].
    pub fn check_resource(&self, resource: &str) -> Result<(), StremioError> {
        if self.provides(resource) {
            Ok(())
        } else {
            Err(StremioError::not_found(resource))
        }
    }
}

/// Build a playable [`Stream`] from a cached torrent entry and its store files.
///
/// Picks the largest known-size file as the playable file (its index drives
/// `fileIdx`, its name the `filename` hint); the `videoSize` hint prefers the
/// chosen file's size, falling back to the torrent's total size when the store
/// reports no per-file size (Req 25.3, mirrors the Store addon's hint shape).
fn build_stream(
    source_name: &str,
    entry: &TorrentEntry,
    files: &[crate::store::MagnetFile],
) -> Stream {
    // Largest file with a known (>0) size; falls back to the first file.
    let best = files
        .iter()
        .filter(|f| f.size > 0)
        .max_by_key(|f| f.size)
        .or_else(|| files.first());

    let file_index = best.and_then(|f| if f.index >= 0 { Some(f.index) } else { None });
    let filename = best.map(|f| f.name.clone());

    let video_size = best
        .map(|f| f.size)
        .filter(|s| *s > 0)
        .or(if entry.size > 0 { Some(entry.size) } else { None });

    let behavior_hints = if video_size.is_some() || filename.is_some() {
        Some(StreamBehaviorHints {
            video_size,
            filename,
            ..StreamBehaviorHints::default()
        })
    } else {
        None
    };

    Stream {
        info_hash: Some(entry.hash.clone()),
        file_index,
        name: Some(source_name.to_string()),
        title: Some(entry.title.clone()),
        behavior_hints,
        ..Stream::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use time::OffsetDateTime;

    use crate::store::{
        AddMagnetData, AddMagnetParams, CheckMagnetData, CheckMagnetItem, GenerateLinkData,
        GenerateLinkParams, GetMagnetData, GetMagnetParams, GetUserParams, ListMagnetsData,
        ListMagnetsParams, MagnetFile, RemoveMagnetData, RemoveMagnetParams, StoreName,
        SubscriptionStatus, User,
    };

    // -- test doubles -------------------------------------------------------

    /// A torrent index recording which access path was taken, so the lazy-pull
    /// behavior (Req 25.4) is observable.
    struct FakeIndex {
        per_content: HashMap<String, Vec<TorrentEntry>>,
        full_set: Vec<TorrentEntry>,
        pull_calls: AtomicUsize,
        full_calls: AtomicBool,
    }

    impl FakeIndex {
        fn new(per_content: HashMap<String, Vec<TorrentEntry>>, full_set: Vec<TorrentEntry>) -> Self {
            Self {
                per_content,
                full_set,
                pull_calls: AtomicUsize::new(0),
                full_calls: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl TorrentIndex for FakeIndex {
        async fn pull(
            &self,
            _content_type: &str,
            id: &str,
        ) -> Result<Vec<TorrentEntry>, AppError> {
            self.pull_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.per_content.get(id).cloned().unwrap_or_default())
        }

        async fn full(&self) -> Result<Vec<TorrentEntry>, AppError> {
            self.full_calls.store(true, Ordering::SeqCst);
            Ok(self.full_set.clone())
        }
    }

    /// A store whose `check_magnet` reports a configured status per hash and
    /// records the magnets it was asked about.
    struct FakeStore {
        statuses: HashMap<String, (MagnetStatus, Vec<MagnetFile>)>,
        checked: std::sync::Mutex<Vec<String>>,
    }

    impl FakeStore {
        fn new(statuses: HashMap<String, (MagnetStatus, Vec<MagnetFile>)>) -> Self {
            Self {
                statuses,
                checked: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Derive the info-hash from a `magnet:?xt=urn:btih:<hash>` URI used by
        /// the tests, falling back to the whole string.
        fn hash_of(magnet: &str) -> String {
            magnet
                .rsplit("btih:")
                .next()
                .unwrap_or(magnet)
                .split('&')
                .next()
                .unwrap_or(magnet)
                .to_string()
        }
    }

    #[async_trait]
    impl Store for FakeStore {
        fn get_name(&self) -> StoreName {
            StoreName::RealDebrid
        }

        async fn get_user(&self, _p: &GetUserParams) -> Result<User, AppError> {
            Ok(User {
                id: "u".into(),
                email: "u@e.c".into(),
                subscription_status: SubscriptionStatus::Premium,
                has_usenet: false,
            })
        }

        async fn check_magnet(
            &self,
            p: &CheckMagnetParams<'_>,
        ) -> Result<CheckMagnetData, AppError> {
            let mut seen = self.checked.lock().unwrap();
            let mut items = Vec::new();
            for magnet in p.magnets {
                seen.push(magnet.clone());
                let hash = Self::hash_of(magnet);
                let (status, files) = self
                    .statuses
                    .get(&hash)
                    .cloned()
                    .unwrap_or((MagnetStatus::Unknown, vec![]));
                items.push(CheckMagnetItem {
                    hash,
                    magnet: magnet.clone(),
                    status,
                    files,
                });
            }
            Ok(CheckMagnetData { items })
        }

        async fn add_magnet(&self, _p: &AddMagnetParams) -> Result<AddMagnetData, AppError> {
            Ok(AddMagnetData {
                id: "m".into(),
                hash: "h".into(),
                magnet: "magnet:?xt=urn:btih:h".into(),
                name: "n".into(),
                size: 0,
                status: MagnetStatus::Queued,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn get_magnet(&self, _p: &GetMagnetParams) -> Result<GetMagnetData, AppError> {
            Ok(GetMagnetData {
                id: "m".into(),
                name: "n".into(),
                hash: "h".into(),
                size: 0,
                status: MagnetStatus::Cached,
                files: vec![],
                private: false,
                added_at: OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn list_magnets(
            &self,
            _p: &ListMagnetsParams,
        ) -> Result<ListMagnetsData, AppError> {
            Ok(ListMagnetsData {
                items: vec![],
                total_items: 0,
            })
        }

        async fn remove_magnet(
            &self,
            _p: &RemoveMagnetParams,
        ) -> Result<RemoveMagnetData, AppError> {
            Ok(RemoveMagnetData { id: "m".into() })
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

    // -- helpers ------------------------------------------------------------

    fn magnet(hash: &str) -> String {
        format!("magnet:?xt=urn:btih:{hash}")
    }

    fn entry(hash: &str, title: &str, size: i64, content_id: &str) -> TorrentEntry {
        TorrentEntry::new(hash, magnet(hash), title, size, content_id)
    }

    fn file(index: i32, name: &str, size: i64) -> MagnetFile {
        MagnetFile {
            index,
            link: None,
            path: name.to_string(),
            name: name.to_string(),
            size,
            video_hash: None,
        }
    }

    fn torz_lazy(lazy: bool) -> Torz {
        Torz::new(
            DEFAULT_ID,
            DEFAULT_NAME,
            "desc",
            vec![ContentType::movie(), ContentType::series()],
            vec!["tt".into()],
            lazy,
        )
    }

    // -- Req 25.2: manifest declares the stream resource --------------------

    #[::core::prelude::v1::test]
    fn manifest_declares_stream_resource() {
        let manifest = torz_lazy(true).manifest();
        assert!(manifest.is_valid());
        assert!(manifest.provides("stream"), "Torz must declare `stream`");
        // Req 26.4: content types + id prefixes declared.
        assert_eq!(
            manifest.types,
            vec![ContentType::movie(), ContentType::series()],
        );
        assert_eq!(manifest.id_prefixes, vec!["tt".to_string()]);
        // The stream resource is offered for the declared content types.
        assert!(manifest.provides_resource("stream", Some("movie")));
        assert!(manifest.provides_resource("stream", Some("series")));
        // Torz provides nothing but `stream`.
        assert!(!manifest.provides("catalog"));
        assert!(!manifest.provides("meta"));
    }

    #[::core::prelude::v1::test]
    fn check_resource_rejects_non_stream_with_not_found() {
        let torz = torz_lazy(true);
        assert!(torz.check_resource("stream").is_ok());
        let err = torz.check_resource("catalog").unwrap_err();
        assert_eq!(err, StremioError::not_found("catalog"));
    }

    #[::core::prelude::v1::test]
    fn manifest_round_trips_through_json() {
        let manifest = torz_lazy(true).manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    // -- Req 25.3: stream results resolved through the store ----------------

    #[tokio::test]
    async fn streams_resolved_through_store_for_cached_torrents() {
        let id = "tt0111161";
        let per_content = HashMap::from([(
            id.to_string(),
            vec![
                entry("aaa", "Movie 1080p", 8_000_000_000, id),
                entry("bbb", "Movie 720p", 4_000_000_000, id),
            ],
        )]);
        let index = FakeIndex::new(per_content, vec![]);

        // `aaa` is cached with two files; `bbb` is not cached -> dropped.
        let statuses = HashMap::from([
            (
                "aaa".to_string(),
                (
                    MagnetStatus::Cached,
                    vec![
                        file(0, "sample.mkv", 50_000_000),
                        file(1, "Movie.1080p.mkv", 7_900_000_000),
                    ],
                ),
            ),
            ("bbb".to_string(), (MagnetStatus::Downloading, vec![])),
        ]);
        let store = FakeStore::new(statuses);

        let resp = torz_lazy(true)
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        // Only the cached torrent is surfaced.
        assert_eq!(resp.streams.len(), 1);
        let s = &resp.streams[0];
        assert_eq!(s.info_hash.as_deref(), Some("aaa"));
        // Largest known file (index 1, 7.9 GB) chosen as the playable file.
        assert_eq!(s.file_index, Some(1));
        let hints = s.behavior_hints.as_ref().expect("hints");
        assert_eq!(hints.video_size, Some(7_900_000_000));
        assert_eq!(hints.filename.as_deref(), Some("Movie.1080p.mkv"));
        assert_eq!(s.title.as_deref(), Some("Movie 1080p"));
        assert_eq!(s.name.as_deref(), Some(DEFAULT_NAME));

        // The store was asked about both matching magnets.
        let checked = store.checked.lock().unwrap();
        assert_eq!(checked.len(), 2);
        assert!(checked.contains(&magnet("aaa")));
        assert!(checked.contains(&magnet("bbb")));
    }

    #[tokio::test]
    async fn cached_torrent_without_per_file_size_falls_back_to_torrent_size() {
        let id = "tt1";
        let per_content =
            HashMap::from([(id.to_string(), vec![entry("ccc", "Some Movie", 1_234, id)])]);
        let index = FakeIndex::new(per_content, vec![]);
        // Cached but no files (e.g. Offcloud) -> use the torrent total size.
        let store = FakeStore::new(HashMap::from([(
            "ccc".to_string(),
            (MagnetStatus::Cached, vec![]),
        )]));

        let resp = torz_lazy(true)
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        assert_eq!(resp.streams.len(), 1);
        let hints = resp.streams[0].behavior_hints.as_ref().unwrap();
        assert_eq!(hints.video_size, Some(1_234));
        assert_eq!(resp.streams[0].file_index, None);
    }

    // -- Req 25.4: lazy-pull on demand vs full-index pre-fetch --------------

    #[tokio::test]
    async fn lazy_pull_queries_index_on_demand_and_never_pulls_full() {
        let id = "tt0111161";
        let per_content =
            HashMap::from([(id.to_string(), vec![entry("aaa", "M", 100, id)])]);
        let index = FakeIndex::new(per_content, vec![entry("zzz", "Z", 1, "other")]);
        let store = FakeStore::new(HashMap::from([(
            "aaa".to_string(),
            (MagnetStatus::Cached, vec![file(0, "m.mkv", 100)]),
        )]));

        let torz = torz_lazy(true);
        assert!(torz.lazy_pull());
        let resp = torz
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        assert_eq!(resp.streams.len(), 1);
        // On-demand pull happened exactly once; the full index was never read.
        assert_eq!(index.pull_calls.load(Ordering::SeqCst), 1);
        assert!(
            !index.full_calls.load(Ordering::SeqCst),
            "lazy-pull must not pre-fetch the full index (Req 25.4)",
        );
    }

    #[tokio::test]
    async fn non_lazy_uses_full_index_and_filters_by_content_id() {
        let id = "tt0111161";
        let full = vec![
            entry("aaa", "Match", 100, id),
            entry("zzz", "Other content", 1, "tt9999999"),
        ];
        let index = FakeIndex::new(HashMap::new(), full);
        let store = FakeStore::new(HashMap::from([
            ("aaa".to_string(), (MagnetStatus::Cached, vec![file(0, "m.mkv", 100)])),
            ("zzz".to_string(), (MagnetStatus::Cached, vec![file(0, "z.mkv", 1)])),
        ]));

        let resp = torz_lazy(false)
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        // Only the entry whose content_id matches is considered.
        assert_eq!(resp.streams.len(), 1);
        assert_eq!(resp.streams[0].info_hash.as_deref(), Some("aaa"));
        assert!(index.full_calls.load(Ordering::SeqCst));
        assert_eq!(index.pull_calls.load(Ordering::SeqCst), 0);
        // The store was only asked about the content-matching magnet.
        let checked = store.checked.lock().unwrap();
        assert_eq!(checked.as_slice(), &[magnet("aaa")]);
    }

    // -- Req 25.5: no matches -> empty stream list --------------------------

    #[tokio::test]
    async fn no_index_matches_returns_empty_list_without_calling_store() {
        let index = FakeIndex::new(HashMap::new(), vec![]);
        let store = FakeStore::new(HashMap::new());

        let resp = torz_lazy(true)
            .streams(&index, &store, &Ctx::default(), "movie", "tt0000000")
            .await
            .unwrap();

        assert!(resp.streams.is_empty(), "no matches -> empty list (Req 25.5)");
        // No magnets matched, so the store was never consulted.
        assert!(store.checked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn matches_that_are_not_cached_yield_empty_list() {
        let id = "tt5";
        let per_content = HashMap::from([(
            id.to_string(),
            vec![entry("aaa", "M", 100, id), entry("bbb", "N", 200, id)],
        )]);
        let index = FakeIndex::new(per_content, vec![]);
        // Both resolve but neither is cached -> nothing playable -> empty.
        let store = FakeStore::new(HashMap::from([
            ("aaa".to_string(), (MagnetStatus::Downloading, vec![])),
            ("bbb".to_string(), (MagnetStatus::Failed, vec![])),
        ]));

        let resp = torz_lazy(true)
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        assert!(resp.streams.is_empty(), "no cached matches -> empty (Req 25.5)");
        // The store WAS consulted (the entries matched the content).
        assert_eq!(store.checked.lock().unwrap().len(), 2);
    }

    // -- streams round-trip through JSON ------------------------------------

    #[tokio::test]
    async fn produced_streams_round_trip_through_json() {
        let id = "tt1";
        let per_content =
            HashMap::from([(id.to_string(), vec![entry("aaa", "Title", 500, id)])]);
        let index = FakeIndex::new(per_content, vec![]);
        let store = FakeStore::new(HashMap::from([(
            "aaa".to_string(),
            (MagnetStatus::Cached, vec![file(2, "v.mkv", 500)]),
        )]));

        let resp = torz_lazy(true)
            .streams(&index, &store, &Ctx::default(), "movie", id)
            .await
            .unwrap();

        let json = serde_json::to_string(&resp).unwrap();
        let back: StreamsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }
}
