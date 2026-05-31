//! Stremio protocol types (`stremio::types`) — Req 26 (serde-compatible with Go).
//!
//! A field-for-field Rust port of the stremthru (Go) `stremio` package
//! (`Manifest`, `Resource`, `Catalog`, `Stream`, `Subtitle`, `Meta`,
//! `BehaviorHints`, `StreamBehaviorHints`, …). serde field names and
//! `#[serde(skip_serializing_if = …)]` reproduce Go's struct tags and
//! `omitempty` semantics so an existing Stremio client cannot tell
//! stream-flow's JSON apart from stremthru's (Req 26.1, 36.9). Every protocol
//! object round-trips through `serde_json` (Req 26.2).
//!
//! Two wire shapes need the same hand-written `MarshalJSON`/`UnmarshalJSON`
//! behaviour the Go code has:
//!
//! * [`Resource`] is **string-or-object**: a bare `"stream"` when it carries no
//!   `types`/`idPrefixes`, an object `{ "name", "types", "idPrefixes"? }`
//!   otherwise. Deserialization accepts either form.
//! * [`CatalogExtraOptions`] **coerces** each array element to a string —
//!   numbers and booleans become their textual form (`5 → "5"`,
//!   `true → "true"`) exactly as Go's `UnmarshalJSON` does.
//!
//! [`Manifest`] declares every supported content type and id prefix (Req 26.4),
//! and [`Manifest::provides`] / [`Manifest::provides_resource`] answer whether
//! the addon serves a given resource so a request for an undeclared resource
//! becomes a [`StremioError::not_found`] (Req 26.3).
//!
//! ## Deviations from the Go source (intentional)
//!
//! * Timestamps (`Meta::released`, `MetaVideo::released`) are modelled as
//!   `Option<String>` (an RFC 3339 string) rather than Go's `time.Time`; real
//!   responses always carry a concrete timestamp and the round-trip property is
//!   cleaner this way.
//! * `Stream::file_index` is `Option<i32>` (per the design) rather than Go's
//!   `int + omitempty`, so a genuine `fileIdx = 0` survives serialization
//!   (Go's `omitempty` would drop it).
//! * [`MetaVideo`] is always serialized in object form; Go's id-only string
//!   short-form optimization is not reproduced (object form is equally valid
//!   Stremio and keeps the type a plain struct). The string-or-object handling
//!   the task calls out is implemented for [`Resource`].

use std::collections::BTreeMap;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, SerializeStruct, Serializer};

// ---------------------------------------------------------------------------
// serde helpers — reproduce Go's `omitempty` / `omitzero` for scalar fields
// ---------------------------------------------------------------------------

/// `skip_serializing_if` predicate for a `bool` Go `omitempty` field: a `false`
/// bool is omitted, matching `json:"...,omitempty"` on a Go `bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// `skip_serializing_if` predicate for an `i32` Go `omitempty` field (omit `0`).
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i32(n: &i32) -> bool {
    *n == 0
}

/// `skip_serializing_if` predicate for the `omitzero` zero-indexed `i32`
/// fields (`MetaVideo::episode`/`season`), whose "unknown" sentinel is `-1`
/// (Go's `ZeroIndexedInt.IsZero()` returns `true` for `-1`).
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_minus_one(n: &i32) -> bool {
    *n == -1
}

/// `#[serde(default = …)]` provider for the zero-indexed `-1` sentinel.
fn minus_one() -> i32 {
    -1
}

/// A tolerant `deserialize_with` that maps a missing-or-`null` value to
/// `T::default()`. Used for the Go slices emitted **without** `omitempty`
/// (`Manifest::resources`/`types`/`catalogs`): Go marshals a `nil` slice as
/// `null`, so accepting `null` keeps us able to ingest a genuine stremthru
/// manifest while still emitting `[]` ourselves.
fn de_null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Human-readable JSON kind, for the `Resource` shape-error message.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// ContentType — Go `type ContentType string`
// ---------------------------------------------------------------------------

/// A Stremio content type (`movie`, `series`, `tv`, …).
///
/// Mirrors Go's `type ContentType string`: a transparent string newtype so it
/// serializes as a bare JSON string and round-trips **any** value, while still
/// exposing the canonical constants and constructors (Req 26.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentType(pub String);

impl ContentType {
    /// `"anime"`.
    pub const ANIME: &'static str = "anime";
    /// `"movie"`.
    pub const MOVIE: &'static str = "movie";
    /// `"series"`.
    pub const SERIES: &'static str = "series";
    /// `"channel"`.
    pub const CHANNEL: &'static str = "channel";
    /// `"tv"`.
    pub const TV: &'static str = "tv";
    /// `"other"`.
    pub const OTHER: &'static str = "other";

    /// Every canonical content type, in Go declaration order — the set an
    /// addon manifest declares when it supports all of them (Req 26.4).
    pub const ALL: [&'static str; 6] = [
        Self::ANIME,
        Self::MOVIE,
        Self::SERIES,
        Self::CHANNEL,
        Self::TV,
        Self::OTHER,
    ];

    /// Wrap an arbitrary content-type string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The `movie` content type.
    pub fn movie() -> Self {
        Self(Self::MOVIE.to_string())
    }

    /// The `series` content type.
    pub fn series() -> Self {
        Self(Self::SERIES.to_string())
    }

    /// The `tv` content type.
    pub fn tv() -> Self {
        Self(Self::TV.to_string())
    }

    /// The `anime` content type.
    pub fn anime() -> Self {
        Self(Self::ANIME.to_string())
    }

    /// The underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Every canonical content type as owned values, for declaring a manifest
    /// that supports all of them (Req 26.4).
    pub fn all() -> Vec<ContentType> {
        Self::ALL
            .iter()
            .map(|s| ContentType((*s).to_string()))
            .collect()
    }
}

impl From<&str> for ContentType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ContentType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Serialize for ContentType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(ContentType(String::deserialize(d)?))
    }
}

// ---------------------------------------------------------------------------
// ResourceName — Go `type ResourceName string`
// ---------------------------------------------------------------------------

/// A Stremio resource name (`catalog`, `meta`, `stream`, `subtitles`,
/// `addon_catalog`). A transparent string newtype mirroring Go's
/// `type ResourceName string`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceName(pub String);

impl ResourceName {
    /// `"catalog"`.
    pub const CATALOG: &'static str = "catalog";
    /// `"meta"`.
    pub const META: &'static str = "meta";
    /// `"stream"`.
    pub const STREAM: &'static str = "stream";
    /// `"subtitles"`.
    pub const SUBTITLES: &'static str = "subtitles";
    /// `"addon_catalog"`.
    pub const ADDON_CATALOG: &'static str = "addon_catalog";

    /// Wrap an arbitrary resource-name string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The `catalog` resource.
    pub fn catalog() -> Self {
        Self(Self::CATALOG.to_string())
    }

    /// The `meta` resource.
    pub fn meta() -> Self {
        Self(Self::META.to_string())
    }

    /// The `stream` resource.
    pub fn stream() -> Self {
        Self(Self::STREAM.to_string())
    }

    /// The `subtitles` resource.
    pub fn subtitles() -> Self {
        Self(Self::SUBTITLES.to_string())
    }

    /// The underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ResourceName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ResourceName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Serialize for ResourceName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResourceName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(ResourceName(String::deserialize(d)?))
    }
}

// ---------------------------------------------------------------------------
// Resource — string-or-object (Go custom Marshal/UnmarshalJSON)
// ---------------------------------------------------------------------------

/// A manifest resource declaration — **string-or-object** on the wire
/// (Go `Resource` with custom `MarshalJSON`/`UnmarshalJSON`).
///
/// * Serialized as a bare string (just [`name`](Resource::name)) when it
///   carries no [`types`](Resource::types) and no
///   [`id_prefixes`](Resource::id_prefixes) — e.g. `"stream"`.
/// * Serialized as an object `{ "name", "types", "idPrefixes"? }` when either
///   is non-empty. `idPrefixes` is omitted when empty (Go `omitempty`); `types`
///   is always present in the object form (Go has no `omitempty` on `types`).
///
/// Deserialization accepts **either** form: a bare string yields empty
/// `types`/`id_prefixes`, an object reads all three fields (Req 26.1, 26.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resource {
    /// The resource name (`catalog`/`meta`/`stream`/`subtitles`/`addon_catalog`).
    pub name: ResourceName,
    /// Content types this resource is offered for. Empty ⇒ string form.
    pub types: Vec<ContentType>,
    /// Id prefixes this resource is offered for (`omitempty`). Empty ⇒ omitted
    /// from the object form, and (with empty `types`) ⇒ string form.
    pub id_prefixes: Vec<String>,
}

impl Resource {
    /// A bare-string resource (no `types`/`idPrefixes`) — serializes to just
    /// its name, e.g. `"stream"`.
    pub fn bare(name: impl Into<ResourceName>) -> Self {
        Self {
            name: name.into(),
            types: Vec::new(),
            id_prefixes: Vec::new(),
        }
    }

    /// A full object resource carrying `types` and (optional) `idPrefixes`.
    pub fn full(
        name: impl Into<ResourceName>,
        types: Vec<ContentType>,
        id_prefixes: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            types,
            id_prefixes,
        }
    }

    /// Whether this resource serializes in the bare-string form, i.e. it
    /// carries neither `types` nor `idPrefixes` (mirrors Go's
    /// `len(Types)==0 && len(IDPrefixes)==0`).
    pub fn is_string_form(&self) -> bool {
        self.types.is_empty() && self.id_prefixes.is_empty()
    }
}

impl Serialize for Resource {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Go: if len(Types)==0 && len(IDPrefixes)==0 -> marshal the name string.
        if self.is_string_form() {
            return self.name.serialize(s);
        }
        // Object form. `types` always present; `idPrefixes` omitted when empty.
        let omit_prefixes = self.id_prefixes.is_empty();
        let field_count = if omit_prefixes { 2 } else { 3 };
        let mut st = s.serialize_struct("Resource", field_count)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("types", &self.types)?;
        if omit_prefixes {
            st.skip_field("idPrefixes")?;
        } else {
            st.serialize_field("idPrefixes", &self.id_prefixes)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        use serde_json::Value;

        // Read into a Value first so we can branch on string-vs-object, exactly
        // as Go's UnmarshalJSON tries `json.Unmarshal(data, &name)` first.
        let value = Value::deserialize(d)?;
        match value {
            Value::String(name) => Ok(Resource {
                name: ResourceName(name),
                types: Vec::new(),
                id_prefixes: Vec::new(),
            }),
            Value::Object(_) => {
                #[derive(serde::Deserialize)]
                struct ResourceObj {
                    name: ResourceName,
                    #[serde(default)]
                    types: Vec<ContentType>,
                    #[serde(default, rename = "idPrefixes")]
                    id_prefixes: Vec<String>,
                }
                let obj: ResourceObj = serde_json::from_value(value).map_err(D::Error::custom)?;
                Ok(Resource {
                    name: obj.name,
                    types: obj.types,
                    id_prefixes: obj.id_prefixes,
                })
            }
            other => Err(D::Error::custom(format!(
                "Resource must be a string or object, got {}",
                json_kind(&other)
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// CatalogExtraOptions — coerce numbers/bools to strings (Go UnmarshalJSON)
// ---------------------------------------------------------------------------

/// A catalog-extra options list whose elements are **coerced to strings** on
/// deserialization (Go `CatalogExtraOptions.UnmarshalJSON`).
///
/// A JSON array such as `["hd", 720, true]` deserializes to
/// `["hd", "720", "true"]`: strings pass through, numbers become their textual
/// form (integers without a decimal point, e.g. `720 → "720"`,
/// `1.5 → "1.5"`), and booleans become `"true"`/`"false"`. Serialization emits
/// a plain JSON array of strings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogExtraOptions(pub Vec<String>);

impl CatalogExtraOptions {
    /// The coerced option strings.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Whether the option list is empty (drives the `omitempty` on
    /// [`CatalogExtra::options`]).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<String>> for CatalogExtraOptions {
    fn from(v: Vec<String>) -> Self {
        Self(v)
    }
}

impl Serialize for CatalogExtraOptions {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for CatalogExtraOptions {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        use serde_json::Value;

        let items = Vec::<Value>::deserialize(d)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let coerced = match item {
                Value::String(s) => s,
                Value::Bool(b) => b.to_string(),
                // serde_json's `Number::to_string` renders integers without a
                // trailing `.0` (`720` not `720.0`) and finite floats compactly
                // (`1.5`), matching Go's `strconv.FormatFloat(v,'f',-1,64)` /
                // `strconv.Itoa` output.
                Value::Number(n) => n.to_string(),
                Value::Null => "null".to_string(),
                // Arrays/objects: Go's `fmt.Sprintf("%v", v)` default branch.
                // These never appear in real catalog-extra options; fall back to
                // the compact JSON rendering rather than failing.
                other => serde_json::to_string(&other).map_err(D::Error::custom)?,
            };
            out.push(coerced);
        }
        Ok(CatalogExtraOptions(out))
    }
}

// ---------------------------------------------------------------------------
// CatalogExtra / Catalog
// ---------------------------------------------------------------------------

/// One `extra` parameter a catalog accepts (`search`, `genre`, `skip`, …).
/// Mirrors Go `CatalogExtra`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogExtra {
    /// The extra parameter name.
    pub name: String,
    /// Whether the parameter is required (`omitempty`).
    #[serde(default, rename = "isRequired", skip_serializing_if = "is_false")]
    pub is_required: bool,
    /// Allowed option values, coerced to strings (`omitempty`).
    #[serde(default, skip_serializing_if = "CatalogExtraOptions::is_empty")]
    pub options: CatalogExtraOptions,
    /// Maximum selectable options (`omitempty`).
    #[serde(default, rename = "optionsLimit", skip_serializing_if = "is_zero_i32")]
    pub options_limit: i32,
}

/// A catalog declaration in a manifest. Mirrors Go `Catalog`, including the
/// legacy `genres`/`extraSupported`/`extraRequired` fields kept for backward
/// compatibility.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Catalog {
    /// Content type of the catalog (`movie`/`series`/…), a bare string.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Catalog id.
    pub id: String,
    /// Human-readable catalog name.
    pub name: String,
    /// The `extra` parameters this catalog accepts (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<CatalogExtra>,

    /// Legacy: supported genres (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genres: Vec<String>,
    /// Legacy: supported extra names (`omitempty`).
    #[serde(default, rename = "extraSupported", skip_serializing_if = "Vec::is_empty")]
    pub extra_supported: Vec<String>,
    /// Legacy: required extra names (`omitempty`).
    #[serde(default, rename = "extraRequired", skip_serializing_if = "Vec::is_empty")]
    pub extra_required: Vec<String>,
}

// ---------------------------------------------------------------------------
// BehaviorHints (manifest-level) / Manifest
// ---------------------------------------------------------------------------

/// Manifest-level behavior hints. Mirrors Go `BehaviorHints` — every field is a
/// bool with `omitempty`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BehaviorHints {
    /// Adult content (`omitempty`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub adult: bool,
    /// Peer-to-peer streams (`omitempty`).
    #[serde(default, rename = "p2p", skip_serializing_if = "is_false")]
    pub p2p: bool,
    /// The addon is configurable (`omitempty`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub configurable: bool,
    /// Configuration is required before use (`omitempty`).
    #[serde(default, rename = "configurationRequired", skip_serializing_if = "is_false")]
    pub configuration_required: bool,
    /// Undocumented: new-episode notifications (`omitempty`).
    #[serde(
        default,
        rename = "newEpisodeNotifications",
        skip_serializing_if = "is_false"
    )]
    pub new_episode_notifications: bool,
}

/// A Stremio addon manifest. Mirrors Go `Manifest` field-for-field (Req 26.1).
///
/// `resources`, `types`, and `catalogs` are emitted **without** `omitempty`
/// (always present, matching Go) so a consumer always sees the arrays; the
/// remaining fields use `omitempty`. The manifest declares every content type
/// and id prefix the addon supports (Req 26.4), and [`Manifest::provides`]
/// answers resource-availability queries for the not-found path (Req 26.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// Addon id (e.g. `st:store:realdebrid`).
    pub id: String,
    /// Human-readable addon name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Semantic version string.
    pub version: String,

    /// Declared resources (string-or-object). Always present.
    #[serde(default, deserialize_with = "de_null_default")]
    pub resources: Vec<Resource>,
    /// Declared content types (Req 26.4). Always present.
    #[serde(default, deserialize_with = "de_null_default")]
    pub types: Vec<ContentType>,
    /// Declared id prefixes (Req 26.4) (`omitempty`).
    #[serde(default, rename = "idPrefixes", skip_serializing_if = "Vec::is_empty")]
    pub id_prefixes: Vec<String>,

    /// Addon catalogs served as an `addon_catalog` resource (`omitempty`).
    #[serde(default, rename = "addonCatalogs", skip_serializing_if = "Vec::is_empty")]
    pub addon_catalogs: Vec<Catalog>,
    /// Declared catalogs. Always present.
    #[serde(default, deserialize_with = "de_null_default")]
    pub catalogs: Vec<Catalog>,

    /// Background image URL (`omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub background: String,
    /// Logo image URL (`omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logo: String,
    /// Contact email (`omitempty`).
    #[serde(default, rename = "contactEmail", skip_serializing_if = "String::is_empty")]
    pub contact_email: String,
    /// Manifest-level behavior hints (`omitempty`).
    #[serde(
        default,
        rename = "behaviorHints",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavior_hints: Option<BehaviorHints>,
}

impl Manifest {
    /// Whether the manifest is valid in the Go sense: a non-empty `id`, `name`,
    /// and `version` (`Manifest.IsValid`).
    pub fn is_valid(&self) -> bool {
        !self.id.is_empty() && !self.name.is_empty() && !self.version.is_empty()
    }

    /// Whether the addon declares the named resource (Req 26.3, 26.4).
    ///
    /// Matches a [`Resource`] in either wire form by its
    /// [`name`](Resource::name). A request naming a resource for which this
    /// returns `false` is answered with a [`StremioError::not_found`].
    pub fn provides(&self, resource: &str) -> bool {
        self.resources.iter().any(|r| r.name.as_str() == resource)
    }

    /// Whether the addon declares the named resource **for the given content
    /// type** (Req 26.3, 26.4).
    ///
    /// A bare-string resource (empty `types`) is offered for *every* type, so
    /// it matches any `content_type`. An object resource matches only when its
    /// `types` contains `content_type`. When `content_type` is `None` this is
    /// equivalent to [`provides`](Manifest::provides).
    pub fn provides_resource(&self, resource: &str, content_type: Option<&str>) -> bool {
        self.resources.iter().any(|r| {
            r.name.as_str() == resource
                && match content_type {
                    None => true,
                    Some(ct) => r.types.is_empty() || r.types.iter().any(|t| t.as_str() == ct),
                }
        })
    }
}

// ---------------------------------------------------------------------------
// Stream / StreamBehaviorHints / ProxyHeaders
// ---------------------------------------------------------------------------

/// Request/response header overrides for a proxied stream
/// (`StreamBehaviorHints.proxyHeaders`). Mirrors Go
/// `StreamBehaviorHintsProxyHeaders`. Order-stable maps keep the round trip
/// deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProxyHeaders {
    /// Headers to inject on the upstream request (`omitempty`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request: BTreeMap<String, String>,
    /// Headers to set on the response to the client (`omitempty`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response: BTreeMap<String, String>,
}

/// Per-stream behavior hints. Mirrors Go `StreamBehaviorHints`; these are the
/// hints the Wrap addon must preserve unchanged through a stream-URL rewrite
/// (Req 24.5, Property 26) and the `videoSize`/`filename` the engine sets
/// (Req 37.12).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamBehaviorHints {
    /// Country allowlist for the stream (`omitempty`).
    #[serde(default, rename = "countryWhitelist", skip_serializing_if = "Vec::is_empty")]
    pub country_whitelist: Vec<String>,
    /// Whether the stream is not directly web-playable (`omitempty`).
    #[serde(default, rename = "notWebReady", skip_serializing_if = "is_false")]
    pub not_web_ready: bool,
    /// Binge-group key for "play next" grouping (`omitempty`).
    #[serde(default, rename = "bingeGroup", skip_serializing_if = "Option::is_none")]
    pub binge_group: Option<String>,
    /// Proxy header overrides (`omitempty`).
    #[serde(default, rename = "proxyHeaders", skip_serializing_if = "Option::is_none")]
    pub proxy_headers: Option<ProxyHeaders>,
    /// OpenSubtitles-style video hash (`omitempty`).
    #[serde(default, rename = "videoHash", skip_serializing_if = "Option::is_none")]
    pub video_hash: Option<String>,
    /// Total video size in bytes, when known (Req 37.12) (`omitempty`).
    #[serde(default, rename = "videoSize", skip_serializing_if = "Option::is_none")]
    pub video_size: Option<i64>,
    /// Suggested filename (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// A playable stream. Mirrors Go `Stream`. The playable URL is always a
/// stream-flow proxy link when produced by the Store/Wrap addons (Req 23.4,
/// 24.4, Property 26); the bytes here only model the wire shape.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Stream {
    /// Direct (proxy) URL of the stream (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// YouTube video id (`omitempty`).
    #[serde(default, rename = "ytId", skip_serializing_if = "Option::is_none")]
    pub youtube_id: Option<String>,
    /// Torrent info-hash (`omitempty`).
    #[serde(default, rename = "infoHash", skip_serializing_if = "Option::is_none")]
    pub info_hash: Option<String>,
    /// File index within the torrent (`omitempty`).
    ///
    /// Modelled as `Option<i32>` (design deviation from Go's `int+omitempty`)
    /// so a genuine `fileIdx = 0` survives the round trip — Go's `omitempty`
    /// would drop a zero index.
    #[serde(default, rename = "fileIdx", skip_serializing_if = "Option::is_none")]
    pub file_index: Option<i32>,
    /// External URL (opened outside the player) (`omitempty`).
    #[serde(default, rename = "externalUrl", skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,

    /// Stream name (the addon/source label) (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Stream title (soon deprecated in favor of `description`) (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Stream description (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Attached subtitle tracks (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subtitles: Vec<Subtitle>,
    /// Tracker / DHT sources for an `infoHash` stream (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Per-stream behavior hints (`omitempty`).
    #[serde(default, rename = "behaviorHints", skip_serializing_if = "Option::is_none")]
    pub behavior_hints: Option<StreamBehaviorHints>,
}

// ---------------------------------------------------------------------------
// Subtitle
// ---------------------------------------------------------------------------

/// A subtitle track. Mirrors Go `Subtitle`, including the undocumented
/// `SubEncoding`/`m`/`g` fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Subtitle {
    /// Subtitle id.
    pub id: String,
    /// Subtitle file URL.
    pub url: String,
    /// ISO language code.
    pub lang: String,

    /// Undocumented: source character encoding (`omitempty`).
    #[serde(default, rename = "SubEncoding", skip_serializing_if = "String::is_empty")]
    pub sub_encoding: String,
    /// Undocumented `m` field (`omitempty`).
    #[serde(default, rename = "m", skip_serializing_if = "String::is_empty")]
    pub m: String,
    /// Undocumented `g` field (`omitempty`).
    #[serde(default, rename = "g", skip_serializing_if = "String::is_empty")]
    pub g: String,
}

// ---------------------------------------------------------------------------
// Meta and supporting types
// ---------------------------------------------------------------------------

/// A meta trailer (legacy form). Mirrors Go `MetaTrailer`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaTrailer {
    /// Trailer source (e.g. a YouTube id).
    pub source: String,
    /// Trailer type (`Trailer`/`Clip`).
    #[serde(rename = "type")]
    pub r#type: String,
}

/// A meta link (actor/director/genre/…). Mirrors Go `MetaLink`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaLink {
    /// Display name.
    pub name: String,
    /// Link category (`actor`/`director`/`writer`/…).
    pub category: String,
    /// Target URL (a `stremio:///` deep link or external URL).
    pub url: String,
}

/// Meta-level behavior hints. Mirrors Go `MetaBehaviorHints`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaBehaviorHints {
    /// Default video id to play (`omitempty`).
    #[serde(default, rename = "defaultVideoId", skip_serializing_if = "Option::is_none")]
    pub default_video_id: Option<String>,
    /// Undocumented: has scheduled videos (`omitempty`).
    #[serde(default, rename = "hasScheduledVideos", skip_serializing_if = "is_false")]
    pub has_scheduled_videos: bool,
}

/// One video (episode) within a [`Meta`]. Mirrors Go `MetaVideo` (object form).
///
/// `episode` and `season` use the `-1` "unknown" sentinel (Go's
/// `ZeroIndexedInt`, whose `IsZero()` is `-1`) and are omitted when `-1`
/// (Go `omitzero`). The Go id-only string short-form is not reproduced — see
/// the module-level deviations note.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaVideo {
    /// Video id (the stream id key).
    pub id: String,
    /// Video title (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Release timestamp (RFC 3339) (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released: Option<String>,
    /// Thumbnail URL (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Attached streams (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<Stream>,
    /// Whether the video is available (`omitempty`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub available: bool,
    /// Episode number, `-1` when unknown (`omitzero` ⇒ omitted when `-1`).
    #[serde(default = "minus_one", skip_serializing_if = "is_minus_one")]
    pub episode: i32,
    /// Season number, `-1` when unknown (`omitzero` ⇒ omitted when `-1`).
    #[serde(default = "minus_one", skip_serializing_if = "is_minus_one")]
    pub season: i32,
    /// Episode overview (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overview: Option<String>,
}

impl Default for MetaVideo {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: None,
            released: None,
            thumbnail: None,
            streams: Vec::new(),
            available: false,
            episode: -1,
            season: -1,
            overview: None,
        }
    }
}

/// A detailed meta item. Mirrors Go `Meta` (the commonly used fields; the long
/// tail of deprecated/undocumented Go fields is intentionally omitted — they
/// are not used by the addons and are accepted-and-dropped on deserialization,
/// which is acceptable for the round-trip of the values we produce).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    /// Meta id (e.g. `tt0111161`).
    pub id: String,
    /// Content type.
    #[serde(rename = "type")]
    pub r#type: ContentType,
    /// Display name.
    pub name: String,
    /// Genres (legacy) (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genres: Vec<String>,
    /// Poster image URL (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poster: Option<String>,
    /// Poster shape (`square`/`poster`/`landscape`) (`omitempty`).
    #[serde(default, rename = "posterShape", skip_serializing_if = "Option::is_none")]
    pub poster_shape: Option<String>,
    /// Background image URL (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    /// Logo image URL (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// Description (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Release info string (e.g. `1994` or `2008-2013`) (`omitempty`).
    #[serde(default, rename = "releaseInfo", skip_serializing_if = "Option::is_none")]
    pub release_info: Option<String>,
    /// IMDb rating string (`omitempty`).
    #[serde(default, rename = "imdbRating", skip_serializing_if = "Option::is_none")]
    pub imdb_rating: Option<String>,
    /// Release timestamp (RFC 3339) (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released: Option<String>,
    /// Links (cast/director/genre deep links) (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<MetaLink>,
    /// Videos (episodes) (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub videos: Vec<MetaVideo>,
    /// Runtime string (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Language (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Country (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Website (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Meta behavior hints (`omitempty`).
    #[serde(default, rename = "behaviorHints", skip_serializing_if = "Option::is_none")]
    pub behavior_hints: Option<MetaBehaviorHints>,
}

/// A catalog preview meta item (`MetaPreview`). Mirrors the commonly used Go
/// `MetaPreview` fields. `poster` is emitted **without** `omitempty` (matching
/// Go) so a preview always carries the field.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaPreview {
    /// Meta id.
    pub id: String,
    /// Content type.
    #[serde(rename = "type")]
    pub r#type: ContentType,
    /// Display name.
    pub name: String,
    /// Poster image URL (always present, matching Go's non-`omitempty` tag).
    pub poster: String,
    /// Poster shape (`omitempty`).
    #[serde(default, rename = "posterShape", skip_serializing_if = "Option::is_none")]
    pub poster_shape: Option<String>,
    /// Genres (legacy) (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genres: Vec<String>,
    /// IMDb rating (`omitempty`).
    #[serde(default, rename = "imdbRating", skip_serializing_if = "Option::is_none")]
    pub imdb_rating: Option<String>,
    /// Release info (`omitempty`).
    #[serde(default, rename = "releaseInfo", skip_serializing_if = "Option::is_none")]
    pub release_info: Option<String>,
    /// Links (`omitempty`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<MetaLink>,
    /// Description (`omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Resource response envelopes (the JSON bodies addon handlers return)
// ---------------------------------------------------------------------------

/// The `{"metas": [...]}` body a `catalog` resource returns.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetasResponse {
    /// Catalog previews.
    #[serde(default)]
    pub metas: Vec<MetaPreview>,
}

/// The `{"meta": {...}}` body a `meta` resource returns.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaResponse {
    /// The meta item.
    pub meta: Meta,
}

/// The `{"streams": [...]}` body a `stream` resource returns. An empty list is
/// the valid "no streams" answer (Req 25.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamsResponse {
    /// The playable streams (possibly empty).
    #[serde(default)]
    pub streams: Vec<Stream>,
}

/// The `{"subtitles": [...]}` body a `subtitles` resource returns.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubtitlesResponse {
    /// The subtitle tracks (possibly empty).
    #[serde(default)]
    pub subtitles: Vec<Subtitle>,
}

// ---------------------------------------------------------------------------
// StremioError — the not-found response (Req 26.3)
// ---------------------------------------------------------------------------

/// A Stremio error response body (`{"err": "..."}`).
///
/// When a resource request names a resource the addon does not declare in its
/// [`Manifest`], the addon answers with [`StremioError::not_found`] (Req 26.3)
/// rather than a bare HTTP 404, so the Stremio client surfaces a meaningful
/// message. The Stremio convention is a JSON object whose `err` field holds a
/// human-readable message; the response is served with HTTP 404.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StremioError {
    /// The error message.
    pub err: String,
}

impl StremioError {
    /// The HTTP status a Stremio not-found response is served with.
    pub const NOT_FOUND_STATUS: u16 = 404;

    /// Build an error with an arbitrary message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            err: message.into(),
        }
    }

    /// The canonical not-found error for an undeclared resource (Req 26.3).
    pub fn not_found(resource: &str) -> Self {
        Self {
            err: format!("resource not found: {resource}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- helpers ------------------------------------------------------------

    /// Round-trip a value through JSON and assert it is recovered unchanged.
    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, value, "round trip via {json}");
    }

    // -- Resource: string-or-object (Req 26.1, 26.2) ------------------------

    #[test]
    fn resource_bare_serializes_as_string() {
        let r = Resource::bare("stream");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, json!("stream"));
        assert!(r.is_string_form());
    }

    #[test]
    fn resource_with_types_serializes_as_object_without_id_prefixes() {
        let r = Resource::full(
            ResourceName::stream(),
            vec![ContentType::movie(), ContentType::series()],
            vec![],
        );
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, json!({ "name": "stream", "types": ["movie", "series"] }));
        // idPrefixes omitted when empty (Go omitempty).
        assert!(!v.as_object().unwrap().contains_key("idPrefixes"));
        assert!(!r.is_string_form());
    }

    #[test]
    fn resource_with_id_prefixes_serializes_as_object_with_id_prefixes() {
        let r = Resource::full(
            ResourceName::stream(),
            vec![ContentType::movie()],
            vec!["tt".into(), "kitsu:".into()],
        );
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({
                "name": "stream",
                "types": ["movie"],
                "idPrefixes": ["tt", "kitsu:"],
            }),
        );
    }

    #[test]
    fn resource_with_only_id_prefixes_still_object_form() {
        // Go: object form whenever len(Types)!=0 OR len(IDPrefixes)!=0; an empty
        // `types` still serializes as `[]` in the object.
        let r = Resource::full(ResourceName::meta(), vec![], vec!["tt".into()]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, json!({ "name": "meta", "types": [], "idPrefixes": ["tt"] }));
    }

    #[test]
    fn resource_deserializes_from_bare_string() {
        let r: Resource = serde_json::from_value(json!("catalog")).unwrap();
        assert_eq!(r.name, ResourceName::catalog());
        assert!(r.types.is_empty());
        assert!(r.id_prefixes.is_empty());
    }

    #[test]
    fn resource_deserializes_from_object() {
        let r: Resource = serde_json::from_value(json!({
            "name": "stream",
            "types": ["movie", "tv"],
            "idPrefixes": ["tt"],
        }))
        .unwrap();
        assert_eq!(r.name, ResourceName::stream());
        assert_eq!(r.types, vec![ContentType::movie(), ContentType::new("tv")]);
        assert_eq!(r.id_prefixes, vec!["tt".to_string()]);
    }

    #[test]
    fn resource_object_missing_optional_fields_defaults_empty() {
        let r: Resource = serde_json::from_value(json!({ "name": "subtitles" })).unwrap();
        assert_eq!(r.name, ResourceName::subtitles());
        assert!(r.types.is_empty());
        assert!(r.id_prefixes.is_empty());
    }

    #[test]
    fn resource_invalid_shape_is_rejected() {
        // A number is neither a string nor an object.
        let err = serde_json::from_value::<Resource>(json!(42));
        assert!(err.is_err());
    }

    #[test]
    fn resource_round_trips_both_forms() {
        assert_round_trip(&Resource::bare("stream"));
        assert_round_trip(&Resource::bare("catalog"));
        assert_round_trip(&Resource::full(
            ResourceName::stream(),
            vec![ContentType::movie()],
            vec!["tt".into()],
        ));
        assert_round_trip(&Resource::full(
            ResourceName::meta(),
            vec![ContentType::series()],
            vec![],
        ));
    }

    // -- CatalogExtraOptions: coercion (Req 26.1, 26.2) ---------------------

    #[test]
    fn catalog_extra_options_coerce_numbers_and_bools_to_strings() {
        let opts: CatalogExtraOptions =
            serde_json::from_value(json!(["hd", 720, 1.5, true, false])).unwrap();
        assert_eq!(
            opts.0,
            vec![
                "hd".to_string(),
                "720".to_string(),
                "1.5".to_string(),
                "true".to_string(),
                "false".to_string(),
            ],
        );
    }

    #[test]
    fn catalog_extra_options_integer_has_no_decimal_point() {
        // Go's strconv.Itoa / FormatFloat(-1) renders 720, not 720.0.
        let opts: CatalogExtraOptions = serde_json::from_value(json!([720, 0, -3])).unwrap();
        assert_eq!(opts.0, vec!["720", "0", "-3"]);
    }

    #[test]
    fn catalog_extra_options_serialize_as_string_array() {
        let opts = CatalogExtraOptions(vec!["a".into(), "b".into()]);
        assert_eq!(serde_json::to_value(&opts).unwrap(), json!(["a", "b"]));
    }

    #[test]
    fn catalog_extra_options_round_trip_after_coercion() {
        // After coercion every element is a string, so a second round trip is a
        // fixed point.
        let opts: CatalogExtraOptions = serde_json::from_value(json!(["x", 9, true])).unwrap();
        assert_round_trip(&opts);
    }

    #[test]
    fn catalog_extra_options_empty_is_empty() {
        let opts: CatalogExtraOptions = serde_json::from_value(json!([])).unwrap();
        assert!(opts.is_empty());
    }

    // -- CatalogExtra / Catalog --------------------------------------------

    #[test]
    fn catalog_extra_omits_defaults() {
        let extra = CatalogExtra {
            name: "genre".into(),
            is_required: false,
            options: CatalogExtraOptions::default(),
            options_limit: 0,
        };
        let v = serde_json::to_value(&extra).unwrap();
        assert_eq!(v, json!({ "name": "genre" }));
    }

    #[test]
    fn catalog_extra_includes_present_fields_and_round_trips() {
        let extra = CatalogExtra {
            name: "search".into(),
            is_required: true,
            options: CatalogExtraOptions(vec!["a".into()]),
            options_limit: 5,
        };
        let v = serde_json::to_value(&extra).unwrap();
        assert_eq!(
            v,
            json!({
                "name": "search",
                "isRequired": true,
                "options": ["a"],
                "optionsLimit": 5,
            }),
        );
        assert_round_trip(&extra);
    }

    #[test]
    fn catalog_serializes_type_field_and_omits_empties() {
        let catalog = Catalog {
            r#type: "movie".into(),
            id: "st-store".into(),
            name: "Store".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&catalog).unwrap();
        assert_eq!(v, json!({ "type": "movie", "id": "st-store", "name": "Store" }));
        assert_round_trip(&catalog);
    }

    // -- BehaviorHints ------------------------------------------------------

    #[test]
    fn behavior_hints_default_is_empty_object() {
        let v = serde_json::to_value(BehaviorHints::default()).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn behavior_hints_emit_only_true_fields_and_round_trip() {
        let bh = BehaviorHints {
            configurable: true,
            configuration_required: true,
            ..Default::default()
        };
        let v = serde_json::to_value(&bh).unwrap();
        assert_eq!(v, json!({ "configurable": true, "configurationRequired": true }));
        assert_round_trip(&bh);
    }

    // -- StreamBehaviorHints / ProxyHeaders / Stream ------------------------

    #[test]
    fn stream_behavior_hints_field_names_match_go() {
        let mut req = BTreeMap::new();
        req.insert("Authorization".to_string(), "Bearer x".to_string());
        let hints = StreamBehaviorHints {
            country_whitelist: vec!["US".into(), "CA".into()],
            not_web_ready: true,
            binge_group: Some("grp".into()),
            proxy_headers: Some(ProxyHeaders {
                request: req,
                response: BTreeMap::new(),
            }),
            video_hash: Some("abc".into()),
            video_size: Some(123_456),
            filename: Some("movie.mkv".into()),
        };
        let v = serde_json::to_value(&hints).unwrap();
        assert_eq!(v["countryWhitelist"], json!(["US", "CA"]));
        assert_eq!(v["notWebReady"], json!(true));
        assert_eq!(v["bingeGroup"], json!("grp"));
        assert_eq!(v["proxyHeaders"], json!({ "request": { "Authorization": "Bearer x" } }));
        assert_eq!(v["videoHash"], json!("abc"));
        assert_eq!(v["videoSize"], json!(123_456));
        assert_eq!(v["filename"], json!("movie.mkv"));
        assert_round_trip(&hints);
    }

    #[test]
    fn stream_behavior_hints_default_is_empty_object() {
        assert_eq!(
            serde_json::to_value(StreamBehaviorHints::default()).unwrap(),
            json!({}),
        );
    }

    #[test]
    fn stream_field_names_match_go_and_omit_none() {
        let stream = Stream {
            url: Some("https://proxy.example/d/token".into()),
            info_hash: Some("deadbeef".into()),
            file_index: Some(0),
            name: Some("RealDebrid".into()),
            title: Some("1080p".into()),
            behavior_hints: Some(StreamBehaviorHints {
                video_size: Some(999),
                filename: Some("a.mkv".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let v = serde_json::to_value(&stream).unwrap();
        assert_eq!(v["url"], json!("https://proxy.example/d/token"));
        assert_eq!(v["infoHash"], json!("deadbeef"));
        // fileIdx = 0 survives (Option, not Go's omitempty int).
        assert_eq!(v["fileIdx"], json!(0));
        assert_eq!(v["name"], json!("RealDebrid"));
        assert_eq!(v["title"], json!("1080p"));
        assert_eq!(v["behaviorHints"]["videoSize"], json!(999));
        // Absent optionals are omitted.
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("ytId"));
        assert!(!obj.contains_key("externalUrl"));
        assert!(!obj.contains_key("description"));
        assert!(!obj.contains_key("subtitles"));
        assert!(!obj.contains_key("sources"));
        assert_round_trip(&stream);
    }

    #[test]
    fn stream_empty_is_empty_object() {
        assert_eq!(serde_json::to_value(Stream::default()).unwrap(), json!({}));
    }

    // -- Subtitle -----------------------------------------------------------

    #[test]
    fn subtitle_required_fields_present_and_undocumented_omitted() {
        let sub = Subtitle {
            id: "1".into(),
            url: "https://x/sub.srt".into(),
            lang: "eng".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&sub).unwrap();
        assert_eq!(v, json!({ "id": "1", "url": "https://x/sub.srt", "lang": "eng" }));
        assert_round_trip(&sub);
    }

    #[test]
    fn subtitle_undocumented_fields_use_go_casing() {
        let sub = Subtitle {
            id: "1".into(),
            url: "u".into(),
            lang: "eng".into(),
            sub_encoding: "UTF-8".into(),
            m: "mm".into(),
            g: "gg".into(),
        };
        let v = serde_json::to_value(&sub).unwrap();
        assert_eq!(v["SubEncoding"], json!("UTF-8"));
        assert_eq!(v["m"], json!("mm"));
        assert_eq!(v["g"], json!("gg"));
        assert_round_trip(&sub);
    }

    // -- Meta / MetaVideo ---------------------------------------------------

    #[test]
    fn meta_minimal_round_trips_and_uses_type_rename() {
        let meta = Meta {
            id: "tt0111161".into(),
            r#type: ContentType::movie(),
            name: "The Shawshank Redemption".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(
            v,
            json!({ "id": "tt0111161", "type": "movie", "name": "The Shawshank Redemption" }),
        );
        assert_round_trip(&meta);
    }

    #[test]
    fn meta_video_omits_minus_one_episode_and_season() {
        let mv = MetaVideo {
            id: "tt:1:1".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&mv).unwrap();
        // episode/season are -1 (unknown) ⇒ omitted (Go omitzero).
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("episode"));
        assert!(!obj.contains_key("season"));
        assert_eq!(v, json!({ "id": "tt:1:1" }));
        assert_round_trip(&mv);
    }

    #[test]
    fn meta_video_includes_zero_episode_and_season() {
        let mv = MetaVideo {
            id: "v".into(),
            episode: 0,
            season: 0,
            ..Default::default()
        };
        let v = serde_json::to_value(&mv).unwrap();
        // 0 is a valid (present) value distinct from the -1 sentinel.
        assert_eq!(v["episode"], json!(0));
        assert_eq!(v["season"], json!(0));
        assert_round_trip(&mv);
    }

    #[test]
    fn meta_video_missing_episode_season_default_to_minus_one() {
        let mv: MetaVideo = serde_json::from_value(json!({ "id": "x" })).unwrap();
        assert_eq!(mv.episode, -1);
        assert_eq!(mv.season, -1);
    }

    #[test]
    fn meta_with_videos_round_trips() {
        let meta = Meta {
            id: "tt1".into(),
            r#type: ContentType::series(),
            name: "Show".into(),
            videos: vec![MetaVideo {
                id: "tt1:1:1".into(),
                title: Some("Pilot".into()),
                season: 1,
                episode: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_round_trip(&meta);
    }

    #[test]
    fn meta_preview_poster_always_present() {
        let preview = MetaPreview {
            id: "tt1".into(),
            r#type: ContentType::movie(),
            name: "Movie".into(),
            poster: String::new(),
            ..Default::default()
        };
        let v = serde_json::to_value(&preview).unwrap();
        // Go's `poster` has no omitempty ⇒ always present, even when empty.
        assert!(v.as_object().unwrap().contains_key("poster"));
        assert_eq!(v["poster"], json!(""));
        assert_round_trip(&preview);
    }

    // -- Manifest (Req 26.1, 26.4) -----------------------------------------

    fn sample_manifest() -> Manifest {
        Manifest {
            id: "st:store:realdebrid".into(),
            name: "StreamFlow Store".into(),
            description: "Debrid store addon".into(),
            version: "0.1.0".into(),
            resources: vec![
                Resource::bare("stream"),
                Resource::full(
                    ResourceName::catalog(),
                    vec![ContentType::movie(), ContentType::series()],
                    vec![],
                ),
            ],
            types: ContentType::all(),
            id_prefixes: vec!["tt".into(), "kitsu:".into()],
            catalogs: vec![Catalog {
                r#type: "movie".into(),
                id: "store-movies".into(),
                name: "Store Movies".into(),
                ..Default::default()
            }],
            behavior_hints: Some(BehaviorHints {
                configurable: true,
                configuration_required: true,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn manifest_declares_all_content_types_and_id_prefixes() {
        let m = sample_manifest();
        // All six canonical content types declared (Req 26.4).
        let types: Vec<&str> = m.types.iter().map(|t| t.as_str()).collect();
        assert_eq!(types, vec!["anime", "movie", "series", "channel", "tv", "other"]);
        // Id prefixes declared (Req 26.4).
        assert_eq!(m.id_prefixes, vec!["tt".to_string(), "kitsu:".to_string()]);
    }

    #[test]
    fn manifest_serializes_required_arrays_even_when_empty() {
        // resources/types/catalogs have no omitempty in Go ⇒ always present.
        let m = Manifest {
            id: "id".into(),
            name: "n".into(),
            description: "d".into(),
            version: "1.0.0".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(v["resources"], json!([]));
        assert_eq!(v["types"], json!([]));
        assert_eq!(v["catalogs"], json!([]));
        // idPrefixes IS omitempty ⇒ omitted when empty.
        assert!(!obj.contains_key("idPrefixes"));
        // Optional string/struct fields omitted.
        assert!(!obj.contains_key("background"));
        assert!(!obj.contains_key("behaviorHints"));
    }

    #[test]
    fn manifest_field_names_match_go() {
        let m = sample_manifest();
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["id"], json!("st:store:realdebrid"));
        assert_eq!(v["idPrefixes"], json!(["tt", "kitsu:"]));
        assert_eq!(v["behaviorHints"]["configurationRequired"], json!(true));
        // The bare resource stays a string; the full one an object.
        assert_eq!(v["resources"][0], json!("stream"));
        assert_eq!(
            v["resources"][1],
            json!({ "name": "catalog", "types": ["movie", "series"] }),
        );
    }

    #[test]
    fn manifest_round_trips() {
        assert_round_trip(&sample_manifest());
    }

    #[test]
    fn manifest_deserializes_from_go_style_null_arrays() {
        // Go marshals a nil slice as null; we must ingest that as empty.
        let m: Manifest = serde_json::from_value(json!({
            "id": "x",
            "name": "n",
            "description": "",
            "version": "1.0.0",
            "resources": null,
            "types": null,
            "catalogs": null,
        }))
        .unwrap();
        assert!(m.resources.is_empty());
        assert!(m.types.is_empty());
        assert!(m.catalogs.is_empty());
    }

    #[test]
    fn manifest_is_valid_predicate() {
        assert!(sample_manifest().is_valid());
        let mut m = sample_manifest();
        m.version.clear();
        assert!(!m.is_valid());
    }

    // -- Manifest::provides / not-found (Req 26.3) -------------------------

    #[test]
    fn manifest_provides_declared_resource() {
        let m = sample_manifest();
        assert!(m.provides("stream"));
        assert!(m.provides("catalog"));
        assert!(!m.provides("meta"));
        assert!(!m.provides("subtitles"));
    }

    #[test]
    fn manifest_provides_resource_respects_content_type() {
        let m = sample_manifest();
        // Bare "stream" resource ⇒ offered for any type.
        assert!(m.provides_resource("stream", Some("movie")));
        assert!(m.provides_resource("stream", Some("tv")));
        // "catalog" only declares movie/series.
        assert!(m.provides_resource("catalog", Some("movie")));
        assert!(m.provides_resource("catalog", Some("series")));
        assert!(!m.provides_resource("catalog", Some("tv")));
        // Undeclared resource never provided.
        assert!(!m.provides_resource("meta", None));
    }

    #[test]
    fn stremio_not_found_error_shape() {
        let err = StremioError::not_found("meta");
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v, json!({ "err": "resource not found: meta" }));
        assert_eq!(StremioError::NOT_FOUND_STATUS, 404);
        assert_round_trip(&err);
    }

    // -- response envelopes -------------------------------------------------

    #[test]
    fn streams_response_empty_list_is_valid() {
        let resp = StreamsResponse::default();
        assert_eq!(serde_json::to_value(&resp).unwrap(), json!({ "streams": [] }));
        assert_round_trip(&resp);
    }

    #[test]
    fn metas_meta_and_subtitles_responses_round_trip() {
        assert_round_trip(&MetasResponse {
            metas: vec![MetaPreview {
                id: "tt1".into(),
                r#type: ContentType::movie(),
                name: "M".into(),
                poster: "p".into(),
                ..Default::default()
            }],
        });
        assert_round_trip(&MetaResponse {
            meta: Meta {
                id: "tt1".into(),
                r#type: ContentType::movie(),
                name: "M".into(),
                ..Default::default()
            },
        });
        assert_round_trip(&SubtitlesResponse {
            subtitles: vec![Subtitle {
                id: "1".into(),
                url: "u".into(),
                lang: "eng".into(),
                ..Default::default()
            }],
        });
    }

    // -- ContentType / ResourceName newtypes --------------------------------

    #[test]
    fn content_type_serializes_as_bare_string() {
        assert_eq!(serde_json::to_value(ContentType::movie()).unwrap(), json!("movie"));
        let ct: ContentType = serde_json::from_value(json!("anime")).unwrap();
        assert_eq!(ct, ContentType::anime());
    }

    #[test]
    fn resource_name_serializes_as_bare_string() {
        assert_eq!(serde_json::to_value(ResourceName::stream()).unwrap(), json!("stream"));
        let rn: ResourceName = serde_json::from_value(json!("addon_catalog")).unwrap();
        assert_eq!(rn.as_str(), ResourceName::ADDON_CATALOG);
    }

    #[test]
    fn content_type_all_lists_six_canonical_types() {
        assert_eq!(ContentType::all().len(), 6);
    }
}
