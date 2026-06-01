//! Property-based test for Stremio protocol type serialization round trips
//! (`stremio::types`, task 26.5).
//!
//! Feature: ZippyPanther, Property 9
//!
//! **Property 9: Stremio protocol serialization round trip**
//!
//! *For any* Stremio protocol object (Manifest, Resource, Catalog, Stream,
//! Subtitle, Meta, BehaviorHints, StreamBehaviorHints), serializing then
//! deserializing the object recovers an equivalent object, including the
//! string-or-object `Resource` form and the coerced `CatalogExtraOptions` form.
//!
//! **Validates: Requirements 26.1, 26.2, 48.3**
//!
//! * Req 26.1 — serde field names and `omitempty` semantics match Go's struct
//!   tags, including the string-or-object `Resource` form and the
//!   `CatalogExtraOptions` coercion.
//! * Req 26.2 — every protocol object round-trips through `serde_json`.
//! * Req 48.3 — the round-trip property is verified over arbitrary inputs
//!   (>= 100 cases).
//!
//! ## How the property is exercised
//!
//! Arbitrary generators produce every key Stremio protocol type. For each
//! generated value the test asserts:
//!
//! 1. `serde_json::to_string(v)` succeeds (serialization never panics or
//!    errors on a well-typed value).
//! 2. `serde_json::from_str::<T>(json)` succeeds (the produced JSON is always
//!    valid for the same type).
//! 3. The deserialized value equals the original (`v == round_tripped`).
//!
//! The `Resource` generator covers both the bare-string form (empty
//! `types`/`id_prefixes`) and the object form (non-empty `types` or
//! `id_prefixes`), exercising the custom `Serialize`/`Deserialize` impls.
//!
//! The `CatalogExtraOptions` generator produces post-coercion string arrays
//! and verifies that the round trip is a fixed point (all elements are already
//! strings after the first deserialization).

use proptest::prelude::*;
use zippy_panther::stremio::types::{
    BehaviorHints, Catalog, CatalogExtra, CatalogExtraOptions, ContentType, Manifest, Meta,
    MetaBehaviorHints, MetaLink, MetaPreview, MetaVideo, ProxyHeaders, Resource, ResourceName,
    Stream, StreamBehaviorHints, Subtitle,
};

// ---------------------------------------------------------------------------
// Generic round-trip helper
// ---------------------------------------------------------------------------

fn round_trip<T>(value: &T) -> Result<(), TestCaseError>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value)
        .map_err(|e| TestCaseError::fail(format!("serialize failed: {e}")))?;
    let back: T = serde_json::from_str(&json)
        .map_err(|e| TestCaseError::fail(format!("deserialize failed: {e}")))?;
    prop_assert_eq!(value, &back, "round trip mismatch");
    Ok(())
}

// ---------------------------------------------------------------------------
// Primitive generators
// ---------------------------------------------------------------------------

/// Arbitrary non-empty ASCII identifier (safe for JSON field values and ids).
fn arb_ident() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_:.-]{1,32}".prop_map(|s| s)
}

/// Arbitrary string (including empty and unicode).
fn arb_string() -> impl Strategy<Value = String> {
    any::<String>()
}

/// Arbitrary optional string.
fn arb_opt_string() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(arb_string())
}

/// Arbitrary `ContentType` — mix of canonical and arbitrary values.
fn arb_content_type() -> impl Strategy<Value = ContentType> {
    prop_oneof![
        Just(ContentType::movie()),
        Just(ContentType::series()),
        Just(ContentType::tv()),
        Just(ContentType::anime()),
        Just(ContentType::new("channel")),
        Just(ContentType::new("other")),
        arb_ident().prop_map(ContentType::new),
    ]
}

/// Arbitrary `ResourceName` — mix of canonical and arbitrary values.
fn arb_resource_name() -> impl Strategy<Value = ResourceName> {
    prop_oneof![
        Just(ResourceName::catalog()),
        Just(ResourceName::meta()),
        Just(ResourceName::stream()),
        Just(ResourceName::subtitles()),
        Just(ResourceName::new("addon_catalog")),
        arb_ident().prop_map(ResourceName::new),
    ]
}

// ---------------------------------------------------------------------------
// Resource generator — covers both wire forms (Req 26.1)
// ---------------------------------------------------------------------------

/// Arbitrary `Resource` covering both the bare-string form (empty
/// `types`/`id_prefixes`) and the object form (non-empty `types` or
/// `id_prefixes`).
fn arb_resource() -> impl Strategy<Value = Resource> {
    prop_oneof![
        // Bare-string form: no types, no id_prefixes.
        arb_resource_name().prop_map(Resource::bare),
        // Object form with types only.
        (
            arb_resource_name(),
            proptest::collection::vec(arb_content_type(), 1..=4),
        )
            .prop_map(|(name, types)| Resource::full(name, types, vec![])),
        // Object form with types and id_prefixes.
        (
            arb_resource_name(),
            proptest::collection::vec(arb_content_type(), 1..=4),
            proptest::collection::vec(arb_ident(), 1..=4),
        )
            .prop_map(|(name, types, prefixes)| Resource::full(name, types, prefixes)),
        // Object form with id_prefixes only (empty types → still object form).
        (
            arb_resource_name(),
            proptest::collection::vec(arb_ident(), 1..=4),
        )
            .prop_map(|(name, prefixes)| Resource::full(name, vec![], prefixes)),
    ]
}

// ---------------------------------------------------------------------------
// CatalogExtraOptions generator — exercises coercion (Req 26.1)
// ---------------------------------------------------------------------------

/// Arbitrary `CatalogExtraOptions` built from already-coerced strings (the
/// round-trip fixed-point form). After the first deserialization all elements
/// are strings, so we generate the post-coercion form directly and verify the
/// round trip is a fixed point.
fn arb_catalog_extra_options() -> impl Strategy<Value = CatalogExtraOptions> {
    proptest::collection::vec(arb_string(), 0..=8).prop_map(CatalogExtraOptions::from)
}

// ---------------------------------------------------------------------------
// CatalogExtra / Catalog generators
// ---------------------------------------------------------------------------

fn arb_catalog_extra() -> impl Strategy<Value = CatalogExtra> {
    (
        arb_ident(),
        any::<bool>(),
        arb_catalog_extra_options(),
        0i32..=100,
    )
        .prop_map(|(name, is_required, options, options_limit)| CatalogExtra {
            name,
            is_required,
            options,
            options_limit,
        })
}

fn arb_catalog() -> impl Strategy<Value = Catalog> {
    (
        arb_ident(), // type
        arb_ident(), // id
        arb_ident(), // name
        proptest::collection::vec(arb_catalog_extra(), 0..=4),
    )
        .prop_map(|(r#type, id, name, extra)| Catalog {
            r#type,
            id,
            name,
            extra,
            ..Default::default()
        })
}

// ---------------------------------------------------------------------------
// BehaviorHints generator
// ---------------------------------------------------------------------------

fn arb_behavior_hints() -> impl Strategy<Value = BehaviorHints> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(adult, p2p, configurable, configuration_required, new_episode_notifications)| {
                BehaviorHints {
                    adult,
                    p2p,
                    configurable,
                    configuration_required,
                    new_episode_notifications,
                }
            },
        )
}

// ---------------------------------------------------------------------------
// ProxyHeaders / StreamBehaviorHints generators
// ---------------------------------------------------------------------------

fn arb_proxy_headers() -> impl Strategy<Value = ProxyHeaders> {
    (
        proptest::collection::btree_map(arb_ident(), arb_string(), 0..=4),
        proptest::collection::btree_map(arb_ident(), arb_string(), 0..=4),
    )
        .prop_map(|(request, response)| ProxyHeaders { request, response })
}

fn arb_stream_behavior_hints() -> impl Strategy<Value = StreamBehaviorHints> {
    (
        proptest::collection::vec(arb_ident(), 0..=4),
        any::<bool>(),
        arb_opt_string(),
        proptest::option::of(arb_proxy_headers()),
        arb_opt_string(),
        proptest::option::of(any::<i64>()),
        arb_opt_string(),
    )
        .prop_map(
            |(
                country_whitelist,
                not_web_ready,
                binge_group,
                proxy_headers,
                video_hash,
                video_size,
                filename,
            )| StreamBehaviorHints {
                country_whitelist,
                not_web_ready,
                binge_group,
                proxy_headers,
                video_hash,
                video_size,
                filename,
            },
        )
}

// ---------------------------------------------------------------------------
// Subtitle generator
// ---------------------------------------------------------------------------

fn arb_subtitle() -> impl Strategy<Value = Subtitle> {
    (
        arb_ident(),
        arb_ident(),
        arb_ident(),
        arb_string(),
        arb_string(),
        arb_string(),
    )
        .prop_map(|(id, url, lang, sub_encoding, m, g)| Subtitle {
            id,
            url,
            lang,
            sub_encoding,
            m,
            g,
        })
}

// ---------------------------------------------------------------------------
// Stream generator
// ---------------------------------------------------------------------------

fn arb_stream() -> impl Strategy<Value = Stream> {
    (
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        proptest::option::of(any::<i32>()),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        proptest::collection::vec(arb_subtitle(), 0..=3),
        proptest::collection::vec(arb_ident(), 0..=3),
        proptest::option::of(arb_stream_behavior_hints()),
    )
        .prop_map(
            |(
                url,
                youtube_id,
                info_hash,
                file_index,
                external_url,
                name,
                title,
                description,
                subtitles,
                sources,
                behavior_hints,
            )| Stream {
                url,
                youtube_id,
                info_hash,
                file_index,
                external_url,
                name,
                title,
                description,
                subtitles,
                sources,
                behavior_hints,
            },
        )
}

// ---------------------------------------------------------------------------
// Meta generators
// ---------------------------------------------------------------------------

fn arb_meta_link() -> impl Strategy<Value = MetaLink> {
    (arb_string(), arb_ident(), arb_string()).prop_map(|(name, category, url)| MetaLink {
        name,
        category,
        url,
    })
}

fn arb_meta_behavior_hints() -> impl Strategy<Value = MetaBehaviorHints> {
    (arb_opt_string(), any::<bool>()).prop_map(|(default_video_id, has_scheduled_videos)| {
        MetaBehaviorHints {
            default_video_id,
            has_scheduled_videos,
        }
    })
}

fn arb_meta_video() -> impl Strategy<Value = MetaVideo> {
    (
        arb_ident(),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        any::<bool>(),
        // episode/season: use -1 (unknown sentinel), 0, or a small positive
        prop_oneof![Just(-1i32), Just(0i32), 1i32..=24],
        prop_oneof![Just(-1i32), Just(0i32), 1i32..=10],
        arb_opt_string(),
    )
        .prop_map(
            |(id, title, released, thumbnail, available, episode, season, overview)| MetaVideo {
                id,
                title,
                released,
                thumbnail,
                streams: vec![],
                available,
                episode,
                season,
                overview,
            },
        )
}

fn arb_meta() -> impl Strategy<Value = Meta> {
    // proptest supports tuples up to 12 elements; use prop_flat_map to chain
    // two groups of fields.
    (
        arb_ident(),
        arb_content_type(),
        arb_string(),
        proptest::collection::vec(arb_string(), 0..=4),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
        arb_opt_string(),
    )
        .prop_flat_map(
            |(
                id,
                r#type,
                name,
                genres,
                poster,
                poster_shape,
                background,
                logo,
                description,
                release_info,
            )| {
                let base = (
                    id,
                    r#type,
                    name,
                    genres,
                    poster,
                    poster_shape,
                    background,
                    logo,
                    description,
                    release_info,
                );
                (
                    Just(base),
                    arb_opt_string(),
                    arb_opt_string(),
                    proptest::collection::vec(arb_meta_link(), 0..=3),
                    proptest::collection::vec(arb_meta_video(), 0..=3),
                    arb_opt_string(),
                    arb_opt_string(),
                    arb_opt_string(),
                    arb_opt_string(),
                    proptest::option::of(arb_meta_behavior_hints()),
                )
            },
        )
        .prop_map(
            |(
                (
                    id,
                    r#type,
                    name,
                    genres,
                    poster,
                    poster_shape,
                    background,
                    logo,
                    description,
                    release_info,
                ),
                imdb_rating,
                released,
                links,
                videos,
                runtime,
                language,
                country,
                website,
                behavior_hints,
            )| Meta {
                id,
                r#type,
                name,
                genres,
                poster,
                poster_shape,
                background,
                logo,
                description,
                release_info,
                imdb_rating,
                released,
                links,
                videos,
                runtime,
                language,
                country,
                website,
                behavior_hints,
            },
        )
}

fn arb_meta_preview() -> impl Strategy<Value = MetaPreview> {
    (
        arb_ident(),
        arb_content_type(),
        arb_string(),
        arb_string(),
        arb_opt_string(),
        proptest::collection::vec(arb_string(), 0..=4),
        arb_opt_string(),
        arb_opt_string(),
        proptest::collection::vec(arb_meta_link(), 0..=3),
        arb_opt_string(),
    )
        .prop_map(
            |(
                id,
                r#type,
                name,
                poster,
                poster_shape,
                genres,
                imdb_rating,
                release_info,
                links,
                description,
            )| {
                MetaPreview {
                    id,
                    r#type,
                    name,
                    poster,
                    poster_shape,
                    genres,
                    imdb_rating,
                    release_info,
                    links,
                    description,
                }
            },
        )
}

// ---------------------------------------------------------------------------
// Manifest generator
// ---------------------------------------------------------------------------

fn arb_manifest() -> impl Strategy<Value = Manifest> {
    // proptest supports tuples up to 12 elements; use prop_flat_map to chain.
    (
        arb_ident(),
        arb_string(),
        arb_string(),
        arb_ident(),
        proptest::collection::vec(arb_resource(), 0..=4),
        proptest::collection::vec(arb_content_type(), 0..=6),
        proptest::collection::vec(arb_ident(), 0..=4),
        proptest::collection::vec(arb_catalog(), 0..=3),
        proptest::collection::vec(arb_catalog(), 0..=3),
        arb_string(),
        arb_string(),
        arb_string(),
    )
        .prop_flat_map(
            |(
                id,
                name,
                description,
                version,
                resources,
                types,
                id_prefixes,
                addon_catalogs,
                catalogs,
                background,
                logo,
                contact_email,
            )| {
                let base = (
                    id,
                    name,
                    description,
                    version,
                    resources,
                    types,
                    id_prefixes,
                    addon_catalogs,
                    catalogs,
                    background,
                    logo,
                    contact_email,
                );
                (Just(base), proptest::option::of(arb_behavior_hints()))
            },
        )
        .prop_map(
            |(
                (
                    id,
                    name,
                    description,
                    version,
                    resources,
                    types,
                    id_prefixes,
                    addon_catalogs,
                    catalogs,
                    background,
                    logo,
                    contact_email,
                ),
                behavior_hints,
            )| Manifest {
                id,
                name,
                description,
                version,
                resources,
                types,
                id_prefixes,
                addon_catalogs,
                catalogs,
                background,
                logo,
                contact_email,
                behavior_hints,
            },
        )
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    // 256 cases (>= 100 required for a property task).
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: ZippyPanther, Property 9 — `Resource` serializes and
    /// deserializes back to an equivalent value, covering both the bare-string
    /// form and the object form. **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn resource_round_trip(r in arb_resource()) {
        round_trip(&r)?;
    }

    /// Feature: ZippyPanther, Property 9 — `CatalogExtraOptions` round-trips
    /// through JSON (post-coercion fixed point). **Validates: Requirements
    /// 26.1, 26.2, 48.3**
    #[test]
    fn catalog_extra_options_round_trip(opts in arb_catalog_extra_options()) {
        round_trip(&opts)?;
    }

    /// Feature: ZippyPanther, Property 9 — `CatalogExtra` round-trips through
    /// JSON. **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn catalog_extra_round_trip(extra in arb_catalog_extra()) {
        round_trip(&extra)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Catalog` round-trips through JSON.
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn catalog_round_trip(catalog in arb_catalog()) {
        round_trip(&catalog)?;
    }

    /// Feature: ZippyPanther, Property 9 — `BehaviorHints` round-trips through
    /// JSON. **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn behavior_hints_round_trip(bh in arb_behavior_hints()) {
        round_trip(&bh)?;
    }

    /// Feature: ZippyPanther, Property 9 — `StreamBehaviorHints` round-trips
    /// through JSON. **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn stream_behavior_hints_round_trip(hints in arb_stream_behavior_hints()) {
        round_trip(&hints)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Subtitle` round-trips through JSON.
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn subtitle_round_trip(sub in arb_subtitle()) {
        round_trip(&sub)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Stream` round-trips through JSON,
    /// including `fileIdx = 0` surviving (Option<i32> vs Go's omitempty int).
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn stream_round_trip(stream in arb_stream()) {
        round_trip(&stream)?;
    }

    /// Feature: ZippyPanther, Property 9 — `MetaVideo` round-trips through
    /// JSON, including the `-1` sentinel for unknown episode/season.
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn meta_video_round_trip(mv in arb_meta_video()) {
        round_trip(&mv)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Meta` round-trips through JSON.
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn meta_round_trip(meta in arb_meta()) {
        round_trip(&meta)?;
    }

    /// Feature: ZippyPanther, Property 9 — `MetaPreview` round-trips through
    /// JSON, including the always-present `poster` field.
    /// **Validates: Requirements 26.1, 26.2, 48.3**
    #[test]
    fn meta_preview_round_trip(preview in arb_meta_preview()) {
        round_trip(&preview)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Manifest` round-trips through JSON,
    /// including mixed bare-string and object `Resource` entries.
    /// **Validates: Requirements 26.1, 26.2, 26.4, 48.3**
    #[test]
    fn manifest_round_trip(manifest in arb_manifest()) {
        round_trip(&manifest)?;
    }

    /// Feature: ZippyPanther, Property 9 — `Resource` string form serializes as
    /// a bare JSON string (not an object), and the object form serializes as a
    /// JSON object. **Validates: Requirements 26.1, 26.2**
    #[test]
    fn resource_wire_form_matches_is_string_form(r in arb_resource()) {
        let json_val = serde_json::to_value(&r)
            .map_err(|e| TestCaseError::fail(format!("serialize failed: {e}")))?;
        if r.is_string_form() {
            prop_assert!(
                json_val.is_string(),
                "bare Resource must serialize as a JSON string, got: {json_val}",
            );
            prop_assert_eq!(
                json_val.as_str().unwrap(),
                r.name.as_str(),
                "bare Resource string must equal the resource name",
            );
        } else {
            prop_assert!(
                json_val.is_object(),
                "non-bare Resource must serialize as a JSON object, got: {json_val}",
            );
            let obj = json_val.as_object().unwrap();
            prop_assert!(obj.contains_key("name"), "object Resource must have 'name' field");
            prop_assert!(obj.contains_key("types"), "object Resource must have 'types' field");
        }
    }

    /// Feature: ZippyPanther, Property 9 — `CatalogExtraOptions` coercion is a
    /// fixed point: after one deserialization all elements are strings, so a
    /// second round trip is identical. **Validates: Requirements 26.1, 26.2**
    #[test]
    fn catalog_extra_options_coercion_is_fixed_point(opts in arb_catalog_extra_options()) {
        // opts is already in post-coercion form (all strings). Serialize and
        // deserialize once — the result must equal opts (fixed point).
        let json = serde_json::to_string(&opts)
            .map_err(|e| TestCaseError::fail(format!("serialize failed: {e}")))?;
        let back: CatalogExtraOptions = serde_json::from_str(&json)
            .map_err(|e| TestCaseError::fail(format!("deserialize failed: {e}")))?;
        prop_assert_eq!(&opts, &back, "CatalogExtraOptions round trip must be a fixed point");

        // A second round trip must also be identical.
        let json2 = serde_json::to_string(&back)
            .map_err(|e| TestCaseError::fail(format!("second serialize failed: {e}")))?;
        let back2: CatalogExtraOptions = serde_json::from_str(&json2)
            .map_err(|e| TestCaseError::fail(format!("second deserialize failed: {e}")))?;
        prop_assert_eq!(
            &opts,
            &back2,
            "CatalogExtraOptions must be a fixed point on second round trip",
        );
    }
}
