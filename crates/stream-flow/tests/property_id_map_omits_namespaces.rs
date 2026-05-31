//! Property-based test: ID-map omits unknown namespaces
//! (task 24.10, Property 25).
//!
//! Feature: stream-flow, Property 25
//!
//! **Property 25: ID-map omits unknown namespaces**
//!
//! *For any* partial identifier mapping, the returned `IdMap` includes exactly
//! the namespaces (IMDB/TMDB/TVDB/Trakt) for which a value is known and omits
//! all others.
//!
//! **Validates: Requirements 22.1, 22.3**
//!
//! Requirement 22.1: "WHEN a GET `/v0/meta/id-map/{idType}/{id}` request is
//! received for a supported id type, THE Orchestration_Layer SHALL return an
//! ID_Map containing the corresponding identifiers across IMDB, TMDB, TVDB,
//! and Trakt."
//!
//! Requirement 22.3: "WHERE an identifier has no known mapping in a target
//! namespace, THE Orchestration_Layer SHALL omit that namespace from the
//! returned ID_Map."
//!
//! ## How the invariant is exercised
//!
//! The id-map endpoint (`src/meta/mod.rs`, task 24.5) serializes its response
//! as a public [`IdMapResponse`] whose four namespace fields are
//! `Option<String>` annotated with `#[serde(skip_serializing_if =
//! "Option::is_none")]`. The serialized JSON is what a client observes.
//!
//! For an arbitrary id-map record where each of the four namespaces
//! (imdb/tmdb/tvdb/trakt) is independently present (`Some`) or absent (`None`),
//! this test serializes the response with `serde_json` and asserts that the
//! resulting JSON object contains a key **exactly** for each present namespace
//! and **omits** keys for absent ones. Key presence is checked against the
//! parsed JSON object map (not substring matching), so namespace values that
//! happen to contain other namespace names as substrings cannot produce a
//! false positive.

use proptest::prelude::*;
use stream_flow::meta::IdMapResponse;

/// The four supported ID namespaces (Req 22.1) — the complete key universe.
const NAMESPACES: &[&str] = &["imdb", "tmdb", "tvdb", "trakt"];

/// Strategy for a single namespace's known value. Mixes realistic identifiers
/// with adversarial strings that embed *other* namespace names as substrings,
/// so the test cannot pass by accident if it ever matched on substrings rather
/// than JSON object keys.
fn arb_namespace_value() -> impl Strategy<Value = String> {
    prop_oneof![
        // Realistic IMDB/TMDB/TVDB/Trakt-style identifiers.
        Just("tt0111161".to_string()),
        Just("278".to_string()),
        Just("70".to_string()),
        Just("289".to_string()),
        // Adversarial values that contain namespace key names as substrings.
        Just("imdb-tmdb-tvdb-trakt".to_string()),
        Just("contains_trakt_inside".to_string()),
        Just("tmdb:tvdb".to_string()),
        // Arbitrary non-empty unicode strings.
        "\\PC{1,24}",
    ]
}

/// Strategy for an optional namespace value: present (`Some`) or absent
/// (`None`) independently.
fn arb_namespace_field() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), arb_namespace_value().prop_map(Some),]
}

/// Strategy producing an arbitrary partial id-map record: each of the four
/// namespaces is independently present or absent.
fn arb_id_map_response() -> impl Strategy<Value = IdMapResponse> {
    (
        arb_namespace_field(),
        arb_namespace_field(),
        arb_namespace_field(),
        arb_namespace_field(),
    )
        .prop_map(|(imdb, tmdb, tvdb, trakt)| IdMapResponse {
            imdb,
            tmdb,
            tvdb,
            trakt,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feature: stream-flow, Property 25 — ID-map omits unknown namespaces.
    /// **Validates: Requirements 22.1, 22.3**
    ///
    /// For an arbitrary partial id-map record, the serialized JSON object
    /// contains a key exactly for each present (`Some`) namespace and omits the
    /// key for each absent (`None`) namespace.
    #[test]
    fn serialized_keys_match_present_namespaces_exactly(resp in arb_id_map_response()) {
        // The presence we expect, derived from the record itself.
        let expected_present: Vec<&str> = NAMESPACES
            .iter()
            .copied()
            .filter(|&ns| match ns {
                "imdb" => resp.imdb.is_some(),
                "tmdb" => resp.tmdb.is_some(),
                "tvdb" => resp.tvdb.is_some(),
                "trakt" => resp.trakt.is_some(),
                _ => unreachable!(),
            })
            .collect();

        // Serialize exactly as the endpoint does (`HttpResponse::Ok().json(..)`).
        let json = serde_json::to_value(&resp).expect("IdMapResponse serializes");
        let obj = json
            .as_object()
            .expect("IdMapResponse serializes to a JSON object");

        // 1) Every present namespace appears as a key (Req 22.1).
        for ns in &expected_present {
            prop_assert!(
                obj.contains_key(*ns),
                "present namespace {:?} must appear as a key; record={:?}, json={}",
                ns,
                resp,
                json,
            );
        }

        // 2) Every absent namespace is omitted — not present even as null (Req 22.3).
        for &ns in NAMESPACES {
            if !expected_present.contains(&ns) {
                prop_assert!(
                    !obj.contains_key(ns),
                    "absent namespace {:?} must be omitted from the JSON; record={:?}, json={}",
                    ns,
                    resp,
                    json,
                );
            }
        }

        // 3) The serialized object contains *no keys other than* the present
        //    namespaces (exactly the present set, nothing extra).
        prop_assert_eq!(
            obj.len(),
            expected_present.len(),
            "serialized object must contain exactly the present namespaces; \
             record={:?}, json={}",
            resp,
            json,
        );

        // 4) No value in the serialized object is JSON null (omission, not null).
        for (key, value) in obj.iter() {
            prop_assert!(
                !value.is_null(),
                "namespace {:?} present with a null value; absent namespaces must be omitted, json={}",
                key,
                json,
            );
        }
    }

    /// Feature: stream-flow, Property 25 — present values are preserved verbatim
    /// and the JSON round-trips back to the same record.
    /// **Validates: Requirements 22.1, 22.3**
    ///
    /// Each present namespace's value survives serialization unchanged, and
    /// deserializing the omitted-key JSON yields an equal `IdMapResponse`
    /// (absent namespaces come back as `None`).
    #[test]
    fn present_values_preserved_and_round_trip(resp in arb_id_map_response()) {
        let json = serde_json::to_value(&resp).expect("IdMapResponse serializes");
        let obj = json
            .as_object()
            .expect("IdMapResponse serializes to a JSON object");

        // Present values are preserved verbatim under their own key.
        let pairs = [
            ("imdb", &resp.imdb),
            ("tmdb", &resp.tmdb),
            ("tvdb", &resp.tvdb),
            ("trakt", &resp.trakt),
        ];
        for (ns, field) in pairs {
            if let Some(expected) = field {
                let got = obj
                    .get(ns)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                prop_assert_eq!(
                    got.as_ref(),
                    Some(expected),
                    "namespace {:?} value must be preserved verbatim; json={}",
                    ns,
                    json,
                );
            }
        }

        // Round trip: omitted keys deserialize back to None, giving an equal record.
        let back: IdMapResponse =
            serde_json::from_value(json.clone()).expect("IdMapResponse deserializes");
        prop_assert_eq!(
            back,
            resp,
            "serialize -> deserialize must be a fixed point; json={}",
            json,
        );
    }
}
