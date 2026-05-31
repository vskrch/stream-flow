//! MPD parser (`mpd::parser`) — Req 2.1, 2.8, 3.
//!
//! Parses an `.mpd` (MPEG-DASH Media Presentation Description) XML document
//! into the structured [`Mpd`](crate::mpd::model::Mpd) tree of periods →
//! adaptation sets → representations, recording each representation's
//! [`SegmentAddressing`](crate::mpd::model::SegmentAddressing) (Req 2.1).
//!
//! Parsing is performed with `quick-xml`'s serde deserializer (design:
//! Technology Choices — "DASH/XMLTV parsing: quick-xml") into a set of `Raw*`
//! shadow structs that mirror the XML 1:1, then mapped onto the domain model
//! with explicit validation so a failure **identifies the failing element**
//! (Req 2.8): a malformed document, or a representation missing its required
//! `@id` / `@bandwidth`, yields a descriptive [`MpdError`] naming the element.
//!
//! Segment-addressing elements (`SegmentTemplate`/`SegmentList`/`SegmentBase`)
//! are inherited from the adaptation set when a representation declares none of
//! its own, matching DASH inheritance. Resolving an addressing mode to concrete
//! segment URLs / byte ranges is task 16.3; this module only records the mode
//! and its raw parameters.

use serde::Deserialize;

use super::error::MpdError;
use super::model::{
    AdaptationSet, Mpd, Period, PresentationType, Representation, SegmentAddressing, SegmentBase,
    SegmentList, SegmentTemplate, SegmentTimeline, SegmentUrl, TimelineEntry, UrlRange,
};

/// Parse an MPD XML document into the structured [`Mpd`] model (Req 2.1).
///
/// Returns a descriptive [`MpdError`] identifying the failing element when the
/// XML is not well-formed ([`MpdError::malformed`]) or a required element /
/// attribute is missing ([`MpdError::missing`]) (Req 2.8).
pub fn parse_mpd(xml: &str) -> Result<Mpd, MpdError> {
    let raw: RawMpd = quick_xml::de::from_str(xml).map_err(|e| MpdError::malformed("MPD", e))?;
    map_mpd(raw)
}

// ---------------------------------------------------------------------------
// Raw shadow structs (mirror the MPD XML 1:1 for quick-xml/serde).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawMpd {
    #[serde(rename = "@type")]
    typ: Option<String>,
    #[serde(rename = "@mediaPresentationDuration")]
    media_presentation_duration: Option<String>,
    #[serde(rename = "BaseURL", default)]
    base_url: Vec<String>,
    #[serde(rename = "Period", default)]
    periods: Vec<RawPeriod>,
}

#[derive(Debug, Deserialize)]
struct RawPeriod {
    #[serde(rename = "@id")]
    id: Option<String>,
    #[serde(rename = "@duration")]
    duration: Option<String>,
    #[serde(rename = "BaseURL", default)]
    base_url: Vec<String>,
    #[serde(rename = "AdaptationSet", default)]
    adaptation_sets: Vec<RawAdaptationSet>,
}

#[derive(Debug, Deserialize)]
struct RawAdaptationSet {
    #[serde(rename = "@mimeType")]
    mime_type: Option<String>,
    #[serde(rename = "@contentType")]
    content_type: Option<String>,
    #[serde(rename = "@lang")]
    lang: Option<String>,
    #[serde(rename = "@codecs")]
    codecs: Option<String>,
    #[serde(rename = "BaseURL", default)]
    base_url: Vec<String>,
    #[serde(rename = "SegmentTemplate")]
    segment_template: Option<RawSegmentTemplate>,
    #[serde(rename = "SegmentList")]
    segment_list: Option<RawSegmentList>,
    #[serde(rename = "SegmentBase")]
    segment_base: Option<RawSegmentBase>,
    #[serde(rename = "Representation", default)]
    representations: Vec<RawRepresentation>,
}

#[derive(Debug, Deserialize)]
struct RawRepresentation {
    #[serde(rename = "@id")]
    id: Option<String>,
    #[serde(rename = "@bandwidth")]
    bandwidth: Option<u64>,
    #[serde(rename = "@width")]
    width: Option<u64>,
    #[serde(rename = "@height")]
    height: Option<u64>,
    #[serde(rename = "@codecs")]
    codecs: Option<String>,
    #[serde(rename = "@mimeType")]
    mime_type: Option<String>,
    #[serde(rename = "@frameRate")]
    frame_rate: Option<String>,
    #[serde(rename = "BaseURL", default)]
    base_url: Vec<String>,
    #[serde(rename = "SegmentTemplate")]
    segment_template: Option<RawSegmentTemplate>,
    #[serde(rename = "SegmentList")]
    segment_list: Option<RawSegmentList>,
    #[serde(rename = "SegmentBase")]
    segment_base: Option<RawSegmentBase>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentTemplate {
    #[serde(rename = "@media")]
    media: Option<String>,
    #[serde(rename = "@initialization")]
    initialization: Option<String>,
    #[serde(rename = "@startNumber")]
    start_number: Option<u64>,
    #[serde(rename = "@duration")]
    duration: Option<u64>,
    #[serde(rename = "@timescale")]
    timescale: Option<u64>,
    #[serde(rename = "SegmentTimeline")]
    timeline: Option<RawSegmentTimeline>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentTimeline {
    #[serde(rename = "S", default)]
    s: Vec<RawS>,
}

#[derive(Debug, Deserialize)]
struct RawS {
    #[serde(rename = "@t")]
    t: Option<u64>,
    #[serde(rename = "@d")]
    d: Option<u64>,
    #[serde(rename = "@r")]
    r: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentList {
    #[serde(rename = "@duration")]
    duration: Option<u64>,
    #[serde(rename = "@timescale")]
    timescale: Option<u64>,
    #[serde(rename = "Initialization")]
    initialization: Option<RawUrlRange>,
    #[serde(rename = "SegmentURL", default)]
    segment_urls: Vec<RawSegmentUrl>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentUrl {
    #[serde(rename = "@media")]
    media: Option<String>,
    #[serde(rename = "@mediaRange")]
    media_range: Option<String>,
    #[serde(rename = "@index")]
    index: Option<String>,
    #[serde(rename = "@indexRange")]
    index_range: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentBase {
    #[serde(rename = "@indexRange")]
    index_range: Option<String>,
    #[serde(rename = "@timescale")]
    timescale: Option<u64>,
    #[serde(rename = "Initialization")]
    initialization: Option<RawUrlRange>,
}

#[derive(Debug, Deserialize)]
struct RawUrlRange {
    #[serde(rename = "@sourceURL")]
    source_url: Option<String>,
    #[serde(rename = "@range")]
    range: Option<String>,
}

// ---------------------------------------------------------------------------
// Raw -> domain mapping with element-identifying validation (Req 2.8).
// ---------------------------------------------------------------------------

fn first(mut v: Vec<String>) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        Some(v.swap_remove(0))
    }
}

fn map_mpd(raw: RawMpd) -> Result<Mpd, MpdError> {
    let presentation_type = match raw.typ.as_deref() {
        Some("dynamic") => PresentationType::Dynamic,
        // `static`, absent, or any other value defaults to VOD (DASH default).
        _ => PresentationType::Static,
    };

    let mut periods = Vec::with_capacity(raw.periods.len());
    for (idx, p) in raw.periods.into_iter().enumerate() {
        periods.push(map_period(p, idx)?);
    }

    Ok(Mpd {
        presentation_type,
        media_presentation_duration: raw.media_presentation_duration,
        base_url: first(raw.base_url),
        periods,
    })
}

fn map_period(raw: RawPeriod, idx: usize) -> Result<Period, MpdError> {
    let label = raw
        .id
        .clone()
        .unwrap_or_else(|| format!("Period[{idx}]"));

    let mut adaptation_sets = Vec::with_capacity(raw.adaptation_sets.len());
    for (a_idx, a) in raw.adaptation_sets.into_iter().enumerate() {
        adaptation_sets.push(map_adaptation_set(a, &label, a_idx)?);
    }

    Ok(Period {
        id: raw.id,
        duration: raw.duration,
        base_url: first(raw.base_url),
        adaptation_sets,
    })
}

fn map_adaptation_set(
    raw: RawAdaptationSet,
    period_label: &str,
    idx: usize,
) -> Result<AdaptationSet, MpdError> {
    let set_label = format!(
        "{period_label}/AdaptationSet[{idx}]{}",
        raw.content_type
            .as_deref()
            .or(raw.mime_type.as_deref())
            .map(|t| format!(" ({t})"))
            .unwrap_or_default()
    );

    // The adaptation-set-level addressing is inherited by representations that
    // declare none of their own (DASH inheritance).
    let inherited = build_segment_addressing(
        raw.segment_template,
        raw.segment_list,
        raw.segment_base,
    );

    let mut representations = Vec::with_capacity(raw.representations.len());
    for (r_idx, r) in raw.representations.into_iter().enumerate() {
        representations.push(map_representation(
            r,
            &set_label,
            r_idx,
            &inherited,
            raw.mime_type.as_deref(),
            raw.codecs.as_deref(),
        )?);
    }

    Ok(AdaptationSet {
        mime_type: raw.mime_type,
        content_type: raw.content_type,
        lang: raw.lang,
        base_url: first(raw.base_url),
        representations,
    })
}

fn map_representation(
    raw: RawRepresentation,
    set_label: &str,
    idx: usize,
    inherited: &SegmentAddressing,
    set_mime_type: Option<&str>,
    set_codecs: Option<&str>,
) -> Result<Representation, MpdError> {
    let label = format!(
        "{set_label}/Representation[{idx}]{}",
        raw.id.as_deref().map(|i| format!(" @id={i}")).unwrap_or_default()
    );

    // `@id` is required by DASH and is what addresses the representation in
    // rewritten URLs (Req 2.3). Naming the element satisfies Req 2.8.
    let id = raw
        .id
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MpdError::missing(&label, "id"))?;

    // `@bandwidth` is required by DASH and becomes the HLS `BANDWIDTH` variant
    // attribute (Req 2.2).
    let bandwidth = raw
        .bandwidth
        .ok_or_else(|| MpdError::missing(&label, "bandwidth"))?;

    // Representation-level addressing wins; otherwise inherit the set's.
    let own = build_segment_addressing(
        raw.segment_template,
        raw.segment_list,
        raw.segment_base,
    );
    let segment_addressing = if matches!(own, SegmentAddressing::None) {
        inherited.clone()
    } else {
        own
    };

    Ok(Representation {
        id,
        bandwidth,
        width: raw.width,
        height: raw.height,
        codecs: raw.codecs.or_else(|| set_codecs.map(str::to_owned)),
        mime_type: raw.mime_type.or_else(|| set_mime_type.map(str::to_owned)),
        frame_rate: raw.frame_rate,
        base_url: first(raw.base_url),
        segment_addressing,
    })
}

/// Choose the addressing mode declared on an element. DASH allows at most one
/// of the three; representation/adaptation-set precedence is handled by the
/// caller. `SegmentTemplate` is preferred, then `SegmentList`, then
/// `SegmentBase`; absent all three → [`SegmentAddressing::None`].
fn build_segment_addressing(
    template: Option<RawSegmentTemplate>,
    list: Option<RawSegmentList>,
    base: Option<RawSegmentBase>,
) -> SegmentAddressing {
    if let Some(t) = template {
        SegmentAddressing::Template(map_template(t))
    } else if let Some(l) = list {
        SegmentAddressing::List(map_list(l))
    } else if let Some(b) = base {
        SegmentAddressing::Base(map_base(b))
    } else {
        SegmentAddressing::None
    }
}

fn map_template(raw: RawSegmentTemplate) -> SegmentTemplate {
    SegmentTemplate {
        media: raw.media,
        initialization: raw.initialization,
        start_number: raw.start_number,
        duration: raw.duration,
        timescale: raw.timescale,
        timeline: raw.timeline.map(map_timeline),
    }
}

fn map_timeline(raw: RawSegmentTimeline) -> SegmentTimeline {
    SegmentTimeline {
        entries: raw
            .s
            .into_iter()
            .map(|s| TimelineEntry {
                t: s.t,
                d: s.d.unwrap_or(0),
                r: s.r.unwrap_or(0),
            })
            .collect(),
    }
}

fn map_list(raw: RawSegmentList) -> SegmentList {
    SegmentList {
        duration: raw.duration,
        timescale: raw.timescale,
        initialization: raw.initialization.map(map_url_range),
        segment_urls: raw
            .segment_urls
            .into_iter()
            .map(|s| SegmentUrl {
                media: s.media,
                media_range: s.media_range,
                index: s.index,
                index_range: s.index_range,
            })
            .collect(),
    }
}

fn map_base(raw: RawSegmentBase) -> SegmentBase {
    SegmentBase {
        index_range: raw.index_range,
        timescale: raw.timescale,
        initialization: raw.initialization.map(map_url_range),
    }
}

fn map_url_range(raw: RawUrlRange) -> UrlRange {
    UrlRange {
        source_url: raw.source_url,
        range: raw.range,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpd::model::{PresentationType, SegmentAddressing};

    /// A representative VOD MPD with two video representations under one
    /// adaptation set using `SegmentTemplate` + `SegmentTimeline`.
    const VOD_MPD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT10S">
  <BaseURL>https://cdn.example.com/movie/</BaseURL>
  <Period id="p0" duration="PT10S">
    <AdaptationSet mimeType="video/mp4" contentType="video" codecs="avc1.4d401f">
      <SegmentTemplate media="$RepresentationID$/seg-$Number$.m4s"
                       initialization="$RepresentationID$/init.mp4"
                       startNumber="1" timescale="1000">
        <SegmentTimeline>
          <S t="0" d="4000" r="1"/>
          <S d="2000"/>
        </SegmentTimeline>
      </SegmentTemplate>
      <Representation id="v0" bandwidth="800000" width="640" height="360" frameRate="30"/>
      <Representation id="v1" bandwidth="2400000" width="1280" height="720" frameRate="30000/1001"/>
    </AdaptationSet>
    <AdaptationSet mimeType="audio/mp4" contentType="audio" lang="en" codecs="mp4a.40.2">
      <SegmentList duration="4000" timescale="1000">
        <Initialization sourceURL="audio/init.mp4"/>
        <SegmentURL media="audio/seg-1.m4s"/>
        <SegmentURL media="audio/seg-2.m4s"/>
      </SegmentList>
      <Representation id="a0" bandwidth="128000"/>
    </AdaptationSet>
  </Period>
</MPD>"#;

    #[test]
    fn parses_periods_adaptation_sets_and_representations() {
        // Req 2.1: structured periods/adaptation-sets/representations.
        let mpd = parse_mpd(VOD_MPD).expect("VOD MPD should parse");

        assert_eq!(mpd.presentation_type, PresentationType::Static);
        assert_eq!(mpd.media_presentation_duration.as_deref(), Some("PT10S"));
        assert_eq!(mpd.base_url.as_deref(), Some("https://cdn.example.com/movie/"));

        assert_eq!(mpd.periods.len(), 1);
        let period = &mpd.periods[0];
        assert_eq!(period.id.as_deref(), Some("p0"));
        assert_eq!(period.adaptation_sets.len(), 2);

        // 3 representations total (2 video + 1 audio).
        assert_eq!(mpd.representation_count(), 3);

        let video = &period.adaptation_sets[0];
        assert_eq!(video.content_type.as_deref(), Some("video"));
        assert_eq!(video.representations.len(), 2);

        let audio = &period.adaptation_sets[1];
        assert_eq!(audio.content_type.as_deref(), Some("audio"));
        assert_eq!(audio.lang.as_deref(), Some("en"));
    }

    #[test]
    fn parses_representation_attributes() {
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let v1 = mpd.representation("v1").expect("v1 present");
        assert_eq!(v1.bandwidth, 2_400_000);
        assert_eq!(v1.resolution(), Some((1280, 720)));
        // codecs inherited from the adaptation set.
        assert_eq!(v1.codecs.as_deref(), Some("avc1.4d401f"));
        // mimeType inherited from the adaptation set.
        assert_eq!(v1.mime_type.as_deref(), Some("video/mp4"));
        assert_eq!(v1.frame_rate.as_deref(), Some("30000/1001"));
    }

    #[test]
    fn representations_inherit_adaptation_set_segment_template() {
        // The video representations declare no addressing of their own; they
        // inherit the adaptation set's SegmentTemplate (DASH inheritance).
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let v0 = mpd.representation("v0").unwrap();
        match &v0.segment_addressing {
            SegmentAddressing::Template(t) => {
                assert_eq!(t.media.as_deref(), Some("$RepresentationID$/seg-$Number$.m4s"));
                assert_eq!(t.initialization.as_deref(), Some("$RepresentationID$/init.mp4"));
                assert_eq!(t.start_number, Some(1));
                assert_eq!(t.timescale, Some(1000));
                let timeline = t.timeline.as_ref().expect("timeline present");
                assert_eq!(timeline.entries.len(), 2);
                assert_eq!(timeline.entries[0].t, Some(0));
                assert_eq!(timeline.entries[0].d, 4000);
                assert_eq!(timeline.entries[0].r, 1);
                assert_eq!(timeline.entries[1].d, 2000);
                assert_eq!(timeline.entries[1].r, 0);
            }
            other => panic!("expected SegmentTemplate, got {other:?}"),
        }
    }

    #[test]
    fn parses_segment_list_addressing() {
        // Req 3.4 shape: SegmentList with Initialization + SegmentURL entries.
        let mpd = parse_mpd(VOD_MPD).unwrap();
        let a0 = mpd.representation("a0").unwrap();
        match &a0.segment_addressing {
            SegmentAddressing::List(l) => {
                assert_eq!(l.duration, Some(4000));
                assert_eq!(
                    l.initialization.as_ref().unwrap().source_url.as_deref(),
                    Some("audio/init.mp4")
                );
                assert_eq!(l.segment_urls.len(), 2);
                assert_eq!(l.segment_urls[0].media.as_deref(), Some("audio/seg-1.m4s"));
            }
            other => panic!("expected SegmentList, got {other:?}"),
        }
    }

    #[test]
    fn parses_segment_base_addressing_with_byte_ranges() {
        // Req 3.3 shape: SegmentBase with indexRange + Initialization range.
        let xml = r#"<?xml version="1.0"?>
<MPD type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <Representation id="r0" bandwidth="500000">
        <BaseURL>single.mp4</BaseURL>
        <SegmentBase indexRange="800-1200" timescale="90000">
          <Initialization range="0-799"/>
        </SegmentBase>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let mpd = parse_mpd(xml).unwrap();
        let r0 = mpd.representation("r0").unwrap();
        assert_eq!(r0.base_url.as_deref(), Some("single.mp4"));
        match &r0.segment_addressing {
            SegmentAddressing::Base(b) => {
                assert_eq!(b.index_range.as_deref(), Some("800-1200"));
                assert_eq!(b.timescale, Some(90000));
                assert_eq!(b.initialization.as_ref().unwrap().range.as_deref(), Some("0-799"));
            }
            other => panic!("expected SegmentBase, got {other:?}"),
        }
    }

    #[test]
    fn detects_dynamic_live_presentation() {
        // Req 2.4: a `dynamic` MPD is a live presentation.
        let xml = r#"<?xml version="1.0"?>
<MPD type="dynamic">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <Representation id="v0" bandwidth="1000000"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let mpd = parse_mpd(xml).unwrap();
        assert_eq!(mpd.presentation_type, PresentationType::Dynamic);
        assert!(mpd.presentation_type.is_live());
    }

    #[test]
    fn absent_type_defaults_to_static_vod() {
        let xml = r#"<?xml version="1.0"?>
<MPD>
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <Representation id="v0" bandwidth="1000000"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let mpd = parse_mpd(xml).unwrap();
        assert_eq!(mpd.presentation_type, PresentationType::Static);
    }

    #[test]
    fn malformed_xml_names_the_failing_element() {
        // Req 2.8: an unparseable body yields a descriptive parse error that
        // identifies the failing element.
        let err = parse_mpd("this is not <xml").unwrap_err();
        match &err {
            MpdError::Malformed { element, .. } => assert_eq!(element, "MPD"),
            other => panic!("expected Malformed, got {other:?}"),
        }
        assert!(err.to_string().contains("MPD"), "error names the element");
    }

    #[test]
    fn representation_missing_id_is_identified() {
        // Req 2.8: a representation missing its required @id names the element.
        let xml = r#"<?xml version="1.0"?>
<MPD type="static">
  <Period id="p0">
    <AdaptationSet mimeType="video/mp4">
      <Representation bandwidth="1000000"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let err = parse_mpd(xml).unwrap_err();
        match &err {
            MpdError::Missing { element, field } => {
                assert_eq!(field, "id");
                // The element path identifies where the failure is.
                assert!(element.contains("p0"), "element path names the period: {element}");
                assert!(element.contains("Representation"), "names the element: {element}");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn representation_missing_bandwidth_is_identified() {
        // Req 2.8: missing required @bandwidth names the element + field.
        let xml = r#"<?xml version="1.0"?>
<MPD type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <Representation id="v0"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let err = parse_mpd(xml).unwrap_err();
        match &err {
            MpdError::Missing { element, field } => {
                assert_eq!(field, "bandwidth");
                assert!(element.contains("v0"), "names the representation id: {element}");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn parses_multiple_periods_in_order() {
        let xml = r#"<?xml version="1.0"?>
<MPD type="static">
  <Period id="first">
    <AdaptationSet mimeType="video/mp4">
      <Representation id="v0" bandwidth="1000000"/>
    </AdaptationSet>
  </Period>
  <Period id="second">
    <AdaptationSet mimeType="video/mp4">
      <Representation id="v1" bandwidth="2000000"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let mpd = parse_mpd(xml).unwrap();
        assert_eq!(mpd.periods.len(), 2);
        assert_eq!(mpd.periods[0].id.as_deref(), Some("first"));
        assert_eq!(mpd.periods[1].id.as_deref(), Some("second"));
        let ids: Vec<&str> = mpd.representations().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["v0", "v1"]);
    }
}
