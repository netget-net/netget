//! `netget::server::onvif` — the ONVIF device's request path past the envelope: the bounded
//! element tree (`wire::parse_request`), then every parser the PTZ, Events and Imaging services
//! put in front of the model or their state, exactly as the handlers call them.
//!
//! - `events::filter_of` and `events::parse_topic_filter`: a CreatePullPointSubscription's topic
//!   expression, bounded in length, alternatives (`MAX_TOPIC_ALTERNATIVES`) and path depth
//!   (`MAX_TOPIC_DEPTH`), parsed without recursion;
//! - `events::time_of` and `wire::parse_duration`: termination times and Timeouts, bounded at
//!   `MAX_DURATION` before any arithmetic;
//! - `ptz::axes` and `ptz::timeout`: PTZ vectors, speeds and the ContinuousMove timeout;
//! - `imaging::requested` and `imaging::focus_move`: SetImagingSettings and Move.
//!
//! The corpus carries `depth_bomb` (elements nested far past `wire::MAX_DEPTH` inside a real
//! Body), `alternatives_bomb` (a filter of 20,000 `|`-separated topics) and `duration_bomb` (a
//! Timeout whose number is 4,000 digits long), next to one well-formed request of each kind.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::onvif::events::{self, Filter, MAX_TOPIC_ALTERNATIVES, MAX_TOPIC_DEPTH};
use netget::server::onvif::{imaging, ptz, wire};

fn check_filter(f: &Filter) {
    if let Filter::Topics(ps) = f {
        assert!(ps.len() <= MAX_TOPIC_ALTERNATIVES);
        assert!(ps.iter().all(|p| p.segments.len() <= MAX_TOPIC_DEPTH));
    }
}

fuzz_target!(|data: &[u8]| {
    // The expression parser alone, on raw text, in every dialect it knows.
    let text = String::from_utf8_lossy(data);
    for dialect in [
        "",
        events::CONCRETE_SET,
        events::WSN_FULL,
        events::WSN_SIMPLE,
    ] {
        if let Ok(f) = events::parse_topic_filter(dialect, &text) {
            check_filter(&f);
            assert_eq!(events::parse_topic_filter(dialect, &text).ok(), Some(f));
        }
    }
    if let Ok(d) = wire::parse_duration(&text) {
        assert!(d <= wire::MAX_DURATION);
    }

    let Ok(request) = wire::parse_request(data) else {
        return;
    };
    let body = &request.body;
    if let Ok(f) = events::filter_of(body) {
        check_filter(&f);
    }
    let now = chrono::Utc::now();
    for element in ["InitialTerminationTime", "TerminationTime"] {
        if let Ok(Some(t)) = events::time_of(body.child(element), now) {
            // A relative time is bounded before it is added; an absolute one is just a time.
            let _ = t;
        }
    }
    if let Some(t) = body.text_of("Timeout") {
        if let Ok(d) = wire::parse_duration(&t) {
            assert!(d <= wire::MAX_DURATION);
        }
    }
    for (element, kind) in [
        ("Velocity", ptz::Kind::Velocity),
        ("Translation", ptz::Kind::Translation),
        ("Position", ptz::Kind::Position),
        ("Speed", ptz::Kind::Speed),
    ] {
        if let Ok(a) = ptz::axes(body.child(element), kind) {
            for v in [a.pan, a.tilt, a.zoom].into_iter().flatten() {
                assert!(v.is_finite() && (-1.0..=1.0).contains(&v));
            }
        }
    }
    if let Ok(t) = ptz::timeout(body) {
        assert!(t <= ptz::MAX_TIMEOUT);
    }
    if let Ok(s) = imaging::requested(&imaging::Settings::default(), body.child("ImagingSettings"))
    {
        assert!(s.levels.iter().all(|l| (0.0..=100.0).contains(l)));
    }
    if let Ok((_, _, to)) = imaging::focus_move(Some(body), 0.5) {
        assert!((0.0..=1.0).contains(&to));
    }
});
