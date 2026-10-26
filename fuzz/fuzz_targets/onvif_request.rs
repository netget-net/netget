//! `netget::server::onvif` — the ONVIF device's request path past the envelope: the bounded
//! element tree (`wire::parse_request`), then every parser the PTZ, Events, Imaging, Basic
//! Notification, Recording and Search services put in front of the model or their state, exactly
//! as the handlers call them.
//!
//! - `events::filter_of` and `events::parse_topic_filter`: a CreatePullPointSubscription's (or a
//!   Subscribe's) topic expression, bounded in length, alternatives (`MAX_TOPIC_ALTERNATIVES`)
//!   and path depth (`MAX_TOPIC_DEPTH`), parsed without recursion;
//! - `events::time_of` and `wire::parse_duration`: termination times and Timeouts, bounded at
//!   `MAX_DURATION` before any arithmetic;
//! - `ptz::axes` and `ptz::timeout`: PTZ vectors, speeds and the ContinuousMove timeout;
//! - `imaging::requested` and `imaging::focus_move`: SetImagingSettings and Move;
//! - `notify::parse_consumer` and `notify::Allowlist`: a Subscribe's consumer EndpointReference
//!   address and the `notify_consumers` allowlist it is judged by — on raw text and on the
//!   Address in a parsed Subscribe;
//! - `recording::scope_of`, `recording::recording_query`, `recording::event_query`,
//!   `recording::page_size` and `recording::configuration_of`: search scopes, time ranges,
//!   MaxMatches, KeepAliveTime, MaxResults and a CreateRecording's configuration;
//! - `recording::archive_from_action`: the model's description of its recordings, when the input
//!   is JSON, and a search over whatever it accepted.
//!
//! The corpus carries `depth_bomb` (elements nested far past `wire::MAX_DEPTH` inside a real
//! Body), `alternatives_bomb` (a filter of 20,000 `|`-separated topics), `duration_bomb` (a
//! Timeout whose number is 4,000 digits long), `consumer_bomb` (a consumer address of 100,000
//! bytes), `scope_bomb` (a search scope naming 10,000 recordings) and `recordings_bomb` (a
//! description of 1,000 recordings), next to one well-formed request of each kind.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::onvif::events::{self, Filter, MAX_TOPIC_ALTERNATIVES, MAX_TOPIC_DEPTH};
use netget::server::onvif::{imaging, notify, ptz, recording, wire};
use std::net::IpAddr;
use std::time::Duration;

fn check_filter(f: &Filter) {
    if let Filter::Topics(ps) = f {
        assert!(ps.len() <= MAX_TOPIC_ALTERNATIVES);
        assert!(ps.iter().all(|p| p.segments.len() <= MAX_TOPIC_DEPTH));
    }
}

/// What `parse_consumer` promises of an address it accepts.
fn check_consumer(text: &str, allow_https: bool) {
    let Ok(c) = notify::parse_consumer(text, allow_https) else {
        return;
    };
    assert!(c.url.len() <= notify::MAX_CONSUMER_URL);
    assert!(!c.url.chars().any(char::is_whitespace));
    assert!(allow_https || !c.https);
    assert_eq!(notify::parse_consumer(text, allow_https), Ok(c.clone()));
    // Whatever the allowlist, the device never delivers to an unspecified, multicast or
    // broadcast address; the default allows loopback and nothing else.
    let everything = notify::Allowlist::parse(&["0.0.0.0/0".into(), "::/0".into()]).unwrap();
    let ip = notify::canonical(c.addr.ip());
    if notify::forbidden(ip) {
        assert!(!everything.allows(ip, ip));
    }
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(
        notify::Allowlist::default_list().allows(ip, loopback),
        ip.is_loopback() && !notify::forbidden(ip)
    );
}

fn check_scope(s: &recording::Scope) {
    assert!(s.sources.len() <= recording::MAX_SCOPE_ITEMS);
    assert!(s.recordings.len() <= recording::MAX_SCOPE_ITEMS);
    assert!(s.recordings.iter().all(|t| recording::token_ok(t)));
}

fn check_query(max_matches: usize, keep_alive: Duration) {
    assert!((1..=recording::MAX_SEARCH_RESULTS).contains(&max_matches));
    assert!(keep_alive >= Duration::from_secs(1) && keep_alive <= recording::MAX_KEEP_ALIVE);
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
    let ten_years = Duration::from_secs(recording::MAX_RETENTION_SECS);
    if let Ok(d) = wire::parse_duration_max(&text, ten_years) {
        assert!(d <= ten_years);
    }
    // A consumer address and an allowlist, on raw text.
    check_consumer(&text, false);
    check_consumer(&text, true);
    let entries: Vec<String> = text.split(',').take(64).map(str::to_string).collect();
    if let Ok(list) = notify::Allowlist::parse(&entries) {
        assert!(list.nets.len() <= notify::MAX_ALLOWLIST);
        assert!(list
            .nets
            .iter()
            .all(|(ip, bits)| *bits <= if ip.is_ipv4() { 32 } else { 128 }));
        for forbidden in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "::", "ff02::1"] {
            let ip: IpAddr = forbidden.parse().unwrap();
            assert!(!list.allows(ip, ip));
        }
    }
    // The model's description of its recordings, when the input is JSON.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Ok(archive) = recording::archive_from_action(&v) {
            assert!(archive.recordings.len() <= recording::MAX_RECORDINGS);
            assert!(archive.jobs.len() <= recording::MAX_JOBS);
            let mut total = 0;
            for r in &archive.recordings {
                assert!(r.tracks.len() <= recording::MAX_TRACKS);
                assert!(r.events.len() <= recording::MAX_RECORDED_EVENTS);
                assert!(r.tracks.iter().all(|t| t.from <= t.to));
                total += r.events.len();
            }
            assert!(total <= recording::MAX_ARCHIVE_EVENTS);
            let everything = recording::RecordingQuery {
                scope: recording::Scope::default(),
                max_matches: recording::MAX_SEARCH_RESULTS,
                keep_alive: recording::DEFAULT_KEEP_ALIVE,
            };
            assert!(
                recording::find_recordings(&archive, &everything).len()
                    <= recording::MAX_RECORDINGS
            );
        }
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
    // Basic Notification: the Subscribe's consumer, as the handler reads it.
    if let Some(address) = body
        .child("ConsumerReference")
        .and_then(|c| c.child("Address"))
    {
        check_consumer(&address.text, false);
    }
    // Search: scopes, time ranges, counts and keep-alives.
    if let Ok(s) = recording::scope_of(body.child("Scope")) {
        check_scope(&s);
    }
    if let Ok(q) = recording::recording_query(body) {
        check_scope(&q.scope);
        check_query(q.max_matches, q.keep_alive);
    }
    if let Ok(q) = recording::event_query(body) {
        check_scope(&q.scope);
        check_filter(&q.filter);
        check_query(q.max_matches, q.keep_alive);
        // The start point is always inside the range, searching either way.
        assert!(q.covers(q.start));
        if let Some(end) = q.end {
            assert!(q.covers(end));
            assert_eq!(q.backwards(), end < q.start);
        }
    }
    if let Ok(n) = recording::page_size(body) {
        assert!((1..=recording::MAX_RESULTS_PAGE).contains(&n));
    }
    if let Ok(c) = recording::configuration_of(body) {
        for s in [
            &c.source.source_id,
            &c.source.name,
            &c.source.location,
            &c.source.description,
            &c.source.address,
            &c.content,
        ] {
            assert!(s.len() <= recording::MAX_TEXT);
        }
        assert!(c.retention <= Duration::from_secs(recording::MAX_RETENTION_SECS));
    }
});
