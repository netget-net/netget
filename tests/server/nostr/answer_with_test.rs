//! The `answer_with` hints `nostr_event` and `nostr_req` carry, and the placeholder examples.
//!
//! A subscription's hint puts its filters into words — kinds, tags, time bounds, limit — and
//! says out loud the one thing a model cannot know: that the events it supplies are published
//! under the relay's key with ids NetGet computes, so an `authors` or `ids` filter naming anyone
//! else can match none of them.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::answer_with --test-threads=100


use netget::server::nostr::actions::{
    event_answer_with, req_answer_with, NOSTR_EVENT_EVENT, NOSTR_REQ_EVENT,
};
use netget::server::nostr::wire::parse_filter;
use serde_json::json;

const RELAY: &str = "0f99fd46ce3cbe912a6840b9bc8cb5b8740a1e376f1cf7f82cdf3b10ff3a0a06";
const OTHER: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

#[test]
fn an_event_names_both_decisions_as_literal_actions() {
    let hint = event_answer_with(1);
    assert!(hint.contains("kind 1"), "{hint}");
    assert!(hint.contains(r#"{"type": "accept_nostr_event"}"#), "{hint}");
    assert!(hint.contains(r#""type": "reject_nostr_event""#), "{hint}");
    assert!(
        hint.contains("already checked its id and signature"),
        "{hint}"
    );
}

#[test]
fn a_subscription_puts_its_filters_into_words() {
    let filters = vec![
        parse_filter(&json!({"kinds": [1, 30023], "#t": ["film"], "since": 10, "limit": 5}))
            .unwrap(),
        parse_filter(&json!({})).unwrap(),
    ];
    let hint = req_answer_with("reviews", &filters, RELAY);
    for part in [
        "\"reviews\"",
        "kind 1 or 30023",
        "a \"t\" tag of \"film\"",
        "created_at at or after 10",
        "at most 5",
        "; or any event",
        "send_nostr_events",
        "events: []",
        "close_nostr_subscription",
    ] {
        assert!(hint.contains(part), "missing {part:?}: {hint}");
    }
    assert!(!hint.contains("Note:"), "{hint}");
}

#[test]
fn an_authors_or_ids_filter_the_relay_cannot_satisfy_is_said_out_loud() {
    let hint = req_answer_with(
        "theirs",
        &[parse_filter(&json!({"authors": [OTHER]})).unwrap()],
        RELAY,
    );
    assert!(hint.contains("filters on authors"), "{hint}");
    assert!(hint.contains(RELAY), "{hint}");

    let ours = req_answer_with(
        "ours",
        &[parse_filter(&json!({"authors": [RELAY]})).unwrap()],
        RELAY,
    );
    assert!(
        !ours.contains("Note:"),
        "the relay's own key can match: {ours}"
    );

    let ids = req_answer_with(
        "ids",
        &[parse_filter(&json!({"ids": [OTHER]})).unwrap()],
        RELAY,
    );
    assert!(ids.contains("filters on ids"), "{ids}");
}

/// The examples a model reads are placeholders, not content it could copy as an answer.
#[test]
fn the_examples_are_placeholders() {
    for event in [&*NOSTR_EVENT_EVENT, &*NOSTR_REQ_EVENT] {
        for action in &event.actions {
            let text = action.example.to_string();
            if text.contains("content") || text.contains("reason") || text.contains("message") {
                assert!(text.contains('<'), "{}: {text}", action.name);
            }
        }
    }
}
