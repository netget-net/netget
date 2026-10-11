//! What the CoAP client refuses before anything reaches the wire, and how a model's request
//! becomes options.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features coap --test client -- coap::request_test --test-threads=100

use netget::client::coap::actions::{request_from_action, ObserveAction};
use serde_json::json;

#[test]
fn a_request_becomes_path_segments_query_items_and_a_content_format() {
    let r = request_from_action(&json!({
        "type": "coap_put",
        "path": "/sensors//temp/",
        "query": "?unit=c&n=3",
        "payload": {"t": 21}
    }))
    .unwrap()
    .unwrap();
    assert_eq!(r.method, "PUT");
    assert_eq!(r.path, vec!["sensors", "temp"]);
    assert_eq!(r.query, vec!["unit=c", "n=3"]);
    assert_eq!(r.content_format, Some(50), "an object is sent as JSON");
    assert_eq!(r.payload, br#"{"t":21}"#.to_vec());
    assert!(r.confirmable, "Confirmable unless the model says otherwise");

    let r = request_from_action(&json!({"type": "coap_post", "path": "/log", "payload": "hi"}))
        .unwrap()
        .unwrap();
    assert_eq!(r.content_format, Some(0), "a string is sent as text/plain");

    let r = request_from_action(&json!({"type": "coap_observe", "path": "/time"}))
        .unwrap()
        .unwrap();
    assert_eq!((r.method, r.observe), ("GET", ObserveAction::Register));
}

#[test]
fn what_cannot_be_sent_is_refused() {
    for bad in [
        json!({"type": "coap_put", "path": "/x"}),
        json!({
            "type": "coap_put",
            "path": "/x",
            "payload": "p".repeat(netget::server::coap::codec::MAX_REPRESENTATION_LEN + 1)
        }),
        json!({"type": "coap_get", "path": format!("/{}", "s".repeat(256))}),
        json!({"type": "coap_get", "path": "/x", "query": format!("q={}", "v".repeat(254))}),
        json!({"type": "coap_get", "path": "/x", "accept": "application/unknown"}),
        json!({"type": "coap_get", "path": "/x", "confirmable": "yes"}),
        json!({"type": "coap_get"}),
    ] {
        assert!(request_from_action(&bad).is_err(), "{bad} must be refused");
    }
    // Exactly the limit is an upload, in Block1 blocks.
    assert!(request_from_action(&json!({
        "type": "coap_put",
        "path": "/x",
        "payload": "p".repeat(netget::server::coap::codec::MAX_REPRESENTATION_LEN)
    }))
    .is_ok());
}
