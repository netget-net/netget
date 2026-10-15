//! What `send_socks5_data` promises the model, and what its executor does with each field.
//!
//! The reason this file exists is one string: `"48656c6c6f"` is simultaneously a perfectly
//! good five-byte payload and a perfectly good ten-character one, and the only thing that can
//! tell them apart is the sender saying which. This client used to declare a single `data_hex`
//! field and `hex::decode` it unconditionally, and its startup example put
//! `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` on the model's screen as 74 hex characters —
//! a request the model could not read, could not point at another host, and could not check.
//!
//! Nothing here needs a proxy, a socket or a model: `execute_action` is pure, so every
//! assertion below is about bytes.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features socks5 \
//!     --test client -- client::socks5::action_test --test-threads=100
//! ```


use netget::client::socks5::actions::{inbound_event_fields, Socks5ClientProtocol};
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::llm::actions::protocol_trait::Protocol;
use netget::state::app_state::AppState;

fn protocol() -> Socks5ClientProtocol {
    Socks5ClientProtocol::new()
}

fn sent(action: serde_json::Value) -> Vec<u8> {
    match protocol()
        .execute_action(action.clone())
        .unwrap_or_else(|e| panic!("{action} should be executable: {e:#}"))
    {
        ClientActionResult::SendData(bytes) => bytes,
        other => panic!("expected SendData for {action}, got {other:?}"),
    }
}

fn refusal(action: serde_json::Value) -> String {
    format!(
        "{:#}",
        protocol()
            .execute_action(action.clone())
            .err()
            .unwrap_or_else(|| panic!("{action} should have been refused"))
    )
}

// ---------------------------------------------------------------------------
// The advertised surface
// ---------------------------------------------------------------------------

/// Every example the model is shown must be one this executor accepts, exactly as written.
#[tokio::test]
async fn every_declared_example_is_accepted_by_its_own_executor() {
    let p = protocol();
    let state = AppState::new();

    let mut checked = 0;
    for action in p
        .get_async_actions(&state)
        .into_iter()
        .chain(p.get_sync_actions())
        .chain(p.get_event_types().into_iter().flat_map(|e| e.actions))
    {
        let example = action.example.clone();
        assert_eq!(
            example.get("type").and_then(|v| v.as_str()),
            Some(action.name.as_str()),
            "the example for '{}' must be an instance of that action, got {example}",
            action.name
        );
        p.execute_action(example.clone()).unwrap_or_else(|e| {
            panic!(
                "'{}' is advertised with an example its own executor refuses: {example} -> {e:#}",
                action.name
            )
        });
        checked += 1;
    }
    assert!(checked >= 4, "expected the whole action set, saw {checked}");
}

/// `data` and `encoding`, and **no** `data_hex`.
///
/// The legacy field is still executed (see below) so an existing static handler keeps working,
/// but it is deliberately not advertised: re-advertising it would put hex back in the model's
/// vocabulary, which is the whole thing this change removed.
#[tokio::test]
async fn send_socks5_data_declares_data_and_encoding_and_not_data_hex() {
    let p = protocol();
    let state = AppState::new();

    let mut seen = 0;
    for action in p
        .get_async_actions(&state)
        .into_iter()
        .chain(p.get_sync_actions())
        .filter(|a| a.name == "send_socks5_data")
    {
        let names: Vec<&str> = action.parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["data", "encoding"],
            "send_socks5_data should offer exactly 'data' and 'encoding'"
        );
        assert!(
            !action.description.contains("data_hex"),
            "the description must not advertise the deprecated field: {}",
            action.description
        );
        let encoding = &action.parameters[1];
        assert!(!encoding.required, "'encoding' defaults to utf8");
        assert!(
            encoding.description.contains("no auto-detection"),
            "the model has to be told nothing is sniffed: {}",
            encoding.description
        );
        seen += 1;
    }
    assert_eq!(seen, 2, "both the async and the sync spelling");
}

/// No example anywhere in this protocol's model-facing surface is a hex blob.
///
/// `tests/example_hex_drift_test.rs` is the tree-wide ratchet; this is the same rule asserted
/// against the values a running build actually produces, which is the thing a model sees.
#[tokio::test]
async fn no_example_hands_the_model_a_hex_blob() {
    let p = protocol();
    let state = AppState::new();

    for action in p
        .get_async_actions(&state)
        .into_iter()
        .chain(p.get_sync_actions())
        .chain(p.get_event_types().into_iter().flat_map(|e| e.actions))
    {
        let Some(data) = action.example.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        assert!(
            !(data.len() > 32 && data.chars().all(|c| c.is_ascii_hexdigit())),
            "'{}' shows the model {data:?}, which is a blob it cannot read or adapt",
            action.name
        );
    }
}

// ---------------------------------------------------------------------------
// What each field does
// ---------------------------------------------------------------------------

/// The default is text, and it applies to a string that *looks* like hex.
///
/// This is the assertion the original bug would have failed. `send_tcp_data` was documented as
/// accepting "text or hex-encoded binary" while its executor did `data.as_bytes()`; the mirror
/// error is an executor that decodes hex whenever the string happens to be hex-shaped. Either
/// way the sender's intent is guessed, and half the time the guess is wrong.
#[tokio::test]
async fn text_that_looks_like_hex_is_sent_as_its_characters() {
    for literal in ["48656c6c6f", "deadbeef", "0123456789abcdef"] {
        assert_eq!(
            sent(serde_json::json!({
                "type": "send_socks5_data",
                "data": literal,
                "encoding": "utf8"
            })),
            literal.as_bytes(),
            "{literal:?} with encoding utf8 must go out as those characters"
        );

        // …and identically with 'encoding' left out, because utf8 is the default.
        assert_eq!(
            sent(serde_json::json!({"type": "send_socks5_data", "data": literal})),
            literal.as_bytes(),
            "{literal:?} with no encoding must go out as those characters"
        );
    }
}

#[tokio::test]
async fn the_same_string_with_encoding_hex_is_the_decoded_bytes() {
    assert_eq!(
        sent(serde_json::json!({
            "type": "send_socks5_data",
            "data": "48656c6c6f",
            "encoding": "hex"
        })),
        b"Hello",
        "the one string, read the other way"
    );
    assert_eq!(
        sent(serde_json::json!({
            "type": "send_socks5_data",
            "data": "deadbeef",
            "encoding": "hex"
        })),
        &[0xde, 0xad, 0xbe, 0xef]
    );
}

/// A readable request goes out byte for byte, which is what the examples now show.
#[tokio::test]
async fn a_readable_http_request_round_trips() {
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(
        sent(serde_json::json!({
            "type": "send_socks5_data",
            "data": request,
            "encoding": "utf8"
        })),
        request.as_bytes()
    );
}

/// Separators a model writes when copying a dump carry no information.
#[tokio::test]
async fn hex_separators_are_tolerated() {
    for spelling in ["48 65 6c 6c 6f", "48:65:6c:6c:6f", "0x48656c6c6f"] {
        assert_eq!(
            sent(serde_json::json!({
                "type": "send_socks5_data",
                "data": spelling,
                "encoding": "hex"
            })),
            b"Hello",
            "{spelling:?} should decode to Hello"
        );
    }
}

// ---------------------------------------------------------------------------
// Backward compatibility, decided rather than inherited
// ---------------------------------------------------------------------------

/// `data_hex` is no longer advertised and is still executed, so a handler written against the
/// old surface keeps working rather than failing with "Missing 'data' field".
#[tokio::test]
async fn the_legacy_data_hex_field_still_sends_its_bytes() {
    assert_eq!(
        sent(serde_json::json!({"type": "send_socks5_data", "data_hex": "48656c6c6f"})),
        b"Hello"
    );
}

/// Both fields together is refused, not resolved by precedence.
///
/// They are two statements about the same wire bytes. Picking one silently is how a payload
/// nobody asked for goes out, and it is the same class of guess the `encoding` field exists to
/// remove.
#[tokio::test]
async fn supplying_both_spellings_is_refused_by_name() {
    let msg = refusal(serde_json::json!({
        "type": "send_socks5_data",
        "data": "Hello",
        "data_hex": "48656c6c6f"
    }));
    assert!(
        msg.contains("data_hex") && msg.contains("'data'"),
        "the refusal must name both fields: {msg}"
    );
    assert!(
        msg.contains("precedence"),
        "and must say that neither wins: {msg}"
    );
}

#[tokio::test]
async fn a_bad_encoding_and_a_missing_payload_are_refused_by_name() {
    let msg = refusal(serde_json::json!({
        "type": "send_socks5_data",
        "data": "Hello",
        "encoding": "base64"
    }));
    assert!(
        msg.contains("base64") && msg.contains("utf8") && msg.contains("hex"),
        "the refusal must name what was sent and what is allowed: {msg}"
    );

    let msg = refusal(serde_json::json!({"type": "send_socks5_data"}));
    assert!(
        msg.contains("'data'"),
        "the refusal must name the missing field: {msg}"
    );

    let msg = refusal(serde_json::json!({
        "type": "send_socks5_data",
        "data": "zzz",
        "encoding": "hex"
    }));
    assert!(
        msg.to_lowercase().contains("hex"),
        "the refusal must name the encoding: {msg}"
    );
}

#[tokio::test]
async fn lifecycle_verbs_map_to_the_lifecycle_results() {
    assert!(matches!(
        protocol().execute_action(serde_json::json!({"type": "disconnect"})),
        Ok(ClientActionResult::Disconnect)
    ));
    assert!(matches!(
        protocol().execute_action(serde_json::json!({"type": "wait_for_more"})),
        Ok(ClientActionResult::WaitForMore)
    ));
    assert!(
        format!(
            "{:#}",
            protocol()
                .execute_action(serde_json::json!({"type": "send_socks5_frame"}))
                .unwrap_err()
        )
        .contains("send_socks5_frame"),
        "an unknown verb must be named back"
    );
}

// ---------------------------------------------------------------------------
// The inbound half
// ---------------------------------------------------------------------------

/// What the target sends back reaches the model readable, and hands straight back.
///
/// `socks5_data_received` used to carry `data_hex` and nothing else, so an HTTP response — the
/// single most likely thing to come down this tunnel — arrived as hex for the model to decode
/// in its head. The pair of fields is chosen so that copying them into `send_socks5_data`
/// reproduces the bytes exactly, in both directions.
#[tokio::test]
async fn received_bytes_are_readable_when_they_are_text_and_hex_when_they_are_not() {
    let text = b"HTTP/1.1 200 OK\r\n\r\nhi";
    let fields = inbound_event_fields(text);
    assert_eq!(fields["encoding"], "utf8");
    assert_eq!(fields["data"], String::from_utf8_lossy(text).to_string());
    assert_eq!(fields["data_length"], text.len() as u64);

    let binary = [0x00u8, 0x01, 0xff, 0xfe];
    let fields = inbound_event_fields(&binary);
    assert_eq!(fields["encoding"], "hex");
    assert_eq!(fields["data"], "0001fffe");
    assert_eq!(fields["data_length"], 4);
}

#[tokio::test]
async fn an_echo_built_from_the_event_reproduces_the_received_bytes() {
    for payload in [
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        // A payload whose text form is itself hex-shaped: the round trip has to survive it.
        b"deadbeef".to_vec(),
        vec![0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01],
    ] {
        let fields = inbound_event_fields(&payload);
        let echoed = sent(serde_json::json!({
            "type": "send_socks5_data",
            "data": fields["data"],
            "encoding": fields["encoding"],
        }));
        assert_eq!(echoed, payload, "echoing {fields} must reproduce the bytes");
    }
}

/// The declared event parameters must be the fields the payload actually carries.
#[tokio::test]
async fn declared_event_parameters_match_the_payload() {
    let payload = inbound_event_fields(b"hello");
    let event = protocol()
        .get_event_types()
        .into_iter()
        .find(|e| e.id == "socks5_data_received")
        .expect("socks5_data_received is declared");

    for param in &event.parameters {
        assert!(
            payload.get(&param.name).is_some(),
            "event declares '{}', which the payload never sets",
            param.name
        );
    }
    assert_eq!(
        event.parameters.len(),
        payload.as_object().unwrap().len(),
        "declared {:?} but the payload carries {:?}",
        event
            .parameters
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>(),
        payload.as_object().unwrap().keys().collect::<Vec<_>>()
    );
}
