//! What the DataLink client promises the model, and what it does with what the model sends
//! back — asserted with **no privileges at all**.
//!
//! Everything else about this client needs a libpcap handle (`/dev/bpf*` on macOS/BSD, root or
//! `CAP_NET_RAW` on Linux), so on an ordinary machine those tests are the only ones that run.
//! Without this file the client's entire model-facing surface — the actions it advertises, the
//! frames it accepts, the event payloads it builds — was covered by nothing an unprivileged
//! run could execute.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features datalink \
//!     --test client -- client::datalink::action_test --test-threads=100
//! ```

#![cfg(all(unix, feature = "libpcap"))]

use netget::client::datalink::actions::{
    DataLinkClientProtocol, ETHERTYPE_NAMES, MAX_ETHERNET_FRAME_BYTES, MIN_ETHERNET_FRAME_BYTES,
};
use netget::client::datalink::{frame_event_fields, MAX_HEX_BYTES_TO_MODEL};
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use netget::llm::actions::protocol_trait::Protocol;
use netget::privilege::SystemCapabilities;
use netget::protocol::metadata::PrivilegeRequirement;
use netget::state::app_state::AppState;

/// A minimal well-formed ARP request: broadcast destination, our source MAC, EtherType 0x0806,
/// then the 28-byte ARP payload from RFC 826. 42 bytes.
const ARP_FRAME_HEX: &str =
    "ffffffffffff001122334455080600010800060400010011223344550a0000010000000000000a000002";

fn protocol() -> DataLinkClientProtocol {
    DataLinkClientProtocol::new()
}

// ---------------------------------------------------------------------------
// The advertised surface
// ---------------------------------------------------------------------------

/// Every action the model can be shown must be one its own executor accepts, sent exactly as
/// the declared `example` writes it — that example is the shape the model copies.
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
                "'{}' is advertised to the model with an example its own executor refuses: \
                 {example} -> {e}",
                action.name
            )
        });
        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected the full action set, checked {checked}"
    );
}

/// Every event the model can see must carry actions, and every one of those must be executable.
/// A client unions async ∪ sync ∪ event actions, so an event with none is not *fatal* here the
/// way it is on a server — but it is still a declaration that means nothing, and the two events
/// that carry frames are the ones the model most needs a vocabulary for.
#[tokio::test]
async fn every_event_offers_an_executable_vocabulary() {
    let p = protocol();
    let events = p.get_event_types();
    assert_eq!(
        events.len(),
        3,
        "expected datalink_connected, datalink_frame_injected and datalink_frame_captured; got {:?}",
        events.iter().map(|e| e.id.clone()).collect::<Vec<_>>()
    );

    for event in events {
        assert!(
            !event.actions.is_empty(),
            "event '{}' declares no actions",
            event.id
        );
        for action in &event.actions {
            p.execute_action(action.example.clone())
                .unwrap_or_else(|e| {
                    panic!(
                        "event '{}' offers '{}', which the executor refuses: {e}",
                        event.id, action.name
                    )
                });
        }
    }
}

/// `interface` and `promiscuous`, and nothing else. A parameter that is declared and never read
/// is a knob the model will turn to no effect; one read and not declared is refused at startup.
#[tokio::test]
async fn startup_parameters_are_exactly_what_connect_reads() {
    let declared: Vec<String> = protocol()
        .get_startup_parameters()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(
        declared,
        vec!["interface".to_string(), "promiscuous".to_string()],
        "connect_with_llm_actions reads exactly these two"
    );
}

/// This client opens a libpcap handle — the same capability the DataLink *server* declares.
/// It used to say `RawSockets`, which is a different capability in `SystemCapabilities`: a
/// macOS user in the ChmodBPF group has capture access without raw sockets, and would have
/// been refused a client that works.
#[tokio::test]
async fn declares_packet_capture_not_raw_sockets() {
    let meta = protocol().metadata();
    assert_eq!(
        meta.privilege_requirement,
        PrivilegeRequirement::PacketCapture,
        "libpcap, not SOCK_RAW"
    );

    let caps = SystemCapabilities::detect();
    assert_eq!(
        meta.privilege_requirement.is_met_by(&caps),
        caps.has_packet_capture_access,
        "PacketCapture must be satisfied by exactly the capture capability"
    );
}

/// The action text is what the model builds its frame from, so it must not ask for the FCS:
/// `pcap::sendpacket` puts exactly the bytes given on the wire and the interface appends the
/// frame check sequence itself. The async definition used to say "including … FCS", which is
/// four bytes of junk payload on every frame a compliant model produced.
#[tokio::test]
async fn inject_frame_does_not_ask_the_model_for_an_fcs() {
    let p = protocol();
    let state = AppState::new();
    for action in p
        .get_async_actions(&state)
        .into_iter()
        .chain(p.get_sync_actions())
    {
        if action.name != "inject_frame" {
            continue;
        }
        let text = format!(
            "{} {}",
            action.description, action.parameters[0].description
        );
        assert!(
            !text
                .to_lowercase()
                .contains("including dst mac, src mac, ethertype, payload, fcs"),
            "inject_frame must not tell the model to append an FCS: {text}"
        );
        assert!(
            text.contains("Do NOT append the FCS"),
            "inject_frame should say who computes the FCS: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// What the executor accepts and refuses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_well_formed_frame_decodes_to_exactly_its_bytes() {
    let result = protocol()
        .execute_action(serde_json::json!({"type": "inject_frame", "frame_hex": ARP_FRAME_HEX}))
        .expect("a 42-byte ARP frame is injectable");

    match result {
        ClientActionResult::SendData(bytes) => {
            assert_eq!(bytes.len(), ARP_FRAME_HEX.len() / 2);
            assert_eq!(hex::encode(&bytes), ARP_FRAME_HEX);
            // Spot-check the header the model is told to build: broadcast, our MAC, ARP.
            assert_eq!(&bytes[0..6], &[0xff; 6], "destination MAC");
            assert_eq!(
                &bytes[6..12],
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                "source MAC"
            );
            assert_eq!(&bytes[12..14], &[0x08, 0x06], "EtherType 0x0806 (ARP)");
        }
        other => panic!("expected SendData, got {other:?}"),
    }
}

/// A model writing hex from a packet dump naturally separates the octets. Those separators
/// carry no information, so refusing them teaches it nothing it can act on.
#[tokio::test]
async fn separators_a_model_would_write_are_tolerated() {
    for spelling in [
        "ff:ff:ff:ff:ff:ff:00:11:22:33:44:55:08:06",
        "ffffffffffff 001122334455 0806",
        "ff-ff-ff-ff-ff-ff-00-11-22-33-44-55-08-06",
    ] {
        let result = protocol()
            .execute_action(serde_json::json!({"type": "inject_frame", "frame_hex": spelling}))
            .unwrap_or_else(|e| panic!("{spelling:?} should decode: {e}"));
        match result {
            ClientActionResult::SendData(bytes) => assert_eq!(
                hex::encode(&bytes),
                "ffffffffffff0011223344550806",
                "{spelling:?} must decode to the same 14 bytes"
            ),
            other => panic!("expected SendData, got {other:?}"),
        }
    }
}

/// A runt has no EtherType. libpcap would either refuse it or put it on the wire as a
/// malformed frame; refusing it here is what lets the model be told what was wrong.
#[tokio::test]
async fn a_frame_too_short_to_be_ethernet_is_refused_by_name() {
    let err = protocol()
        .execute_action(serde_json::json!({"type": "inject_frame", "frame_hex": "ffffffffffff"}))
        .expect_err("6 bytes is not an Ethernet frame");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("6 bytes") && msg.contains(&MIN_ETHERNET_FRAME_BYTES.to_string()),
        "the refusal must say what was sent and what is needed, got: {msg}"
    );
}

#[tokio::test]
async fn an_oversized_frame_is_refused_before_libpcap_sees_it() {
    let oversized = "ab".repeat(MAX_ETHERNET_FRAME_BYTES + 1);
    let err = protocol()
        .execute_action(serde_json::json!({"type": "inject_frame", "frame_hex": oversized}))
        .expect_err("a frame larger than the snaplen is refused");
    assert!(
        format!("{err:#}").contains(&MAX_ETHERNET_FRAME_BYTES.to_string()),
        "the refusal must name the limit, got: {err:#}"
    );
}

#[tokio::test]
async fn undecodable_hex_and_unknown_verbs_are_refused() {
    let err = protocol()
        .execute_action(serde_json::json!({"type": "inject_frame", "frame_hex": "zzzz"}))
        .expect_err("'zzzz' is not hex");
    assert!(
        format!("{err:#}").to_lowercase().contains("hex"),
        "the refusal must name the encoding, got: {err:#}"
    );

    let err = protocol()
        .execute_action(serde_json::json!({"type": "inject_vlan_frame"}))
        .expect_err("an action this protocol does not implement");
    assert!(
        format!("{err:#}").contains("inject_vlan_frame"),
        "the refusal must name the verb, got: {err:#}"
    );

    let err = protocol()
        .execute_action(serde_json::json!({"type": "inject_frame"}))
        .expect_err("inject_frame without a frame");
    assert!(
        format!("{err:#}").contains("frame_hex"),
        "the refusal must name the missing field, got: {err:#}"
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
}

// ---------------------------------------------------------------------------
// The event payload, against literal bytes
// ---------------------------------------------------------------------------

/// What a captured or injected frame looks like to the model. Asserted against literal bytes
/// because this is the one part of a pcap protocol that can be checked without a pcap handle.
#[tokio::test]
async fn a_short_frame_is_reported_whole() {
    let frame = hex::decode(ARP_FRAME_HEX).unwrap();
    let data = frame_event_fields(&frame);

    assert_eq!(data["frame_hex"], ARP_FRAME_HEX);
    assert_eq!(data["frame_length"], 42);
    assert_eq!(data["captured_length"], 42);
    assert_eq!(data["truncated"], false);
}

/// A frame can be 65535 bytes and all of it as hex is 131070 characters of prompt, so the
/// event carries a prefix and says so. `frame_length` stays the real length: a model told a
/// 9000-byte frame was 2048 bytes long would draw the wrong conclusion from it.
#[tokio::test]
async fn a_long_frame_is_cut_and_says_so() {
    let frame = vec![0xa5u8; MAX_HEX_BYTES_TO_MODEL + 500];
    let data = frame_event_fields(&frame);

    assert_eq!(data["frame_length"], (MAX_HEX_BYTES_TO_MODEL + 500) as u64);
    assert_eq!(data["captured_length"], MAX_HEX_BYTES_TO_MODEL as u64);
    assert_eq!(data["truncated"], true);
    assert_eq!(
        data["frame_hex"].as_str().unwrap().len(),
        MAX_HEX_BYTES_TO_MODEL * 2,
        "hex is two characters per byte and must stop at the cut"
    );

    // Exactly at the boundary nothing is cut.
    let exact = frame_event_fields(&vec![0u8; MAX_HEX_BYTES_TO_MODEL]);
    assert_eq!(exact["truncated"], false);
    assert_eq!(exact["captured_length"], MAX_HEX_BYTES_TO_MODEL as u64);
}

/// The declared event parameters must be the fields the payload actually carries. They drifted
/// before: the events advertised `frame_hex` and `frame_length` only, while nothing said the
/// hex could be a prefix.
#[tokio::test]
async fn declared_event_parameters_match_the_payload() {
    let payload = frame_event_fields(&hex::decode(ARP_FRAME_HEX).unwrap());

    for event in protocol()
        .get_event_types()
        .into_iter()
        .filter(|e| e.id != "datalink_connected")
    {
        for param in &event.parameters {
            assert!(
                payload.get(&param.name).is_some(),
                "event '{}' declares parameter '{}', which frame_event_fields never sets",
                event.id,
                param.name
            );
        }
        assert_eq!(
            event.parameters.len(),
            payload.as_object().unwrap().len(),
            "event '{}' declares {:?} but the payload carries {:?}",
            event.id,
            event
                .parameters
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>(),
            payload.as_object().unwrap().keys().collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// The structured spelling
// ---------------------------------------------------------------------------
//
// `inject_frame` used to take one field, `frame_hex`, and its example was the 42-byte ARP
// request above written out as 84 hex characters — on the action and on two event types. A
// model cannot proofread that, cannot point it at a different host, and nothing downstream
// catches what it copies. An Ethernet frame is structured, so it is spelled out as fields.

fn built(action: serde_json::Value) -> Vec<u8> {
    match protocol()
        .execute_action(action.clone())
        .unwrap_or_else(|e| panic!("{action} should be injectable: {e:#}"))
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

/// The header is assembled from the fields, in order, and the payload follows it.
#[tokio::test]
async fn structured_fields_assemble_the_same_bytes_as_the_hex_spelling() {
    // The ARP frame from the top of this file, written as fields instead of as a blob.
    let frame = built(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": "arp",
        "payload": &ARP_FRAME_HEX[28..],
        "payload_encoding": "hex"
    }));
    assert_eq!(
        hex::encode(&frame),
        ARP_FRAME_HEX,
        "the structured spelling must produce the frame the hex spelling produces"
    );
}

/// Every spelling of a MAC a model might write, and a refusal that says what is wrong.
#[tokio::test]
async fn mac_addresses_are_accepted_in_the_spellings_a_model_writes() {
    for dst in [
        "ff:ff:ff:ff:ff:ff",
        "ff-ff-ff-ff-ff-ff",
        "ffffffffffff",
        "FF:FF:FF:FF:FF:FF",
    ] {
        let frame = built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": dst,
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "ipv4"
        }));
        assert_eq!(&frame[0..6], &[0xff; 6], "{dst:?} is the broadcast address");
        assert_eq!(&frame[6..12], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&frame[12..14], &[0x08, 0x00], "ipv4");
    }

    let msg = refusal(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": "00:11:22",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": "arp"
    }));
    assert!(
        msg.contains("dst_mac") && msg.contains("3 bytes"),
        "the refusal must name the field and what it decoded to: {msg}"
    );
}

/// A name, a number and a `0x` string all mean the same two bytes; a bare `"0806"` does not
/// mean anything in particular, so it is refused rather than guessed.
#[tokio::test]
async fn ethertype_accepts_a_name_a_number_and_a_hex_string_but_not_a_bare_one() {
    let header = |ethertype: serde_json::Value| -> [u8; 2] {
        let frame = built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": ethertype
        }));
        [frame[12], frame[13]]
    };

    assert_eq!(header(serde_json::json!("arp")), [0x08, 0x06]);
    assert_eq!(header(serde_json::json!("ARP")), [0x08, 0x06]);
    assert_eq!(header(serde_json::json!("0x0806")), [0x08, 0x06]);
    assert_eq!(header(serde_json::json!(2054)), [0x08, 0x06]);
    assert_eq!(header(serde_json::json!("ipv6")), [0x86, 0xdd]);

    for (name, value) in ETHERTYPE_NAMES {
        assert_eq!(
            header(serde_json::json!(name)),
            value.to_be_bytes(),
            "the name {name:?} must mean {value:#06x}"
        );
    }

    // 0806 is 2054 as hex and 806 as decimal. Only the caller knows which.
    let msg = refusal(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": "0806"
    }));
    assert!(
        msg.contains("2054") && msg.contains("806"),
        "the refusal must say why the bare form is ambiguous: {msg}"
    );

    assert!(
        refusal(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": 70000
        }))
        .contains("EtherType"),
        "a value that does not fit in two bytes must be refused"
    );
}

/// **The assertion the original bug would have failed.**
///
/// `"deadbeef"` is four bytes as hex and eight characters as text, and `"48656c6c6f"` is five
/// bytes or ten characters. Nothing sniffs: `payload_encoding` says which, and a payload
/// declared `utf8` goes out as the literal characters even when every one of them is a hex
/// digit.
#[tokio::test]
async fn a_utf8_payload_that_looks_like_hex_goes_out_as_those_characters() {
    for literal in ["deadbeef", "48656c6c6f", "0123456789abcdef"] {
        let frame = built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "0x88b5",
            "payload": literal,
            "payload_encoding": "utf8"
        }));
        assert_eq!(
            &frame[MIN_ETHERNET_FRAME_BYTES..],
            literal.as_bytes(),
            "{literal:?} declared utf8 must be its characters, not its decoding"
        );

        let decoded = built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "0x88b5",
            "payload": literal,
            "payload_encoding": "hex"
        }));
        assert_eq!(
            &decoded[MIN_ETHERNET_FRAME_BYTES..],
            hex::decode(literal).unwrap(),
            "{literal:?} declared hex must be its decoding"
        );
        assert_ne!(
            frame, decoded,
            "{literal:?} must mean two different frames, which is why the field is required"
        );
    }
}

/// `payload_encoding` has no default. `send_tcp_data`'s `encoding` defaults to utf8 because a
/// TCP payload is usually text; an Ethernet payload is usually ARP or IP, so the same default
/// here would put the ASCII of an ARP body on the wire for the frames most likely to be built.
#[tokio::test]
async fn a_payload_without_its_encoding_is_refused_rather_than_guessed() {
    let msg = refusal(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": "arp",
        "payload": "0001080006040001"
    }));
    assert!(
        msg.contains("payload_encoding") && msg.contains("deadbeef"),
        "the refusal must name the field and show why guessing is not possible: {msg}"
    );

    assert!(
        refusal(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "arp",
            "payload": "00",
            "payload_encoding": "base64"
        }))
        .contains("base64"),
        "an encoding that is neither hex nor utf8 must be named back"
    );

    // A header-only frame needs no payload and therefore no encoding.
    assert_eq!(
        built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_mac": "00:11:22:33:44:55",
            "ethertype": "arp"
        }))
        .len(),
        MIN_ETHERNET_FRAME_BYTES
    );
}

/// The two spellings are two statements about the same wire bytes.
#[tokio::test]
async fn the_structured_and_hex_spellings_cannot_be_combined() {
    let msg = refusal(serde_json::json!({
        "type": "inject_frame",
        "frame_hex": ARP_FRAME_HEX,
        "dst_mac": "ff:ff:ff:ff:ff:ff"
    }));
    assert!(
        msg.contains("frame_hex") && msg.contains("dst_mac"),
        "the refusal must name both spellings: {msg}"
    );
    assert!(
        msg.contains("precedence"),
        "and must say that neither wins: {msg}"
    );

    let msg = refusal(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "ethertype": "arp"
    }));
    assert!(
        msg.contains("src_mac"),
        "a half-written structured frame must be refused by the name of what is missing, not \
         completed with zeros: {msg}"
    );
}

/// No example anywhere in this protocol's model-facing surface is a hex blob.
#[tokio::test]
async fn no_example_hands_the_model_a_frame_as_hex() {
    let p = protocol();
    let state = AppState::new();

    for action in p
        .get_async_actions(&state)
        .into_iter()
        .chain(p.get_sync_actions())
        .chain(p.get_event_types().into_iter().flat_map(|e| e.actions))
    {
        assert!(
            action.example.get("frame_hex").is_none(),
            "'{}' shows the model a whole frame as hex: {}",
            action.name,
            action.example
        );
    }
}

// ---------------------------------------------------------------------------
// The event half
// ---------------------------------------------------------------------------

/// A captured frame is readable: the header is read out, and the payload carries the encoding
/// that says how to read it. Every one of those fields is spelled the way `inject_frame`
/// accepts it back, which is the whole point.
#[tokio::test]
async fn a_captured_frame_is_reported_as_fields_and_hands_straight_back() {
    let frame = hex::decode(ARP_FRAME_HEX).unwrap();
    let data = frame_event_fields(&frame);

    assert_eq!(data["dst_mac"], "ff:ff:ff:ff:ff:ff");
    assert_eq!(data["src_mac"], "00:11:22:33:44:55");
    assert_eq!(data["ethertype"], "0x0806");
    assert_eq!(data["payload_encoding"], "hex");
    assert_eq!(data["payload"], &ARP_FRAME_HEX[28..]);

    // Copying the reported fields into inject_frame reproduces the captured bytes.
    let replayed = built(serde_json::json!({
        "type": "inject_frame",
        "dst_mac": data["dst_mac"],
        "src_mac": data["src_mac"],
        "ethertype": data["ethertype"],
        "payload": data["payload"],
        "payload_encoding": data["payload_encoding"],
    }));
    assert_eq!(replayed, frame, "the round trip must be exact");

    // …and so does the escape hatch, which is why it stays.
    assert_eq!(
        built(serde_json::json!({"type": "inject_frame", "frame_hex": data["frame_hex"]})),
        frame
    );
}

/// A printable payload is reported as text, so a model reading an experimental-EtherType frame
/// is not made to decode hex in its head.
#[tokio::test]
async fn a_printable_payload_is_reported_as_text() {
    let mut frame = vec![0xffu8; 6];
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x88, 0xb5]);
    frame.extend_from_slice(b"netget");

    let data = frame_event_fields(&frame);
    assert_eq!(data["ethertype"], "0x88b5");
    assert_eq!(data["payload"], "netget");
    assert_eq!(data["payload_encoding"], "utf8");

    assert_eq!(
        built(serde_json::json!({
            "type": "inject_frame",
            "dst_mac": data["dst_mac"],
            "src_mac": data["src_mac"],
            "ethertype": data["ethertype"],
            "payload": data["payload"],
            "payload_encoding": data["payload_encoding"],
        })),
        frame
    );
}

/// libpcap can hand back fewer bytes than an Ethernet header. Inventing one would be worse
/// than saying there is none, so the header fields are null and `frame_hex` still carries what
/// was seen.
#[tokio::test]
async fn a_runt_reports_no_header_rather_than_an_invented_one() {
    let data = frame_event_fields(&[0xde, 0xad]);
    assert!(data["dst_mac"].is_null());
    assert!(data["src_mac"].is_null());
    assert!(data["ethertype"].is_null());
    assert_eq!(data["payload"], "");
    assert_eq!(data["frame_hex"], "dead");
    assert_eq!(data["frame_length"], 2);
}
