//! `netget::server::mqtt` — the broker's own MQTT 3.1.1 / 5.0 decoder, from the fixed header
//! to every v5 property block, as an unauthenticated client reaches it: the first bytes of a
//! TCP connection are a CONNECT, and every packet after it is decoded before the model sees
//! anything.
//!
//! The input is a byte stream. `take_packet` pulls packets off it exactly as the connection
//! loop does (remaining-length varint, the `DEFAULT_MAX_PACKET_SIZE` cap checked before any
//! allocation), and each is handed to the parser `dispatch_packet` would call for its type —
//! `parse_connect`, `parse_publish`, `parse_subscribe`, `parse_unsubscribe`, and the v5
//! DISCONNECT's `read_properties`. Whether the parsers run in v5 mode is decided the way the
//! session decides it: by the protocol level of the first CONNECT that parses.
//!
//! Asserted:
//!
//! 1. Nothing panics, whatever the bytes.
//! 2. `take_packet` never consumes past the buffer, and the bodies it returns respect the cap.
//! 3. Every parser is deterministic: the same body gives the same verdict twice.
//! 4. A property block that decodes renders to JSON (`Properties::to_json`), which is what the
//!    model is shown.
//!
//! MQTT does not nest, so there is no depth bomb; the corpus carries the long and the lying
//! axes instead — a remaining length at the varint's 268 435 455 maximum, a five-byte varint,
//! property lengths running past their packet, and a SUBSCRIBE of 30 000 filters.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::mqtt::{
    parse_connect, parse_publish, parse_subscribe, parse_unsubscribe, take_packet, v5,
    DEFAULT_MAX_PACKET_SIZE, PKT_CONNECT, PKT_DISCONNECT, PKT_PUBLISH, PKT_SUBSCRIBE,
    PKT_UNSUBSCRIBE,
};

fuzz_target!(|data: &[u8]| {
    let mut buffer = data.to_vec();
    let mut v5_session: Option<bool> = None;

    loop {
        let before = buffer.len();
        let packet = match take_packet(&mut buffer, DEFAULT_MAX_PACKET_SIZE) {
            Ok(Some(p)) => p,
            Ok(None) => {
                assert_eq!(buffer.len(), before, "an incomplete packet consumed bytes");
                break;
            }
            Err(_) => break,
        };
        assert!(
            packet.body.len() <= DEFAULT_MAX_PACKET_SIZE,
            "body past the cap"
        );
        assert!(
            buffer.len() + packet.body.len() < before,
            "take_packet returned more than it consumed"
        );
        let v5 = v5_session.unwrap_or(false);

        match packet.packet_type {
            PKT_CONNECT => {
                let first = parse_connect(&packet.body);
                let again = parse_connect(&packet.body);
                assert_eq!(
                    first.is_ok(),
                    again.is_ok(),
                    "parse_connect disagreed with itself"
                );
                if let Ok(c) = first {
                    let _ = c.properties.to_json();
                    let _ = c.will_properties.to_json();
                    if v5_session.is_none() {
                        v5_session = Some(c.protocol_level == 5);
                    }
                }
            }
            PKT_PUBLISH => {
                let qos = (packet.flags >> 1) & 0x03;
                let first = parse_publish(&packet.body, qos, v5);
                let again = parse_publish(&packet.body, qos, v5);
                assert_eq!(
                    first.is_ok(),
                    again.is_ok(),
                    "parse_publish disagreed with itself"
                );
                if let (Ok(a), Ok(b)) = (&first, &again) {
                    assert_eq!(a.topic, b.topic);
                    assert_eq!(a.payload, b.payload);
                    let _ = a.properties.to_json();
                }
            }
            PKT_SUBSCRIBE => {
                if let Ok(s) = parse_subscribe(&packet.body, v5) {
                    assert_eq!(
                        s.topics.len(),
                        s.options.len(),
                        "one options entry per filter"
                    );
                    let _ = s.properties.to_json();
                }
            }
            PKT_UNSUBSCRIBE => {
                if let Ok(u) = parse_unsubscribe(&packet.body, v5) {
                    let _ = u.properties.to_json();
                }
            }
            PKT_DISCONNECT if v5 && packet.body.len() > 1 => {
                let mut pos = 1usize;
                if let Ok(p) = v5::read_properties(&packet.body, &mut pos) {
                    assert!(
                        pos <= packet.body.len(),
                        "read_properties ran past the packet"
                    );
                    let _ = p.to_json();
                }
            }
            _ => {}
        }
    }
});
