//! CPU-only regressions for the remaining IPP, DHT and FIDO2 recursive-decoder exceptions.
//! No sockets, model calls, USB enumeration, or device handles are used.

mod ipp {
    use netget::llm::actions::protocol_trait::{ActionResult, Server};
    use netget::server::ipp::actions::{validate_attributes, IppProtocol, MAX_IPP_ATTRIBUTE_DEPTH};
    use serde_json::{json, Map, Value};

    fn nested(depth: usize, objects: bool) -> Value {
        (0..depth).fold(json!(7), |value, level| {
            if objects && level % 2 == 0 {
                Value::Object(Map::from_iter([("inner".into(), value)]))
            } else {
                Value::Array(vec![value])
            }
        })
    }

    fn attributes(value: Value) -> Map<String, Value> {
        Map::from_iter([("printer-info".into(), value)])
    }

    fn encode(attributes: Map<String, Value>) -> anyhow::Result<Vec<u8>> {
        let action = Value::Object(Map::from_iter([
            ("type".into(), json!("ipp_printer_attributes")),
            ("attributes".into(), Value::Object(attributes)),
        ]));
        match IppProtocol::new().execute_action(action)? {
            ActionResult::Custom { data, .. } => {
                Ok(hex::decode(data["body_hex"].as_str().unwrap())?)
            }
            _ => panic!("IPP must return its encoded response"),
        }
    }

    fn drop_iteratively(value: Value) {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            match value {
                Value::Array(values) => pending.extend(values),
                Value::Object(values) => pending.extend(values.into_values()),
                _ => {}
            }
        }
    }

    #[test]
    fn exact_depth_is_accepted_and_the_next_level_is_refused() {
        for objects in [false, true] {
            let at_limit = attributes(nested(MAX_IPP_ATTRIBUTE_DEPTH, objects));
            assert!(validate_attributes(&at_limit).is_ok());
            assert!(encode(at_limit).is_ok());
            let too_deep = attributes(nested(MAX_IPP_ATTRIBUTE_DEPTH + 1, objects));
            assert!(encode(too_deep)
                .unwrap_err()
                .to_string()
                .contains("nesting exceeds"));
        }
    }

    #[test]
    fn directly_constructed_deep_trees_are_refused_without_recursive_walking() {
        for objects in [false, true] {
            let value = attributes(nested(20_000, objects));
            let result = validate_attributes(&value);
            // serde_json::Value itself drops recursively; isolate the validation under test.
            drop_iteratively(Value::Object(value));
            assert!(result.unwrap_err().to_string().contains("nesting exceeds"));
        }
    }

    #[test]
    fn json_fallback_checks_escaped_bytes_without_truncating_the_field() {
        let at_limit = json!({"x": "x".repeat(u16::MAX as usize - 8)});
        let expected = at_limit.to_string();
        assert_eq!(expected.len(), u16::MAX as usize);
        let body = encode(attributes(at_limit)).unwrap();
        assert!(body
            .windows(expected.len())
            .any(|part| part == expected.as_bytes()));

        for value in [
            json!({"x": "x".repeat(u16::MAX as usize - 7)}),
            json!({"x": "\n".repeat(32_764)}),
            json!([["x".repeat(u16::MAX as usize)]]),
            json!([{ "x": "x".repeat(u16::MAX as usize) }]),
        ] {
            let error = encode(attributes(value)).unwrap_err();
            assert!(format!("{error:#}").contains("cannot be encoded in full"));
        }
    }

    #[test]
    fn ordinary_sets_and_json_object_numbers_preserve_their_representation() {
        let object = json!({"large": u64::MAX, "fraction": 1.25, "nested": [true, null]});
        let expected = object.to_string();
        let body = encode(attributes(object)).unwrap();
        assert!(body
            .windows(expected.len())
            .any(|part| part == expected.as_bytes()));
        assert!(encode(attributes(json!([1, 2, i32::MAX]))).is_ok());
        assert!(encode(attributes(json!([1, i64::MAX]))).is_err());
    }
}

mod dht {
    use netget::server::torrent_dht::{TorrentDhtServer, MAX_DHT_VALUE_DEPTH};
    use serde_bencode::value::Value;
    use serde_json::json;
    use std::collections::HashMap;

    fn nested(depth: usize, dictionaries: bool) -> Value {
        (0..depth).fold(Value::Int(7), |value, level| {
            if dictionaries && level % 2 == 0 {
                Value::Dict(HashMap::from([(b"inner".to_vec(), value)]))
            } else {
                Value::List(vec![value])
            }
        })
    }

    fn drop_iteratively(value: Value) {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            match value {
                Value::List(values) => pending.extend(values),
                Value::Dict(values) => pending.extend(values.into_values()),
                _ => {}
            }
        }
    }

    #[test]
    fn ordinary_bencode_preserves_text_binary_and_integer_values() {
        let value = Value::Dict(HashMap::from([
            (b"text".to_vec(), Value::Bytes(b"hello\tworld".to_vec())),
            (b"binary".to_vec(), Value::Bytes(vec![0, 255])),
            (b"unicode".to_vec(), Value::Bytes("é".as_bytes().to_vec())),
            (
                b"list".to_vec(),
                Value::List(vec![Value::Int(i64::MIN), Value::Int(7)]),
            ),
        ]));
        assert_eq!(
            TorrentDhtServer::bencode_to_json(&value).unwrap(),
            json!({"text":"hello\tworld", "binary":"00ff", "unicode":"c3a9", "list":[i64::MIN,7]})
        );
    }

    #[test]
    fn maximum_depth_converts_in_full_and_excess_returns_an_error() {
        for dictionaries in [false, true] {
            let converted =
                TorrentDhtServer::bencode_to_json(&nested(MAX_DHT_VALUE_DEPTH, dictionaries))
                    .unwrap();
            let mut leaf = &converted;
            for _ in 0..MAX_DHT_VALUE_DEPTH {
                leaf = if leaf.is_array() {
                    &leaf[0]
                } else {
                    &leaf["inner"]
                };
            }
            assert_eq!(leaf, &json!(7));
            assert!(TorrentDhtServer::bencode_to_json(&nested(
                MAX_DHT_VALUE_DEPTH + 1,
                dictionaries
            ))
            .unwrap_err()
            .to_string()
            .contains("nesting exceeds"));
        }
    }

    #[test]
    fn in_memory_trees_cannot_bypass_the_depth_bound() {
        for dictionaries in [false, true] {
            let value = nested(20_000, dictionaries);
            let result = TorrentDhtServer::bencode_to_json(&value);
            drop_iteratively(value);
            assert!(result.unwrap_err().to_string().contains("nesting exceeds"));
        }
    }
}

#[cfg(all(unix, feature = "libusb"))]
mod fido {
    use netget::server::usb::fido2::approval::{ApprovalDecision, ApprovalDetails};
    use netget::server::usb::fido2::ctaphid::MAX_MESSAGE_SIZE;
    use netget::server::usb::fido2::Fido2HidHandler;
    use serde_cbor::Value as Cbor;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;
    use usbip::{SetupPacket, UsbEndpoint, UsbInterface, UsbInterfaceHandler};

    const CID: u32 = 0x0102_0304;
    const MSG: u8 = 0x03;
    const CBOR: u8 = 0x10;
    const KEEPALIVE: u8 = 0x3b;
    const ERROR: u8 = 0x3f;

    struct Harness {
        handler: Fido2HidHandler,
        interface: UsbInterface,
    }

    impl Harness {
        fn new(handler: Fido2HidHandler) -> Self {
            Self {
                handler,
                // handle_urb does not access this handler: this is only an in-memory
                // descriptor satisfying the public trait's interface argument.
                interface: UsbInterface {
                    interface_class: 3,
                    interface_subclass: 0,
                    interface_protocol: 0,
                    endpoints: vec![],
                    string_interface: 0,
                    class_specific_descriptor: vec![],
                    handler: Arc::new(Mutex::new(Box::new(Fido2HidHandler::new(false, false)))),
                },
            }
        }

        fn urb(&mut self, input: bool, data: &[u8]) -> Vec<u8> {
            self.handler
                .handle_urb(
                    &self.interface,
                    UsbEndpoint {
                        address: if input { 0x81 } else { 0x01 },
                        attributes: 3,
                        max_packet_size: 64,
                        interval: 5,
                    },
                    64,
                    SetupPacket::default(),
                    data,
                )
                .unwrap()
        }

        fn send(&mut self, cmd: u8, payload: &[u8]) {
            assert!(payload.len() <= MAX_MESSAGE_SIZE);
            let mut first = [0; 64];
            first[..4].copy_from_slice(&CID.to_be_bytes());
            first[4] = 0x80 | cmd;
            first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            let initial = payload.len().min(57);
            first[7..7 + initial].copy_from_slice(&payload[..initial]);
            assert!(self.urb(false, &first).is_empty());
            for (seq, chunk) in payload[initial..].chunks(59).enumerate() {
                let mut packet = [0; 64];
                packet[..4].copy_from_slice(&CID.to_be_bytes());
                packet[4] = seq as u8;
                packet[5..5 + chunk.len()].copy_from_slice(chunk);
                assert!(self.urb(false, &packet).is_empty());
            }
        }

        fn receive(&mut self) -> (u8, Vec<u8>) {
            let first = self.urb(true, &[]);
            assert_eq!(first.len(), 64);
            assert_eq!(&first[..4], &CID.to_be_bytes());
            assert_ne!(first[4] & 0x80, 0);
            let size = u16::from_be_bytes([first[5], first[6]]) as usize;
            let mut payload = first[7..7 + size.min(57)].to_vec();
            let mut sequence = 0;
            while payload.len() < size {
                let packet = self.urb(true, &[]);
                assert_eq!(packet.len(), 64);
                assert_eq!(&packet[..4], &CID.to_be_bytes());
                assert_eq!(packet[4], sequence);
                sequence += 1;
                let count = (size - payload.len()).min(59);
                payload.extend_from_slice(&packet[5..5 + count]);
            }
            (first[4] & 0x7f, payload)
        }
    }

    fn registration(cmd: u8) -> Vec<u8> {
        if cmd == MSG {
            let mut request = vec![0, 1, 0, 0, 0, 0, 64];
            request.extend_from_slice(&[7; 64]);
            request
        } else {
            let params = Cbor::Map(BTreeMap::from([
                (Cbor::Integer(1), Cbor::Bytes(vec![7; 32])),
                (
                    Cbor::Integer(2),
                    Cbor::Map(BTreeMap::from([(
                        Cbor::Text("id".into()),
                        Cbor::Text("fixture.example".into()),
                    )])),
                ),
                (
                    Cbor::Integer(3),
                    Cbor::Map(BTreeMap::from([
                        (Cbor::Text("id".into()), Cbor::Bytes(vec![8; 8])),
                        (Cbor::Text("name".into()), Cbor::Text("fixture".into())),
                    ])),
                ),
            ]));
            let mut request = vec![1];
            request.extend_from_slice(&serde_cbor::to_vec(&params).unwrap());
            request
        }
    }

    fn denial(cmd: u8) -> Vec<u8> {
        if cmd == MSG {
            vec![0x69, 0x85]
        } else {
            vec![0x27]
        }
    }

    #[test]
    fn missing_or_closed_approval_channels_deny_both_protocols_without_parking() {
        for closed in [false, true] {
            let mut handler = Fido2HidHandler::new(true, true);
            if closed {
                let (tx, rx) = mpsc::unbounded_channel::<ApprovalDetails>();
                drop(rx);
                handler = handler.with_approvals(tx);
            }
            let mut harness = Harness::new(handler);
            for _ in 0..32 {
                for cmd in [MSG, CBOR] {
                    harness.send(cmd, &registration(cmd));
                    assert_eq!(harness.receive(), (cmd, denial(cmd)));
                    assert!(harness.urb(true, &[]).is_empty());
                    assert!(harness.handler.describe_credentials().is_empty());
                }
            }
        }
    }

    #[test]
    fn attached_channel_preserves_approval_denial_and_busy_behavior() {
        for cmd in [MSG, CBOR] {
            let (tx, mut rx) = mpsc::unbounded_channel::<ApprovalDetails>();
            let mut harness = Harness::new(Fido2HidHandler::new(true, true).with_approvals(tx));
            for decision in [ApprovalDecision::Denied, ApprovalDecision::Approved] {
                harness.send(cmd, &registration(cmd));
                assert_eq!(harness.receive(), (KEEPALIVE, vec![2]));
                let details = rx.try_recv().unwrap();
                assert_eq!(details.credential_count, 0);
                harness.send(1, b"busy");
                assert_eq!(harness.receive(), (ERROR, vec![6]));
                assert!(
                    rx.try_recv().is_err(),
                    "the parked request must not be replaced"
                );
                harness.handler.resolve_approval(decision);
                let (response_cmd, response) = harness.receive();
                assert_eq!(response_cmd, cmd);
                if decision == ApprovalDecision::Denied {
                    assert_eq!(response, denial(cmd));
                    assert!(harness.handler.describe_credentials().is_empty());
                } else {
                    if cmd == MSG {
                        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
                    } else {
                        assert_eq!(response[0], 0);
                    }
                    assert_eq!(harness.handler.describe_credentials().len(), 1);
                }
                assert!(harness.urb(true, &[]).is_empty());
            }
        }
    }

    #[test]
    fn framing_boundary_and_invalid_commands_still_return_exact_responses() {
        let mut harness = Harness::new(Fido2HidHandler::new(true, true));
        let payload = vec![0xa5; MAX_MESSAGE_SIZE];
        harness.send(1, &payload);
        assert_eq!(harness.receive(), (1, payload));
        let mut oversized = [0; 64];
        oversized[..4].copy_from_slice(&CID.to_be_bytes());
        oversized[4] = 0x81;
        oversized[5..7].copy_from_slice(&((MAX_MESSAGE_SIZE + 1) as u16).to_be_bytes());
        harness.urb(false, &oversized);
        assert_eq!(harness.receive(), (ERROR, vec![3]));
        harness.send(MSG, &[]);
        assert_eq!(harness.receive(), (MSG, vec![0x6a, 0x80]));
        harness.send(CBOR, &[]);
        assert_eq!(harness.receive(), (CBOR, vec![0x12]));
        harness.send(1, b"still alive");
        assert_eq!(harness.receive(), (1, b"still alive".to_vec()));
    }
}
