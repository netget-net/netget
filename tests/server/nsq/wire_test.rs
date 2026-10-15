//! The NSQ codec on its own: every command parsed from what a client writes, every refusal in
//! nsqd's own words, sizes judged from the size field before the body arrives, the frames the
//! server writes read back, and a property-based round trip of both directions.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nsq --test server -- nsq::wire --test-threads=100

use netget::server::nsq::wire::{self, Command};
use proptest::prelude::*;

fn parse_all(bytes: &[u8]) -> Command {
    let (command, used) = wire::parse_command(bytes)
        .expect("parses")
        .expect("complete");
    assert_eq!(used, bytes.len(), "the whole command was consumed");
    command
}

#[test]
fn every_command_parses_from_what_a_client_writes() {
    assert_eq!(parse_all(b"NOP\n"), Command::Nop);
    assert_eq!(parse_all(b"CLS\r\n"), Command::Cls);
    assert_eq!(parse_all(b"RDY 200\n"), Command::Rdy(200));
    assert_eq!(parse_all(b"RDY\n"), Command::Rdy(1), "RDY alone means 1");
    assert_eq!(
        parse_all(b"SUB orders workers#ephemeral\n"),
        Command::Sub {
            topic: "orders".into(),
            channel: "workers#ephemeral".into()
        }
    );
    assert_eq!(
        parse_all(b"FIN 0123456789abcdef\n"),
        Command::Fin("0123456789abcdef".into())
    );
    assert_eq!(
        parse_all(b"REQ 0123456789abcdef 5000\n"),
        Command::Req {
            id: "0123456789abcdef".into(),
            timeout_ms: 5000
        }
    );
    assert_eq!(
        parse_all(b"REQ 0123456789abcdef 99999999999\n"),
        Command::Req {
            id: "0123456789abcdef".into(),
            timeout_ms: wire::MAX_REQ_TIMEOUT_MS
        },
        "nsqd clamps an out-of-range REQ timeout"
    );
    assert_eq!(
        parse_all(b"PUB t\n\0\0\0\x05hello"),
        Command::Pub {
            topic: "t".into(),
            body: b"hello".to_vec()
        }
    );
    assert_eq!(
        parse_all(b"DPUB t 1500\n\0\0\0\x01x"),
        Command::Dpub {
            topic: "t".into(),
            defer_ms: 1500,
            body: b"x".to_vec()
        }
    );
    let mpub = wire::encode_command(&Command::Mpub {
        topic: "t".into(),
        messages: vec![b"a".to_vec(), b"bc".to_vec()],
    });
    assert_eq!(
        parse_all(&mpub),
        Command::Mpub {
            topic: "t".into(),
            messages: vec![b"a".to_vec(), b"bc".to_vec()]
        }
    );
    assert_eq!(
        parse_all(b"IDENTIFY\n\0\0\0\x02{}"),
        Command::Identify(b"{}".to_vec())
    );
}

#[test]
fn every_prefix_of_a_command_asks_for_more_bytes() {
    // The session loop drops a half-read command when a heartbeat wins the race and parses the
    // buffer again later, so no prefix may be mistaken for a whole command or an error.
    for command in [
        Command::Pub {
            topic: "orders".into(),
            body: b"order 1".to_vec(),
        },
        Command::Mpub {
            topic: "orders".into(),
            messages: vec![b"a".to_vec(), b"b".to_vec()],
        },
        Command::Identify(br#"{"feature_negotiation":true}"#.to_vec()),
        Command::Sub {
            topic: "t".into(),
            channel: "c".into(),
        },
    ] {
        let bytes = wire::encode_command(&command);
        for cut in 0..bytes.len() {
            assert_eq!(
                wire::parse_command(&bytes[..cut]),
                Ok(None),
                "{command:?} cut at {cut}"
            );
        }
    }
}

#[test]
fn message_ids_reject_control_and_non_hex_bytes_before_accepting_a_command() {
    // Reduced from the 274-byte input in Fuzz run 36918355914. Previously FIN
    // accepted the 16-byte ID ending in CR because a space followed it. Re-encoding
    // discarded the extra parameter, making that CR part of CRLF and the ID 15 bytes.
    let regression = b"FIN 000000000000000\r \n";
    assert_eq!(regression.len(), 22);
    let error = wire::parse_command(regression).expect_err("a CR cannot be part of a message ID");
    assert_eq!(
        (error.code, error.message.as_str()),
        ("E_INVALID", "Invalid Message ID")
    );
    assert!(error.fatal);

    // Keep this finite: every ASCII byte in every position, for each ID-bearing
    // command. A trailing ignored parameter keeps CR out of the line terminator.
    for verb in ["FIN", "TOUCH", "REQ"] {
        for position in 0..wire::MSG_ID_LEN {
            for byte in 0u8..=127 {
                if byte.is_ascii_hexdigit() || matches!(byte, b' ' | b'\n') {
                    continue; // Separators already end the parameter/command.
                }
                let mut id = [b'0'; wire::MSG_ID_LEN];
                id[position] = byte;
                let mut input = format!("{verb} ").into_bytes();
                input.extend_from_slice(&id);
                input.extend_from_slice(if verb == "REQ" { b" 0 \n" } else { b" \n" });
                let error = wire::parse_command(&input).expect_err("IDs contain only ASCII hex");
                assert_eq!(
                    error.code, "E_INVALID",
                    "{verb}, byte {byte}, position {position}"
                );
                assert!(error.fatal);
            }
        }
    }
}

#[test]
fn valid_message_ids_round_trip_with_lf_crlf_and_extra_parameters() {
    let mut ids = vec![
        "0123456789abcdef".to_string(),
        "0123456789ABCDEF".to_string(),
    ];
    for n in [0, 1, 0xabc, u64::MAX] {
        ids.push(String::from_utf8(wire::message_id_for(n).to_vec()).unwrap());
    }
    for id in ids {
        for command in [
            Command::Fin(id.clone()),
            Command::Touch(id.clone()),
            Command::Req {
                id: id.clone(),
                timeout_ms: 0,
            },
        ] {
            let encoded = wire::encode_command(&command);
            for ending in [b"\n".as_slice(), b"\r\n", b" ignored\n"] {
                let mut input = encoded[..encoded.len() - 1].to_vec();
                input.extend_from_slice(ending);
                assert_eq!(parse_all(&input), command);
            }
            assert_eq!(parse_all(&encoded), command);
        }
    }
}

#[test]
fn refusals_use_nsqds_codes_and_are_judged_from_the_declared_size() {
    let err = |bytes: &[u8]| wire::parse_command(bytes).expect_err("refused");

    let e = err(b"PUB t\n\0\x10\0\x01");
    assert_eq!(e.code, "E_BAD_MESSAGE");
    assert_eq!(e.message, "PUB message too big 1048577 > 1048576");
    assert!(e.fatal);

    let e = err(b"PUB t\n\0\0\0\0");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("E_BAD_MESSAGE", "PUB invalid message body size 0")
    );

    // 5 MiB + 1, with no body behind it.
    let e = err(b"MPUB t\n\0\x50\0\x01");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("E_BAD_BODY", "MPUB body too big 5242881 > 5242880")
    );

    // A legal body size with an impossible message count: refused from the count alone.
    let mut mpub = b"MPUB t\n".to_vec();
    mpub.extend_from_slice(&100u32.to_be_bytes());
    mpub.extend_from_slice(&((wire::MAX_MPUB_MESSAGES + 1) as u32).to_be_bytes());
    let e = err(&mpub);
    assert_eq!(e.code, "E_BAD_BODY");
    assert!(
        e.message.starts_with("MPUB invalid message count"),
        "{}",
        e.message
    );

    let e = err(b"PUB bad*topic\n");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("E_BAD_TOPIC", "PUB topic name \"bad*topic\" is not valid")
    );
    let e = err(b"SUB t bad*channel\n");
    assert_eq!(e.code, "E_BAD_CHANNEL");
    assert_eq!(err(b"SUB t\n").code, "E_INVALID");
    assert_eq!(
        err(b"RDY 2501\n").message,
        "RDY count 2501 out of range 0-2500"
    );
    assert_eq!(err(b"RDY many\n").message, "RDY could not parse count many");
    assert_eq!(err(b"FIN short\n").message, "Invalid Message ID");
    assert_eq!(err(b"FROB\n").message, "invalid command FROB");
    assert_eq!(err(b"IDENTIFY\n\0\0\0\0").code, "E_BAD_BODY");

    let long = vec![b'x'; wire::MAX_LINE];
    assert_eq!(
        err(&long).message,
        "command line too long (over 1024 bytes)"
    );
    let mut line = vec![b'x'; wire::MAX_LINE - 1];
    line.push(b'\n');
    assert_eq!(
        err(&line).message.len(),
        "invalid command ".len() + wire::MAX_LINE - 1,
        "a line of exactly the limit, newline included, is read as a line"
    );
}

#[test]
fn an_mpub_whose_messages_do_not_fit_its_body_is_refused() {
    let mut body = 2u32.to_be_bytes().to_vec();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.push(b'a');
    body.extend_from_slice(&10u32.to_be_bytes());
    body.extend_from_slice(b"short");
    let e = wire::split_mpub(&body).expect_err("refused");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("E_BAD_MESSAGE", "MPUB failed to read message body")
    );
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        wire::split_mpub(&body).expect_err("refused").message,
        "MPUB invalid message(0) body size 0"
    );
}

#[test]
fn names_follow_nsqds_rule() {
    for ok in [
        "t",
        "orders.v1",
        "a_b-c",
        "workers#ephemeral",
        &"x".repeat(64),
    ] {
        assert!(wire::valid_name(ok), "{ok}");
    }
    for bad in [
        "",
        "#ephemeral",
        "a b",
        "a*b",
        "é",
        &"x".repeat(65),
        "a#ephemeral#ephemeral",
    ] {
        assert!(!wire::valid_name(bad), "{bad}");
    }
    assert!(wire::is_ephemeral("c#ephemeral"));
}

#[test]
fn frames_read_back() {
    let f = wire::response_frame(b"OK");
    assert_eq!(f, b"\0\0\0\x06\0\0\0\0OK");
    let e = wire::error_frame("E_PUB_FAILED", "no\nway");
    let (frame, used) = wire::parse_frame(&e).unwrap().unwrap();
    assert_eq!(used, e.len());
    assert_eq!(frame.frame_type, wire::FRAME_ERROR);
    assert_eq!(
        frame.data, b"E_PUB_FAILED no way",
        "one line, no control characters"
    );
    assert_eq!(
        wire::parse_frame(&wire::error_frame("E_INVALID", ""))
            .unwrap()
            .unwrap()
            .0
            .data,
        b"E_INVALID"
    );

    let id = wire::message_id_for(0xabc);
    assert_eq!(&id, b"0000000000000abc");
    let m = wire::message_frame(1_700_000_000_000_000_000, 3, &id, b"body");
    let (frame, _) = wire::parse_frame(&m).unwrap().unwrap();
    assert_eq!(frame.frame_type, wire::FRAME_MESSAGE);
    let message = wire::parse_message(&frame.data).unwrap();
    assert_eq!(message.timestamp_ns, 1_700_000_000_000_000_000);
    assert_eq!(message.attempts, 3);
    assert_eq!(&message.id, b"0000000000000abc");
    assert_eq!(message.body, b"body");

    assert!(
        wire::parse_frame(b"\0\0\0\x02xx").is_err(),
        "size below the type"
    );
    assert!(
        wire::parse_frame(b"\xff\xff\xff\xff").is_err(),
        "size past any frame"
    );
}

#[test]
fn identify_follows_nsqds_heartbeat_rules() {
    let hb = |v: serde_json::Value| wire::parse_identify(v.to_string().as_bytes());
    assert_eq!(hb(serde_json::json!({})).unwrap().heartbeat_ms, Some(0));
    assert_eq!(
        hb(serde_json::json!({"heartbeat_interval": -1}))
            .unwrap()
            .heartbeat_ms,
        None
    );
    assert_eq!(
        hb(serde_json::json!({"heartbeat_interval": 1000}))
            .unwrap()
            .heartbeat_ms,
        Some(1000)
    );
    for bad in [999, 60_001, -2] {
        let e = hb(serde_json::json!({"heartbeat_interval": bad})).unwrap_err();
        assert_eq!(e.code, "E_BAD_BODY");
        assert_eq!(
            e.message,
            format!("IDENTIFY heartbeat interval ({bad}) is invalid")
        );
    }
    assert!(wire::parse_identify(b"[1,2]").is_err());
    assert!(wire::parse_identify(b"not json").is_err());

    let reply: serde_json::Value =
        serde_json::from_slice(&wire::identify_response(60_000)).unwrap();
    assert_eq!(reply["max_rdy_count"], 2500);
    for off in ["tls_v1", "deflate", "snappy", "auth_required"] {
        assert_eq!(reply[off], false, "{off}");
    }
}

fn name() -> impl Strategy<Value = String> {
    "[.a-zA-Z0-9_-]{1,54}(#ephemeral)?"
}

fn id() -> impl Strategy<Value = String> {
    "[0-9a-f]{16}"
}

fn body() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..200)
}

fn command() -> impl Strategy<Value = Command> {
    prop_oneof![
        Just(Command::Nop),
        Just(Command::Cls),
        (0..=wire::MAX_RDY_COUNT).prop_map(Command::Rdy),
        (name(), name()).prop_map(|(topic, channel)| Command::Sub { topic, channel }),
        id().prop_map(Command::Fin),
        id().prop_map(Command::Touch),
        (id(), 0..=wire::MAX_REQ_TIMEOUT_MS)
            .prop_map(|(id, timeout_ms)| Command::Req { id, timeout_ms }),
        (name(), body()).prop_map(|(topic, body)| Command::Pub { topic, body }),
        (name(), 0..=wire::MAX_REQ_TIMEOUT_MS, body()).prop_map(|(topic, defer_ms, body)| {
            Command::Dpub {
                topic,
                defer_ms,
                body,
            }
        }),
        (name(), proptest::collection::vec(body(), 1..8))
            .prop_map(|(topic, messages)| Command::Mpub { topic, messages }),
        body().prop_map(Command::Identify),
        body().prop_map(Command::Auth),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_command_round_trips(cmd in command(), tail in proptest::collection::vec(any::<u8>(), 0..16)) {
        let mut bytes = wire::encode_command(&cmd);
        let len = bytes.len();
        bytes.extend_from_slice(&tail);
        let (parsed, used) = wire::parse_command(&bytes).unwrap().unwrap();
        prop_assert_eq!(parsed, cmd);
        prop_assert_eq!(used, len, "exactly the command, not the bytes behind it");
    }

    #[test]
    fn a_message_frame_round_trips(ts in any::<i64>(), attempts in any::<u16>(), n in any::<u64>(), body in body()) {
        let id = wire::message_id_for(n);
        let bytes = wire::message_frame(ts, attempts, &id, &body);
        let (frame, used) = wire::parse_frame(&bytes).unwrap().unwrap();
        prop_assert_eq!(used, bytes.len());
        let m = wire::parse_message(&frame.data).unwrap();
        prop_assert_eq!((m.timestamp_ns, m.attempts, m.id, m.body), (ts, attempts, id, body));
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_parser(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = wire::parse_command(&bytes);
        let _ = wire::parse_frame(&bytes);
        let _ = wire::split_mpub(&bytes);
        let _ = wire::parse_identify(&bytes);
    }
}
