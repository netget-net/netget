//! The Zabbix wire format in isolation: header round trips in both sizes, the declared-length
//! check, request parsing, and the response `zabbix_sender` scans — as properties and tables.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features zabbix --test server -- zabbix::wire --test-threads=100

use netget::server::zabbix::wire::{
    encode, encode_large, header_len, info_string, parse_header, parse_request, read_result,
    render_failed, render_result, HeaderError, Request, RequestError, FLAG_LARGE, FLAG_PROTOCOL,
    MAX_DATA_BYTES,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever the payload, both header forms parse back to its length, and the body starts
    /// exactly where the header says.
    #[test]
    fn a_header_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..2048), large in any::<bool>()) {
        let packet = if large { encode_large(&payload) } else { encode(&payload) };
        let header = parse_header(&packet).unwrap();
        prop_assert_eq!(header.flags & FLAG_LARGE != 0, large);
        prop_assert_eq!(header.data_len as usize, payload.len());
        prop_assert_eq!(&packet[header_len(header.flags)..], &payload[..]);
    }

    /// Any declared length past the bound is refused, in either header form.
    #[test]
    fn a_declared_length_past_the_bound_is_refused(len in (MAX_DATA_BYTES as u64 + 1)..u64::MAX, large in any::<bool>()) {
        let mut header = b"ZBXD".to_vec();
        if large {
            header.push(FLAG_PROTOCOL | FLAG_LARGE);
            header.extend_from_slice(&len.to_le_bytes());
            header.extend_from_slice(&0u64.to_le_bytes());
        } else {
            let len32 = len.min(u64::from(u32::MAX)) as u32;
            prop_assume!(u64::from(len32) > MAX_DATA_BYTES as u64);
            header.push(FLAG_PROTOCOL);
            header.extend_from_slice(&len32.to_le_bytes());
            header.extend_from_slice(&0u32.to_le_bytes());
        }
        prop_assert!(matches!(parse_header(&header), Err(HeaderError::TooLarge(_))));
    }

    /// The response zabbix_sender scans reads back to the counts it was built from, and its
    /// info string has exactly zabbix_sender's sscanf shape.
    #[test]
    fn a_result_round_trips(processed in 0u64..1_000_000, failed in 0u64..1_000_000, secs in 0f64..1000.0) {
        let packet = render_result(processed, failed, processed + failed, secs);
        prop_assert_eq!(read_result(&packet), Some((processed, failed, processed + failed)));
        let info = info_string(processed, failed, processed + failed, secs);
        let re = regex::Regex::new(r"^processed: \d+; failed: \d+; total: \d+; seconds spent: \d+\.\d{6}$").unwrap();
        prop_assert!(re.is_match(&info), "{}", info);
    }

    /// No input panics the request parser.
    #[test]
    fn the_request_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_request(&data);
        let _ = parse_header(&data);
    }
}

#[test]
fn header_refusals() {
    assert_eq!(
        parse_header(b"ZBXE\x01\0\0\0\0\0\0\0\0"),
        Err(HeaderError::BadMagic)
    );
    assert_eq!(
        parse_header(b"ZBXD\x00\0\0\0\0\0\0\0\0"),
        Err(HeaderError::BadFlags(0))
    );
    assert_eq!(
        parse_header(b"ZBXD\x09\0\0\0\0\0\0\0\0"),
        Err(HeaderError::BadFlags(9))
    );
    assert_eq!(
        parse_header(b"ZBXD\x03\x0a\0\0\0\xe8\x03\0\0"),
        Err(HeaderError::Compressed)
    );
    let exact = encode(&vec![b' '; MAX_DATA_BYTES]);
    assert_eq!(
        parse_header(&exact).unwrap().data_len,
        MAX_DATA_BYTES as u64
    );
}

#[test]
fn requests_parse_as_zabbix_sender_writes_them() {
    // Byte for byte what zabbix_sender 7.4 sent to a capture listener.
    let sent = br#"{"request":"sender data","data":[{"host":"host1","key":"key1","value":"42"}],"clock":1790403191,"ns":583083000}"#;
    match parse_request(sent).unwrap() {
        Request::SenderData { items, clock } => {
            assert_eq!(clock, Some(1790403191));
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].host, "host1");
            assert_eq!(items[0].key, "key1");
            assert_eq!(items[0].value, "42");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        parse_request(br#"{"request":"active checks"}"#),
        Ok(Request::Other("active checks".into()))
    );
    assert_eq!(parse_request(b"[1,2]"), Err(RequestError::NotJson));
    assert_eq!(parse_request(b"{}"), Err(RequestError::NoRequest));
    assert_eq!(
        parse_request(br#"{"request":"sender data","data":[{"key":"k"}]}"#),
        Err(RequestError::BadData)
    );
    // serde_json's own recursion limit turns a nesting bomb into a parse error.
    let bomb = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(parse_request(bomb.as_bytes()), Err(RequestError::NotJson));
}

#[test]
fn a_failed_response_is_zabbix_shaped() {
    let packet = render_failed("unsupported request");
    let header = parse_header(&packet).unwrap();
    assert_eq!(header.flags, FLAG_PROTOCOL);
    let body: serde_json::Value = serde_json::from_slice(&packet[13..]).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"response": "failed", "info": "unsupported request"})
    );
    assert_eq!(read_result(&packet), None);
}
