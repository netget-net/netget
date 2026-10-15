//! What the NFC client can be tested on with no reader attached.
//!
//! This file used to hold one `#[ignore]`d `fn test_nfc_client_basic()` whose body was a TODO
//! comment. It asserted nothing, needed hardware it could never have, and counted as coverage
//! in exactly the way the root `CLAUDE.md` warns about — an `#[ignore]`d test is not evidence.
//!
//! Everything that touches a card genuinely does need hardware: `SCardConnect` requires a card
//! in the reader's field, and a contactless card cannot be emulated through PC/SC. That half
//! lives in `command_channel_test.rs`, correctly ignored and correctly described.
//!
//! But the two things most likely to be wrong need no hardware at all, because both are pure
//! functions over bytes: the **NDEF codec** and the **APDU builder**. Those are what this file
//! pins, against literal bytes from the specifications rather than against our own output.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nfc-client --test client -- nfc --test-threads=100

#![cfg(all(unix, feature = "pcsc"))]

use netget::client::nfc::ndef::{decode_message, encode_message};
use netget::client::nfc::NfcClientProtocol;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;

/// The hex an action puts on the wire, or the error it refused with.
fn apdu_of(action: serde_json::Value) -> Result<String, String> {
    match NfcClientProtocol.execute_action(action) {
        Ok(ClientActionResult::Custom { name, data }) if name == "send_apdu" => Ok(data
            ["apdu_hex"]
            .as_str()
            .expect("send_apdu must carry apdu_hex")
            .to_string()),
        Ok(other) => Err(format!("expected a send_apdu custom result, got {other:?}")),
        Err(e) => Err(e.to_string()),
    }
}

/// The NDEF bytes a `write_ndef` action encodes to, or the error it refused with.
fn ndef_of(action: serde_json::Value) -> Result<String, String> {
    match NfcClientProtocol.execute_action(action) {
        Ok(ClientActionResult::Custom { name, data }) if name == "write_ndef" => Ok(data
            ["message_hex"]
            .as_str()
            .expect("write_ndef must carry the encoded message")
            .to_string()),
        Ok(other) => Err(format!(
            "expected a write_ndef custom result, got {other:?}"
        )),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// NDEF encoding, against the NFC Forum specifications
// ---------------------------------------------------------------------------

/// NFC Forum RTD Text 1.0: payload is a status byte, the language code, then UTF-8 text.
///
/// `D1` = MB|ME|SR|TNF=1 (well known), `01` type length, `0D` payload length,
/// `54` = 'T', `02` status byte (UTF-8, two-byte language), `656E` = "en", then the text.
#[test]
fn a_text_record_is_encoded_byte_for_byte_as_rtd_text_specifies() {
    let bytes = encode_message(&[json!({"type": "text", "language": "en", "text": "Hello NFC!"})])
        .expect("a plain text record must encode");
    assert_eq!(
        hex::encode_upper(&bytes),
        // D1 01 0D 54 | 02 'e' 'n' | "Hello NFC!"
        "D1010D5402656E48656C6C6F204E464321",
        "text record must match RTD Text 1.0"
    );
}

/// NFC Forum RTD URI 1.0: payload is a one-byte prefix identifier, then the rest.
///
/// `04` is "https://", so only "example.com" is carried literally — the abbreviation is the
/// whole point of the prefix table.
#[test]
fn a_uri_record_abbreviates_through_the_prefix_table() {
    let bytes = encode_message(&[json!({"type": "uri", "uri": "https://example.com"})])
        .expect("a uri record must encode");
    assert_eq!(
        hex::encode_upper(&bytes),
        format!("D1010C5504{}", hex::encode_upper(b"example.com")),
        "uri record must match RTD URI 1.0 with prefix code 04"
    );
}

/// Codes 2 ("https://www.") and 4 ("https://") both match `https://www.example.com`. The
/// longest must win, or the record carries a literal "www." it did not need to.
#[test]
fn the_longest_matching_uri_prefix_wins() {
    let bytes = encode_message(&[json!({"type": "uri", "uri": "https://www.example.com"})])
        .expect("a www uri must encode");
    assert_eq!(
        hex::encode_upper(&bytes),
        format!("D1010C5502{}", hex::encode_upper(b"example.com")),
        "https://www. is prefix code 02, not 04 followed by a literal www."
    );
}

/// Message Begin and Message End are per-*record* flags, and with two records they land on
/// different ones: `91` (MB|SR|TNF1) then `51` (ME|SR|TNF1).
#[test]
fn message_begin_and_message_end_sit_on_the_first_and_last_records() {
    let bytes = encode_message(&[
        json!({"type": "text", "language": "en", "text": "a"}),
        json!({"type": "uri", "uri": "https://example.com"}),
    ])
    .expect("two records must encode");
    assert_eq!(bytes[0], 0x91, "first record: MB set, ME clear, SR set");

    // The second record's header is at the offset the first one ends at:
    // header + type length + payload length + type + payload.
    let first_end = 1 + 1 + 1 + bytes[1] as usize + bytes[2] as usize;
    assert_eq!(
        bytes[first_end], 0x51,
        "second record: ME set, MB clear, SR set"
    );

    let records = decode_message(&bytes).expect("decode");
    assert_eq!(records[0]["message_end"], false);
    assert_eq!(records[1]["message_end"], true);
}

/// A payload over 255 bytes has to use the four-byte length form, which means clearing SR.
#[test]
fn a_long_payload_switches_to_the_four_byte_length_form() {
    let long = "x".repeat(400);
    let bytes = encode_message(&[json!({"type": "text", "language": "en", "text": long})])
        .expect("a 400-byte text record must encode");
    assert_eq!(bytes[0], 0xC1, "MB|ME|TNF=1 with SR clear");
    assert_eq!(bytes[1], 0x01, "type length");
    assert_eq!(
        u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        403,
        "four-byte payload length: status byte + 'en' + 400 characters"
    );
    assert_eq!(bytes[6], 0x54, "type field 'T' follows the length");
}

// ---------------------------------------------------------------------------
// NDEF encoding refuses what it must
// ---------------------------------------------------------------------------

/// An NDEF URI record is what a phone offers to open, so a URI that is not the printable
/// US-ASCII RFC 3986 allows must not be written at all. CR/LF is the classic one.
#[test]
fn a_uri_carrying_a_control_character_is_refused() {
    let err = encode_message(&[json!({"type": "uri", "uri": "https://example.com\r\nX"})])
        .expect_err("a URI with CRLF must be refused");
    assert!(
        err.to_string().contains("RFC 3986"),
        "the refusal must say why, got: {err}"
    );
}

/// U+202E RIGHT-TO-LEFT OVERRIDE renders `gpj.exe` as `exe.jpg`. It is valid UTF-8 and would
/// have gone onto the tag silently.
#[test]
fn text_carrying_a_bidirectional_override_is_refused() {
    let err = encode_message(&[json!({
        "type": "text", "language": "en", "text": "invoice\u{202E}gpj.exe"
    })])
    .expect_err("a bidi override must be refused");
    assert!(
        err.to_string().contains("202E"),
        "the refusal must name the character, got: {err}"
    );
}

/// The Text status byte carries the language length in six bits, so 64 characters cannot be
/// expressed. Caught before the cast; wrapping it would have produced a record whose declared
/// language length did not match its own payload.
#[test]
fn a_language_code_too_long_for_the_status_byte_is_refused() {
    let err = encode_message(&[json!({
        "type": "text", "language": "e".repeat(64), "text": "x"
    })])
    .expect_err("a 64-byte language code must be refused");
    assert!(
        err.to_string().contains("six bits"),
        "the refusal must explain the limit, got: {err}"
    );
}

/// `payload_text` and `payload_hex` are mutually exclusive for the same reason
/// `respond_to_apdu`'s two body spellings are: "48656C6C6F" is both.
#[test]
fn a_record_supplying_both_payload_spellings_is_refused() {
    let err = encode_message(&[json!({
        "type": "mime", "mime_type": "text/plain",
        "payload_text": "Hello", "payload_hex": "48656C6C6F"
    })])
    .expect_err("both spellings at once must be refused");
    assert!(err.to_string().contains("not both"), "got: {err}");
}

// ---------------------------------------------------------------------------
// NDEF decoding
// ---------------------------------------------------------------------------

#[test]
fn a_message_survives_encode_then_decode() {
    let bytes = encode_message(&[
        json!({"type": "text", "language": "en-GB", "text": "Hello NFC!"}),
        json!({"type": "uri", "uri": "https://example.com/a?b=c"}),
    ])
    .expect("encode");
    let records = decode_message(&bytes).expect("decode");

    assert_eq!(records.len(), 2, "two records in, two out: {records:?}");
    assert_eq!(records[0]["type"], "text");
    assert_eq!(records[0]["language"], "en-GB");
    assert_eq!(records[0]["text"], "Hello NFC!");
    assert_eq!(records[0]["text_encoding"], "utf-8");
    assert_eq!(records[0]["message_end"], false);
    assert_eq!(records[1]["type"], "uri");
    assert_eq!(records[1]["uri"], "https://example.com/a?b=c");
    assert_eq!(records[1]["message_end"], true);
}

/// The stack-overflow guard, and it is structural: NDEF nests (a Smart Poster's payload is
/// itself an NDEF message) and a recursive decoder without a counter dies on a SIGSEGV that
/// `catch_unwind` cannot see. The decoder never descends, so a nested message comes back as
/// hex and 5000 levels of nesting is just a long payload.
#[test]
fn decoding_never_descends_into_a_nested_message() {
    // Wrap a leaf record in message-inside-a-message until the wrapping is thousands deep.
    let mut payload = encode_message(&[json!({"type": "text", "language": "en", "text": "leaf"})])
        .expect("leaf encodes");
    let mut depth = 0;
    while payload.len() < 40_000 {
        payload = encode_message(&[json!({
            "type": "mime",
            "mime_type": "application/vnd.nfc.msg",
            "payload_hex": hex::encode_upper(&payload),
        })])
        .expect("each wrapper encodes");
        depth += 1;
    }
    assert!(
        depth > 8,
        "the nesting must be deep enough to matter: {depth}"
    );

    let records = decode_message(&payload).expect("a deeply nested message must still decode");
    assert_eq!(records.len(), 1, "only the outermost record is decoded");
    assert_eq!(records[0]["type"], "mime");
    assert!(
        records[0]["payload_hex"].is_string(),
        "the nested message must come back as hex, not as decoded records"
    );
    assert!(
        records[0].get("records").is_none(),
        "the decoder must not have descended into the payload"
    );
}

/// A tag is allowed to lie about its own lengths. That must be a reported record, never an
/// index panic inside the client's task.
#[test]
fn a_record_claiming_more_bytes_than_it_has_is_reported_not_panicked() {
    // D1 01 FF 54 ... : a short record announcing a 255-byte payload with two bytes present.
    let records = decode_message(&[0xD1, 0x01, 0xFF, 0x54, 0x02, 0x65])
        .expect("a malformed message must still return");
    assert_eq!(records.last().expect("a record")["type"], "undecodable");
}

/// Decoding cannot refuse — the model has to be told what the tag actually held — so a
/// hostile URI comes back scrubbed and flagged, with the raw bytes still attached.
#[test]
fn a_hostile_uri_from_a_tag_is_scrubbed_and_flagged() {
    // A URI record, prefix 04 ("https://"), whose text carries U+202E.
    let mut payload = vec![0x04];
    payload.extend_from_slice("example.com/\u{202E}gpj.exe".as_bytes());
    let mut bytes = vec![0xD1, 0x01, payload.len() as u8, 0x55];
    bytes.extend_from_slice(&payload);

    let records = decode_message(&bytes).expect("decode");
    assert_eq!(records[0]["type"], "uri");
    assert_eq!(
        records[0]["unsafe_characters_removed"], true,
        "the model must be told the tag carried an override character"
    );
    assert!(
        !records[0]["uri"].as_str().unwrap().contains('\u{202E}'),
        "the override must not survive into the field the model reads"
    );
    assert!(
        records[0]["payload_hex"]
            .as_str()
            .unwrap()
            .contains("E280AE"),
        "the raw bytes stay available: {:?}",
        records[0]["payload_hex"]
    );
}

// ---------------------------------------------------------------------------
// The APDU builder
// ---------------------------------------------------------------------------

/// SELECT the NDEF application, the first command of every Type 4 exchange.
#[test]
fn send_apdu_builds_the_select_ndef_application_command() {
    assert_eq!(
        apdu_of(json!({
            "type": "send_apdu", "cla": "00", "ins": "A4", "p1": "04", "p2": "00",
            "data": "D2760000850101", "le": "00"
        }))
        .expect("the declared example must build"),
        "00A4040007D276000085010100",
        "CLA INS P1 P2 Lc DATA Le, with Lc derived from the decoded data"
    );
}

/// A case-1 APDU is the bare header, with no Lc and no Le.
#[test]
fn send_apdu_omits_lc_and_le_when_neither_was_given() {
    assert_eq!(
        apdu_of(json!({"type": "send_apdu", "cla": "00", "ins": "84", "p1": "00", "p2": "00"}))
            .expect("a case-1 APDU must build"),
        "00840000"
    );
}

/// `data.len() / 2` floored an odd hex string, so `"A4F"` became one byte of Lc over two
/// characters of data — a command shifted by half a byte that the card would still try to
/// execute. It is an error now.
#[test]
fn an_odd_length_data_field_is_refused() {
    let err = apdu_of(json!({
        "type": "send_apdu", "cla": "00", "ins": "A4", "p1": "04", "p2": "00", "data": "A4F"
    }))
    .expect_err("odd-length hex must be refused");
    assert!(err.contains("even number of hex digits"), "got: {err}");
}

/// The header fields were interpolated as strings, so a single-digit `p1` displaced every
/// byte after it and produced a *different valid command*, not a malformed one.
#[test]
fn a_header_field_that_is_not_exactly_one_byte_is_refused() {
    let err = apdu_of(json!({
        "type": "send_apdu", "cla": "00", "ins": "A4", "p1": "4", "p2": "00"
    }))
    .expect_err("a one-digit p1 must be refused");
    assert!(err.contains("'p1'"), "the error must name the field: {err}");

    let err = apdu_of(json!({
        "type": "send_apdu", "cla": "0000", "ins": "A4", "p1": "04", "p2": "00"
    }))
    .expect_err("a two-byte cla must be refused");
    assert!(err.contains("exactly one byte"), "got: {err}");
}

/// `format!("{:02X}", 256)` prints "100" — three digits into a two-digit field, shifting the
/// whole data field by four bits. `{:02X}` pads, it does not truncate.
#[test]
fn more_data_than_a_short_form_lc_can_describe_is_refused() {
    let err = apdu_of(json!({
        "type": "send_apdu", "cla": "00", "ins": "D6", "p1": "00", "p2": "00",
        "data": "AB".repeat(256)
    }))
    .expect_err("256 data bytes must be refused by the short form");
    assert!(
        err.contains("send_apdu_raw"),
        "the error must offer the way out: {err}"
    );
}

/// A raw APDU shorter than its own header cannot be a command; catching it here rather than
/// at the card means a static handler fails where it is written.
#[test]
fn a_raw_apdu_shorter_than_its_header_is_refused() {
    let err = apdu_of(json!({"type": "send_apdu_raw", "apdu_hex": "00A404"}))
        .expect_err("three bytes cannot be an APDU");
    assert!(err.contains("header"), "got: {err}");

    let err = apdu_of(json!({"type": "send_apdu_raw", "apdu_hex": "00A4zz"}))
        .expect_err("non-hex must be refused");
    assert!(err.contains("hexadecimal"), "got: {err}");
}

// ---------------------------------------------------------------------------
// The NDEF verbs the actions layer exposes
// ---------------------------------------------------------------------------

/// `write_ndef` declared `records` while the client looked for `message_hex` / `message`,
/// which nothing declared and nothing produced — so the verb was advertised, accepted, and
/// could never write a byte. `execute_action` now encodes the records it was given.
#[test]
fn write_ndef_hands_the_client_encoded_ndef_bytes() {
    let encoded = ndef_of(json!({
        "type": "write_ndef",
        "records": [{"type": "text", "language": "en", "text": "Hello NFC!"}]
    }))
    .expect("the declared example must encode");
    assert_eq!(
        encoded,
        format!(
            "D1010D540265{}{}",
            hex::encode_upper(b"n"),
            hex::encode_upper(b"Hello NFC!")
        ),
        "write_ndef must carry real NDEF bytes, not just the records back"
    );
}

/// A record the encoder refuses must fail where the action is written, not halfway through
/// writing the tag: `write_ndef` zeroes NLEN before the body goes out.
#[test]
fn write_ndef_refuses_a_record_it_cannot_encode() {
    let err = ndef_of(json!({
        "type": "write_ndef",
        "records": [{"type": "smart_poster", "title": "x"}]
    }))
    .expect_err("an unsupported record type must be refused");
    assert!(
        err.contains("smart_poster"),
        "the error must name it: {err}"
    );
}

/// `file_id` is declared on both NDEF verbs and used to be dropped by `execute_action`, so a
/// tag whose NDEF file is not E104 could not be reached however the model asked.
#[test]
fn the_ndef_file_id_reaches_the_client() {
    let result = NfcClientProtocol
        .execute_action(json!({"type": "read_ndef", "file_id": "e105"}))
        .expect("read_ndef with a file_id must execute");
    match result {
        ClientActionResult::Custom { data, .. } => {
            assert_eq!(
                data["file_id"], "E105",
                "the file id must be passed through"
            )
        }
        other => panic!("expected a custom result, got {other:?}"),
    }

    let result = NfcClientProtocol
        .execute_action(json!({"type": "read_ndef"}))
        .expect("read_ndef without a file_id must execute");
    match result {
        ClientActionResult::Custom { data, .. } => {
            assert_eq!(
                data["file_id"], "E104",
                "the default is the usual NDEF file"
            )
        }
        other => panic!("expected a custom result, got {other:?}"),
    }

    assert!(
        NfcClientProtocol
            .execute_action(json!({"type": "read_ndef", "file_id": "E1"}))
            .is_err(),
        "a one-byte file id must be refused rather than padded"
    );
}
