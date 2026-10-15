//! A `{N}` literal whose count disagrees with what follows is refused, not relayed.
//!
//! `send_imap_response`'s `response` field relays a **pre-framed, model-authored** response
//! straight to the socket, and nothing checked its framing. RFC 3501 §4.3 makes a client read
//! *exactly* the declared number of octets, so a wrong count desynchronises the connection
//! **permanently**: the client swallows the start of the next line as message body, reads the
//! remainder as a response it cannot parse, and every tag after that is off by the difference.
//! There is no recovery, and no error the server can send afterwards that the client will
//! understand.
//!
//! It is also invisible to the assertions a test naturally writes. `tests/server/imap/test.rs`
//! carried `{50}` over a 46-octet body and passed for as long as it existed, because every
//! assertion there is `line.contains("FETCH")` on a **trimmed** string — and trimming discards
//! precisely the framing the RFC cares about. The pcap oracle found it by handing the raw bytes
//! to Wireshark's dissector. The fixture was corrected; this file is the other half, on our
//! side of the socket, so a model that miscounts is refused rather than obeyed.
//!
//! **Both directions are asserted.** A guard that refused every literal would satisfy the
//! mismatch cases alone, so the correct fixture — the real 46-octet FETCH the suite sends — is
//! asserted to still pass, byte for byte, along with the two-attribute form where the literal
//! is followed by a space rather than a paren.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features imap \
//!       --test server -- imap::literal_framing --test-threads=100


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::imap::actions::{validate_imap_literals, ImapProtocol};

/// The body the suite's FETCH fixture carries: 22+2 + 13+2 + 2 + 5 = 46 octets.
const BODY: &str = "From: test@example.com\r\nSubject: Test\r\n\r\nHello";

fn fetch_response(declared: usize) -> String {
    format!("* 1 FETCH (FLAGS (\\Seen) BODY[] {{{declared}}}\r\n{BODY})\r\nA004 OK FETCH completed")
}

/// Run `send_imap_response` through the protocol's own executor, as the event path does.
fn send_response(response: &str) -> Result<Vec<u8>, String> {
    match ImapProtocol::new().execute_action(serde_json::json!({
        "type": "send_imap_response",
        "response": response,
    })) {
        Ok(ActionResult::Output(bytes)) => Ok(bytes),
        Ok(other) => Err(format!("expected Output, got {other:?}")),
        Err(e) => Err(format!("{e:#}")),
    }
}

#[test]
fn the_body_is_the_length_the_fixture_claims() {
    assert_eq!(BODY.len(), 46, "the rest of this file is calibrated on 46");
}

/// The exact defect the pcap oracle found: `{50}` over 46 octets.
///
/// It is long enough to exist — 74 octets follow the marker — so a length check alone would
/// pass it. What gives it away is where octet 50 lands: inside `A004`, which is neither a
/// space, a `)`, nor the CR of a CRLF.
#[test]
fn an_overstated_literal_is_refused() {
    let error = send_response(&fetch_response(50))
        .expect_err("{50} over a 46-octet body must be refused, not relayed");
    assert!(
        error.contains("50"),
        "the refusal must name the declared count, got {error}"
    );
    assert!(
        error.contains("send_imap_response"),
        "the refusal must name the action the model sent, got {error}"
    );
}

/// The other direction. `{40}` lands inside the body itself, mid-`Hello`.
#[test]
fn an_understated_literal_is_refused() {
    send_response(&fetch_response(40))
        .expect_err("{40} over a 46-octet body must be refused, not relayed");
}

/// A literal longer than the response: the client would block on octets never sent.
#[test]
fn a_literal_longer_than_the_response_is_refused() {
    let error = send_response("* 1 FETCH (BODY[] {9000}\r\nshort)\r\nA004 OK FETCH completed")
        .expect_err("a literal claiming more octets than exist must be refused");
    assert!(
        error.contains("9000"),
        "the refusal must name the declared count, got {error}"
    );
}

/// A literal that consumes the response to its very last octet leaves its line unterminated.
///
/// The response here already ends in CRLF, so the executor adds nothing and the literal's two
/// octets *are* that CRLF: there is no rest-of-line and no terminator after it, and the client
/// would sit waiting for both. A response that merely stops after the payload is a different
/// case and is legal — the executor appends the missing CRLF, which the literal is then
/// followed by.
#[test]
fn a_literal_that_consumes_the_whole_response_is_refused() {
    send_response("* 1 FETCH (BODY[] {2}\r\n\r\n")
        .expect_err("a literal is an element of a line, not the line");
}

/// **The control.** The corrected fixture must still go out, byte for byte.
///
/// Without this the three refusals above are satisfied by a guard that refuses everything,
/// which would take IMAP's whole literal vocabulary with it.
#[test]
fn the_correct_literal_is_relayed_unchanged() {
    let sent = send_response(&fetch_response(46)).expect("a correct literal must be relayed");
    let expected = format!("{}\r\n", fetch_response(46));
    assert_eq!(
        String::from_utf8_lossy(&sent),
        expected,
        "the response must reach the wire exactly as framed, plus the terminating CRLF"
    );
}

/// A literal followed by a space, because another attribute comes after it.
///
/// This is the shape `send_imap_fetch` produces when `BODY[]` is not the last item, so a guard
/// that only accepted `)` would refuse this server's own output.
#[test]
fn a_literal_followed_by_another_attribute_is_relayed() {
    send_response(&format!(
        "* 1 FETCH (BODY[] {{{}}}\r\n{BODY} UID 7)\r\nA004 OK FETCH completed",
        BODY.len()
    ))
    .expect("a literal followed by a space and another attribute is legal");
}

/// Braces that are not a literal marker are ordinary text and must be left alone.
///
/// `{46}` is only a literal when CRLF immediately follows it. A guard that treated every
/// brace-wrapped number as a count would refuse perfectly good responses.
#[test]
fn braces_that_are_not_a_literal_marker_are_left_alone() {
    send_response("A001 OK fetched {46} bytes").expect("braces in free text are not a literal");
    send_response("A001 OK done {} {abc} {").expect("malformed braces are not literals either");
}

/// A `{N}CRLF` sequence *inside* a literal's payload is data, not a second marker.
///
/// The walk has to skip over each literal's octets for this to hold; a scanner that restarted
/// after the marker would read the inner one and refuse a correct response.
#[test]
fn a_literal_marker_inside_a_body_is_not_read_as_a_marker() {
    let inner = "line one\r\n{999}\r\nline two";
    send_response(&format!(
        "* 1 FETCH (BODY[] {{{}}}\r\n{inner})\r\nA004 OK FETCH completed",
        inner.len()
    ))
    .expect("a brace sequence inside the payload is message data");
}

/// The validator directly, on the two cases that decide everything above.
#[test]
fn the_validator_agrees_with_the_executor() {
    assert!(validate_imap_literals(fetch_response(46).as_bytes()).is_ok());
    assert!(validate_imap_literals(fetch_response(50).as_bytes()).is_err());
}
