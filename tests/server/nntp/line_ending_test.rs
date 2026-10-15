//! What `send_nntp_message` puts at the end of a line.
//!
//! NNTP lines end in CRLF (RFC 3977 §3.1). The action adds the terminator when the model leaves
//! it off, and used to turn a message ending in a bare `\n` into `...\n\r`, which ends no line at
//! all: a client reading for CRLF keeps waiting, and the stray `\r` lands at the start of the
//! next line. Found while adding the NNTP suite to the real-model eval.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nntp --test server -- nntp::line_ending --test-threads=100

use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::nntp::actions::NntpProtocol;
use serde_json::json;

fn wire(message: &str) -> Vec<u8> {
    match NntpProtocol::new()
        .execute_action(json!({"type": "send_nntp_message", "message": message}))
        .expect("send_nntp_message executes")
    {
        ActionResult::Output(bytes) => bytes,
        other => panic!("send_nntp_message must write bytes, got {other:?}"),
    }
}

#[test]
fn a_bare_trailing_newline_becomes_crlf() {
    assert_eq!(wire("200 NetGet ready\n"), b"200 NetGet ready\r\n");
}

#[test]
fn a_message_without_a_terminator_gets_crlf() {
    assert_eq!(wire("200 NetGet ready"), b"200 NetGet ready\r\n");
}

#[test]
fn a_message_already_ending_in_crlf_is_unchanged() {
    assert_eq!(wire("200 NetGet ready\r\n"), b"200 NetGet ready\r\n");
}
