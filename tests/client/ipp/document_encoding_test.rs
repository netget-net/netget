//! `print_job` guessed whether its document was base64, and printing the word `Test` got you
//! three bytes of binary.
//!
//! The parameter was documented as "Document content (text or base64 for binary)" and the
//! executor resolved the ambiguity by sniffing: all ASCII alphanumeric (plus `+`, `/`, `=`) and
//! a length divisible by four meant base64, anything else meant text. Those two sets overlap,
//! and they overlap on completely ordinary documents — `Test`, `Note`, `Data`, `Memo`, any
//! four-, eight- or twelve-character alphanumeric string.
//!
//! This is the `send_tcp_data` defect the root CLAUDE.md names as the reference case, wearing
//! base64 instead of hex: *"`48656c6c6f` is simultaneously valid text and valid hex and only
//! the sender knows which it means"*. The fix is the same — an explicit `encoding` field,
//! defaulting to text, never sniffed.
//!
//! The old guess had a second half worth pinning: a genuine base64 error was swallowed by
//! `unwrap_or_else(|_| document_data.as_bytes().to_vec())`, so a truncated document was printed
//! as its own base64 *text* and the model was told the job succeeded.


use netget::client::ipp::IppClientProtocol;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;

/// The bytes `print_job` would put in the document, or the executor's refusal.
fn document_bytes(action: serde_json::Value) -> Result<Vec<u8>, String> {
    match IppClientProtocol::new().execute_action(action) {
        Ok(ClientActionResult::Custom { data, .. }) => Ok(data["document_data"]
            .as_array()
            .expect("document_data must be a byte array")
            .iter()
            .map(|v| u8::try_from(v.as_u64().expect("a byte")).expect("0-255"))
            .collect()),
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::test]
async fn a_four_character_document_is_printed_as_itself() {
    // The case that makes the sniff indefensible: `Test` is all-alphanumeric with a length
    // divisible by four, so the guess decoded it and put three bytes of binary on the wire.
    for text in ["Test", "Note", "Data", "Memo", "abcdefgh", "Hello World!"] {
        let bytes = document_bytes(json!({
            "type": "print_job",
            "job_name": "j",
            "document_data": text
        }))
        .unwrap_or_else(|e| panic!("plain text must print as text: {e}"));
        assert_eq!(
            bytes,
            text.as_bytes(),
            "{text:?} must reach the printer as itself, not as whatever base64 makes of it"
        );
    }
}

#[tokio::test]
async fn base64_is_decoded_only_when_declared() {
    // "SGVsbG8=" is "Hello" in base64. Which of the two the model meant is not recoverable
    // from the string, which is exactly why it has to say.
    let as_text = document_bytes(json!({
        "type": "print_job",
        "job_name": "j",
        "document_data": "SGVsbG8="
    }))
    .expect("no encoding means text");
    assert_eq!(
        as_text, b"SGVsbG8=",
        "without `encoding` the string is the document"
    );

    let as_binary = document_bytes(json!({
        "type": "print_job",
        "job_name": "j",
        "document_data": "SGVsbG8=",
        "encoding": "base64"
    }))
    .expect("declared base64 decodes");
    assert_eq!(as_binary, b"Hello");
}

#[tokio::test]
async fn invalid_base64_is_refused_rather_than_printed_as_its_own_text() {
    let err = document_bytes(json!({
        "type": "print_job",
        "job_name": "j",
        "document_data": "!!!not base64!!!",
        "encoding": "base64"
    }))
    .expect_err(
        "a document declared base64 that is not base64 must fail, not be printed verbatim \
         while the model is told the job went through",
    );
    assert!(
        err.contains("base64"),
        "the error must say what is wrong: {err}"
    );
}

#[tokio::test]
async fn an_unknown_encoding_is_refused() {
    let err = document_bytes(json!({
        "type": "print_job",
        "job_name": "j",
        "document_data": "x",
        "encoding": "rot13"
    }))
    .expect_err("an encoding the executor cannot honour must not silently become the default");
    assert!(err.contains("encoding"), "{err}");
}

#[tokio::test]
async fn binary_survives_a_round_trip() {
    // The actual point of the field: a PDF header has bytes no UTF-8 string can carry.
    use base64::{engine::general_purpose, Engine as _};
    let pdf: Vec<u8> = vec![
        0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x00, 0xff,
    ];
    let encoded = general_purpose::STANDARD.encode(&pdf);

    let bytes = document_bytes(json!({
        "type": "print_job",
        "job_name": "doc.pdf",
        "document_format": "application/pdf",
        "document_data": encoded,
        "encoding": "base64"
    }))
    .expect("a real PDF must survive");
    assert_eq!(bytes, pdf);
}
