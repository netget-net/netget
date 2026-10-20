//! The TCP client's `send_tcp_data` reads `data` the way its `encoding` says, like the server's.
//!
//! `"48656c6c6f"` is valid text and valid hex, so the executor never guesses: without
//! `encoding` the characters go out as they are, with `encoding: "hex"` they are decoded. The
//! `tcp_connected` example is what a model copies on its first turn, so it has to mean what
//! it looks like it means when run through that rule.

use netget::client::tcp::actions::TCP_CLIENT_CONNECTED_EVENT;
use netget::client::tcp::TcpClientProtocol;
use netget::llm::actions::client_trait::{Client, ClientActionResult};
use serde_json::json;

fn sent(action: serde_json::Value) -> Vec<u8> {
    match TcpClientProtocol::new().execute_action(action.clone()) {
        Ok(ClientActionResult::SendData(bytes)) => bytes,
        Ok(other) => panic!("{action} did not send data: {other:?}"),
        Err(e) => panic!("{action} was refused: {e}"),
    }
}

#[test]
fn text_is_sent_as_text_and_hex_only_when_asked() {
    assert_eq!(
        sent(json!({"type": "send_tcp_data", "data": "48656c6c6f"})),
        b"48656c6c6f"
    );
    assert_eq!(
        sent(json!({"type": "send_tcp_data", "data": "48656c6c6f", "encoding": "hex"})),
        b"Hello"
    );
    assert_eq!(
        sent(json!({"type": "send_tcp_data", "data": "48 65 6c 6c 6f", "encoding": "hex"})),
        b"Hello"
    );
    assert_eq!(
        sent(json!({"type": "send_tcp_data", "data": "GET /\r\n", "encoding": "utf8"})),
        b"GET /\r\n"
    );
    // Accepted for handlers written against it, though no longer shown to the model.
    assert_eq!(
        sent(json!({"type": "send_tcp_data", "data_hex": "776f726c64"})),
        b"world"
    );
}

#[test]
fn a_bad_encoding_or_bad_hex_is_refused_rather_than_sent() {
    let client = TcpClientProtocol::new();
    for action in [
        json!({"type": "send_tcp_data", "data": "zz", "encoding": "hex"}),
        json!({"type": "send_tcp_data", "data": "abc", "encoding": "base64"}),
        json!({"type": "send_tcp_data"}),
    ] {
        assert!(
            client.execute_action(action.clone()).is_err(),
            "{action} should be refused"
        );
    }
}

#[test]
fn the_connected_example_sends_the_text_it_shows() {
    let example = TCP_CLIENT_CONNECTED_EVENT.response_example.clone();
    let shown = example["data"].as_str().expect("the example carries data");
    assert_eq!(sent(example.clone()), shown.as_bytes(), "{example}");
}
