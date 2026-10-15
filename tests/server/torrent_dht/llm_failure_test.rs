//! What a querying DHT node gets when the LLM backend fails.
//!
//! A KRPC query is a request/response exchange over UDP: the querying node holds the
//! transaction id open and retries, then gives up and marks the node as bad. Saying nothing
//! is therefore not "not me" the way an ARP or mDNS non-answer is — it is a stall, and it is
//! what this server used to do on every LLM error.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. The
//! `dht_ping_query` event then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage.
//!
//! Two things are asserted, and both matter:
//!
//! 1. The reply is a BEP 5 error message (`y = "e"`) echoing the query's transaction id, with
//!    code 201 ("Generic Error") — the non-transient category. An overloaded backend maps to
//!    202 instead so a querying node can back off rather than record a permanent fault.
//! 2. The human-readable half carries **nothing** from the error: no backend URL, no model
//!    name, no path, no `anyhow` chain. It is the fixed `WireFailure` category text.

use crate::helpers::*;
use serde_bencode::value::Value;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

/// The dual-logged line that proves the refusal came from the LLM-error path rather than
/// from the model answering with `send_dht_error_response`.
const FAIL_CLOSED_LOG: &str = "decision=fail_closed_llm_error";

/// Anything from netget's internals that must never reach a stranger's DHT node.
const FORBIDDEN_IN_WIRE_TEXT: &[&str] = &[
    "✗", "retries", "http://", "11434", "qwen", "/Users/", "LLM", "llama", "Ollama", "ollama",
    "model",
];

#[tokio::test]
async fn test_dht_answers_krpc_error_when_llm_fails() -> E2EResult<()> {
    let config = NetGetConfig::new_no_scripts(
        "Listen on port {AVAILABLE_PORT} via torrent-dht and answer DHT queries.".to_string(),
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("torrent-dht")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "Torrent-DHT",
                "instruction": "DHT node for peer discovery"
            }]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for dht_ping_query: the mock answers HTTP 500, which drives
        // the server down its LLM-failure path.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let dht_addr = format!("127.0.0.1:{}", server.port);

    let mut query = HashMap::new();
    query.insert(b"t".to_vec(), Value::Bytes(b"zz".to_vec()));
    query.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
    query.insert(b"q".to_vec(), Value::Bytes(b"ping".to_vec()));
    let mut args = HashMap::new();
    args.insert(
        b"id".to_vec(),
        Value::Bytes(b"abcdefghij0123456789".to_vec()),
    );
    query.insert(b"a".to_vec(), Value::Dict(args));

    let query_bytes = serde_bencode::to_bytes(&Value::Dict(query))?;
    socket.send_to(&query_bytes, &dht_addr).await?;

    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), socket.recv_from(&mut buf))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no KRPC reply: an LLM failure left the querying node waiting out its own \
                 timeout, which is the defect this test exists for",
            )
        })??;

    let dict = match serde_bencode::from_bytes::<Value>(&buf[..n])? {
        Value::Dict(d) => d,
        other => panic!("KRPC reply must be a dictionary, got {:?}", other),
    };

    let bytes_field = |key: &[u8]| -> Option<Vec<u8>> {
        match dict.get(key) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        }
    };

    assert_eq!(
        bytes_field(b"y").as_deref(),
        Some(b"e".as_ref()),
        "an LLM failure must produce a BEP 5 error message (y = \"e\"), never a fabricated \
         successful reply"
    );
    assert_eq!(
        bytes_field(b"t").as_deref(),
        Some(b"zz".as_ref()),
        "the error reply must echo the query's transaction id, or the querying node discards \
         it and stalls exactly as if we had said nothing"
    );

    let error_list = match dict.get(b"e" as &[u8]) {
        Some(Value::List(items)) => items.clone(),
        other => panic!("error reply must carry an `e` list, got {:?}", other),
    };
    assert_eq!(error_list.len(), 2, "`e` is [code, message]");

    match &error_list[0] {
        Value::Int(code) => assert_eq!(
            *code, 201,
            "a backend error that is not an overload is the non-transient category, BEP 5 code \
             201; 202 is reserved for the overloaded case so a client can back off"
        ),
        other => panic!("error code must be an integer, got {:?}", other),
    }

    let message = match &error_list[1] {
        Value::Bytes(b) => String::from_utf8_lossy(b).to_string(),
        other => panic!("error message must be a byte string, got {:?}", other),
    };
    assert!(
        !message.is_empty(),
        "the error message must say something about the category"
    );
    for token in FORBIDDEN_IN_WIRE_TEXT {
        assert!(
            !message.to_lowercase().contains(&token.to_lowercase()),
            "the KRPC error message leaked {:?} from netget's internals: {:?}. The peer gets a \
             category; the error goes to the log.",
            token,
            message
        );
    }

    // The refusal must be recorded, and distinguishably: a model that answers with
    // `send_dht_error_response` never writes this line, only a failed call does.
    server.wait_for_log(FAIL_CLOSED_LOG, 15).await?;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
