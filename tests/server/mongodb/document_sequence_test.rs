//! OP_MSG kind-1 sections — document sequences — reach the model.
//!
//! A driver sends the arrays that can be large as kind-1 sections after the kind-0 body:
//! `insert`'s `documents`, `update`'s `updates`, `delete`'s `deletes`. `parse_op_msg` used to
//! decode the kind-0 body and stop, so every such array was dropped without a word: an
//! `insert_many` reached the model as an insert of nothing, and the model acknowledged it.
//! `parse_op_msg_sections` now merges each sequence into the body as the field it names.
//!
//! Two halves:
//!
//! * **The official driver** does an `insert_many`, an `update_one` and a `delete_one`, and a
//!   mock rule accepts each only if the event carries what the driver sent — otherwise it
//!   answers `error_response`, which the driver raises. Three LLM calls plus startup.
//! * **Raw OP_MSG**, built here from the wire-protocol spec rather than by a driver, so the
//!   kind-1 encoding is certain rather than a driver's choice: a sequence reaches the event (a
//!   `script` rule echoes it back as a cursor, so the reply is the proof), a sequence whose
//!   field the body also carries is refused, a sequence member nested past the depth guard gets
//!   MongoDB's own `Overflow` error, and a message with an unknown *required* flag bit is
//!   refused. Zero LLM calls.


use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// The official driver
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn driver_write_batches_reach_the_model_in_full() -> crate::helpers::E2EResult<()> {
    use crate::helpers::{start_netget_server, NetGetConfig};

    let config =
        NetGetConfig::new("Listen on port {AVAILABLE_PORT} via MongoDB").with_mock(|mock| {
            mock.on_instruction_containing("MongoDB")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "MongoDB server for testing"
                }]))
                .expect_calls(1)
                .and()
                // One rule, branching on the command: accept only what the driver really sent.
                .on_event("mongodb_command")
                .respond_with_actions_from_event(|event| {
                    let refuse = |why: &str| {
                        serde_json::json!([{
                            "type": "error_response",
                            "code": 2,
                            "message": format!("test: {why}; event was {event}")
                        }])
                    };
                    match event["command"].as_str().unwrap_or("") {
                        "insert" => {
                            let names: Vec<&str> = event["document"]
                                .as_array()
                                .map(|docs| docs.iter().filter_map(|d| d["name"].as_str()).collect())
                                .unwrap_or_default();
                            if names == ["Ada", "Grace", "Barbara"] {
                                serde_json::json!([{"type": "insert_response", "inserted_count": 3}])
                            } else {
                                refuse("insert documents did not reach the event")
                            }
                        }
                        "update" => {
                            let first = &event["updates"][0];
                            if first["q"]["name"] == "Ada" && first["u"]["$set"]["age"] == 37 {
                                serde_json::json!([{
                                    "type": "update_response",
                                    "matched_count": 1,
                                    "modified_count": 1
                                }])
                            } else {
                                refuse("update statements did not reach the event")
                            }
                        }
                        "delete" => {
                            if event["deletes"][0]["q"]["name"] == "Grace" {
                                serde_json::json!([{"type": "delete_response", "deleted_count": 1}])
                            } else {
                                refuse("delete statements did not reach the event")
                            }
                        }
                        other => refuse(&format!("unexpected command {other}")),
                    }
                })
                .expect_calls(3)
                .and()
        });

    let server = start_netget_server(config).await?;
    let client =
        mongodb::Client::with_uri_str(format!("mongodb://127.0.0.1:{}", server.port)).await?;
    let users = client
        .database("testdb")
        .collection::<mongodb::bson::Document>("users");

    let inserted = users
        .insert_many(vec![
            mongodb::bson::doc! { "name": "Ada", "age": 36 },
            mongodb::bson::doc! { "name": "Grace", "age": 85 },
            mongodb::bson::doc! { "name": "Barbara", "age": 72 },
        ])
        .await
        .map_err(|e| {
            format!("insert_many was refused — its documents did not reach the model: {e}")
        })?;
    assert_eq!(inserted.inserted_ids.len(), 3);

    let updated = users
        .update_one(
            mongodb::bson::doc! { "name": "Ada" },
            mongodb::bson::doc! { "$set": { "age": 37 } },
        )
        .await
        .map_err(|e| {
            format!("update_one was refused — its statement did not reach the model: {e}")
        })?;
    assert_eq!(updated.modified_count, 1);

    let deleted = users
        .delete_one(mongodb::bson::doc! { "name": "Grace" })
        .await
        .map_err(|e| {
            format!("delete_one was refused — its statement did not reach the model: {e}")
        })?;
    assert_eq!(deleted.deleted_count, 1);

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Raw OP_MSG
// ---------------------------------------------------------------------------------------------

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..100 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("MongoDB server #{} never bound a port", id.as_u32());
}

/// A server whose only rule is a script that answers every command with a cursor holding the
/// event's `document` field — so what reached the event comes back on the wire.
async fn start_echo_server(state: &AppState) -> u16 {
    let script = r#"import json, sys
data = json.load(sys.stdin)
docs = data["event"].get("document") or []
if not isinstance(docs, list):
    docs = [docs]
print(json.dumps({"actions": [{"type": "find_response", "documents": docs}]}))"#;
    let (tx, _rx) = mpsc::unbounded_channel();
    let server_id = ServerForm {
        protocol: "mongodb".to_string(),
        port: Some(0),
        instruction: Some(String::new()),
        event_handlers: Some(vec![serde_json::json!({
            "event_pattern": "mongodb_command",
            "handler": { "type": "script", "language": "python", "code": script }
        })]),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("create mongodb server");
    wait_for_port(state, server_id).await
}

fn document(elements: &[u8]) -> Vec<u8> {
    let len = (4 + elements.len() + 1) as i32;
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(elements);
    out.push(0);
    out
}

fn element(kind: u8, key: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(value);
    out
}

fn bson_string(s: &str) -> Vec<u8> {
    let mut out = ((s.len() + 1) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out
}

fn named(name: &str) -> Vec<u8> {
    document(&element(0x02, "name", &bson_string(name)))
}

/// `{a: {a: … {} …}}` with `levels` documents in all.
fn nested(levels: usize) -> Vec<u8> {
    let mut doc = document(&[]);
    for _ in 1..levels {
        doc = document(&element(0x03, "a", &doc));
    }
    doc
}

/// `{insert: "c", $db: "test"}`, optionally with an inline `documents` array too.
fn insert_body(inline_documents: bool) -> Vec<u8> {
    let mut elements = element(0x02, "insert", &bson_string("c"));
    if inline_documents {
        elements.extend(element(
            0x04,
            "documents",
            &document(&element(0x03, "0", &named("x"))),
        ));
    }
    elements.extend(element(0x02, "$db", &bson_string("test")));
    document(&elements)
}

/// A kind-1 section: kind byte, `int32 size` (counting itself), C-string identifier, documents.
fn sequence(identifier: &str, documents: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = documents.concat();
    let size = (4 + identifier.len() + 1 + payload.len()) as i32;
    let mut out = vec![1u8];
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(identifier.as_bytes());
    out.push(0);
    out.extend_from_slice(&payload);
    out
}

/// An OP_MSG: header, `flagBits`, a kind-0 section with `body`, then `extra` sections verbatim.
fn op_msg(request_id: i32, flags: u32, body: &[u8], extra: &[u8]) -> Vec<u8> {
    let len = (16 + 4 + 1 + body.len() + extra.len()) as i32;
    let mut msg = len.to_le_bytes().to_vec();
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2013i32.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(body);
    msg.extend_from_slice(extra);
    msg
}

async fn read_reply(stream: &mut TcpStream) -> (i32, bson::Document) {
    let mut header = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut header))
        .await
        .expect("a reply within 20s")
        .expect("read reply header");
    let len = i32::from_le_bytes(header[0..4].try_into().unwrap());
    let response_to = i32::from_le_bytes(header[8..12].try_into().unwrap());
    let mut body = vec![0u8; (len - 16) as usize];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("reply body within 10s")
        .expect("read reply body");
    let doc = bson::Document::from_reader(&body[5..]).expect("reply is a BSON document");
    (response_to, doc)
}

async fn expect_closed(stream: &mut TcpStream, what: &str) {
    let mut sink = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut sink))
        .await
        .unwrap_or_else(|_| panic!("{what}: the connection was neither answered nor closed"));
    // A reset is as closed as an EOF.
    if read.is_ok() {
        assert!(
            sink.is_empty(),
            "{what}: expected a close, got {} bytes",
            sink.len()
        );
    }
}

#[tokio::test]
async fn a_document_sequence_is_merged_into_the_command_the_model_sees() {
    let state = new_state().await;
    let port = start_echo_server(&state).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    let seq = sequence("documents", &[named("Ada"), named("Grace")]);
    stream
        .write_all(&op_msg(7, 0, &insert_body(false), &seq))
        .await
        .expect("write");
    let (response_to, reply) = read_reply(&mut stream).await;
    assert_eq!(response_to, 7);
    let batch = reply
        .get_document("cursor")
        .and_then(|c| c.get_array("firstBatch"))
        .unwrap_or_else(|e| panic!("expected the echo cursor, got {reply:?} ({e})"));
    let names: Vec<&str> = batch
        .iter()
        .filter_map(|d| d.as_document()?.get_str("name").ok())
        .collect();
    assert_eq!(
        names,
        ["Ada", "Grace"],
        "both documents of the kind-1 sequence must reach the event, in order"
    );

    // The checksum bit is understood: the trailing four octets are stripped, not parsed as a
    // section. The same sequence comes back.
    let mut with_checksum = op_msg(8, 1, &insert_body(false), &seq);
    with_checksum.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let new_len = (with_checksum.len() as i32).to_le_bytes();
    with_checksum[..4].copy_from_slice(&new_len);
    stream.write_all(&with_checksum).await.expect("write");
    let (response_to, reply) = read_reply(&mut stream).await;
    assert_eq!(response_to, 8);
    assert_eq!(
        reply
            .get_document("cursor")
            .and_then(|c| c.get_array("firstBatch"))
            .map(|b| b.len())
            .ok(),
        Some(2),
        "with checksumPresent set, the sequence must still be read; got {reply:?}"
    );
}

#[tokio::test]
async fn a_sequence_that_duplicates_a_body_field_is_refused() {
    let state = new_state().await;
    let port = start_echo_server(&state).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // The wire protocol forbids a field arriving both ways; which one would the model be
    // shown? Neither — the message is malformed and the connection is closed.
    let seq = sequence("documents", &[named("Ada")]);
    stream
        .write_all(&op_msg(9, 0, &insert_body(true), &seq))
        .await
        .expect("write");
    expect_closed(&mut stream, "a field supplied inline and as a sequence").await;
}

#[tokio::test]
async fn a_sequence_member_past_the_depth_guard_gets_mongodbs_overflow_error() {
    let state = new_state().await;
    let port = start_echo_server(&state).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // 10 000 levels: without the scan, `bson` recurses once per level and the process dies.
    let seq = sequence("documents", &[named("ok"), nested(10_000)]);
    stream
        .write_all(&op_msg(10, 0, &insert_body(false), &seq))
        .await
        .expect("write");
    let (response_to, reply) = read_reply(&mut stream).await;
    assert_eq!(response_to, 10);
    assert_eq!(reply.get_i32("ok").ok(), Some(0), "got {reply:?}");
    assert_eq!(
        reply.get_i32("code").ok(),
        Some(15),
        "expected Overflow, got {reply:?}"
    );

    // Merging puts a member two levels down (command → array → member), so a member is held to
    // MAX_BSON_DEPTH - 2 and the merged command stays within MAX_BSON_DEPTH.
    let limit = netget::utils::bson_depth::MAX_BSON_DEPTH;
    for (levels, refused) in [(limit - 2, false), (limit - 1, true)] {
        let seq = sequence("documents", &[nested(levels)]);
        stream
            .write_all(&op_msg(11, 0, &insert_body(false), &seq))
            .await
            .expect("write");
        let (_, reply) = read_reply(&mut stream).await;
        assert_eq!(
            reply.get_i32("code").ok() == Some(15),
            refused,
            "a {levels}-level sequence member: expected refused={refused}, got {reply:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_required_flag_bit_is_refused() {
    let state = new_state().await;
    let port = start_echo_server(&state).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");

    // Bit 2 is in the required range (0-15) and undefined: the receiver must not guess.
    stream
        .write_all(&op_msg(12, 1 << 2, &insert_body(false), &[]))
        .await
        .expect("write");
    expect_closed(&mut stream, "an unknown required flag bit").await;
}
