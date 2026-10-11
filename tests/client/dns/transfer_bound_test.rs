//! A hostile server cannot make the DNS client's zone transfer hold what it sends.
//!
//! The fake server below answers an AXFR with an SOA and then nearly-64-KiB TXT records, one
//! message each, without ever closing the transfer. Record count alone would let it send
//! `MAX_TRANSFER_RECORDS` of them — gigabytes — before the client gave up; the client ends the
//! transfer with an error once the messages pass `MAX_TRANSFER_BYTES`, keeping only the first
//! `MAX_REPORTED_RECORDS` records meanwhile.
//!
//! Zero LLM calls: the client's model points at an unreachable URL and the transfer is
//! injected through the command channel, the dashboard's `[ send ]` path.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dns --test client -- dns::transfer_bound --test-threads=100

#![cfg(feature = "dns")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{SOA, TXT};
use hickory_proto::rr::{RData, Record};
use netget::cli::management::ClientForm;
use netget::client::dns::actions::MAX_TRANSFER_BYTES;
use netget::state::app_state::AppState;
use netget::state::ClientId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// The fake server stops by itself past this, so the test cannot run away if the client
/// never stops reading.
const SERVER_SEND_LIMIT: usize = 4 * MAX_TRANSFER_BYTES;

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DNS client #{} never registered a command handle",
        id.as_u32()
    );
}

/// One framed response to `query`, carrying `answers`.
fn framed_response(query: &Message, answers: Vec<Record>) -> Vec<u8> {
    let mut m = Message::new();
    m.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(query.op_code())
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);
    for q in query.queries() {
        m.add_query(q.clone());
    }
    m.add_answers(answers);
    let bytes = m.to_vec().expect("the response encodes");
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    framed
}

/// Accept one connection, read its AXFR, and stream large records until the client stops
/// reading or `SERVER_SEND_LIMIT` is reached. Counts what it wrote into `sent`.
async fn hostile_axfr_server(listener: TcpListener, sent: Arc<AtomicUsize>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let Ok(len) = stream.read_u16().await else {
        return;
    };
    let mut buf = vec![0u8; len as usize];
    if stream.read_exact(&mut buf).await.is_err() {
        return;
    }
    let query = Message::from_vec(&buf).expect("the client's AXFR decodes");
    let zone = query.queries()[0].name().clone();

    let soa = Record::from_rdata(
        zone.clone(),
        300,
        RData::SOA(SOA::new(
            zone.clone(),
            zone.clone(),
            1,
            3600,
            600,
            604_800,
            300,
        )),
    );
    // 250 character-strings of 255 octets: ~64 000 octets of RDATA, one record a message.
    let big = Record::from_rdata(
        zone.clone(),
        300,
        RData::TXT(TXT::new(vec!["x".repeat(255); 250])),
    );

    let first = framed_response(&query, vec![soa, big.clone()]);
    let next = framed_response(&query, vec![big]);
    let mut message = first;
    loop {
        if stream.write_all(&message).await.is_err() {
            return;
        }
        if sent.fetch_add(message.len(), Ordering::SeqCst) + message.len() > SERVER_SEND_LIMIT {
            return;
        }
        message = next.clone();
    }
}

#[tokio::test]
async fn an_endless_transfer_of_large_records_ends_at_the_byte_bound() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("server addr");
    let sent = Arc::new(AtomicUsize::new(0));
    tokio::spawn(hostile_axfr_server(listener, sent.clone()));

    let client_id = ClientForm {
        protocol: "dns".to_string(),
        remote_addr: Some(server_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create dns client");
    wait_for_client_handle(&state, client_id).await;

    let error = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "send_dns_zone_transfer", "zone": "big.test."}),
            Duration::from_secs(120),
        )
        .await
        .expect_err("a transfer that never ends and passes the byte bound must fail");
    let message = format!("{error:#}");
    assert!(
        message.contains(&format!("passed {MAX_TRANSFER_BYTES} bytes; abandoned")),
        "the transfer ends on the byte bound, not on a timeout or the record count: {message}"
    );
    // The server really did send past the bound before the client stopped it.
    let written = sent.load(Ordering::SeqCst);
    assert!(
        written > MAX_TRANSFER_BYTES,
        "the server wrote {written} bytes"
    );
}
