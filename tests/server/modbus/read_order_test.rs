//! One Modbus/TCP connection's bytes are framed in the order they arrived, and its requests
//! answered in that order.
//!
//! The Modbus reader hands each read to the connection's accumulator and goes straight back to
//! `read()`, so a client that writes in quick succession has several reads in the server at
//! once. They must join the accumulator in arrival order: a read appended ahead of the one
//! before it puts the back of an ADU in front of its MBAP header, which is a framing error and
//! a closed connection, or — if the bytes happen to line up — a request answered out of turn.
//!
//! Every request here is a Read Holding Registers with a quantity of zero, which the
//! specification answers (exception 0x03) with no model call, so the answers are as fast as the
//! server can make them — which is when two reads racing each other is most likely. Each ADU is
//! written in two halves, split inside the MBAP header, with up to four requests outstanding at
//! once, and the transaction ids of the answers must come back in the order the requests were
//! written.
//!
//! Modbus declares batching `Unsupported`, so there is one mode to drive. Loopback only; the
//! LLM endpoint is a dead port, and nothing may reach it.

use std::time::Duration;

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Requests per connection, each written in two halves.
const REQUESTS: u16 = 300;
/// Connections, each driven at the same time as the others.
const CONNECTIONS: u16 = 4;
/// Where each ADU is split: inside the MBAP header, so neither half is a frame on its own.
const SPLIT: usize = 5;
/// Requests a connection has written and not yet seen answered. Pipelining is legal, but the
/// server holds at most `MAX_BUFFERED` (eight ADUs) behind the request it is answering and
/// closes past that, so a client that never waited would be measuring that bound instead.
/// Four requests is eight reads, which is plenty to race.
const WINDOW: usize = 4;

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("Modbus server #{} never bound a port", id.as_u32());
}

/// Read Holding Registers at address 0 for a quantity of zero: refused by the specification.
fn zero_quantity_read(transaction_id: u16) -> Vec<u8> {
    let pdu = [0x03, 0x00, 0x00, 0x00, 0x00];
    let mut adu = Vec::with_capacity(7 + pdu.len());
    adu.extend_from_slice(&transaction_id.to_be_bytes());
    adu.extend_from_slice(&[0x00, 0x00]);
    adu.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    adu.push(1);
    adu.extend_from_slice(&pdu);
    adu
}

/// Write `REQUESTS` numbered requests, each in two writes, and return the transaction ids of
/// the answers in the order they came back.
async fn requests_and_answers(port: u16, connection: u16) -> Vec<u16> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut read_half, mut write_half) = stream.into_split();
    let first = connection * 1000;
    let window = std::sync::Arc::new(tokio::sync::Semaphore::new(WINDOW));

    let writer_window = window.clone();
    let writer = tokio::spawn(async move {
        for i in 0..REQUESTS {
            writer_window.acquire().await.expect("window").forget();
            let adu = zero_quantity_read(first + i);
            for half in [&adu[..SPLIT], &adu[SPLIT..]] {
                write_half.write_all(half).await.expect("write");
                // Let the server read between writes, so each half is likely a read of its
                // own and many reads are in the server at once.
                tokio::task::yield_now().await;
            }
        }
        write_half
    });

    let mut ids = Vec::with_capacity(REQUESTS as usize);
    let read = tokio::time::timeout(Duration::from_secs(60), async {
        while ids.len() < REQUESTS as usize {
            let mut answer = [0u8; 9];
            if let Err(e) = read_half.read_exact(&mut answer).await {
                panic!(
                    "connection {connection}: closed after {} of {REQUESTS} answers: {e}",
                    ids.len()
                );
            }
            assert_eq!(
                &answer[2..],
                &[0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03],
                "connection {connection}: answer {} is not exception 0x03 to a register read",
                ids.len()
            );
            ids.push(u16::from_be_bytes([answer[0], answer[1]]));
            window.add_permits(1);
        }
    })
    .await;
    let _write_half = writer.await.expect("writer");
    assert!(
        read.is_ok(),
        "connection {connection}: only {} of {REQUESTS} answers within the deadline",
        ids.len()
    );
    ids
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn modbus_reads_are_framed_and_answered_in_the_order_they_arrived() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "modbus".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // An empty instruction really is model-free; `None` is replaced by a default one.
        instruction: Some(String::new()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create modbus server");
    let port = wait_for_port(&state, id).await;

    let peers: Vec<_> = (0..CONNECTIONS)
        .map(|c| tokio::spawn(requests_and_answers(port, c)))
        .collect();
    for (c, peer) in peers.into_iter().enumerate() {
        let c = c as u16;
        let got = peer.await.expect("peer");
        let want: Vec<u16> = (0..REQUESTS).map(|i| c * 1000 + i).collect();
        if got != want {
            let at = want.iter().zip(&got).position(|(a, b)| a != b).unwrap_or(0);
            let from = at.saturating_sub(3);
            panic!(
                "connection {c}: answers came back out of order from answer {at}:\n  asked    ...{:?}\n  answered ...{:?}",
                &want[from..(at + 5).min(want.len())],
                &got[from..(at + 5).min(got.len())],
            );
        }
    }
    let _ = state.remove_server(id).await;
}
