//! The dashboard's `[ send ]` path on a BitTorrent DHT client: `AppState::send_to_client`
//! injects an action from outside the client's receive loop and the resulting bencode query
//! really leaves the socket.
//!
//! Zero LLM calls: the client's LLM points at an unreachable URL, so its connected-event
//! call fails immediately and the loop must tolerate that - which is part of what this
//! verifies. The "DHT node" is a plain UDP socket owned by the test; it never answers, so
//! no `dht_response` event fires and no further LLM call is attempted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-dht --test client -- torrent_dht::command_channel --test-threads=100

use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId, ClientStatus};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "DHT client #{} never registered a command handle",
        id.as_u32()
    );
}

async fn wait_for_log_containing(state: &AppState, owner: AccessLogOwner, needle: &str) {
    for _ in 0..1_000 {
        for entry in state.list_access_logs_for(Some(owner), None).await {
            if serde_json::to_string(&entry)
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("no access-log entry for {owner:?} containing {needle:?}");
}

#[tokio::test]
async fn injected_dht_query_reaches_the_node() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // A stand-in DHT node: we only need it to receive.
    let node = UdpSocket::bind("127.0.0.1:0").await.expect("bind node");
    let node_addr = node.local_addr().unwrap();

    let client_id = ClientForm {
        protocol: "BitTorrent DHT".to_string(),
        remote_addr: Some(node_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create torrent-dht client");

    wait_for_client_handle(&state, client_id).await;

    // The client's own wire verb, injected from outside its loop.
    //
    // `node_id` is 40 hex characters, because that is what the parameter description says it
    // is. This used to read "abcdefghij0123456789" — twenty characters of text, which is not
    // hex at all — and it passed, because the client bencoded whatever string it was given
    // without decoding. A model obeying the description therefore put 40 bytes on the wire
    // where BEP 5 requires 20, and NetGet's own DHT server, which does hex-decode, could not
    // read its own client.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "dht_ping",
                "node_id": "0123456789abcdef0123456789abcdef01234567",
                "transaction_id": "00aa"
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    let bytes_sent = match outcome {
        ClientSendOutcome::Sent { bytes_sent } => bytes_sent,
        other => panic!("expected Sent, got {other:?}"),
    };

    // The datagram is real: it arrives at the node and is the bencoded ping we asked for.
    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), node.recv_from(&mut buf))
        .await
        .expect("node received no datagram")
        .expect("recv_from");
    assert_eq!(
        n, bytes_sent,
        "reported bytes_sent must equal what reached the wire"
    );
    let wire = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        wire.contains("4:ping") && wire.contains("1:q"),
        "expected a bencoded DHT ping query, got {wire:?}"
    );

    // The part that actually pins the encoding: the node id must be twenty *decoded* bytes,
    // not the forty characters the model wrote. Decode the datagram and look.
    let decoded: serde_bencode::value::Value =
        serde_bencode::from_bytes(&buf[..n]).expect("the query must be well-formed bencode");
    let serde_bencode::value::Value::Dict(msg) = decoded else {
        panic!("a KRPC query is a dictionary");
    };
    let Some(serde_bencode::value::Value::Dict(args)) = msg.get::<[u8]>(b"a") else {
        panic!("a KRPC query carries an `a` dictionary");
    };
    match args.get::<[u8]>(b"id") {
        Some(serde_bencode::value::Value::Bytes(id)) => {
            assert_eq!(
                id.len(),
                20,
                "BEP 5 node ids are 20 raw bytes; 40 means the hex was never decoded"
            );
            assert_eq!(
                hex::encode(id),
                "0123456789abcdef0123456789abcdef01234567",
                "the bytes on the wire must be the hex the caller supplied"
            );
        }
        other => panic!("expected `id` to be a byte string, got {other:?}"),
    }
    match msg.get::<[u8]>(b"t") {
        Some(serde_bencode::value::Value::Bytes(t)) => assert_eq!(
            t.as_slice(),
            &[0x00, 0xaa],
            "the transaction id must be the two decoded bytes, not four hex characters"
        ),
        other => panic!("expected `t` to be a byte string, got {other:?}"),
    }

    // A node id that is not hex is refused with an error that names the field, rather than
    // being silently put on the wire as text.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "dht_ping", "node_id": "abcdefghij0123456789"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client");
    match outcome {
        ClientSendOutcome::Rejected { error } => assert!(
            error.contains("node_id"),
            "the refusal must name the field the model got wrong, got {error:?}"
        ),
        other => panic!("a non-hex node_id must be Rejected, got {other:?}"),
    }

    // Recorded on the client like LLM-produced traffic.
    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;

    // An action the protocol does not know is refused, not silently swallowed.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "definitely_not_a_dht_verb"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client unknown");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    // UDP has no wire close, so an injected `disconnect` means: stop receiving, release the
    // socket, drop the handle so [ send ] is greyed out again.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(5),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        let status = state.get_client(client_id).await.map(|c| c.status);
        if matches!(status, Some(ClientStatus::Disconnected))
            && !state.has_client_handle(client_id).await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "client should be Disconnected with no command handle; status={:?} has_handle={}",
        state.get_client(client_id).await.map(|c| c.status),
        state.has_client_handle(client_id).await
    );
}
