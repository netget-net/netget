//! A hostile SIP response must not kill the client's read loop.
//!
//! Two panics used to be reachable from the peer, and both take the worst possible shape: they
//! fire inside the `tokio::spawn`ed read loop, which swallows the panic, so the client stays
//! `Connected` in the dashboard, the log says nothing, and every later response is ignored.
//!
//! 1. **`extract_uri` sliced backwards.** It searched the whole header value for `<` and,
//!    independently, for `>`, then sliced between them. A display name containing a `>` before
//!    the angle-bracketed URI — `"ev>il" <sip:victim@host>` — put the slice's start past its
//!    end, which is an immediate panic on a `&str`. It is reached from the automatic-ACK path,
//!    i.e. from any `200` whose CSeq method is `INVITE`. **That is what this test drives.**
//!
//! 2. **The automatic ACK's `.unwrap()`s.** The same path read the dialog's Call-ID and From
//!    tag with `.unwrap()`, and both are `None` until this client has itself sent a request —
//!    so an *unsolicited* `200 OK`/`CSeq: n INVITE` panicked. There is no dialog to acknowledge
//!    in that case, so the fix logs it and sends nothing. It is **not** driven here, and the
//!    reason is a harness limit worth stating rather than hiding: the client binds an ephemeral
//!    port and `connect`s, so a test peer only learns its address once the client has spoken —
//!    and speaking is exactly what fills those two fields in. Reaching the `None` arm from the
//!    wire needs the client's local address to be recorded in `AppState`, which
//!    `cli/client_startup.rs` does not currently do.
//!
//! The peer is a plain UDP socket, so nothing depends on server behaviour, and the client's LLM
//! points at a closed port so no model is involved.


use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
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
        "SIP client #{} never registered a command handle",
        id.as_u32()
    );
}

/// Inject an OPTIONS through the dashboard's `[ send ]` path and assert it left the socket.
async fn inject_options(state: &AppState, id: ClientId, context: &str) {
    let outcome = state
        .send_to_client(
            id,
            serde_json::json!({
                "type": "sip_options",
                "from": "sip:probe@127.0.0.1",
                "to": "sip:peer@127.0.0.1",
                "request_uri": "sip:peer@127.0.0.1",
            }),
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_else(|e| panic!("{context}: send_to_client failed: {e}"));
    assert!(
        matches!(outcome, ClientSendOutcome::Sent { .. }),
        "{context}: the client did not send: {outcome:?}"
    );
}

/// A final response whose display names close an angle bracket before opening one. `CSeq: 1
/// INVITE` with a `200` status line is what drives the client into the automatic-ACK path,
/// which is where `extract_uri` is called on these headers.
const HOSTILE_RESPONSE: &str = "SIP/2.0 200 OK\r\n\
     Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-hostile\r\n\
     From: \"ev>il\" <sip:attacker@127.0.0.1>;tag=att\r\n\
     To: \"ev>il\" <sip:victim@127.0.0.1>;tag=vic\r\n\
     Call-ID: hostile@127.0.0.1\r\n\
     CSeq: 1 INVITE\r\n\
     Content-Length: 0\r\n\
     \r\n";

/// Receive one datagram from the peer socket, or fail with `context`.
async fn recv(peer: &UdpSocket, buf: &mut [u8], context: &str) -> (usize, std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(10), peer.recv_from(buf))
        .await
        .unwrap_or_else(|_| panic!("{context}: nothing arrived within 10s"))
        .unwrap_or_else(|e| panic!("{context}: recv_from failed: {e}"))
}

#[tokio::test]
async fn a_hostile_uri_in_an_invite_200_does_not_kill_the_read_loop() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();

    // Stand-in for the SIP server. The client `connect`s its UDP socket to this address, so
    // this is the only source whose datagrams it accepts — which is exactly the peer being
    // modelled as hostile.
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let client_id = ClientForm {
        protocol: "sip".to_string(),
        remote_addr: Some(peer_addr.to_string()),
        instruction: Some("test client".to_string()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create sip client");

    wait_for_client_handle(&state, client_id).await;

    // Make the client speak, so the peer learns its address.
    inject_options(&state, client_id, "first probe").await;
    let mut buf = vec![0u8; 65535];
    let (n, client_addr) = recv(&peer, &mut buf, "the client's first OPTIONS").await;
    let first = String::from_utf8_lossy(&buf[..n]).to_string();

    // Via must name this client's own socket, not the `127.0.0.1:5060` literal it used to
    // hardcode: Via is where an RFC 3261 server sends its response, so a wrong one means every
    // reply from a real server goes somewhere this client is not listening. It worked only
    // against netget's own SIP server, which answers the datagram's source address instead.
    assert!(
        first.contains(&format!("Via: SIP/2.0/UDP {}", client_addr)),
        "Via must carry this client's real address ({client_addr}):\n{first}"
    );
    assert!(
        first.contains(";rport"),
        "Via should ask for rport (RFC 3581) so a server behind NAT answers the observed \
         source:\n{first}"
    );
    // (Contact is only sent on REGISTER and INVITE, so it is not asserted on this OPTIONS; it
    // takes its default from the same `local_addr`.)

    // The hostile response. RFC 3261 obliges the client to ACK a 200 to an INVITE, so this is
    // answered — the question is whether it is answered or the task dies.
    peer.send_to(HOSTILE_RESPONSE.as_bytes(), client_addr)
        .await
        .expect("send hostile response");

    let (n, _) = recv(&peer, &mut buf, "the ACK for the hostile 200 OK").await;
    let ack = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        ack.starts_with("ACK "),
        "expected an ACK for the 200 OK, got:\n{ack}"
    );
    // The URIs came out of headers whose display name contains a `>`. Getting them *right*
    // is what proves the bracket search now runs forward from `<` rather than independently.
    assert!(
        ack.contains("To: <sip:victim@127.0.0.1>;tag=vic"),
        "the To URI was mis-extracted from a display name containing '>':\n{ack}"
    );
    assert!(
        ack.contains("From: <sip:attacker@127.0.0.1>"),
        "the From URI was mis-extracted from a display name containing '>':\n{ack}"
    );
    assert!(
        ack.contains("ACK sip:victim@127.0.0.1 SIP/2.0"),
        "the ACK request-URI was mis-extracted:\n{ack}"
    );

    // And the read loop is still alive: a second hostile datagram is consumed and a second
    // injected request still reaches the wire. Without the first of these, a dead read loop
    // would be indistinguishable from a live one, because the command loop is its own task.
    peer.send_to(HOSTILE_RESPONSE.as_bytes(), client_addr)
        .await
        .expect("send second hostile response");
    let (n, _) = recv(&peer, &mut buf, "the ACK for the second hostile 200 OK").await;
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("ACK "),
        "the read loop stopped processing responses after the first hostile one"
    );

    inject_options(&state, client_id, "after the hostile responses").await;
    let (n, _) = recv(&peer, &mut buf, "the OPTIONS after the hostile responses").await;
    let after = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        after.starts_with("OPTIONS "),
        "expected an OPTIONS request, got:\n{after}"
    );
}
