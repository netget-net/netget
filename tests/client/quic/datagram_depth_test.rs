//! Datagram answers to datagrams are bounded.
//!
//! NetGet's own QUIC server echoes every DATAGRAM, and the client's handler answers every
//! DATAGRAM it receives with another one, so without a bound the two trade datagrams for as
//! long as the client's LLM budget lasts. The client stops answering after
//! `MAX_FOLLOWUP_DEPTH` (4) consecutive datagram replies: the operator's first datagram plus at
//! most four answers reach the server, and the client sees at most five echoes. No LLM calls:
//! python handlers answer every event.
use crate::helpers::quic_peer::*;
use netget::state::{client_handles::ClientSendOutcome, AccessLogOwner};
use serde_json::json;
use std::time::Duration;

const ECHO: &str = "import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'send_quic_datagram','data':e['data'],'encoding':e['encoding']}]}))";

#[tokio::test]
async fn datagram_answers_to_an_echoing_peer_stop_at_the_follow_up_depth() {
    let state = state();
    let cert = Certificate::new();
    let (_server_id, addr) = server(
        &state,
        "quic",
        &cert,
        json!({}),
        vec![
            json!({"event_pattern":"quic_datagram_received","handler":{"type":"script","language":"python","code":ECHO}}),
            empty_handler(),
        ],
    )
    .await;
    let id = client(
        &state,
        "quic",
        addr.to_string(),
        cert.trust(),
        vec![
            json!({"event_pattern":"quic_datagram_received","handler":{"type":"script","language":"python","code":ECHO}}),
            empty_handler(),
        ],
    )
    .await;

    let sent = state
        .send_to_client(
            id,
            json!({"type":"send_quic_datagram","data":"ping"}),
            Duration::from_secs(4),
        )
        .await
        .unwrap();
    assert!(
        matches!(sent, ClientSendOutcome::Executed { .. }),
        "{sent:?}"
    );

    let received = || async {
        state
            .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
            .await
            .iter()
            .filter(|e| e.event_type == "quic_datagram_received")
            .count()
    };
    // Wait for the exchange to go quiet: the count has held still for three seconds, polled
    // every 100 ms, within a deadline an unbounded exchange would pass the bound long before.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut later = received().await;
    let mut still_since = std::time::Instant::now();
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = received().await;
        if now != later {
            later = now;
            still_since = std::time::Instant::now();
        } else if later >= 2 && still_since.elapsed() >= Duration::from_secs(3) {
            break;
        }
    }
    let settled = later;
    assert!(
        settled >= 2,
        "the echo exchange never ran: {settled} datagrams received"
    );
    assert!(
        later <= 5,
        "the client answered past the follow-up depth: {later} datagrams received"
    );
    assert!(
        still_since.elapsed() >= Duration::from_secs(3),
        "the exchange was still running at the deadline: {later} datagrams received"
    );
    state.remove_client(id).await;
}
