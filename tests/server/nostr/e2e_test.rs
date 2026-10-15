//! The relay end to end with a mocked model, driven by a raw WebSocket peer.
//!
//! One relay, one rule per event type branching on what the event carries (first-match-wins
//! makes two rules on one event a trap). Seven model calls: the instruction, three published
//! events, three subscriptions. Everything else a peer sends here — a tampered event, a
//! `CLOSE` — must cost none, and `verify_mocks` pins the counts.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::e2e --test-threads=100

use super::common::{event_frame, note, Peer};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::nostr::wire::verify_event;
use serde_json::json;

#[tokio::test]
async fn the_model_decides_events_and_answers_subscriptions() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via nostr. A relay for film notes, no adverts.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("via nostr")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "nostr",
                "instruction": "A relay for film notes, no adverts"
            }]))
            .expect_calls(1)
            .and()
            .on_event("nostr_event")
            .respond_with_actions_from_event(|e| {
                if e["content"].as_str().unwrap_or("").contains("buy now") {
                    json!([{"type": "reject_nostr_event", "reason": "adverts are not allowed"}])
                } else {
                    json!([{"type": "accept_nostr_event"}])
                }
            })
            .expect_calls(3)
            .and()
            .on_event("nostr_req")
            .respond_with_actions_from_event(|e| match e["subscription_id"].as_str() {
                Some("members") => json!([{
                    "type": "close_nostr_subscription",
                    "reason": "members only"
                }]),
                Some("live") => json!([{"type": "send_nostr_events", "events": []}]),
                _ => json!([{
                    "type": "send_nostr_events",
                    "events": [
                        {"kind": 1, "content": "Review: Stalker", "tags": [["t", "film"]]},
                        {"kind": 7, "content": "+"},
                        {"kind": 1, "content": "Review: Solaris", "created_at": 1700000000}
                    ]
                }]),
            })
            .expect_calls(3)
            .and()
    });
    let server = start_netget_server(config).await?;
    let mut peer = Peer::connect(server.port).await;

    // 1. Accepted.
    let first = note("first note", vec![], 1700000100);
    peer.send(&event_frame(&first)).await;
    assert_eq!(peer.json(30).await, json!(["OK", first.id, true, ""]));

    // 2. Rejected, with NIP-01's default prefix added to the model's bare reason.
    let advert = note("buy now, cheap tickets", vec![], 1700000101);
    peer.send(&event_frame(&advert)).await;
    assert_eq!(
        peer.json(30).await,
        json!(["OK", advert.id, false, "blocked: adverts are not allowed"])
    );

    // 3. Tampered after signing: refused by NetGet, no model call.
    let mut tampered = note("honest words", vec![], 1700000102).to_json();
    tampered["content"] = json!("dishonest words");
    peer.send(&json!(["EVENT", tampered]).to_string()).await;
    let reply = peer.json(10).await;
    assert_eq!(reply[0], "OK");
    assert_eq!(reply[2], false);
    assert!(
        reply[3].as_str().unwrap().starts_with("invalid:"),
        "{reply}"
    );

    // 4. A subscription: NetGet signs the model's events, drops the kind 7 the filter excludes,
    //    then EOSE.
    peer.send_json(json!(["REQ", "films", {"kinds": [1]}]))
        .await;
    let mut got = Vec::new();
    loop {
        let message = peer.json(30).await;
        if message[0] == "EOSE" {
            assert_eq!(message, json!(["EOSE", "films"]));
            break;
        }
        assert_eq!(message[0], "EVENT", "{message}");
        assert_eq!(message[1], "films");
        got.push(verify_event(&message[2]).expect("NetGet signed it"));
    }
    let contents: Vec<&str> = got.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, vec!["Review: Stalker", "Review: Solaris"]);
    assert_eq!(
        got[1].created_at, 1700000000,
        "the model's created_at is kept"
    );
    assert_eq!(got[0].tags, vec![vec!["t".to_string(), "film".to_string()]]);

    // 5. A refused subscription: CLOSED with the reason, and no EOSE after it.
    peer.send_json(json!(["REQ", "members", {"#t": ["private"]}]))
        .await;
    assert_eq!(
        peer.json(30).await,
        json!(["CLOSED", "members", "restricted: members only"])
    );

    // 6. CLOSE is NetGet's: nothing is sent back and no model is asked.
    peer.send_json(json!(["CLOSE", "films"])).await;

    // 7. Live delivery: a second connection subscribes; an event the model accepts on the
    //    first reaches it with its author's own signature.
    let mut subscriber = Peer::connect(server.port).await;
    subscriber
        .send_json(json!(["REQ", "live", {"kinds": [1], "#t": ["live"]}]))
        .await;
    assert_eq!(subscriber.json(30).await, json!(["EOSE", "live"]));
    let live = note(
        "happening now",
        vec![vec!["t".into(), "live".into()]],
        1700000200,
    );
    peer.send(&event_frame(&live)).await;
    assert_eq!(peer.json(30).await, json!(["OK", live.id, true, ""]));
    assert_eq!(
        subscriber.json(30).await,
        json!(["EVENT", "live", live.to_json()])
    );
    // The publisher's own closed "films" subscription gets nothing.
    peer.assert_silent(1, "a closed subscription").await;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
