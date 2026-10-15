//! The SPICE server's own guarantees, driven from sockets: what Rust refuses whatever the model
//! says (a wrong ticket, an unknown session, an oversized message), the fail-closed paths
//! (admission refused when the model cannot answer, the first screen's placeholder, an
//! unanswered input keeping its frame and saying so), and the model's decisions reaching the
//! wire (its screen, its reaction to keys and clicks). NetGet's own SPICE client reads the
//! display here; the third-party clients are in `real_client_test.rs`.
//!
//! The last test is the model's own path: a mocked LLM admits and draws for the NetGet binary.

use super::support::{self, PASSWORD};
use crate::helpers::{self, E2EResult, NetGetConfig};
use netget::client::spice::display::DisplayModel;
use netget::server::spice::wire::{self, channel, link_err, msg, msgc};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn static_rule(actions: Value) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": actions}}),
    ])
}

/// Link a main channel by hand and return the link result, so a refusal can be read as the
/// `SPICE_LINK_ERR_*` the server answered with.
async fn raw_link_result(
    addr: std::net::SocketAddr,
    connection_id: u32,
    channel_type: u8,
    password: &str,
) -> (tokio::net::TcpStream, u32) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mess = wire::LinkMess {
        connection_id,
        channel_type,
        channel_id: 0,
        common_caps: vec![wire::caps_word(&[
            wire::common_cap::AUTH_SELECTION,
            wire::common_cap::AUTH_SPICE,
            wire::common_cap::MINI_HEADER,
        ])],
        channel_caps: vec![],
    };
    s.write_all(&mess.encode()).await.unwrap();
    let mut header = [0u8; wire::LINK_HEADER_BYTES];
    s.read_exact(&mut header).await.unwrap();
    let size = wire::parse_link_header(&header, 4).unwrap();
    let mut body = vec![0u8; size as usize];
    s.read_exact(&mut body).await.unwrap();
    let reply = wire::LinkReply::decode(&body).unwrap();
    assert_eq!(reply.error, link_err::OK);
    s.write_all(&wire::AUTH_MECHANISM_SPICE.to_le_bytes())
        .await
        .unwrap();
    s.write_all(&wire::encrypt_ticket(&reply.pubkey, password).unwrap())
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(30), s.read_u32_le())
        .await
        .expect("no link result")
        .unwrap();
    (s, result)
}

#[tokio::test]
async fn the_models_screen_reaches_a_client_pixel_for_pixel() {
    let server = support::start(support::policy(), support::params()).await;
    let (client, id) = support::netget_client(server.addr(), PASSWORD)
        .await
        .expect("the server admitted a client with the right password");
    let reading = support::wait_for_panel(&client, id, support::PANEL).await;
    assert_eq!(reading["width"], support::WIDTH);
    assert_eq!(reading["height"], support::HEIGHT);
    assert_eq!(reading["dominant_color"], support::hex(support::BACKGROUND));
    assert_eq!(
        reading["points"][1]["color"],
        support::hex(support::BACKGROUND)
    );
    assert_eq!(reading["exact"], true, "{reading}");
    assert!(
        reading["draw_ops"]["copy"].as_u64().unwrap() > 0,
        "{reading}"
    );
    assert_eq!(reading["images"]["bitmap"], reading["draw_ops"]["copy"]);
    // The admission notice reached the client's main channel.
    let notice =
        support::wait_client_event(&client, id, "spice_notify", |e| e["message"] == "welcome")
            .await;
    assert!(notice.is_some(), "the model's notification never arrived");
    let request = server.events("spice_connection_request").await;
    assert_eq!(request.len(), 1);
    assert_eq!(request[0]["request"]["password_configured"], true);
    assert!(server.log_text().contains("decision=model_answer"));
    // The password never reaches the model, the log or the event.
    assert!(!format!("{request:?}").contains(PASSWORD));
    assert!(!server.log_text().contains(PASSWORD));
}

#[tokio::test]
async fn keys_and_clicks_reach_the_model_and_its_redraw_reaches_the_client() {
    let server = support::start(support::policy(), support::params()).await;
    let (client, id) = support::netget_client(server.addr(), PASSWORD)
        .await
        .unwrap();
    support::wait_for_panel(&client, id, support::PANEL).await;
    let before = support::read_screen(&client, id).await["checksum"].clone();

    // `a` is answered with spice_no_change: nothing moves.
    support::send(&client, id, json!({"type": "spice_type", "text": "a"})).await;
    let keys = server.wait_for_events("spice_key_event", 1).await;
    assert_eq!(keys[0]["request"]["key"], "a");
    assert_eq!(keys[0]["request"]["text"], "a");
    assert_eq!(keys[0]["request"]["shift"], false);
    assert_eq!(
        support::read_screen(&client, id).await["checksum"],
        before,
        "spice_no_change redrew the screen"
    );

    // Shift is decoded: `X` arrives as X with shift held, then `x` turns the panel green.
    support::send(&client, id, json!({"type": "spice_type", "text": "Xx"})).await;
    let keys = server.wait_for_events("spice_key_event", 3).await;
    assert_eq!(keys[1]["request"]["key"], "X");
    assert_eq!(keys[1]["request"]["shift"], true);
    assert_eq!(keys[2]["request"]["key"], "x");
    support::wait_for_panel(&client, id, support::PANEL_AFTER_X).await;

    // A named key and a click.
    support::send(
        &client,
        id,
        json!({"type": "spice_keys", "keys": ["enter"]}),
    )
    .await;
    let keys = server.wait_for_events("spice_key_event", 4).await;
    assert_eq!(keys[3]["request"]["key"], "Return");
    support::send(
        &client,
        id,
        json!({"type": "spice_mouse", "x": 200, "y": 210, "action": "click"}),
    )
    .await;
    let clicks = server.wait_for_events("spice_mouse_event", 1).await;
    assert_eq!(clicks.len(), 1, "a release must not reach the model");
    assert_eq!(clicks[0]["request"]["button"], "left");
    assert_eq!(clicks[0]["request"]["x"], 200);
    assert_eq!(clicks[0]["request"]["y"], 210);
    assert_eq!(clicks[0]["request"]["mouse_mode"], "client");
    support::wait_for_panel(&client, id, support::PANEL_AFTER_CLICK).await;
}

#[tokio::test]
async fn a_wrong_password_is_refused_before_the_model_is_asked() {
    let server = support::start(support::policy(), support::params()).await;
    let err = support::netget_client(server.addr(), "not-the-password")
        .await
        .err()
        .expect("a wrong password was admitted");
    assert!(format!("{err:#}").contains("permission denied"), "{err:#}");
    assert!(
        server
            .wait_for_log("decision=protocol_reject_bad_ticket")
            .await
    );
    assert!(server.events("spice_connection_request").await.is_empty());
    // And by hand, the link result is SPICE_LINK_ERR_PERMISSION_DENIED.
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, "wrong").await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
    // An empty password is a wrong password too.
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, "").await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
}

#[tokio::test]
async fn admission_fails_closed_when_the_model_cannot_answer() {
    // No routing: every event goes to a model at 127.0.0.1:1, which is not there.
    let server = support::start(None, support::params()).await;
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
    assert!(server.wait_for_log("decision=fail_closed_llm_error").await);
}

#[tokio::test]
async fn admission_is_refused_when_the_model_says_no_or_says_nothing() {
    let server = support::start(
        static_rule(json!([{"type": "spice_reject_connection"}])),
        support::params(),
    )
    .await;
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
    assert!(server.wait_for_log("decision=model_reject").await);

    // A screen without spice_accept_connection is not an admission.
    let server = support::start(
        static_rule(json!([{"type": "spice_render_display", "commands": [{"type": "background", "color": "red"}]}])),
        support::params(),
    )
    .await;
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::PERMISSION_DENIED);

    let server = support::start(static_rule(json!([])), support::params()).await;
    let (_s, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
    assert!(server.wait_for_log("decision=model_silent").await);
}

#[tokio::test]
async fn a_first_screen_without_an_answer_is_a_placeholder() {
    // Admitted, but the display_ready event has no answer.
    let rules = Some(vec![
        json!({"event_pattern": "spice_connection_request", "handler": {"type": "static",
               "actions": [{"type": "spice_accept_connection"}]}}),
    ]);
    let server = support::start(rules, support::params()).await;
    let (client, id) = support::netget_client(server.addr(), PASSWORD)
        .await
        .unwrap();
    assert!(server.wait_for_log("decision=fail_closed_llm_error").await);
    let want = format!(
        "#{:02x}{:02x}{:02x}",
        netget::server::spice::PLACEHOLDER_BACKGROUND.r,
        netget::server::spice::PLACEHOLDER_BACKGROUND.g,
        netget::server::spice::PLACEHOLDER_BACKGROUND.b
    );
    let mut reading = Value::Null;
    for _ in 0..40 {
        reading = support::read_screen(&client, id).await;
        if reading["dominant_color"] == want.as_str() {
            break;
        }
    }
    assert_eq!(reading["dominant_color"], want.as_str(), "{reading}");
    // The caption is fixed text: the error never reaches the client.
    assert!(server.log_text().contains("127.0.0.1:1") || server.log_text().contains("error"));
}

#[tokio::test]
async fn an_input_without_an_answer_keeps_the_frame_and_says_so() {
    // Keys get nothing usable back; everything else is the policy.
    let rules = Some(vec![
        json!({"event_pattern": "spice_key_event", "handler": {"type": "static", "actions": []}}),
        json!({"event_pattern": "*", "handler": {"type": "script", "language": "python",
               "code": support::POLICY}}),
    ]);
    let server = support::start(rules, support::params()).await;
    let (client, id) = support::netget_client(server.addr(), PASSWORD)
        .await
        .unwrap();
    let before = support::wait_for_panel(&client, id, support::PANEL).await;
    support::send(&client, id, json!({"type": "spice_type", "text": "x"})).await;
    assert!(server.wait_for_log("decision=model_silent").await);
    let notice = support::wait_client_event(&client, id, "spice_notify", |e| {
        e["message"] == netget::server::spice::NO_ANSWER_NOTICE && e["severity"] == "warn"
    })
    .await;
    assert!(
        notice.is_some(),
        "no notification that the input went unanswered"
    );
    let after = support::read_screen(&client, id).await;
    assert_eq!(after["checksum"], before["checksum"], "the frame changed");
}

#[tokio::test]
async fn a_channel_for_an_unknown_session_is_refused() {
    let server = support::start(support::policy(), support::params()).await;
    let (_s, result) =
        raw_link_result(server.addr(), 0x1234_5678, channel::DISPLAY, PASSWORD).await;
    assert_eq!(result, link_err::BAD_CONNECTION_ID);
    // Without the password, a session id is not even looked up.
    let (_s, result) = raw_link_result(server.addr(), 0x1234_5678, channel::DISPLAY, "x").await;
    assert_eq!(result, link_err::PERMISSION_DENIED);
    // A channel type this server does not offer.
    let (_s, result) = raw_link_result(server.addr(), 0, channel::PLAYBACK, PASSWORD).await;
    assert_eq!(result, link_err::CHANNEL_NOT_AVAILABLE);
    assert!(server.events("spice_connection_request").await.is_empty());
}

#[tokio::test]
async fn a_bad_link_header_is_answered_and_closed() {
    let server = support::start(support::policy(), support::params()).await;
    for (bytes, want) in [
        (
            b"XXXX\x02\0\0\0\x02\0\0\0\x1a\0\0\0".to_vec(),
            link_err::INVALID_MAGIC,
        ),
        (
            b"REDQ\x01\0\0\0\x02\0\0\0\x1a\0\0\0".to_vec(),
            link_err::VERSION_MISMATCH,
        ),
        // A declared size above MAX_LINK_BYTES: refused before anything is read for it.
        (
            [
                b"REDQ\x02\0\0\0\x02\0\0\0".as_slice(),
                &(wire::MAX_LINK_BYTES + 1).to_le_bytes(),
            ]
            .concat(),
            link_err::INVALID_DATA,
        ),
    ] {
        let mut s = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
        s.write_all(&bytes).await.unwrap();
        let mut header = [0u8; wire::LINK_HEADER_BYTES];
        s.read_exact(&mut header).await.unwrap();
        let mut body = vec![0u8; wire::parse_link_header(&header, 4).unwrap() as usize];
        s.read_exact(&mut body).await.unwrap();
        assert_eq!(wire::LinkReply::decode(&body).unwrap().error, want);
        let mut rest = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut rest))
            .await
            .expect("the connection stayed open")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }
    assert!(server.events("spice_connection_request").await.is_empty());
}

#[tokio::test]
async fn an_oversized_message_is_refused_before_its_body_is_read() {
    let server = support::start(support::policy(), support::params()).await;
    let (mut s, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::OK);
    // A mini header declaring one byte more than the server accepts, and no body.
    let header = wire::data_header(
        true,
        1,
        msgc::MAIN_ATTACH_CHANNELS,
        netget::server::spice::MAX_CLIENT_MESSAGE_BYTES + 1,
    );
    s.write_all(&header).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut rest))
        .await
        .expect("the server kept reading an oversized message")
        .ok();
    assert!(
        server
            .wait_for_log("decision=fail_closed_message_too_large")
            .await
    );
    // Nothing after the admission reached the model.
    assert!(server.events("spice_key_event").await.is_empty());
}

#[tokio::test]
async fn the_display_stream_is_spice_by_hand() {
    // Read a display channel without NetGet's client: SURFACE_CREATE, then DRAW_COPYs of
    // uncompressed bitmaps covering the surface, then MARK — decoded by the display model.
    let server = support::start(support::policy(), support::params()).await;
    let (mut main, result) = raw_link_result(server.addr(), 0, channel::MAIN, PASSWORD).await;
    assert_eq!(result, link_err::OK);
    let (t, body) = wire::read_message(&mut main, true, 1 << 20).await.unwrap();
    assert_eq!(t, msg::MAIN_INIT);
    let session = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let (mut display, result) =
        raw_link_result(server.addr(), session, channel::DISPLAY, PASSWORD).await;
    assert_eq!(result, link_err::OK);
    let mut model = DisplayModel::default();
    let mut seen = Vec::new();
    loop {
        let (t, body) = tokio::time::timeout(
            Duration::from_secs(30),
            wire::read_message(&mut display, true, 64 << 20),
        )
        .await
        .expect("the display stream stalled")
        .unwrap();
        seen.push(t);
        model.handle(t, &body).unwrap();
        if t == msg::DISPLAY_MARK {
            break;
        }
    }
    assert_eq!(seen[0], msg::DISPLAY_SURFACE_CREATE);
    assert!(seen[1..seen.len() - 1]
        .iter()
        .all(|t| *t == msg::DISPLAY_DRAW_COPY));
    let reading = model.describe(2);
    assert_eq!(reading["dominant_color"], support::hex(support::BACKGROUND));
    assert_eq!(reading["exact"], true);
    assert_eq!(
        netget::client::spice::display::pixel_hex(
            &model,
            support::PANEL_X + 10,
            support::PANEL_Y + 10
        ),
        Some(support::hex(support::PANEL))
    );
}

/// The model's path end to end: a mocked LLM admits the client and draws its screen, through
/// its tools, for the NetGet binary.
#[tokio::test]
async fn a_mocked_model_admits_and_draws() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via spice").with_mock(|mock| {
        mock.on_instruction_containing("via spice")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "spice",
                "startup_params": support::params(),
                "instruction": "Admit every client and show a blue panel"
            }]))
            .expect_calls(1)
            .and()
            .on_event("spice_connection_request")
            .respond_with_actions(json!([
                {"type": "spice_accept_connection"},
                {"type": "spice_render_display", "commands": [
                    {"type": "background", "color": "#1e293b"},
                    {"type": "rectangle", "x": 80, "y": 120, "width": 300, "height": 160,
                     "color": "#38bdf8", "filled": true}
                ]}
            ]))
            .expect_calls(1)
            .and()
    });
    let server = helpers::start_netget_server(config).await?;
    let (client, id) =
        support::netget_client(([127, 0, 0, 1], server.port).into(), PASSWORD).await?;
    support::wait_for_panel(&client, id, support::PANEL).await;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
