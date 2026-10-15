//! What the SPICE client refuses whatever a server says, driven by a server written in this file
//! that links every channel and then misbehaves on the display channel: a surface or image past
//! the size limits, a message past the message limit, a bitmap that claims more bytes than its
//! message carries, too many clip rectangles, a main channel that never sends INIT. Each is
//! refused before anything is allocated for it and ends the session with the reason. The last
//! test bounds the model's own follow-up chain.
use netget::cli::management::ClientForm;
use netget::client::spice::MAX_SERVER_MESSAGE_BYTES;
use netget::server::spice::wire::{self, channel, common_cap, link_err, msg, msgc};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// One message for the fake server to write on the display channel: a well-formed one, or raw
/// bytes for the cases a well-formed one cannot express.
enum Out {
    Msg(u16, Vec<u8>),
    Raw(Vec<u8>),
}

fn mini(t: u16, body: &[u8]) -> Vec<u8> {
    let mut v = wire::data_header(true, 0, t, body.len() as u32);
    v.extend_from_slice(body);
    v
}

/// Link one incoming channel, accepting any ticket. Returns the link message.
async fn accept_link(s: &mut TcpStream, pubkey: &[u8]) -> wire::LinkMess {
    let mut header = [0u8; wire::LINK_HEADER_BYTES];
    s.read_exact(&mut header).await.unwrap();
    let size = wire::parse_link_header(&header, wire::LINK_MESS_BYTES).unwrap();
    let mut body = vec![0u8; size as usize];
    s.read_exact(&mut body).await.unwrap();
    let link = wire::LinkMess::decode(&body).unwrap();
    let reply = wire::LinkReply {
        error: link_err::OK,
        pubkey: pubkey.to_vec(),
        common_caps: vec![wire::caps_word(&[
            common_cap::AUTH_SELECTION,
            common_cap::AUTH_SPICE,
            common_cap::MINI_HEADER,
        ])],
        channel_caps: vec![],
    };
    s.write_all(&reply.encode()).await.unwrap();
    let mut mechanism = [0u8; 4];
    s.read_exact(&mut mechanism).await.unwrap();
    let mut ticket = [0u8; wire::TICKET_BYTES];
    s.read_exact(&mut ticket).await.unwrap();
    s.write_all(&link_err::OK.to_le_bytes()).await.unwrap();
    link
}

/// A server that links anything, sends `before_init` main-channel messages then INIT (unless
/// `init` is false), answers ATTACH_CHANNELS with a display channel, and writes `display` on it.
async fn fake_server(before_init: usize, init: bool, display: Vec<Out>) -> SocketAddr {
    let key = tokio::task::spawn_blocking(wire::generate_ticket_key)
        .await
        .unwrap()
        .unwrap();
    let pubkey = Arc::new(wire::ticket_public_key(&key).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let display = Arc::new(display);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let pubkey = pubkey.clone();
            let display = display.clone();
            tokio::spawn(async move {
                let link = accept_link(&mut s, &pubkey).await;
                if link.channel_type == channel::MAIN {
                    for _ in 0..before_init {
                        let _ = s
                            .write_all(&mini(msg::MAIN_MULTI_MEDIA_TIME, &0u32.to_le_bytes()))
                            .await;
                    }
                    if !init {
                        let mut sink = Vec::new();
                        let _ = s.read_to_end(&mut sink).await;
                        return;
                    }
                    let init = wire::main_init(7, 1, 1, 1, 0, 0, 0, 0);
                    let _ = s.write_all(&mini(msg::MAIN_INIT, &init)).await;
                    loop {
                        let Ok((t, _)) = wire::read_message(&mut s, true, 1 << 20).await else {
                            return;
                        };
                        if t == msgc::MAIN_ATTACH_CHANNELS {
                            let list = wire::channels_list(&[(channel::DISPLAY, 0)]);
                            let _ = s.write_all(&mini(msg::MAIN_CHANNELS_LIST, &list)).await;
                        }
                    }
                } else {
                    for out in display.iter() {
                        let bytes = match out {
                            Out::Msg(t, body) => mini(*t, body),
                            Out::Raw(b) => b.clone(),
                        };
                        if s.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    let mut sink = Vec::new();
                    let _ = s.read_to_end(&mut sink).await;
                }
            });
        }
    });
    addr
}

async fn client(addr: SocketAddr, handlers: Vec<Value>) -> anyhow::Result<(AppState, ClientId)> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "SPICE".into(),
        remote_addr: Some(addr.to_string()),
        instruction: Some("Look".into()),
        event_handlers: Some(handlers),
        startup_params: Some(json!({"password": "anything"})),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok((state, id))
}

fn silent() -> Vec<Value> {
    vec![json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}})]
}

async fn events(state: &AppState, id: ClientId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == kind)
        .map(|e| e["request"].clone())
        .collect()
}

/// The reason the session ended, once it has.
async fn ended(state: &AppState, id: ClientId) -> String {
    for _ in 0..400 {
        if let Some(e) = events(state, id, "spice_disconnected").await.first() {
            return e["reason"].as_str().unwrap_or_default().to_string();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the session never ended");
}

fn surface(w: u32, h: u32) -> Out {
    Out::Msg(
        msg::DISPLAY_SURFACE_CREATE,
        wire::surface_create(
            0,
            w,
            h,
            wire::SURFACE_FMT_32_XRGB,
            wire::SURFACE_FLAGS_PRIMARY,
        ),
    )
}

#[tokio::test]
async fn a_surface_past_the_size_limit_is_refused_before_it_is_allocated() {
    let addr = fake_server(0, true, vec![surface(5000, 5000)]).await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("4096 pixels a side"), "{reason}");
    assert!(events(&state, id, "spice_surface_created").await.is_empty());
    // 4096 a side is allowed, but not 4096 x 4096 in all.
    let addr = fake_server(0, true, vec![surface(4096, 4096)]).await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("pixel limit"), "{reason}");
}

#[tokio::test]
async fn a_message_past_the_limit_ends_the_session_before_its_body_is_read() {
    let header = wire::data_header(
        true,
        0,
        msg::DISPLAY_DRAW_COPY,
        MAX_SERVER_MESSAGE_BYTES + 1,
    );
    let addr = fake_server(0, true, vec![surface(64, 64), Out::Raw(header)]).await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("above the"), "{reason}");
}

#[tokio::test]
async fn a_bitmap_claiming_more_than_its_message_carries_is_refused() {
    let mut copy = wire::draw_copy_bitmap(0, 0, 0, 64, 64, 1, &vec![0x40; 64 * 64 * 4]);
    copy.truncate(copy.len() - 100);
    let addr = fake_server(
        0,
        true,
        vec![surface(64, 64), Out::Msg(msg::DISPLAY_DRAW_COPY, copy)],
    )
    .await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("a bitmap of 16384 bytes"), "{reason}");
}

#[tokio::test]
async fn an_image_past_the_size_limit_is_refused() {
    let copy = wire::draw_copy_bitmap(0, 0, 0, 5000, 1, 1, &vec![0; 5000 * 4]);
    let addr = fake_server(
        0,
        true,
        vec![surface(64, 64), Out::Msg(msg::DISPLAY_DRAW_COPY, copy)],
    )
    .await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("an image of 5000x1"), "{reason}");
}

#[tokio::test]
async fn clip_rectangles_past_the_limit_are_refused() {
    // DisplayBase with a RECTS clip claiming 5000 rectangles.
    let mut fill = 0u32.to_le_bytes().to_vec();
    for v in [0i32, 0, 10, 10] {
        fill.extend_from_slice(&v.to_le_bytes());
    }
    fill.push(1);
    fill.extend_from_slice(&5000u32.to_le_bytes());
    let addr = fake_server(
        0,
        true,
        vec![surface(64, 64), Out::Msg(msg::DISPLAY_DRAW_FILL, fill)],
    )
    .await;
    let (state, id) = client(addr, silent()).await.unwrap();
    let reason = ended(&state, id).await;
    assert!(reason.contains("5000 clip rects"), "{reason}");
}

#[tokio::test]
async fn a_main_channel_that_never_sends_init_fails_the_connection() {
    let addr = fake_server(300, false, vec![]).await;
    let err = client(addr, silent())
        .await
        .err()
        .expect("connected without INIT");
    assert!(
        format!("{err:#}").contains("no SPICE_MSG_MAIN_INIT"),
        "{err:#}"
    );
}

#[tokio::test]
async fn the_models_follow_up_chain_is_bounded() {
    // A model that answers every reading with another reading.
    let read =
        json!({"type": "static", "actions": [{"type": "spice_read_screen", "settle_ms": 0}]});
    let again = vec![
        json!({"event_pattern": "spice_connected", "handler": read}),
        json!({"event_pattern": "spice_screen", "handler": read}),
        json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
    ];
    let addr = fake_server(
        0,
        true,
        vec![surface(64, 64), Out::Msg(msg::DISPLAY_MARK, vec![])],
    )
    .await;
    let (state, id) = client(addr, again).await.unwrap();
    let mut last = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let n = events(&state, id, "spice_screen").await.len();
        if n == last && n > 0 {
            break;
        }
        last = n;
    }
    let n = events(&state, id, "spice_screen").await.len();
    assert!(
        (1..=netget::client::spice::MAX_FOLLOWUP_DEPTH as usize).contains(&n),
        "{n} readings: the chain did not stop at {}",
        netget::client::spice::MAX_FOLLOWUP_DEPTH
    );
}
