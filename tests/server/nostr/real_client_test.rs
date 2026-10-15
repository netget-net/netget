//! The Nostr relay against real, independent clients: `nak` and rust-nostr.
//!
//! **nak** (fiatjaf's "nostr army knife", Go, built on go-nostr and coder/websocket) is run as a
//! subprocess. It shares no code with NetGet: not the WebSocket framing (NetGet frames with
//! tungstenite), not the JSON, not the id or signature code. What it printed is asserted:
//!
//! * `nak event` builds and signs an event with its own key and reports the relay's `OK`;
//! * `nak req` sends a REQ, reads `EVENT`s until `EOSE` and **verifies each event's id and
//!   signature itself** (it has a `--no-verify` flag to turn that off, which these tests never
//!   pass) — and each event it printed is then fed to `nak verify` as well;
//! * `nak relay` reads the NIP-11 document.
//!
//! **rust-nostr** (`pip install nostr-sdk`, the Python bindings of the Rust `nostr` crate) is the
//! second client: it publishes through its own relay pool and fetches through its own filter and
//! event types, verifying signatures as it goes. It is independent of NetGet's NIP-01 code; its
//! WebSocket layer is also tungstenite-based, which is why nak — a different WebSocket stack —
//! carries the framing evidence and rust-nostr the protocol evidence.
//!
//! **These tests FAIL, they do not skip, when nak or nostr-sdk is absent.**
//!
//! Every case but the last is model-free (static and script handlers). The last puts a mocked
//! model behind nak, because the model path is what the relay exists for. The first also relays
//! nak's connection through a recorder and runs the pcap oracle (Wireshark's HTTP and WebSocket
//! dissectors) over what crossed the wire.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features nostr --test server -- nostr::real_client --test-threads=100


use super::common::{
    self, relay_handlers, require_tool, run_nak, Chunk, Recorder, AUTHOR_PUBKEY, AUTHOR_SECRET,
    RELAY_SECRET,
};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::server::nostr::wire::RelayKey;
use serde_json::{json, Value};
use std::time::Duration;

fn relay_pubkey() -> String {
    RelayKey::from_hex(RELAY_SECRET)
        .unwrap()
        .pubkey_hex()
        .to_string()
}

fn pinned_key() -> Option<Value> {
    Some(json!({"relay_secret_key": RELAY_SECRET}))
}

/// Every JSON line nak printed on stdout.
fn events_printed(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("nak prints one event per line"))
        .collect()
}

/// `nak verify` on one event; it prints nothing and exits 0 when the id and signature hold.
async fn nak_verifies(event: &Value) {
    let (code, stdout, stderr) = run_nak(&["verify"], Some(&event.to_string())).await;
    assert_eq!(
        code, 0,
        "nak verify rejected an event NetGet signed: {event}\n{stdout}{stderr}"
    );
}

/// Accept notes unless they mention spam; answer every REQ with four events, three of which
/// are kind 1 and one of those older than the tests' `since`.
const RELAY_SCRIPT: &str = r#"import json, sys
i = json.load(sys.stdin)
e = i['event']
if i['event_type_id'] == 'nostr_event':
    if 'spam' in e['content']:
        a = [{'type': 'reject_nostr_event', 'reason': 'blocked: no spam here'}]
    else:
        a = [{'type': 'accept_nostr_event'}]
else:
    a = [{'type': 'send_nostr_events', 'events': [
        {'kind': 1, 'content': 'Review: Stalker (1979)', 'tags': [['t', 'film']], 'created_at': 1700000100},
        {'kind': 7, 'content': '+', 'created_at': 1700000200},
        {'kind': 1, 'content': 'Review: Solaris (1972)', 'tags': [['t', 'film']], 'created_at': 1700000300},
        {'kind': 1, 'content': 'an old note', 'created_at': 1600000000},
    ]}]
print(json.dumps({'actions': a}))
"#;

fn script_handler() -> Vec<Value> {
    vec![json!({
        "event_pattern": "*",
        "handler": {"type": "script", "language": "python", "code": RELAY_SCRIPT}
    })]
}

#[tokio::test]
async fn nak_publishes_and_the_pcap_oracle_reads_clean_http_and_websocket() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, script_handler(), pinned_key()).await;
    let relay = Recorder::start(port).await;

    let url = format!("ws://127.0.0.1:{}", relay.port);
    let (code, stdout, stderr) = run_nak(
        &[
            "event",
            "--sec",
            AUTHOR_SECRET,
            "-c",
            "hello from nak",
            &url,
        ],
        None,
    )
    .await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains("success"),
        "nak reports the relay's OK true as success: {stderr}"
    );
    let published = &events_printed(&stdout)[0];
    assert_eq!(published["pubkey"], AUTHOR_PUBKEY);
    let lines = common::wait_for_log(&mut rx, "decision=model_answer", 10).await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains(published["id"].as_str().unwrap())),
        "the relay decided on the event nak signed: {lines:#?}"
    );

    let chunks = relay.finished(30).await;
    let mut oracle = PcapOracle::tcp("nostr");
    for chunk in &chunks {
        oracle = match chunk {
            Chunk::ToServer(b) => oracle.to_server(b),
            Chunk::FromServer(b) => oracle.from_server(b),
        };
    }
    let report = oracle.check().expect("tshark ran");
    assert!(report.is_clean(), "{:#?}", report.failures);
    // `http` in each direction would satisfy the oracle's own check on the handshake alone;
    // the frames after it must be read as WebSocket, both ways (the text payload shows as
    // data-text-lines: Wireshark reads WebSocket text as JSON only with a preference set).
    for (dir, label) in [
        (crate::helpers::pcap_oracle::Dir::ToServer, "client"),
        (crate::helpers::pcap_oracle::Dir::FromServer, "relay"),
    ] {
        assert!(
            report
                .packets
                .iter()
                .any(|p| p.dir == Some(dir) && p.protocols.contains("websocket")),
            "no {label} packet dissected as websocket: {:#?}",
            report.packets
        );
    }
}

#[tokio::test]
async fn nak_reads_a_rejection_with_its_reason() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, script_handler(), None).await;
    let url = format!("ws://127.0.0.1:{port}");
    let (code, stdout, stderr) = run_nak(
        &["event", "--sec", AUTHOR_SECRET, "-c", "buy spam now", &url],
        None,
    )
    .await;
    let out = format!("{stdout}{stderr}");
    assert!(
        out.contains("blocked: no spam here"),
        "nak prints the OK false message: {out}"
    );
    assert!(
        !stderr.contains("success"),
        "a rejected event is not a success: {out}"
    );
    let _ = code;
}

#[tokio::test]
async fn nak_req_receives_exactly_the_matching_events_and_verifies_them() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, script_handler(), pinned_key()).await;
    let url = format!("ws://127.0.0.1:{port}");

    let (code, stdout, stderr) =
        run_nak(&["req", "-k", "1", "--since", "1700000000", &url], None).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let events = events_printed(&stdout);
    let contents: Vec<&str> = events
        .iter()
        .map(|e| e["content"].as_str().unwrap())
        .collect();
    assert_eq!(
        contents.len(),
        2,
        "kind 7 and the note older than since are filtered out by NetGet: {contents:?}"
    );
    assert!(contents.contains(&"Review: Stalker (1979)"), "{contents:?}");
    assert!(contents.contains(&"Review: Solaris (1972)"), "{contents:?}");
    for event in &events {
        assert_eq!(
            event["pubkey"],
            relay_pubkey(),
            "the model's events are signed by the relay's key"
        );
        assert_eq!(event["kind"], 1);
        assert_eq!(event["tags"], json!([["t", "film"]]));
        nak_verifies(event).await;
    }
    common::wait_for_log(&mut rx, "then EOSE", 10).await;

    // limit: the newest one only.
    let (code, stdout, _) = run_nak(&["req", "-k", "1", "-l", "1", &url], None).await;
    assert_eq!(code, 0);
    let events = events_printed(&stdout);
    assert_eq!(events.len(), 1, "{stdout}");
    assert_eq!(events[0]["content"], "Review: Solaris (1972)");

    // A tag filter.
    let (_, stdout, _) = run_nak(&["req", "-t", "t=film", &url], None).await;
    assert_eq!(events_printed(&stdout).len(), 2, "{stdout}");

    // An authors filter naming someone else: nothing the relay signs can match it.
    let (_, stdout, _) = run_nak(&["req", "-a", AUTHOR_PUBKEY, &url], None).await;
    assert!(events_printed(&stdout).is_empty(), "{stdout}");
}

#[tokio::test]
async fn nak_reads_the_nip11_document() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        Vec::new(),
        Some(json!({
            "relay_name": "Film club relay",
            "relay_description": "Notes about films",
            "relay_secret_key": RELAY_SECRET,
        })),
    )
    .await;
    let (code, stdout, stderr) = run_nak(&["relay", &format!("ws://127.0.0.1:{port}")], None).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let info: Value = serde_json::from_str(stdout.trim()).expect("nak prints the document");
    assert_eq!(info["name"], "Film club relay");
    assert_eq!(info["description"], "Notes about films");
    assert_eq!(info["supported_nips"], json!([1, 11]));
    assert_eq!(info["self"], relay_pubkey());
    assert_eq!(
        info["limitation"]["max_message_length"],
        netget::server::nostr::MAX_MESSAGE_BYTES
    );
}

#[tokio::test]
async fn an_accepted_event_reaches_a_streaming_subscriber_with_its_own_signature() {
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, relay_handlers(json!([])), None).await;
    let url = format!("ws://127.0.0.1:{port}");

    let nak = require_tool("nak");
    let mut subscriber = tokio::process::Command::new(&nak)
        .args(["req", "--stream", "-k", "1", "-t", "t=live", &url])
        // nak reads a filter from stdin when stdin is not a terminal.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn nak req --stream");
    let stdout = subscriber.stdout.take().unwrap();
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stdout));

    // Publish until the subscriber has seen it: its REQ may reach the relay after the first
    // publish, and a relay keeps nothing to replay.
    let mut received = None;
    for attempt in 0..20 {
        let content = format!("live note {attempt}");
        let (code, out, err) = run_nak(
            &[
                "event",
                "--sec",
                AUTHOR_SECRET,
                "-t",
                "t=live",
                "-c",
                &content,
                &url,
            ],
            None,
        )
        .await;
        assert_eq!(code, 0, "{out}{err}");
        if let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_millis(500), lines.next_line()).await
        {
            received = Some((line, events_printed(&out).remove(0)));
            break;
        }
    }
    let Some((line, published)) = received else {
        let _ = subscriber.start_kill();
        let output = subscriber.wait_with_output().await.expect("nak req output");
        panic!(
            "the streaming subscriber never received the event; its stderr:\n{}\nrelay log:\n{:#?}",
            String::from_utf8_lossy(&output.stderr),
            common::drain(&mut rx)
        );
    };
    let got: Value = serde_json::from_str(&line).expect("nak prints the event");
    assert_eq!(
        got, published,
        "the subscriber got the publisher's event byte for byte: its author, id and signature"
    );
    let _ = subscriber.kill().await;
}

/// Drives rust-nostr's Python bindings: publish one note, then fetch kind-1 events.
const NOSTR_SDK_DRIVER: &str = r#"import asyncio, json, sys
from datetime import timedelta
from nostr_sdk import Client, EventBuilder, Filter, Keys, Kind, RelayUrl, ReqTarget

async def main():
    url = RelayUrl.parse(sys.argv[1])
    keys = Keys.parse(sys.argv[2])
    client = Client()
    await client.add_relay(url)
    await client.try_connect(timedelta(seconds=10))
    out = {}
    event = EventBuilder(Kind(1), "hello from rust-nostr").finalize(keys)
    sent = await client.send_event(event)
    out['published_id'] = event.id().to_hex()
    out['published_ok'] = [str(u) for u in sent.success]
    out['published_failed'] = {str(k): v for k, v in sent.failed.items()}
    target = ReqTarget.auto([Filter().kind(Kind(1))])
    events = await client.fetch_events(target, timedelta(seconds=10))
    out['fetched'] = [json.loads(e.as_json()) for e in events]
    await client.shutdown()
    print(json.dumps(out))

asyncio.run(main())
"#;

fn require_nostr_sdk() {
    let probe = std::process::Command::new("python3")
        .args(["-c", "import nostr_sdk"])
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        other => panic!(
            "the Python Nostr client `nostr-sdk` (rust-nostr's bindings) is not importable \
             ({other:?}). This test drives it against NetGet's relay as the second independent \
             client; skipping would leave that evidence resting on nothing, so this is a \
             failure and not a skip. Install with `python3 -m pip install nostr-sdk`."
        ),
    }
}

#[tokio::test]
async fn rust_nostr_publishes_and_fetches() {
    require_nostr_sdk();
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(&state, script_handler(), pinned_key()).await;
    let url = format!("ws://127.0.0.1:{port}");

    let mut command = tokio::process::Command::new("python3");
    command
        .args(["-c", NOSTR_SDK_DRIVER, &url, AUTHOR_SECRET])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(90), command.output())
        .await
        .expect("the nostr-sdk driver did not finish within 90s")
        .expect("run python3");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    println!(
        "--- python3 -c <nostr-sdk driver> {url} (exit {:?}) ---\n{stdout}{stderr}",
        output.status.code()
    );
    assert!(output.status.success(), "{stderr}");
    let out: Value = serde_json::from_str(stdout.trim()).expect("driver prints JSON");

    assert_eq!(
        out["published_ok"].as_array().map(Vec::len),
        Some(1),
        "rust-nostr read the relay's OK true: {out}"
    );
    let fetched = out["fetched"].as_array().expect("fetched");
    let mut contents: Vec<&str> = fetched
        .iter()
        .map(|e| e["content"].as_str().unwrap())
        .collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![
            "Review: Solaris (1972)",
            "Review: Stalker (1979)",
            "an old note"
        ],
        "rust-nostr kept every kind-1 event the relay sent and verified: {out}"
    );
    for event in fetched {
        assert_eq!(event["pubkey"], relay_pubkey());
    }
}

/// The model path, behind nak.
#[tokio::test]
async fn nak_talks_to_a_relay_the_model_answers() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via nostr. A relay for film notes.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("via nostr")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "nostr",
                "instruction": "A relay for film notes"
            }]))
            .expect_calls(1)
            .and()
            .on_event("nostr_event")
            .and_event_data_contains("content", "Stalker is a masterpiece")
            .respond_with_actions(json!([{"type": "accept_nostr_event"}]))
            .expect_calls(1)
            .and()
            .on_event("nostr_req")
            .respond_with_actions(json!([{
                "type": "send_nostr_events",
                "events": [{"kind": 1, "content": "Tonight: Stalker at 8pm", "tags": [["t", "film"]]}]
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let url = format!("ws://127.0.0.1:{}", server.port);
    let (code, stdout, stderr) = run_nak(
        &[
            "event",
            "--sec",
            AUTHOR_SECRET,
            "-c",
            "Stalker is a masterpiece",
            &url,
        ],
        None,
    )
    .await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stderr.contains("success"), "{stderr}");

    let (code, stdout, stderr) = run_nak(&["req", "-k", "1", &url], None).await;
    assert_eq!(code, 0, "{stdout}{stderr}");
    let events = events_printed(&stdout);
    assert_eq!(events.len(), 1, "{stdout}");
    assert_eq!(events[0]["content"], "Tonight: Stalker at 8pm");
    nak_verifies(&events[0]).await;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
