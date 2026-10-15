//! The dashboard's `[ send ]` path on a BitTorrent tracker client: `AppState::send_to_client`
//! injects a `tracker_announce` from outside the client's own loop and the announce reaches a
//! stub tracker on loopback.
//!
//! Zero LLM calls and no external endpoint: a `*` static handler with no actions answers every
//! client event, and the client's LLM points at an unreachable URL anyway.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features torrent-tracker --test client -- torrent_tracker::command_channel --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// Every client event is answered by a no-action static handler, so nothing in this test
/// reaches an LLM backend.
fn no_llm_handlers() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "event_pattern": "*",
        "handler": { "type": "static", "actions": [] }
    })]
}

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
        "Tracker client #{} never registered a command handle",
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

/// Read one whole HTTP/1.1 request (headers plus a Content-Length body) off the socket.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(idx) = text.find("\r\n\r\n") {
            let content_len = text[..idx]
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= idx + 4 + content_len {
                return Some(text);
            }
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

/// A loopback HTTP/1.1 stub. Records every request it sees and answers each with whatever
/// `respond` returns for it. Bound to 127.0.0.1, so no external endpoint is contacted.
async fn spawn_http_stub<F>(respond: F) -> (u16, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let respond: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_task.clone();
            let respond = respond.clone();
            tokio::spawn(async move {
                let request = read_request(&mut socket).await.unwrap_or_default();
                let body = respond(&request);
                seen.lock().await.push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// A minimal bencoded announce/scrape reply. `TrackerResponse`'s fields are all optional,
/// so an interval and peer counts are enough to parse.
fn tracker_stub_body(_request: &str) -> String {
    "d8:intervali1800e8:completei1e10:incompletei0ee".to_string()
}

async fn open_client(state: &AppState, port: u16, tx: mpsc::UnboundedSender<String>) -> ClientId {
    ClientForm {
        protocol: "torrent_tracker".to_string(),
        remote_addr: Some(format!("http://127.0.0.1:{port}/announce")),
        instruction: Some("test client".to_string()),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create torrent tracker client")
}

#[tokio::test]
async fn injected_announce_reaches_the_tracker() {
    let (port, seen) = spawn_http_stub(tracker_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;

    // Rule 2's regression guard: the handle exists before anything is injected. A tracker
    // client has no read loop at all, so this task is the only thing that can reach it.
    wait_for_client_handle(&state, client_id).await;

    // The command loop awaits the announce, so the outcome describes an HTTP GET that
    // really completed - but reqwest owns the socket, so there is no honest byte count and
    // it reports Executed rather than Sent.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "tracker_announce",
                "info_hash": "dashboardmarkerhash1",
                "peer_id": "dashboardmarkerpeer1",
                "port": 6881,
                "uploaded": 0,
                "downloaded": 0,
                "left": 0,
                "event": "started"
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("tracker_announce"),
            "unexpected detail: {detail}"
        ),
        other => panic!("expected Executed, got {other:?}"),
    }

    let requests = seen.lock().await.clone();
    assert!(
        requests
            .iter()
            .any(|r| r.contains("/announce?") && r.contains("dashboardmarkerhash1")),
        "stub tracker never saw the announce: {requests:?}"
    );

    wait_for_log_containing(
        &state,
        AccessLogOwner::Client(client_id.as_u32()),
        "injected_action",
    )
    .await;
}

/// A model-supplied `info_hash` cannot add query parameters of its own.
///
/// The announce URL is built with `format!`, so before these values were percent-encoded an
/// `&` in one of them was a separator: the model was asked to announce a torrent and could
/// instead append `&event=completed`, overwrite `port`, or cut the query short with a `#`.
/// The value is normalised to twenty bytes and encoded exactly once, whichever of the three
/// spellings a model uses.
#[tokio::test]
async fn a_model_supplied_info_hash_cannot_inject_query_parameters() {
    let (port, seen) = spawn_http_stub(tracker_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;
    wait_for_client_handle(&state, client_id).await;

    state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "tracker_announce",
                // Separators, and a fragment that would truncate everything after it.
                "info_hash": "abc&event=completed&port=1#x",
                "peer_id": "-NG0001-abcdefghijkl",
                "port": 6881
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");

    let requests = seen.lock().await.clone();
    let announce = requests
        .iter()
        .find(|r| r.contains("/announce?"))
        .unwrap_or_else(|| panic!("stub tracker never saw the announce: {requests:?}"))
        .clone();
    let line = announce.lines().next().unwrap_or_default().to_string();

    // The injected text is escaped, so it is one parameter value and not four.
    assert!(
        line.contains("%26event%3Dcompleted"),
        "the `&` and `=` must be escaped, not passed through as separators: {line}"
    );
    assert!(
        line.contains("%23x"),
        "the `#` must be escaped or it truncates the query: {line}"
    );
    assert_eq!(
        line.matches("event=").count(),
        1,
        "exactly one `event=` parameter -- the injected one must not have become a second: \
         {line}"
    );
    assert_eq!(
        line.matches("port=").count(),
        1,
        "exactly one `port=` parameter: {line}"
    );

    // `left` is omitted above. BEP 3 reads `left=0` as "I have the complete torrent", so a
    // model that says nothing must not be announced as a seeder.
    assert!(
        !line.contains("left=0&") && !line.contains("left=0 "),
        "an omitted `left` must not default to 0, which claims a complete torrent: {line}"
    );
}

/// Whichever of the three spellings the model uses, the same twenty bytes reach the tracker.
#[tokio::test]
async fn info_hash_spellings_all_normalise_to_the_same_twenty_bytes() {
    let (port, seen) = spawn_http_stub(tracker_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;
    wait_for_client_handle(&state, client_id).await;

    // The same twenty bytes written as 40 hex characters, and pre-percent-encoded. Blind
    // escaping would have turned the second into `%2512...`, i.e. the literal characters.
    for spelling in [
        "123456789abcdef0123456789abcdef012345678",
        "%12%34%56%78%9a%bc%de%f0%12%34%56%78%9a%bc%de%f0%12%34%56%78",
    ] {
        let hash = if spelling.len() == 40 {
            "123456789abcdef0123456789abcdef012345678"
        } else {
            spelling
        };
        state
            .send_to_client(
                client_id,
                serde_json::json!({
                    "type": "tracker_announce",
                    "info_hash": hash,
                    "peer_id": "-NG0001-abcdefghijkl",
                    "port": 6881
                }),
                Duration::from_secs(30),
            )
            .await
            .expect("send_to_client");
    }

    let requests = seen.lock().await.clone();
    let hashes: Vec<String> = requests
        .iter()
        .filter_map(|r| r.lines().next())
        .filter_map(|line| {
            let start = line.find("info_hash=")? + "info_hash=".len();
            let rest = &line[start..];
            let end = rest.find('&').unwrap_or(rest.len());
            Some(rest[..end].to_string())
        })
        .collect();
    assert_eq!(hashes.len(), 2, "expected two announces, got {requests:?}");
    assert_eq!(
        hashes[0], hashes[1],
        "40 hex characters and the pre-encoded form must produce the same bytes on the wire"
    );
}

#[tokio::test]
async fn injected_unknown_action_is_rejected_and_disconnect_drops_the_handle() {
    let (port, _seen) = spawn_http_stub(tracker_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = open_client(&state, port, tx.clone()).await;
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "not_a_tracker_action"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client rejected action");
    assert!(
        matches!(outcome, ClientSendOutcome::Rejected { .. }),
        "expected Rejected, got {outcome:?}"
    );

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({"type": "disconnect"}),
            Duration::from_secs(10),
        )
        .await
        .expect("send_to_client disconnect");
    assert!(
        matches!(outcome, ClientSendOutcome::Disconnected),
        "expected Disconnected, got {outcome:?}"
    );

    for _ in 0..1_000 {
        if !state.has_client_handle(client_id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("command handle should be gone after an injected disconnect");
}

/// A bare `host:port` — what the dashboard's `[ + BitTorrent Tracker client ]` fills in —
/// announces to `http://host:port/announce`. The announce URL used to be built straight on the
/// bare address (`127.0.0.1:6969?info_hash=…`), which is not an absolute URL, so every request
/// failed before leaving the process.
#[tokio::test]
async fn a_bare_tracker_address_announces_over_http() {
    let (port, seen) = spawn_http_stub(tracker_stub_body).await;
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let client_id = ClientForm {
        protocol: "torrent_tracker".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("test client".to_string()),
        event_handlers: Some(no_llm_handlers()),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx,
    )
    .await
    .expect("create torrent tracker client");
    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "tracker_announce",
                "info_hash": "baretrackermarker001",
                "peer_id": "baretrackerpeer00001",
                "port": 6881,
                "uploaded": 0,
                "downloaded": 0,
                "left": 0,
                "event": "started"
            }),
            Duration::from_secs(30),
        )
        .await
        .expect("send_to_client");
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { detail } if detail.contains("tracker_announce")),
        "expected an executed announce, got {outcome:?}"
    );
    let requests = seen.lock().await.clone();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /announce?") && r.contains("baretrackermarker001")),
        "the stub tracker never saw an announce on /announce: {requests:?}"
    );
}

#[test]
fn tracker_urls_resolve_to_absolute_http_announce_urls() {
    use netget::client::torrent_tracker::resolve_tracker_url;
    assert_eq!(
        resolve_tracker_url("127.0.0.1:6969"),
        "http://127.0.0.1:6969/announce"
    );
    assert_eq!(
        resolve_tracker_url(" tracker.local:80/custom/announce "),
        "http://tracker.local:80/custom/announce"
    );
    assert_eq!(
        resolve_tracker_url("https://tracker.example/announce"),
        "https://tracker.example/announce"
    );
    assert_eq!(
        resolve_tracker_url("http://127.0.0.1:1/announce"),
        "http://127.0.0.1:1/announce"
    );
}
