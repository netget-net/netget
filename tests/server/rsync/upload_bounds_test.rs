//! The upload bounds of NetGet's rsync daemon, driven by a hand-written protocol-29 client so
//! that the client can lie: list a file at one size and send more, send more file data than an
//! upload may carry, list more entries than an upload may hold, or name a path that puts a
//! multi-byte character across the cut of the daemon's error message. Static handlers play the
//! model; no rsync binary and no LLM are involved.
use netget::cli::management::ServerForm;
use netget::server::rsync::wire::{
    self, Entry, FlistLimits, FlistWriter, Kind, MuxReader, Request,
};
use netget::server::rsync::{self, MAX_UPLOAD_BYTES, MAX_UPLOAD_FILE_BYTES};
use netget::state::app_state::AppState;
use netget::state::server::ConnectionStatus;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A daemon whose model answers every `rsync_upload_request` with `upload_answer` and every
/// other event with nothing.
async fn daemon(upload_answer: Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "rsync".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern":"rsync_upload_request","handler":{"type":"static","actions":[upload_answer]}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

fn accept_all() -> Value {
    json!({"type": "rsync_accept_upload"})
}

/// Every `kind` event the daemon raised so far.
async fn events(state: &AppState, id: ServerId, kind: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .into_iter()
        .filter(|e| e.event_type == kind)
        .map(|e| e.request)
        .collect()
}

/// Wait until every connection the daemon accepted has ended. The completion event, when there
/// is one, is raised before the connection is marked closed.
async fn closed(state: &AppState, id: ServerId) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if s.connections
                    .values()
                    .all(|c| matches!(c.status, ConnectionStatus::Closed))
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the daemon did not close the connection");
}

/// What an uploading client asks for: `-r` into the root of module `inbox`.
fn request() -> Request {
    Request {
        recursive: true,
        ..Default::default()
    }
}

fn file(path: &str, declared: u64) -> Entry {
    Entry {
        path: path.into(),
        kind: Kind::File,
        data: vec![],
        mode: wire::S_IFREG | 0o644,
        mtime: 1_700_000_000,
        uid: 0,
        gid: 0,
        size: declared,
    }
}

/// A character device: listed by mode only, and skipped by the daemon's reader.
fn device(i: usize) -> Entry {
    Entry {
        mode: 0o020644,
        ..file(&format!("dev{i:05}"), 0)
    }
}

/// The list as an uploading client sends it at protocol 29 (raw, no multiplexing).
fn list_bytes(entries: &[Entry]) -> Vec<u8> {
    let r = request();
    let mut out = Vec::new();
    let mut w = FlistWriter::default();
    for e in entries {
        w.entry(e, false, &r, &mut out);
    }
    FlistWriter::finish(&r, 0, &mut out);
    out
}

struct Push {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    seed: i32,
}

async fn line(rd: &mut OwnedReadHalf) -> String {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        rd.read_exact(&mut b)
            .await
            .expect("the daemon closed during the handshake");
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    String::from_utf8(out).unwrap()
}

/// The handshake of an upload to `inbox/`, up to the checksum seed.
async fn push(port: u16) -> Push {
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut rd, mut wr) = s.into_split();
    assert_eq!(line(&mut rd).await, "@RSYNCD: 29.0");
    wr.write_all(b"@RSYNCD: 29.0\ninbox\n").await.unwrap();
    assert_eq!(line(&mut rd).await, "@RSYNCD: OK");
    wr.write_all(b"--server\n-r\n.\ninbox/\n\n").await.unwrap();
    let mut seed = [0u8; 4];
    rd.read_exact(&mut seed).await.unwrap();
    Push {
        rd,
        wr,
        seed: i32::from_le_bytes(seed),
    }
}

/// Answer each file the daemon requests with `payload(index)` as literal tokens and its MD4,
/// then make the end-of-run exchange.
async fn exchange(
    mux: &mut MuxReader<&mut OwnedReadHalf>,
    wr: &mut OwnedWriteHalf,
    seed: i32,
    payload: &dyn Fn(usize) -> Vec<u8>,
) -> anyhow::Result<()> {
    loop {
        let ndx = mux.int().await?;
        if ndx == wire::NDX_DONE {
            break;
        }
        let _iflags = mux.short().await?;
        for _ in 0..4 {
            mux.int().await?;
        }
        let data = payload(ndx as usize);
        let mut reply = wire::le32(ndx).to_vec();
        reply.extend_from_slice(&(wire::ITEM_TRANSFER | wire::ITEM_IS_NEW).to_le_bytes());
        for _ in 0..4 {
            reply.extend_from_slice(&wire::le32(0));
        }
        for chunk in data.chunks(wire::CHUNK) {
            reply.extend_from_slice(&wire::le32(chunk.len() as i32));
            reply.extend_from_slice(chunk);
        }
        reply.extend_from_slice(&wire::le32(0));
        reply.extend_from_slice(&wire::file_sum(seed, &data));
        wr.write_all(&reply).await?;
    }
    wr.write_all(&wire::le32(wire::NDX_DONE)).await?;
    for _ in 0..2 {
        anyhow::ensure!(
            mux.int().await? == wire::NDX_DONE,
            "the daemon did not end its phases"
        );
    }
    let mut two = wire::le32(wire::NDX_DONE).to_vec();
    two.extend_from_slice(&wire::le32(wire::NDX_DONE));
    wr.write_all(&two).await?;
    anyhow::ensure!(
        mux.int().await? == wire::NDX_DONE,
        "the daemon sent no final DONE"
    );
    Ok(())
}

/// Send `entries` as the upload's list and serve the daemon's requests. Returns the messages
/// the daemon sent and whether the run ended cleanly; both halves are closed on return.
async fn run(
    p: Push,
    entries: &[Entry],
    payload: impl Fn(usize) -> Vec<u8>,
) -> (Vec<(u8, String)>, anyhow::Result<()>) {
    let Push {
        mut rd,
        mut wr,
        seed,
    } = p;
    wr.write_all(&list_bytes(entries)).await.unwrap();
    let mut mux = MuxReader::new(&mut rd);
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        exchange(&mut mux, &mut wr, seed, &payload),
    )
    .await
    .expect("the exchange stalled");
    (mux.messages, result)
}

fn said(messages: &[(u8, String)], text: &str) -> bool {
    messages.iter().any(|(_, m)| m.contains(text))
}

/// A file that brings more data than its listed size is refused on its own, and none of its
/// data reaches the model; a file that keeps to its size is taken.
#[tokio::test]
async fn a_file_sending_more_than_its_listed_size_is_refused() {
    let (state, id, port) = daemon(accept_all()).await;
    let entries = [file("a.txt", 3), file("b.txt", 5)];
    let (messages, result) = run(push(port).await, &entries, |i| match i {
        0 => b"hello world".to_vec(),
        _ => b"hello".to_vec(),
    })
    .await;
    result.expect("the run ends cleanly");
    assert!(
        said(
            &messages,
            "rsync: [receiver] a.txt: more data than its listed size, file discarded"
        ),
        "{messages:?}"
    );
    closed(&state, id).await;
    let complete = events(&state, id, "rsync_upload_complete").await;
    assert_eq!(complete.len(), 1, "{complete:?}");
    let files = complete[0]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0]["path"], "b.txt");
    assert_eq!(files[0]["content"], "hello");
    assert_eq!(
        complete[0]["refused"],
        json!([{"path": "a.txt", "reason": "more data than its listed size"}])
    );
}

/// Files listed at size 0 that each send a whole MiB: the bytes received are counted as they
/// arrive, and past MAX_UPLOAD_BYTES the upload is refused and nothing reaches the model.
#[tokio::test]
async fn file_data_received_is_capped_for_the_whole_upload() {
    let (state, id, port) = daemon(accept_all()).await;
    let files = (MAX_UPLOAD_BYTES / MAX_UPLOAD_FILE_BYTES) as usize + 2;
    let entries: Vec<Entry> = (0..files).map(|i| file(&format!("f{i:02}"), 0)).collect();
    let (messages, result) = run(push(port).await, &entries, |_| {
        vec![b'x'; MAX_UPLOAD_FILE_BYTES as usize]
    })
    .await;
    assert!(result.is_err(), "the daemon must end the upload");
    let over = format!(
        "f{:02}: over this daemon's upload limit",
        MAX_UPLOAD_BYTES / MAX_UPLOAD_FILE_BYTES
    );
    assert!(said(&messages, &over), "{messages:?}");
    closed(&state, id).await;
    assert_eq!(events(&state, id, "rsync_upload_request").await.len(), 1);
    assert!(events(&state, id, "rsync_upload_complete").await.is_empty());
}

/// A refused upload still ends with the end-of-run exchange, and raises no completion event
/// (which would list its directories as received).
#[tokio::test]
async fn a_refused_upload_raises_no_completion_event() {
    let (state, id, port) =
        daemon(json!({"type": "rsync_refuse", "message": "inbox is closed"})).await;
    let mut entries = vec![
        Entry {
            kind: Kind::Dir,
            mode: wire::S_IFDIR | 0o755,
            size: 4096,
            ..file("d", 0)
        },
        file("d/f.txt", 2),
    ];
    wire::sort(&mut entries);
    let (messages, result) = run(push(port).await, &entries, |_| b"hi".to_vec()).await;
    result.expect("a refusal still ends the run cleanly");
    assert!(said(&messages, "inbox is closed"), "{messages:?}");
    closed(&state, id).await;
    assert_eq!(events(&state, id, "rsync_upload_request").await.len(), 1);
    assert!(events(&state, id, "rsync_upload_complete").await.is_empty());
}

/// A path that puts a two-byte character across the message cut: the refusal naming it is
/// sent, cut on a character boundary, and the run goes on.
#[tokio::test]
async fn a_refusal_naming_a_multibyte_path_is_cut_on_a_character_boundary() {
    let (state, id, port) = daemon(accept_all()).await;
    // "rsync: [receiver] " is 18 bytes, so the first "é" spans bytes 3999 and 4000.
    let prefix = "rsync: [receiver] ";
    let name = format!(
        "{}{}",
        "a".repeat(rsync::MAX_MESSAGE_BYTES - 1 - prefix.len()),
        "é".repeat(20)
    );
    let entries = [file(&name, MAX_UPLOAD_FILE_BYTES + 1)];
    let (messages, result) = run(push(port).await, &entries, |_| vec![]).await;
    result.expect("the run ends cleanly");
    let full = format!("{prefix}{name}: larger than this daemon accepts");
    let cut = messages
        .iter()
        .map(|(_, m)| m)
        .find(|m| m.starts_with(prefix))
        .unwrap_or_else(|| panic!("no refusal in {messages:?}"));
    assert!(cut.len() <= rsync::MAX_MESSAGE_BYTES, "{}", cut.len());
    assert!(full.starts_with(cut.as_str()));
    closed(&state, id).await;
    let complete = events(&state, id, "rsync_upload_complete").await;
    assert_eq!(
        complete[0]["refused"],
        json!([{"path": name, "reason": "larger than this daemon accepts"}])
    );
}

#[test]
fn message_text_cuts_on_a_character_boundary() {
    for pad in rsync::MAX_MESSAGE_BYTES - 5..=rsync::MAX_MESSAGE_BYTES {
        for ch in ["é", "€", "😀"] {
            let text = format!("{}{}", "a".repeat(pad), ch.repeat(8));
            let t = rsync::message_text(&text);
            assert!(t.ends_with('\n'));
            let body = t.trim_end_matches('\n');
            assert!(body.len() <= rsync::MAX_MESSAGE_BYTES, "{pad} {ch}");
            assert!(text.starts_with(body), "{pad} {ch}");
        }
    }
    assert_eq!(rsync::message_text("short"), "short\n");
}

/// An uploading client's list is bounded in entries (skipped devices included) and in name
/// bytes; a downloading client's list keeps the larger download bounds.
#[tokio::test]
async fn an_upload_list_is_bounded_in_entries_and_name_bytes() {
    let r = request();
    let at: Vec<Entry> = (0..wire::MAX_UPLOAD_LIST_ENTRIES).map(device).collect();
    let bytes = list_bytes(&at);
    let (got, _) = MuxReader::raw(&bytes[..])
        .file_list_bounded(&r, FlistLimits::UPLOAD)
        .await
        .unwrap();
    assert!(got.is_empty(), "devices are skipped");

    let over: Vec<Entry> = (0..=wire::MAX_UPLOAD_LIST_ENTRIES).map(device).collect();
    let bytes = list_bytes(&over);
    let err = MuxReader::raw(&bytes[..])
        .file_list_bounded(&r, FlistLimits::UPLOAD)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("file-list entries"), "{err}");
    MuxReader::raw(&bytes[..]).file_list(&r).await.unwrap();

    let n = wire::MAX_UPLOAD_LIST_NAME_BYTES / 4000 + 1;
    let long: Vec<Entry> = (0..n)
        .map(|i| file(&format!("{i:05}{}", "n".repeat(3995)), 1))
        .collect();
    let bytes = list_bytes(&long);
    let err = MuxReader::raw(&bytes[..])
        .file_list_bounded(&r, FlistLimits::UPLOAD)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("bytes of file-list names"),
        "{err}"
    );
    let (got, _) = MuxReader::raw(&bytes[..]).file_list(&r).await.unwrap();
    assert_eq!(got.len(), n);
}

/// Over the entry bound, the daemon refuses the list itself: the client is told, and the model
/// never sees it.
#[tokio::test]
async fn the_daemon_refuses_an_oversized_upload_list_before_the_model() {
    let (state, id, port) = daemon(accept_all()).await;
    let over: Vec<Entry> = (0..=wire::MAX_UPLOAD_LIST_ENTRIES).map(device).collect();
    let (messages, result) = run(push(port).await, &over, |_| vec![]).await;
    assert!(result.is_err(), "the daemon must end the upload");
    assert!(said(&messages, "file list refused"), "{messages:?}");
    closed(&state, id).await;
    assert!(events(&state, id, "rsync_upload_request").await.is_empty());
}
