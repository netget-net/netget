//! `REST`, `STOU`, `ABOR` and binary transfers, driven from a raw socket: each new bound from
//! both sides and each reply sequence byte for byte.
//!
//! | Bound | Under it | Over it |
//! |---|---|---|
//! | `REST` offset | equal to the file's length: `150`, nothing on the data connection, `226` | one past it: `554` and no `150` |
//! | `max_hex_upload_bytes` (8) | an 8-byte binary upload reaches the handler as `upload_hex` | 9 bytes reach it as `upload_bytes` alone |
//!
//! In-process server, mocked model. Loopback only.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// 23 bytes.
const NOTES: &str = "first line\nsecond line\n";
const BLOB: &[u8] = b"\x00\xff\r\n\x80\n\x1a";
/// More than a client with a 4 KiB receive buffer and the server's unread send buffer hold, so
/// the server is still writing when `ABOR` comes.
const HUGE: usize = 1024 * 1024;

fn mock_rules() -> MockLlmBuilder {
    let file = |command: &'static str, action: serde_json::Value| (command, action);
    let files = [
        file(
            "RETR notes.txt",
            json!([{"type": "send_ftp_data", "data": NOTES}]),
        ),
        file(
            "RETR blob.bin",
            json!([{"type": "send_ftp_data", "encoding": "hex", "data": hex::encode(BLOB)}]),
        ),
        file(
            "RETR spaced.bin",
            json!([{"type": "send_ftp_data", "encoding": "hex", "data": "00 ff\n0d0a"}]),
        ),
        file(
            "RETR badhex.bin",
            json!([{"type": "send_ftp_data", "encoding": "hex", "data": "zz"}]),
        ),
        file(
            "RETR base64.bin",
            json!([{"type": "send_ftp_data", "encoding": "base64", "data": "AP8="}]),
        ),
        file(
            "RETR huge.bin",
            json!([{"type": "send_ftp_data", "data": "x".repeat(HUGE)}]),
        ),
        file(
            "NOOP",
            json!([{"type": "send_ftp_response", "code": 200, "message": "noop ok"}]),
        ),
    ];
    let mut mock = MockLlmBuilder::new()
        .on_event("ftp_command")
        .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
        .respond_with_actions(
            json!([{"type": "send_ftp_response", "code": 220, "message": "ready"}]),
        )
        .expect_at_least(1)
        .and();
    for (command, action) in files {
        mock = mock
            .on_event("ftp_command")
            .and_event_data_contains("command", command)
            .respond_with_actions(action)
            .expect_at_least(0)
            .and();
    }
    // Every upload is answered with what reached the handler, so the client reads it back.
    for verb in ["STOR", "STOU", "APPE"] {
        mock = mock
            .on_event("ftp_command")
            .and_event_data_contains("command", verb)
            .respond_with_actions_from_event(|e| {
                json!([{
                    "type": "send_ftp_response",
                    "code": 226,
                    "message": format!(
                        "bytes={} hex={} restart={} name={}",
                        e["upload_bytes"],
                        e["upload_hex"].as_str().unwrap_or("-"),
                        e["restart_offset"],
                        e["unique_name"].as_str().unwrap_or("-")
                    )
                }])
            })
            .expect_at_least(0)
            .and();
    }
    mock
}

struct Ftp {
    _mock: MockOllamaServer,
    state: AppState,
    id: ServerId,
    port: u16,
}

async fn start(startup_params: serde_json::Value) -> Ftp {
    let mock = MockOllamaServer::start(mock_rules().build())
        .await
        .expect("mock ollama");
    let state = AppState::new_with_options(false, mock.base_url());
    state
        .set_llm_client(netget::llm::OllamaClient::new(mock.base_url()))
        .await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "ftp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some("Serve notes.txt and blob.bin; accept uploads.".to_string()),
        startup_params: Some(startup_params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("create ftp server");
    let mut port = 0;
    for _ in 0..300 {
        if let Some(addr) = state.get_server(id).await.and_then(|s| s.local_addr) {
            port = addr.port();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_ne!(port, 0, "server never bound");
    Ftp {
        _mock: mock,
        state,
        id,
        port,
    }
}

impl Ftp {
    /// How many times `command` reached the handler.
    async fn asked(&self, command: &str) -> usize {
        self.state
            .list_access_logs_for(
                Some(netget::state::AccessLogOwner::Server(self.id.as_u32())),
                None,
            )
            .await
            .iter()
            .filter(|e| {
                serde_json::to_string(e)
                    .unwrap_or_default()
                    .contains(command)
            })
            .count()
    }
}

struct Session {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Session {
    async fn open(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, w) = stream.into_split();
        let mut s = Self {
            reader: BufReader::new(r),
            writer: w,
        };
        let greeting = s.line().await;
        assert!(greeting.starts_with("220"), "{greeting}");
        s
    }

    async fn line(&mut self) -> String {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(20), self.reader.read_line(&mut line))
            .await
            .expect("no reply within 20s")
            .unwrap();
        assert!(n > 0, "control connection closed");
        assert!(
            line.ends_with("\r\n"),
            "reply not CRLF-terminated: {line:?}"
        );
        line.trim_end().to_string()
    }

    async fn write(&mut self, command: &str) {
        self.writer
            .write_all(format!("{command}\r\n").as_bytes())
            .await
            .unwrap();
    }

    async fn send(&mut self, command: &str) -> String {
        self.write(command).await;
        self.line().await
    }

    async fn epsv(&mut self) -> SocketAddr {
        let r = self.send("EPSV").await;
        let port: u16 = r
            .strip_prefix("229 Entering Extended Passive Mode (|||")
            .and_then(|rest| rest.strip_suffix("|)"))
            .unwrap_or_else(|| panic!("not a 229: {r}"))
            .parse()
            .unwrap();
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// `EPSV`, a download, and everything that crossed the data connection.
    async fn download(&mut self, command: &str) -> (String, Vec<u8>, String) {
        let data = self.epsv().await;
        let conn = TcpStream::connect(data).await.unwrap();
        let opening = self.send(command).await;
        let bytes = read_all(conn).await;
        let completion = self.line().await;
        (opening, bytes, completion)
    }

    /// `EPSV`, an upload of `bytes`, and the completion reply.
    async fn upload(&mut self, command: &str, bytes: &[u8]) -> (String, String) {
        let data = self.epsv().await;
        let mut conn = TcpStream::connect(data).await.unwrap();
        let opening = self.send(command).await;
        assert!(opening.starts_with("150 "), "{opening}");
        conn.write_all(bytes).await.unwrap();
        drop(conn);
        (opening, self.line().await)
    }
}

async fn read_all(mut stream: TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut data))
        .await
        .expect("data connection did not close")
        .unwrap();
    data
}

/// `send_ftp_data` with `encoding: "hex"` puts exactly those bytes on the wire in TYPE I, and
/// a hex field that does not decode, or an encoding that is not one of the two, is refused
/// (`451`) before any `150`.
#[tokio::test]
async fn binary_downloads_are_byte_exact_and_bad_encodings_fail_closed() {
    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    let (opening, bytes, completion) = s.download("RETR blob.bin").await;
    assert!(opening.starts_with("150 Opening BINARY mode"), "{opening}");
    assert_eq!(bytes, BLOB);
    assert_eq!(completion, "226 Transfer complete");

    // Whitespace between hex pairs is layout, not data.
    let (_, bytes, _) = s.download("RETR spaced.bin").await;
    assert_eq!(bytes, b"\x00\xff\r\n");

    for refused in ["RETR badhex.bin", "RETR base64.bin"] {
        let _ = s.epsv().await;
        assert_eq!(
            s.send(refused).await,
            "451 Requested action aborted: local error in processing",
            "{refused}"
        );
    }

    // TYPE A converts a hex file's line endings like any other file's.
    assert_eq!(s.send("TYPE A").await, "200 Type set to A");
    let (_, bytes, _) = s.download("RETR blob.bin").await;
    assert_eq!(bytes, b"\x00\xff\r\n\x80\r\n\x1a");
}

/// `max_hex_upload_bytes`, both sides: a binary upload of exactly the bound reaches the handler
/// as hex, one byte more as its size alone. A text upload is unaffected.
#[tokio::test]
async fn binary_uploads_reach_the_handler_as_bounded_hex() {
    let ftp = start(json!({"max_hex_upload_bytes": 8})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    let (_, reply) = s
        .upload("STOR eight.bin", b"\xff\x00\x01\x02\x03\x04\x05\x06")
        .await;
    assert_eq!(
        reply,
        "226 bytes=8 hex=ff00010203040506 restart=null name=-"
    );
    let (_, reply) = s
        .upload("STOR nine.bin", b"\xff\x00\x01\x02\x03\x04\x05\x06\x07")
        .await;
    assert_eq!(
        reply, "226 bytes=9 hex=- restart=null name=-",
        "a binary upload over max_hex_upload_bytes must reach the handler as its size alone"
    );
    let (_, reply) = s
        .upload("STOR text.txt", b"plain text, 25 bytes long")
        .await;
    assert_eq!(reply, "226 bytes=25 hex=- restart=null name=-");
}

/// `REST`: the marker skips that many bytes of the file the handler gave; at the file's length
/// the transfer is empty, one past it is `554` before any `150`; it is consumed by the transfer
/// after it, reaches a restarted `STOR` as `restart_offset`, and is never the handler's.
#[tokio::test]
async fn rest_restarts_retr_and_stor_within_the_file() {
    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    assert_eq!(
        s.send("REST 6").await,
        "350 Restarting at 6. Send STOR or RETR to start the transfer"
    );
    let (opening, bytes, completion) = s.download("RETR notes.txt").await;
    assert!(opening.contains("(17 bytes)"), "{opening}");
    assert_eq!(bytes, &NOTES.as_bytes()[6..]);
    assert_eq!(completion, "226 Transfer complete");

    // Consumed: the next RETR is the whole file again.
    let (_, bytes, _) = s.download("RETR notes.txt").await;
    assert_eq!(bytes, NOTES.as_bytes());

    // At the end of the file: an empty, successful transfer.
    assert!(s.send("REST 23").await.starts_with("350 "));
    let (opening, bytes, completion) = s.download("RETR notes.txt").await;
    assert!(opening.starts_with("150 "), "{opening}");
    assert!(bytes.is_empty());
    assert_eq!(completion, "226 Transfer complete");

    // One past it: refused before any 150, and the channel is spent.
    assert!(s.send("REST 24").await.starts_with("350 "));
    let _ = s.epsv().await;
    assert_eq!(
        s.send("RETR notes.txt").await,
        "554 Restart offset 24 is past the end of the file (23 bytes)"
    );
    assert_eq!(
        s.send("RETR notes.txt").await,
        "425 Use PASV, EPSV, PORT or EPRT first"
    );

    // A restarted STOR tells the handler where the upload begins.
    assert!(s.send("REST 100").await.starts_with("350 "));
    let (_, reply) = s.upload("STOR tail.bin", b"tail").await;
    assert_eq!(reply, "226 bytes=4 hex=- restart=100 name=-");

    // REST 0 clears the marker; a marker before a listing or APPE is dropped there.
    assert!(s.send("REST 9").await.starts_with("350 "));
    assert!(s.send("REST 0").await.starts_with("350 "));
    let (_, bytes, _) = s.download("RETR notes.txt").await;
    assert_eq!(bytes, NOTES.as_bytes());
    assert!(s.send("REST 9").await.starts_with("350 "));
    let (_, reply) = s.upload("APPE more.txt", b"more").await;
    assert_eq!(reply, "226 bytes=4 hex=- restart=null name=-");

    assert_eq!(
        s.send("REST x").await,
        "501 REST needs a byte offset (stream mode)"
    );
    assert_eq!(ftp.asked("REST").await, 0, "REST reached the handler");
}

/// `STOU`: the server names the file in its `150` (RFC 1123's `FILE: <name>`), and the handler
/// gets the same name.
#[tokio::test]
async fn stou_names_the_file_in_the_150_and_the_event() {
    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;

    let (opening, reply) = s.upload("STOU", b"unique\n").await;
    let name = opening
        .strip_prefix("150 FILE: ")
        .unwrap_or_else(|| panic!("not a STOU 150: {opening}"));
    assert!(name.starts_with("ftp-") && name.len() == 20, "{name}");
    assert_eq!(reply, format!("226 bytes=7 hex=- restart=null name={name}"));

    let (opening, _) = s.upload("STOU", b"again\n").await;
    assert_ne!(
        opening.strip_prefix("150 FILE: ").unwrap(),
        name,
        "two STOUs got the same name"
    );
}

/// `ABOR` while the server waits for the data connection, reads an upload, or writes a
/// download: the data connection is closed, the transfer is answered `426` and `ABOR` `226`,
/// in that order. With nothing in progress it is `225`. A different command sent during a
/// transfer is answered after the transfer's own completion, in order.
#[tokio::test]
async fn abor_ends_a_transfer_with_426_then_226() {
    let ftp = start(json!({"data_connect_timeout_secs": 30, "data_idle_timeout_secs": 30})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    // Nothing in progress.
    assert_eq!(s.send("ABOR").await, "225 No transfer to abort");

    // While the server waits for a data connection that never comes.
    let _ = s.epsv().await;
    assert!(s.send("RETR notes.txt").await.starts_with("150 "));
    let started = Instant::now();
    assert_eq!(
        s.send("ABOR").await,
        "426 Connection closed; transfer aborted"
    );
    assert_eq!(s.line().await, "226 Abort successful");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "ABOR waited for the 30s connect bound"
    );

    // While it reads an upload. Telnet's IP and DM in front of the verb are not part of it.
    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR big.bin").await.starts_with("150 "));
    conn.write_all(b"partial").await.unwrap();
    s.writer
        .write_all(b"\xff\xf4\xff\xf2ABOR\r\n")
        .await
        .unwrap();
    assert_eq!(s.line().await, "426 Connection closed; transfer aborted");
    assert_eq!(s.line().await, "226 Abort successful");
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(10), conn.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "the data connection was left open");
    assert_eq!(ftp.asked("STOR big.bin").await, 0);

    // While it writes a download the client has stopped reading, its receive buffer small so
    // the server's writes block. This ABOR goes as python's ftplib sends it: the whole line as
    // TCP urgent data, which makes its last byte, the `\n`, the urgent one.
    let data = s.epsv().await;
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut conn = socket.connect(data).await.unwrap();
    let opening = s.send("RETR huge.bin").await;
    assert!(opening.starts_with("150 "), "{opening}");
    let mut first = [0u8; 4096];
    conn.read_exact(&mut first).await.unwrap();
    socket2::SockRef::from(s.writer.as_ref())
        .send_out_of_band(b"ABOR\r\n")
        .unwrap();
    assert_eq!(s.line().await, "426 Connection closed; transfer aborted");
    assert_eq!(s.line().await, "226 Abort successful");
    let mut drained = 0usize;
    let mut buf = vec![0u8; 1 << 16];
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    })
    .await
    .expect("the data connection was left open after ABOR");
    assert!(
        drained + first.len() < HUGE,
        "the whole file crossed: ABOR did not stop the transfer"
    );
    // The urgent `\n` that ended that ABOR is not read as a command of its own.
    assert_eq!(s.send("NOOP").await, "200 noop ok");

    // A command pipelined behind an upload waits for the upload's 226, then is answered.
    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR queued.bin").await.starts_with("150 "));
    s.write("NOOP").await;
    conn.write_all(b"data").await.unwrap();
    drop(conn);
    assert_eq!(s.line().await, "226 bytes=4 hex=- restart=null name=-");
    assert_eq!(s.line().await, "200 noop ok");
    assert_eq!(ftp.asked("ABOR").await, 0, "ABOR reached the handler");
}
