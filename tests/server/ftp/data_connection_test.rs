//! The FTP server's data connections, driven from a raw socket: every bound on both sides, the
//! setup verbs the server answers itself, and the fail-closed answers when the handler gives
//! a transfer nothing to send.
//!
//! In-process server, mocked model. The bounds are set low through their startup parameters,
//! which also proves each parameter is read: an ignored one would leave the default (60s, 300s,
//! 1 MiB) in force and the test on the far side of it would time out or pass the wrong way.
//!
//! | Bound | Under it | Over it |
//! |---|---|---|
//! | `data_connect_timeout_secs` | the client connects 1s into a 3s window: 150, listing, 226 | it never connects: 150, then 425 at ~3s |
//! | `data_idle_timeout_secs` | an upload pauses 1s of a 3s window and completes: 226 | it stalls: 426 at ~3s |
//! | `max_upload_bytes` | exactly 64 of 64 bytes reach the handler: 226 | 65 bytes: 552, the handler never asked |
//!
//! Loopback only.

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

fn reply(code: u16, message: &str) -> serde_json::Value {
    json!([{"type": "send_ftp_response", "code": code, "message": message}])
}

/// Model rules shared by every test here. Counts are asserted per test through the access log
/// where they matter; the mock's own expectations are deliberately loose.
fn mock_rules() -> MockLlmBuilder {
    MockLlmBuilder::new()
        .on_event("ftp_command")
        .and_event_data_contains("command", "CONNECTION_ESTABLISHED")
        .respond_with_actions(reply(220, "ready"))
        .expect_at_least(1)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "LIST")
        .respond_with_actions(json!([{"type": "send_ftp_list", "entries": ["a.txt", "b.txt"]}]))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "RETR silent.txt")
        .respond_with_actions(json!([]))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "RETR claims.txt")
        .respond_with_actions(reply(226, "Transfer complete"))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "RETR stray.txt")
        .respond_with_actions(json!([
            {"type": "send_ftp_response", "code": 150, "message": "my own opening"},
            {"type": "send_ftp_data", "data": "stray\n"},
            {"type": "send_ftp_response", "code": 200, "message": "not a completion"}
        ]))
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "STOR")
        .respond_with_actions_from_event(|e| {
            json!([{
                "type": "send_ftp_response",
                "code": 226,
                "message": format!("stored {} bytes", e["upload_bytes"])
            }])
        })
        .expect_at_least(0)
        .and()
        .on_event("ftp_command")
        .and_event_data_contains("command", "NOOP")
        .respond_with_actions(json!([]))
        .expect_at_least(0)
        .and()
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
        instruction: Some("Serve a.txt and b.txt; accept uploads.".to_string()),
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
        let n = tokio::time::timeout(Duration::from_secs(15), self.reader.read_line(&mut line))
            .await
            .expect("no reply within 15s")
            .unwrap();
        assert!(n > 0, "control connection closed");
        assert!(
            line.ends_with("\r\n"),
            "reply not CRLF-terminated: {line:?}"
        );
        line.trim_end().to_string()
    }

    async fn send(&mut self, command: &str) -> String {
        self.writer
            .write_all(format!("{command}\r\n").as_bytes())
            .await
            .unwrap();
        self.line().await
    }

    /// `EPSV`, returning the data address the reply names.
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
}

async fn read_all(mut stream: TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut data))
        .await
        .expect("data connection did not close")
        .unwrap();
    data
}

/// `data_connect_timeout_secs`, both sides, and a transfer with no data connection at all.
#[tokio::test]
async fn data_connection_must_open_within_its_window() {
    let ftp = start(json!({"data_connect_timeout_secs": 3})).await;
    let mut s = Session::open(ftp.port).await;

    // No PASV/EPSV/PORT/EPRT first: refused by the server, the handler never asked.
    assert_eq!(
        s.send("LIST").await,
        "425 Use PASV, EPSV, PORT or EPRT first"
    );
    assert_eq!(ftp.asked("LIST").await, 0);

    // Under the bound: the client connects 1s into a 3s window.
    let data = s.epsv().await;
    assert!(s.send("LIST").await.starts_with("150 "));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let listing = read_all(TcpStream::connect(data).await.unwrap()).await;
    assert_eq!(listing, b"a.txt\r\nb.txt\r\n");
    assert_eq!(s.line().await, "226 Transfer complete");

    // Over it: the client never connects.
    let _unused = s.epsv().await;
    let started = Instant::now();
    assert!(s.send("LIST").await.starts_with("150 "));
    assert_eq!(s.line().await, "425 Can't open data connection");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(2500) && waited < Duration::from_secs(10),
        "425 after {waited:?}; data_connect_timeout_secs is 3"
    );

    // The session goes on: one channel was one transfer, and a new one works.
    let data = s.epsv().await;
    assert!(s.send("LIST").await.starts_with("150 "));
    assert_eq!(
        read_all(TcpStream::connect(data).await.unwrap()).await,
        b"a.txt\r\nb.txt\r\n"
    );
    assert_eq!(s.line().await, "226 Transfer complete");
}

/// `max_upload_bytes`, both sides: exactly the bound reaches the handler, one byte more never
/// does.
#[tokio::test]
async fn upload_is_bounded_in_bytes() {
    let ftp = start(json!({"max_upload_bytes": 64})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR exact.bin").await.starts_with("150 "));
    conn.write_all(&[b'x'; 64]).await.unwrap();
    drop(conn);
    assert_eq!(s.line().await, "226 stored 64 bytes");

    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR over.bin").await.starts_with("150 "));
    // The server may close the data connection as soon as it has read past the bound, so a
    // write error here is part of the refusal, not a test failure.
    let _ = conn.write_all(&[b'x'; 65]).await;
    let _ = conn.shutdown().await;
    assert_eq!(
        s.line().await,
        "552 Requested file action aborted: exceeded storage allocation"
    );
    assert_eq!(ftp.asked("STOR exact.bin").await, 1);
    assert_eq!(
        ftp.asked("STOR over.bin").await,
        0,
        "an upload over the bound must never reach the handler"
    );
}

/// `data_idle_timeout_secs`, both sides: a pause inside the window completes, a stall is 426.
#[tokio::test]
async fn stalled_upload_is_aborted_with_426() {
    let ftp = start(json!({"data_idle_timeout_secs": 3})).await;
    let mut s = Session::open(ftp.port).await;
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");

    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR paused.bin").await.starts_with("150 "));
    conn.write_all(b"12345").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    conn.write_all(b"67890").await.unwrap();
    drop(conn);
    assert_eq!(s.line().await, "226 stored 10 bytes");

    let data = s.epsv().await;
    let mut conn = TcpStream::connect(data).await.unwrap();
    assert!(s.send("STOR stalled.bin").await.starts_with("150 "));
    conn.write_all(b"12345").await.unwrap();
    let started = Instant::now();
    assert_eq!(s.line().await, "426 Connection closed; transfer aborted");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(2500) && waited < Duration::from_secs(10),
        "426 after {waited:?}; data_idle_timeout_secs is 3"
    );
    assert_eq!(ftp.asked("STOR stalled.bin").await, 0);
    drop(conn);
}

/// The setup verbs the server answers itself, and the bounce guard on active mode.
#[tokio::test]
async fn setup_verbs_are_answered_by_the_server() {
    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;

    assert_eq!(s.send("TYPE A").await, "200 Type set to A");
    assert_eq!(s.send("TYPE L 8").await, "200 Type set to I");
    assert_eq!(s.send("TYPE A N").await, "200 Type set to A");
    assert!(s.send("TYPE E").await.starts_with("504 "));
    assert!(s.send("TYPE").await.starts_with("501 "));
    assert_eq!(s.send("MODE S").await, "200 Mode set to S");
    assert!(s.send("MODE B").await.starts_with("504 "));
    assert_eq!(s.send("STRU F").await, "200 Structure set to F");
    assert!(s.send("STRU R").await.starts_with("504 "));

    // PASV names the control connection's own address.
    let pasv = s.send("PASV").await;
    assert!(
        pasv.starts_with("227 Entering Passive Mode (127,0,0,1,"),
        "{pasv}"
    );
    assert!(s.send("EPSV 2").await.starts_with("522 "));
    assert!(s.send("EPSV x").await.starts_with("501 "));

    // Active mode only to the client itself, never to a privileged port: otherwise PORT is
    // the FTP bounce attack.
    assert_eq!(
        s.send("PORT 10,0,0,1,19,136").await,
        "500 Illegal PORT command"
    );
    assert_eq!(
        s.send("PORT 127,0,0,1,0,25").await,
        "500 Illegal PORT command"
    );
    assert_eq!(
        s.send("EPRT |1|10.0.0.1|5000|").await,
        "500 Illegal EPRT command"
    );
    assert!(s.send("EPRT |3|x|1|").await.starts_with("522 "));
    assert!(s.send("PORT 1,2,3").await.starts_with("501 "));

    // Active mode end to end: the server connects to the client's own listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = listener.local_addr().unwrap().port();
    assert_eq!(
        s.send(&format!("PORT 127,0,0,1,{},{}", p >> 8, p & 0xff))
            .await,
        "200 PORT command successful"
    );
    assert!(s.send("LIST").await.starts_with("150 "));
    let (conn, _) = listener.accept().await.unwrap();
    assert_eq!(read_all(conn).await, b"a.txt\r\nb.txt\r\n");
    assert_eq!(s.line().await, "226 Transfer complete");

    // After EPSV ALL, every other setup command is refused.
    assert_eq!(s.send("EPSV ALL").await, "200 EPSV ALL ok");
    assert!(s.send("PASV").await.starts_with("501 "));
    assert!(s
        .send(&format!("PORT 127,0,0,1,{},{}", p >> 8, p & 0xff))
        .await
        .starts_with("501 "));

    // None of these reached the handler.
    for command in ["TYPE A", "PASV", "EPSV", "PORT 10,0,0,1,19,136", "EPSV ALL"] {
        assert_eq!(ftp.asked(command).await, 0, "{command} reached the handler");
    }
}

/// A transfer the handler gives nothing to send is answered 451, never left hanging, and
/// never preceded by a 150 it cannot complete. The same holds for an ordinary command.
#[tokio::test]
async fn unanswered_steps_fail_closed_with_451() {
    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;

    // The handler answered with no action at all.
    let _ = s.epsv().await;
    assert_eq!(
        s.send("RETR silent.txt").await,
        "451 Requested action aborted: local error in processing"
    );
    // A 226 with no payload claims a transfer of nothing.
    let _ = s.epsv().await;
    assert_eq!(
        s.send("RETR claims.txt").await,
        "451 Requested action aborted: local error in processing"
    );
    // An ordinary command the handler did not answer.
    assert_eq!(
        s.send("NOOP").await,
        "451 Requested action aborted: local error in processing"
    );

    // Replies the handler wrote around a payload are not sent: the server owns 150 and 226.
    let data = s.epsv().await;
    let opening = s.send("RETR stray.txt").await;
    assert!(
        opening.starts_with("150 Opening ASCII mode data connection for stray.txt"),
        "{opening}"
    );
    assert_eq!(
        read_all(TcpStream::connect(data).await.unwrap()).await,
        b"stray\r\n",
        "TYPE A (the default) sends the file's line endings as CRLF"
    );
    assert_eq!(s.line().await, "226 Transfer complete");
    assert_eq!(s.send("TYPE I").await, "200 Type set to I");
}

/// A passive listener binds the server's configured host, not every interface: the passive
/// port of a server on 127.0.0.1 must refuse a connection to this machine's own LAN address.
#[tokio::test]
async fn passive_listener_binds_only_the_configured_host() {
    // The address this machine would use to reach the outside: connecting a UDP socket sends
    // nothing and only picks a route. 192.0.2.1 is TEST-NET-1, so nothing is contacted.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    probe.connect("192.0.2.1:9").expect(
        "no route to pick a non-loopback address from: this test needs one interface besides \
         loopback to tell a 127.0.0.1 bind from a 0.0.0.0 one",
    );
    let lan_ip = probe.local_addr().unwrap().ip();
    assert!(
        !lan_ip.is_loopback() && !lan_ip.is_unspecified(),
        "{lan_ip}"
    );

    let ftp = start(json!({})).await;
    let mut s = Session::open(ftp.port).await;
    let data = s.epsv().await;
    let wider = SocketAddr::new(lan_ip, data.port());
    let attempt = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(wider)).await;
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "the passive port answered on {wider}: it is bound wider than the configured 127.0.0.1"
    );
    // And it does answer on the configured host.
    assert!(s.send("LIST").await.starts_with("150 "));
    assert_eq!(
        read_all(TcpStream::connect(data).await.unwrap()).await,
        b"a.txt\r\nb.txt\r\n"
    );
    assert_eq!(s.line().await, "226 Transfer complete");
}
