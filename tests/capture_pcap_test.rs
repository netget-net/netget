//! Packet capture: NetGet writes a pcap of what its own sockets carried
//! (`src/capture/`), and an independent dissector reads it back.
//!
//! Every assertion is made on what `tshark` reads out of the file NetGet wrote — never on
//! NetGet's own counters — because the claim under test is "Wireshark can open this and
//! follow the conversation", and only Wireshark's dissector can say whether that is true.
//! The TCP assertions go through "Follow TCP Stream" (`-z follow,tcp,raw`), which is exactly
//! what an operator does with the file and which only reassembles when the synthesised
//! sequence numbers advance by exactly the bytes each side carried.
//!
//! Each server is answered by a static handler, so no model is involved and the bytes on the
//! wire are known in advance. `tshark` missing fails the test (`pcap_oracle::require_tshark`).
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test capture_pcap_test -- --test-threads=8

#[path = "helpers/pcap_oracle.rs"]
mod pcap_oracle;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use netget::capture::{CaptureOwner, CaptureSpec};
use netget::cli::management::{update_server, ClientForm, ServerForm};
use netget::state::app_state::AppState;
use netget::state::ServerId;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// A TCP server that answers every read with `pong\n`, and nothing else.
fn tcp_pong_form(capture: Option<CaptureSpec>) -> ServerForm {
    ServerForm {
        protocol: "tcp".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        // Empty, so nothing can reach a model: the static handler answers everything.
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({
            "event_pattern": "tcp_data_received",
            "handler": {"type": "static", "actions": [{"type": "send_tcp_data", "data": "pong\n"}]}
        })]),
        capture,
        ..Default::default()
    }
}

async fn wait_for_port(state: &AppState, id: ServerId) -> u16 {
    for _ in 0..300 {
        if let Some(s) = state.get_server(id).await {
            if let Some(addr) = s.local_addr {
                return addr.port();
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server #{} never bound a port", id.as_u32());
}

fn status_sink() -> mpsc::UnboundedSender<String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tx
}

/// Send `line`, and read one line back.
async fn exchange(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    line: &str,
) -> String {
    writer.write_all(line.as_bytes()).await.expect("write");
    let mut reply = String::new();
    tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut reply))
        .await
        .unwrap_or_else(|_| panic!("no reply to {line:?}"))
        .expect("read reply");
    reply
}

/// One TCP stream as "Follow TCP Stream" reassembles it: who each node is, and every byte each
/// sent, in order.
#[derive(Debug)]
struct Followed {
    node0: String,
    node1: String,
    from_node0: Vec<u8>,
    from_node1: Vec<u8>,
}

fn follow_tcp(path: &Path, stream: u32) -> Followed {
    pcap_oracle::require_tshark();
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(["-n", "-q", "-z", &format!("follow,tcp,raw,{stream}")])
        .output()
        .expect("run tshark");
    assert!(
        out.status.success(),
        "tshark could not read {}: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut f = Followed {
        node0: String::new(),
        node1: String::new(),
        from_node0: Vec::new(),
        from_node1: Vec::new(),
    };
    let mut in_body = false;
    for line in text.lines() {
        if let Some(n) = line.strip_prefix("Node 0: ") {
            f.node0 = n.trim().to_string();
            continue;
        }
        if let Some(n) = line.strip_prefix("Node 1: ") {
            f.node1 = n.trim().to_string();
            in_body = true;
            continue;
        }
        if !in_body || line.starts_with("====") || line.trim().is_empty() {
            continue;
        }
        let (target, hexpart) = match line.strip_prefix('\t') {
            Some(rest) => (&mut f.from_node1, rest),
            None => (&mut f.from_node0, line),
        };
        target.extend(hex::decode(hexpart.trim()).unwrap_or_else(|e| {
            panic!("tshark printed a line that is not hex ({e}): {line:?}\n{text}")
        }));
    }
    assert!(
        !f.node0.is_empty(),
        "tshark found no TCP stream {stream} in {}:\n{text}",
        path.display()
    );
    f
}

/// `tshark -T fields` rows for `fields`, optionally under a display filter and a decode-as.
fn fields(path: &Path, decode_as: Option<&str>, filter: &str, fields: &[&str]) -> Vec<Vec<String>> {
    pcap_oracle::require_tshark();
    let mut cmd = Command::new("tshark");
    cmd.arg("-r").arg(path).arg("-n");
    if let Some(d) = decode_as {
        cmd.args(["-d", d]);
    }
    if !filter.is_empty() {
        cmd.args(["-Y", filter]);
    }
    cmd.args(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a"]);
    for f in fields {
        cmd.args(["-e", f]);
    }
    let out = cmd.output().expect("run tshark");
    assert!(
        out.status.success(),
        "tshark: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// A boolean field as `tshark -T fields` prints it: `1`/`0` before Wireshark 4.2, `True`/`False`
/// after.
fn truthy(v: &str) -> bool {
    matches!(v, "1" | "True" | "true")
}

fn assert_no_warnings(path: &Path, decode_as: Option<&str>) {
    let packets = pcap_oracle::dissect_file(path, decode_as).expect("tshark reads the capture");
    assert!(!packets.is_empty(), "{} holds no packets", path.display());
    let failures = pcap_oracle::expert_failures(&packets);
    assert!(
        failures.is_empty(),
        "tshark raised warnings on NetGet's capture {}:\n  {}\nchains: {:?}",
        path.display(),
        failures.join("\n  "),
        packets.iter().map(|p| &p.protocols).collect::<Vec<_>>()
    );
}

fn temp_pcap(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

/// A TCP server started with `capture`: the whole conversation is in the file, opened with a
/// handshake and closed with a FIN per side, and Follow TCP Stream reassembles it byte for byte.
#[tokio::test]
async fn tcp_server_capture_reassembles_the_whole_conversation() {
    pcap_oracle::require_tshark();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_pcap(&dir, "tcp.pcap");
    let state = AppState::new();
    let id = tcp_pong_form(Some(CaptureSpec::Path(path.display().to_string())))
        .create(&state, status_sink())
        .await
        .expect("start a capturing tcp server");
    let port = wait_for_port(&state, id).await;
    let status = state
        .capture
        .status(CaptureOwner::Server(id))
        .expect("the capture is running");
    assert_eq!(Path::new(&status.path), path.as_path());
    assert!(status.adopted, "tcp feeds its capture");

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let client_addr = stream.local_addr().unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    assert_eq!(exchange(&mut r, &mut w, "ping\n").await, "pong\n");
    assert_eq!(exchange(&mut r, &mut w, "bye\n").await, "pong\n");
    w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut rest)).await;

    // Stopping the server ends its connections and then closes the file, so it is complete.
    state.remove_server(id).await;
    assert!(state.capture.status(CaptureOwner::Server(id)).is_none());

    assert_no_warnings(&path, None);
    let f = follow_tcp(&path, 0);
    assert_eq!(
        f.node0,
        client_addr.to_string(),
        "the peer opened the connection"
    );
    assert_eq!(f.node1, format!("127.0.0.1:{port}"));
    assert_eq!(
        String::from_utf8_lossy(&f.from_node0),
        "ping\nbye\n",
        "client → server, reassembled"
    );
    assert_eq!(
        String::from_utf8_lossy(&f.from_node1),
        "pong\npong\n",
        "server → client, reassembled"
    );

    // A real open and a real close: SYN and SYN-ACK, and a FIN from each side.
    let syns = fields(&path, None, "tcp.flags.syn==1", &["tcp.flags.ack"]);
    assert_eq!(syns.len(), 2, "SYN and SYN-ACK: {syns:?}");
    let fins = fields(&path, None, "tcp.flags.fin==1", &["tcp.srcport"]);
    let mut fin_ports: Vec<String> = fins.into_iter().map(|r| r[0].clone()).collect();
    fin_ports.sort();
    let mut want = vec![client_addr.port().to_string(), port.to_string()];
    want.sort();
    assert_eq!(fin_ports, want, "one FIN from each side");
}

/// DNS over UDP: one datagram in the file per query and per answer, and tshark's DNS dissector
/// reads both — the question, and the address the static handler answered with.
#[tokio::test]
async fn dns_server_capture_holds_the_query_and_the_answer() {
    pcap_oracle::require_tshark();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_pcap(&dir, "dns.pcap");
    let state = AppState::new();
    let id = ServerForm {
        protocol: "dns".to_string(),
        port: Some(0),
        host: Some("127.0.0.1".to_string()),
        instruction: Some(String::new()),
        event_handlers: Some(vec![json!({
            "event_pattern": "dns_query",
            "handler": {"type": "static", "actions": [{
                "type": "send_dns_a_response", "query_id": 4660,
                "domain": "capture.test", "ip": "192.0.2.7", "ttl": 60
            }]}
        })]),
        capture: Some(CaptureSpec::Path(path.display().to_string())),
        ..Default::default()
    }
    .create(&state, status_sink())
    .await
    .expect("start a capturing dns server");
    let port = wait_for_port(&state, id).await;

    // id 0x1234, RD, one question: capture.test A IN.
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["capture", "test"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&query, ("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(20), sock.recv_from(&mut buf))
        .await
        .expect("a DNS answer")
        .unwrap();
    assert!(
        n > 12 && buf[0..2] == [0x12, 0x34],
        "an answer to our query"
    );

    state.remove_server(id).await;

    let decode = format!("udp.port=={port},dns");
    assert_no_warnings(&path, Some(&decode));
    let rows = fields(
        &path,
        Some(&decode),
        "dns",
        &[
            "dns.flags.response",
            "dns.id",
            "dns.qry.name",
            "dns.a",
            "udp.srcport",
        ],
    );
    assert_eq!(rows.len(), 2, "one query and one answer: {rows:?}");
    assert!(!truthy(&rows[0][0]), "the query first: {rows:?}");
    assert_eq!(rows[0][2], "capture.test");
    assert_eq!(rows[0][4], sock.local_addr().unwrap().port().to_string());
    assert!(truthy(&rows[1][0]), "then the answer: {rows:?}");
    assert_eq!(
        u32::from_str_radix(rows[1][1].trim_start_matches("0x"), 16).ok(),
        Some(0x1234),
        "the answer carries the query's id: {rows:?}"
    );
    assert_eq!(rows[1][3], "192.0.2.7", "tshark reads the answered address");
    assert_eq!(rows[1][4], port.to_string());
}

/// Capture is hot: started on a running server, it picks up a connection that was already open
/// — opening its stream in the file at that point — and stopped, it records nothing more.
#[tokio::test]
async fn capture_starts_and_stops_on_a_running_server_without_a_restart() {
    pcap_oracle::require_tshark();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_pcap(&dir, "hot.pcap");
    let state = AppState::new();
    let id = tcp_pong_form(None)
        .create(&state, status_sink())
        .await
        .expect("start tcp");
    let port = wait_for_port(&state, id).await;
    assert!(state.capture.status(CaptureOwner::Server(id)).is_none());

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    assert_eq!(exchange(&mut r, &mut w, "before\n").await, "pong\n");

    let on = ServerForm {
        capture: Some(CaptureSpec::Path(path.display().to_string())),
        ..Default::default()
    };
    let outcome = update_server(&state, id, on, status_sink())
        .await
        .expect("turn capture on");
    assert!(
        !outcome.restarted,
        "capture is hot-applied: {}",
        outcome.summary
    );
    assert_eq!(outcome.id, id.as_u32());

    assert_eq!(exchange(&mut r, &mut w, "during\n").await, "pong\n");

    let off = ServerForm {
        capture: Some(CaptureSpec::Toggle(false)),
        ..Default::default()
    };
    update_server(&state, id, off, status_sink())
        .await
        .expect("turn capture off");
    assert!(state.capture.status(CaptureOwner::Server(id)).is_none());

    assert_eq!(exchange(&mut r, &mut w, "after\n").await, "pong\n");
    state.remove_server(id).await;

    assert_no_warnings(&path, None);
    let f = follow_tcp(&path, 0);
    assert_eq!(String::from_utf8_lossy(&f.from_node0), "during\n");
    assert_eq!(String::from_utf8_lossy(&f.from_node1), "pong\n");
    let syns = fields(&path, None, "tcp.flags.syn==1", &["tcp.srcport"]);
    assert_eq!(
        syns.len(),
        2,
        "the connection already open was opened in the file when capture began: {syns:?}"
    );
}

/// The TCP client's capture: NetGet is the initiator, and what it said on connect is in the
/// file because capture starts before the client connects.
#[tokio::test]
async fn tcp_client_capture_records_its_side_from_the_first_byte() {
    pcap_oracle::require_tshark();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_pcap(&dir, "client.pcap");
    let state = AppState::new();
    let server = tcp_pong_form(None)
        .create(&state, status_sink())
        .await
        .expect("start tcp");
    let port = wait_for_port(&state, server).await;

    let client = ClientForm {
        protocol: "tcp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some(String::new()),
        event_handlers: Some(vec![
            json!({"event_pattern": "tcp_connected", "handler": {"type": "static",
                "actions": [{"type": "send_tcp_data", "data": "hello\n"}]}}),
            json!({"event_pattern": "*", "handler": {"type": "static", "actions": []}}),
        ]),
        capture: Some(CaptureSpec::Path(path.display().to_string())),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        status_sink(),
    )
    .await
    .expect("connect a capturing tcp client");

    // Handshake (3), hello, pong.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let packets = state
            .capture
            .status(CaptureOwner::Client(client))
            .map(|s| s.packets)
            .unwrap_or(0);
        if packets >= 5 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client's capture holds {packets} packet(s), not the 5 a handshake, hello and \
             pong make"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    state.remove_client(client).await;
    state.remove_server(server).await;

    assert_no_warnings(&path, None);
    let f = follow_tcp(&path, 0);
    assert_eq!(
        f.node1,
        format!("127.0.0.1:{port}"),
        "NetGet dialled the server"
    );
    assert_eq!(String::from_utf8_lossy(&f.from_node0), "hello\n");
    assert_eq!(String::from_utf8_lossy(&f.from_node1), "pong\n");
}

/// What a capture refuses, before anything starts: an existing file that is not a pcap (it is
/// never overwritten), and — from an action — any path outside the capture directory.
#[tokio::test]
async fn capture_refuses_to_overwrite_or_escape() {
    let dir = tempfile::tempdir().unwrap();
    let precious = dir.path().join("notes.txt");
    std::fs::write(&precious, b"do not overwrite me").unwrap();
    let state = AppState::new();

    let err = tcp_pong_form(Some(CaptureSpec::Path(precious.display().to_string())))
        .create(&state, status_sink())
        .await
        .expect_err("a file that is not a pcap is refused");
    assert!(err.to_string().contains("not a pcap"), "{err}");
    assert_eq!(std::fs::read(&precious).unwrap(), b"do not overwrite me");
    assert!(
        state.get_all_servers().await.is_empty(),
        "refused before anything started"
    );

    let owner = CaptureOwner::Server(ServerId::new(1));
    for escaping in ["/tmp/x.pcap", "../x.pcap", "sub/x.pcap"] {
        assert!(
            state
                .capture
                .resolve_path(owner, "tcp", &CaptureSpec::Path(escaping.into()), true)
                .is_err(),
            "an action may not name {escaping}"
        );
    }
    let inside = state
        .capture
        .resolve_path(owner, "tcp", &CaptureSpec::Path("ok.pcap".into()), true)
        .unwrap()
        .unwrap();
    assert_eq!(inside, state.capture.directory().join("ok.pcap"));
}

/// The file is bounded: past its limit it rotates to `<path>.1` and starts again, and both
/// halves are pcaps tshark reads.
#[tokio::test]
async fn capture_rotates_at_its_bound() {
    pcap_oracle::require_tshark();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_pcap(&dir, "rot.pcap");
    let state = AppState::new();
    state.capture.set_max_file_bytes(4096);
    let id = tcp_pong_form(Some(CaptureSpec::Path(path.display().to_string())))
        .create(&state, status_sink())
        .await
        .expect("start");
    let port = wait_for_port(&state, id).await;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let line = format!("{}\n", "x".repeat(500));
    for _ in 0..12 {
        assert_eq!(exchange(&mut r, &mut w, &line).await, "pong\n");
    }
    let status = state.capture.stop(CaptureOwner::Server(id)).await.unwrap();
    state.remove_server(id).await;

    assert!(
        status.rotations >= 1,
        "6 KB through a 4 KB bound: {status:?}"
    );
    let rotated = PathBuf::from(format!("{}.1", path.display()));
    for p in [&path, &rotated] {
        let len = std::fs::metadata(p).unwrap().len();
        assert!(
            len <= 4096,
            "{} is {len} bytes, over its bound",
            p.display()
        );
        assert!(
            !pcap_oracle::dissect_file(p, None).unwrap().is_empty(),
            "{} is a readable capture",
            p.display()
        );
    }
}
