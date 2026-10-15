//! SMB against real, independent clients.
//!
//! **Samba's `smbclient`** (GPLv3; Homebrew `samba`, Ubuntu `smbclient`) is a separate C
//! implementation of SMB2 that NetGet neither links nor wrote. It is run as a subprocess and
//! takes the server through the whole of an anonymous session: NEGOTIATE, SPNEGO/NTLMSSP
//! SESSION_SETUP in two legs, TREE_CONNECT, CREATE of the share root, QUERY_DIRECTORY until
//! `STATUS_NO_MORE_FILES`, the file-system size query behind `ls`'s "blocks available" line,
//! CREATE, QUERY_INFO and READ for `get`, then CLOSE, TREE_DISCONNECT and LOGOFF. The file it
//! fetches is 70 000 non-text bytes, more than one 64 KiB READ, so the range the server slices
//! out of the model's content is checked at two offsets; the bytes on disk afterwards are
//! compared with what the model said.
//!
//! **The Python `smbprotocol` library** (MIT; `python3 -m pip install smbprotocol`) is a
//! second, unrelated implementation, driven as a subprocess. It logs in as a named guest over
//! bare NTLMSSP, lists the share and reads the same file. It trusts the EndOfFile of the CREATE
//! response and never asks again, which `smbclient` does not, so it is the check on
//! `smb_create_file`'s `size`.
//!
//! Every answer comes from a mocked model (`.with_mock`), and every mock rule is counted.
//! The smbclient session is recorded through a relay and handed to the pcap oracle, which
//! reads it with Wireshark's `nbss` and `smb2` dissectors and must find no malformed frame.
//!
//! **These tests FAIL, they do not skip, when a client is absent.** A skip gate returns
//! `Ok(())` on a runner without the tool, so the suite reports a silent pass and the maturity
//! rating ends up resting on nothing; `tests/server/memcached/real_client_test.rs` is the
//! precedent. `registry-audit` installs both.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smb --test server -- smb::real_client --test-threads=100

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::helpers::pcap_oracle::PcapOracle;
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};

/// Locate a binary, or fail saying why a skip would be worse. Named `require_tool("…")` so
/// `scripts/beta_evidence_table.py` can see which third-party client this file drives.
fn require_tool(name: &str) -> String {
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let candidate = std::path::Path::new(prefix).join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        if let Some(found) = path
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(name))
            .find(|candidate| candidate.exists())
        {
            return found.to_string_lossy().into_owned();
        }
    }
    panic!(
        "`{name}` not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         This test drives Samba's own smbclient against NetGet's SMB server, and it is the \
         only independent check that our framing, headers, NTLMSSP exchange and file replies \
         are what a real SMB2 client expects. Skipping would leave SMB's evidence resting on \
         nothing, so this is a failure and not a skip. Install with `brew install samba` \
         (macOS) or `apt-get install -y smbclient` (Debian/Ubuntu)."
    );
}

/// Fail, naming the install command, unless `python3` can import smbprotocol.
fn require_smbprotocol() {
    let ok = std::process::Command::new("python3")
        .args(["-c", "import smbprotocol, smbclient"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        ok,
        "`python3 -c 'import smbprotocol'` failed. This test drives the Python smbprotocol \
         library against NetGet's SMB server as a second, independent SMB2 client; skipping \
         would leave SMB's evidence resting on one client, so this is a failure and not a \
         skip. Install with `python3 -m pip install smbprotocol`."
    );
}

/// The file both clients fetch: 70 000 bytes that are neither text nor a repeating pattern a
/// wrong offset could reproduce, so it arrives in two READs and any slip shows.
fn file_bytes() -> Vec<u8> {
    let mut state: u32 = 0x2545_F491;
    (0..70_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

fn file_base64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(file_bytes())
}

const FILE_NAME: &str = "report.bin";

/// Bytes that crossed a relayed connection, in order.
#[derive(Clone)]
enum Chunk {
    ToServer(Vec<u8>),
    FromServer(Vec<u8>),
}

/// A TCP relay in front of the server that records the first connection through it.
struct Recorder {
    port: u16,
    chunks: Arc<Mutex<Vec<Chunk>>>,
    done: Arc<tokio::sync::Notify>,
}

impl Recorder {
    async fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let port = listener.local_addr().unwrap().port();
        let chunks: Arc<Mutex<Vec<Chunk>>> = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(tokio::sync::Notify::new());
        let (rec, fin) = (chunks.clone(), done.clone());
        tokio::spawn(async move {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let server = TcpStream::connect(("127.0.0.1", upstream))
                .await
                .expect("relay connect upstream");
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            let rec_up = rec.clone();
            let up = async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = cr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    rec_up.lock().await.push(Chunk::ToServer(buf[..n].to_vec()));
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = sw.shutdown().await;
            };
            let down = async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = sr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    rec.lock().await.push(Chunk::FromServer(buf[..n].to_vec()));
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
            };
            tokio::join!(up, down);
            fin.notify_one();
        });
        Self { port, chunks, done }
    }

    /// Wait until the recorded connection has closed in both directions.
    async fn finished(&self, secs: u64) -> Vec<Chunk> {
        tokio::time::timeout(Duration::from_secs(secs), self.done.notified())
            .await
            .expect("the recorded connection never finished");
        self.chunks.lock().await.clone()
    }
}

/// What each client uploads: 100 000 bytes, a different sequence from [`file_bytes`], so the
/// upload arrives in more than one 64 KiB WRITE and a write reassembled at the wrong offset, or
/// confused with the download, shows.
fn upload_bytes() -> Vec<u8> {
    let mut state: u32 = 0x9E37_79B9;
    (0..100_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 16) as u8
        })
        .collect()
}

const UPLOAD_NAME: &str = "upload.bin";
const NEW_DIR: &str = "newdir";

/// Every `write` event the model saw: path, offset and the decoded bytes.
type Writes = Arc<std::sync::Mutex<Vec<(String, u64, Vec<u8>)>>>;

/// The file the model was shown, reassembled from its `write` events by offset. Fails on a
/// write to any other path, an overlap or a gap: each is a byte the model did not see where
/// the client put it.
fn reassemble(writes: &Writes, path: &str) -> Vec<u8> {
    let mut writes = writes.lock().unwrap().clone();
    for (p, _, _) in &writes {
        assert_eq!(p, path, "a write reached the model for an unexpected path");
    }
    writes.sort_by_key(|(_, offset, _)| *offset);
    let mut out = Vec::new();
    for (_, offset, data) in writes {
        assert_eq!(
            offset as usize,
            out.len(),
            "the writes the model saw leave a gap or overlap at offset {offset}"
        );
        out.extend_from_slice(&data);
    }
    out
}

/// Every path the model was asked to open with `delete_on_close`: a delete request.
type Deletes = Arc<std::sync::Mutex<Vec<String>>>;

/// Every SMB2 message in one direction of a recorded connection, as (command, status).
/// Compound chains are split on `NextCommand`.
fn smb2_messages(bytes: &[u8]) -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let len = u32::from_be_bytes([0, bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let kind = bytes[i];
        let Some(frame) = bytes.get(i + 4..i + 4 + len) else {
            panic!("a recorded frame runs past the end of the capture");
        };
        i += 4 + len;
        if kind != 0 {
            continue;
        }
        let mut at = 0;
        while let Some(h) = frame.get(at..at + 64) {
            assert_eq!(&h[0..4], b"\xFESMB", "an SMB2 header was expected here");
            out.push((
                u16::from_le_bytes([h[12], h[13]]),
                u32::from_le_bytes([h[8], h[9], h[10], h[11]]),
            ));
            let next = u32::from_le_bytes([h[20], h[21], h[22], h[23]]) as usize;
            if next == 0 {
                break;
            }
            at += next;
        }
    }
    out
}

const COMMAND_NAMES: &[(u16, &str)] = &[
    (0x00, "NEGOTIATE"),
    (0x01, "SESSION_SETUP"),
    (0x02, "LOGOFF"),
    (0x03, "TREE_CONNECT"),
    (0x04, "TREE_DISCONNECT"),
    (0x05, "CREATE"),
    (0x06, "CLOSE"),
    (0x07, "FLUSH"),
    (0x08, "READ"),
    (0x09, "WRITE"),
    (0x0A, "LOCK"),
    (0x0B, "IOCTL"),
    (0x0C, "CANCEL"),
    (0x0D, "ECHO"),
    (0x0E, "QUERY_DIRECTORY"),
    (0x0F, "CHANGE_NOTIFY"),
    (0x10, "QUERY_INFO"),
    (0x11, "SET_INFO"),
    (0x12, "OPLOCK_BREAK"),
];

fn command_name(code: u16) -> &'static str {
    COMMAND_NAMES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n)
        .unwrap_or("?")
}

/// The verbs a recorded session drove, counted from the bytes rather than from what the
/// client says it did: every command the client sent, and the statuses the server answered
/// each with. Asserts that each of `expected` was sent **and** answered STATUS_SUCCESS at least
/// once, and prints the whole table so the verb-by-verb count is in the test log.
fn assert_verbs(client: &str, chunks: &[Chunk], expected: &[&str]) {
    let (mut up, mut down) = (Vec::new(), Vec::new());
    for chunk in chunks {
        match chunk {
            Chunk::ToServer(b) => up.extend_from_slice(b),
            Chunk::FromServer(b) => down.extend_from_slice(b),
        }
    }
    let sent = smb2_messages(&up);
    let answered = smb2_messages(&down);
    let mut table: std::collections::BTreeMap<
        &str,
        (usize, std::collections::BTreeMap<u32, usize>),
    > = std::collections::BTreeMap::new();
    for (cmd, _) in &sent {
        table.entry(command_name(*cmd)).or_default().0 += 1;
    }
    for (cmd, status) in &answered {
        *table
            .entry(command_name(*cmd))
            .or_default()
            .1
            .entry(*status)
            .or_default() += 1;
    }
    println!("--- {client}: SMB2 verbs on the wire (sent, answers by NTSTATUS) ---");
    for (name, (count, statuses)) in &table {
        let answers: Vec<String> = statuses
            .iter()
            .map(|(s, n)| format!("0x{s:08X}x{n}"))
            .collect();
        println!(
            "  {name:<16} sent {count:>3}  answered {}",
            answers.join(" ")
        );
    }
    for name in expected {
        let (count, statuses) = table.get(name).cloned().unwrap_or_default();
        assert!(
            count > 0,
            "{client} never sent {name}; the table above is what it did send"
        );
        assert!(
            statuses.contains_key(&0),
            "{client} sent {name} and never had it answered STATUS_SUCCESS: {statuses:x?}"
        );
    }
}

/// The model's side of both sessions: the share root is a directory holding one file; the
/// client may create `upload.bin` and `newdir`; every write is recorded.
///
/// `create_size` decides whether `smb_create_file` names report.bin's size. smbclient is given
/// none, so its `get` has to ask through QUERY_INFO; smbprotocol is given it, because the
/// CREATE response's EndOfFile is all it reads.
fn mock_config(
    prompt: &'static str,
    auth_type: &'static str,
    create_size: bool,
    writes: Writes,
    deletes: Deletes,
) -> NetGetConfig {
    let content = file_base64();
    let size = file_bytes().len();
    let upload_size = upload_bytes().len();
    NetGetConfig::new(prompt).with_mock(move |mock| {
        mock.on_event("smb_operation")
            .and_event_data_contains("operation", "session_setup")
            .and_event_data_contains("auth_type", auth_type)
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "smb_auth_success",
                    "username": event["username"].as_str().unwrap_or_default()
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "create")
            .respond_with_actions_from_event(move |event| {
                let path = event["path"].as_str().unwrap_or_default().to_string();
                let dir_requested = event["directory_requested"].as_bool().unwrap_or(false);
                if event["delete_on_close"].as_bool() == Some(true) {
                    deletes.lock().unwrap().push(path.clone());
                }
                if path == "/" || (path == format!("/{NEW_DIR}") && dir_requested) {
                    serde_json::json!([{"type": "smb_create_directory", "path": path}])
                } else if path == format!("/{FILE_NAME}") {
                    if create_size {
                        serde_json::json!([{"type": "smb_create_file", "path": path, "size": size}])
                    } else {
                        serde_json::json!([{"type": "smb_create_file", "path": path}])
                    }
                } else if path == format!("/{UPLOAD_NAME}") {
                    serde_json::json!([{"type": "smb_create_file", "path": path}])
                } else {
                    // Anything else does not exist: no create action is a refusal.
                    serde_json::json!([])
                }
            })
            .expect_at_least(4)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "write")
            .respond_with_actions_from_event(move |event| {
                use base64::Engine as _;
                let path = event["path"].as_str().unwrap_or_default().to_string();
                let offset = event["offset"].as_u64().unwrap_or(u64::MAX);
                let data = event["data"].as_str().unwrap_or_default();
                let bytes = match event["encoding"].as_str() {
                    Some("base64") => base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .expect("the write event's base64 decodes"),
                    _ => data.as_bytes().to_vec(),
                };
                let n = bytes.len();
                writes.lock().unwrap().push((path.clone(), offset, bytes));
                serde_json::json!([{"type": "smb_write_file", "path": path, "bytes_written": n}])
            })
            .expect_at_least(2)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "query_directory")
            .respond_with_actions_from_event(move |event| {
                // The share root as the model knows it: report.bin, and upload.bin once a
                // client has put it (smbclient's `rm` lists the name before it deletes it).
                let mut files = vec![serde_json::json!({
                    "name": FILE_NAME,
                    "size": size,
                    "is_directory": false,
                    "modified_time": "2026-03-04T05:06:07Z"
                })];
                if event["pattern"].as_str() == Some(UPLOAD_NAME) {
                    files.push(serde_json::json!({
                        "name": UPLOAD_NAME,
                        "size": upload_size,
                        "is_directory": false
                    }));
                }
                serde_json::json!([{"type": "smb_list_directory", "path": "/", "files": files}])
            })
            .expect_at_least(1)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "query_info")
            .respond_with_actions_from_event(move |event| {
                let path = event["path"].as_str().unwrap_or_default().to_string();
                let size = if path == format!("/{UPLOAD_NAME}") {
                    upload_size
                } else {
                    size
                };
                serde_json::json!([{
                    "type": "smb_get_file_info",
                    "path": path,
                    "size": size,
                    "is_directory": false,
                    "modified_time": "2026-03-04T05:06:07Z"
                }])
            })
            .expect_at_least(0)
            .and()
            .on_event("smb_operation")
            .and_event_data_contains("operation", "read")
            .respond_with_actions(serde_json::json!([{
                "type": "smb_read_file",
                "path": format!("/{FILE_NAME}"),
                "content": content,
                "encoding": "base64"
            }]))
            .expect_at_least(1)
            .and()
            .on_any()
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "SMB",
                "instruction": prompt
            }]))
            .expect_calls(1)
            .and()
    })
}

/// Hand a recorded session to Wireshark's own `nbss`/`smb2` dissectors.
fn assert_pcap_clean(chunks: &[Chunk]) {
    let mut oracle = PcapOracle::tcp("smb");
    for chunk in chunks {
        oracle = match chunk {
            Chunk::ToServer(b) => oracle.to_server(b),
            Chunk::FromServer(b) => oracle.from_server(b),
        };
    }
    oracle.assert_clean();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smbclient_lists_gets_puts_and_mkdirs_and_the_pcap_oracle_reads_clean_smb2() -> E2EResult<()>
{
    let smbclient = require_tool("smbclient");
    let writes: Writes = Arc::default();
    let deletes: Deletes = Arc::default();
    let server = start_netget_server(mock_config(
        "Serve a share over smb holding report.bin.",
        "anonymous",
        false,
        writes.clone(),
        deletes.clone(),
    ))
    .await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let relay = Recorder::start(server.port).await;

    let dir = tempfile::TempDir::new()?;
    let local = dir.path().join("got.bin");
    let to_upload = dir.path().join("up.bin");
    std::fs::write(&to_upload, upload_bytes())?;
    let commands = format!(
        "ls; get {FILE_NAME} {}; put {} {UPLOAD_NAME}; mkdir {NEW_DIR}; rm {UPLOAD_NAME}; \
         echo 2 ping; tdis; logoff",
        local.display(),
        to_upload.display()
    );
    let output = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new(&smbclient)
            .args([
                "//127.0.0.1/share",
                "-p",
                &relay.port.to_string(),
                // An empty user and password: an anonymous login, not an attempt as the
                // Unix user running the test that is refused and then retried anonymously.
                "-U",
                "%",
                "-N",
                "-m",
                "SMB2",
                "-c",
                &commands,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("smbclient did not exit within 90s")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "--- smbclient -c '{commands}' (exit {:?}) ---\n{text}",
        output.status.code()
    );

    let chunks = relay.finished(30).await;
    assert_verbs(
        "smbclient",
        &chunks,
        &[
            "NEGOTIATE",
            "SESSION_SETUP",
            "TREE_CONNECT",
            "CREATE",
            "QUERY_DIRECTORY",
            "QUERY_INFO",
            "READ",
            "WRITE",
            "CLOSE",
            "ECHO",
            "TREE_DISCONNECT",
            "LOGOFF",
        ],
    );

    assert!(
        output.status.success(),
        "smbclient exited non-zero:\n{text}"
    );
    let listed = text
        .lines()
        .find(|l| l.trim_start().starts_with(FILE_NAME))
        .unwrap_or_else(|| panic!("`ls` did not list {FILE_NAME}:\n{text}"));
    assert!(
        listed.contains(" N ") || listed.contains(" A "),
        "`ls` shows {FILE_NAME} as a plain file: {listed:?}"
    );
    assert!(
        listed.contains("70000"),
        "`ls` shows the size the model gave: {listed:?}"
    );
    assert!(
        listed.contains("2026"),
        "`ls` shows the modified time the model gave: {listed:?}"
    );
    assert!(
        text.contains("blocks available"),
        "`ls` read the volume size (FileFsFullSizeInformation):\n{text}"
    );
    let got = std::fs::read(&local)?;
    assert_eq!(
        got.len(),
        file_bytes().len(),
        "smbclient fetched the whole file"
    );
    assert!(
        got == file_bytes(),
        "smbclient fetched exactly the bytes the model served"
    );
    let uploaded = reassemble(&writes, &format!("/{UPLOAD_NAME}"));
    assert_eq!(
        uploaded.len(),
        upload_bytes().len(),
        "the model saw every byte smbclient put"
    );
    assert!(
        uploaded == upload_bytes(),
        "the model saw exactly the bytes smbclient put, at the offsets it put them"
    );
    // `rm` is an open with FILE_DELETE_ON_CLOSE and a close; the model has to be told the open
    // is a delete, or the client is told a file is gone that the model still believes exists.
    assert_eq!(
        *deletes.lock().unwrap(),
        vec![format!("/{UPLOAD_NAME}")],
        "smbclient's rm reached the model as a delete of exactly the file it named"
    );

    // Everything that crossed the wire, read by Wireshark's own SMB2 dissector.
    assert_pcap_clean(&chunks);

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The smbprotocol driver. `smbclient` here is smbprotocol's high-level module, not Samba's
/// binary. Each step prints one line the test asserts on.
const SMBPROTOCOL_DRIVER: &str = r#"
import sys
import smbprotocol
import smbclient
from smbclient._pool import get_smb_tree

port = int(sys.argv[1])
out = sys.argv[2]
upload = open(sys.argv[3], "rb").read()
share = r"\\127.0.0.1\share"
# A guest session has no key, so there is nothing to sign FSCTL_VALIDATE_NEGOTIATE_INFO
# with; smbprotocol itself says to turn the check off for guest access.
smbclient.ClientConfig(require_secure_negotiate=False)
smbclient.register_session("127.0.0.1", port=port, username="guest", password="",
                           auth_protocol="ntlm", require_signing=False)
names = smbclient.listdir(share, port=port)
print("LIST " + ",".join(sorted(names)))
with smbclient.open_file(share + r"\report.bin", mode="rb", port=port) as f:
    data = f.read()
open(out, "wb").write(data)
print("READ %d" % len(data))
# A compound CREATE + five QUERY_INFOs + CLOSE, all RELATED_OPERATIONS.
st = smbclient.stat(share + r"\report.bin", port=port)
print("STAT %d" % st.st_size)
# Two WRITEs at two offsets, then an explicit SMB2 FLUSH on the open (the buffered writer's
# own flush() drains Python's buffer and sends nothing), then the CLOSE.
with smbclient.open_file(share + r"\upload.bin", mode="wb", port=port) as f:
    f.write(upload[:60000])
    f.flush()
    f.write(upload[60000:])
    f.flush()
    f.raw.fd.flush()
print("WROTE %d" % len(upload))
smbclient.mkdir(share + r"\newdir", port=port)
print("MKDIR")
tree, _ = get_smb_tree(share, port=port)
tree.session.connection.echo(sid=tree.session.session_id)
print("ECHO")
# Tears the pooled connection down: TREE_DISCONNECT, LOGOFF, then the socket.
smbclient.reset_connection_cache()
print("DONE")
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smbprotocol_lists_reads_stats_writes_and_mkdirs_and_the_pcap_oracle_reads_clean_smb2(
) -> E2EResult<()> {
    require_smbprotocol();
    // A named guest over NTLMSSP: the model sees `auth_type` "ntlm" and `password_verified`
    // false. smbprotocol trusts the CREATE's EndOfFile, so the size rides on
    // smb_create_file and the stat is answered from the handle.
    let writes: Writes = Arc::default();
    let deletes: Deletes = Arc::default();
    let server = start_netget_server(mock_config(
        "Serve a share over smb holding report.bin.",
        "ntlm",
        true,
        writes.clone(),
        deletes.clone(),
    ))
    .await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let relay = Recorder::start(server.port).await;

    let dir = tempfile::TempDir::new()?;
    let local = dir.path().join("got.bin");
    let to_upload = dir.path().join("up.bin");
    std::fs::write(&to_upload, upload_bytes())?;
    let output = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new("python3")
            .args([
                "-c",
                SMBPROTOCOL_DRIVER,
                &relay.port.to_string(),
                &local.display().to_string(),
                &to_upload.display().to_string(),
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the smbprotocol driver did not exit within 90s")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "--- smbprotocol (exit {:?}) ---\n{text}",
        output.status.code()
    );

    let chunks = relay.finished(30).await;
    assert_verbs(
        "smbprotocol",
        &chunks,
        &[
            "NEGOTIATE",
            "SESSION_SETUP",
            "TREE_CONNECT",
            "CREATE",
            "QUERY_DIRECTORY",
            "QUERY_INFO",
            "READ",
            "WRITE",
            "FLUSH",
            "CLOSE",
            "ECHO",
            "TREE_DISCONNECT",
            "LOGOFF",
        ],
    );

    assert!(
        output.status.success(),
        "the smbprotocol driver failed:\n{text}"
    );
    assert!(
        text.contains(&format!("LIST {FILE_NAME}")),
        "smbprotocol listed exactly the one file the model named:\n{text}"
    );
    assert!(
        text.contains(&format!("STAT {}", file_bytes().len())),
        "smbprotocol's stat read the size the model gave:\n{text}"
    );
    assert!(text.contains("DONE"), "the driver ran to the end:\n{text}");
    let got = std::fs::read(&local)?;
    assert_eq!(
        got.len(),
        file_bytes().len(),
        "smbprotocol read the whole file"
    );
    assert!(
        got == file_bytes(),
        "smbprotocol read exactly the bytes the model served"
    );
    let uploaded = reassemble(&writes, &format!("/{UPLOAD_NAME}"));
    assert_eq!(
        uploaded.len(),
        upload_bytes().len(),
        "the model saw every byte smbprotocol wrote"
    );
    assert!(
        uploaded == upload_bytes(),
        "the model saw exactly the bytes smbprotocol wrote, at the offsets it wrote them"
    );

    assert_pcap_clean(&chunks);

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
