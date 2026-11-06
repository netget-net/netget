//! The vendored opensrv-mysql in `vendor/opensrv-mysql` is the one Cargo builds, and it has the
//! fixes `vendor/opensrv-mysql/README.md` lists.
//!
//! Two halves, like `vendored_pgwire_patch_test.rs`:
//!
//! - Cargo must actually build the copy. `[patch.crates-io]` silently stops applying (it is
//!   listed under `[[patch.unused]]`) when something wants a different opensrv-mysql.
//! - The crate itself, run bare over an in-memory pipe with a shim of the test's own, and fed
//!   every shape upstream 0.7.0 gets wrong: two pipelined packets in one read (parsed out of a
//!   freed buffer), an execute too short to parse (answered OK), a malformed command that has
//!   no reply (answered OK), `COM_STMT_RESET` (not parsed, long data kept). The MySQL
//!   server's own suite (`tests/server/mysql/`) covers the server built on it.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opensrv_mysql::{
    AsyncMysqlIntermediary, AsyncMysqlShim, Column, ColumnFlags, ColumnType, OkResponse,
    ParamParser, QueryResultWriter, StatementMetaWriter, ValueInner,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn manifest_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(v) = line.strip_prefix("version = ") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    panic!("vendor/opensrv-mysql/Cargo.toml has no [package] version");
}

#[test]
fn cargo_builds_the_vendored_opensrv_mysql_at_the_vendored_version() {
    for (manifest, lockfile, entry) in [
        (
            "Cargo.toml",
            Some("Cargo.lock"),
            r#"opensrv-mysql = { path = "vendor/opensrv-mysql" }"#,
        ),
        // The fuzz workspace's lock is not committed; its manifest must still patch.
        (
            "fuzz/Cargo.toml",
            None,
            r#"opensrv-mysql = { path = "../vendor/opensrv-mysql" }"#,
        ),
    ] {
        let root = read(manifest);
        // The section header is a line of its own; the same words also appear in comments
        // (fuzz/Cargo.toml explains "the [patch.crates-io] below"), so match the line.
        let patch = root
            .split_once("\n[patch.crates-io]\n")
            .map(|(_, rest)| rest.split("\n[").next().unwrap_or(rest))
            .unwrap_or("");
        assert!(
            patch.lines().any(|l| l.trim() == entry),
            "{manifest}'s [patch.crates-io] must point opensrv-mysql at vendor/opensrv-mysql \
             (vendor/opensrv-mysql/README.md)"
        );
        let Some(lockfile) = lockfile else { continue };

        let vendored = manifest_version(&read("vendor/opensrv-mysql/Cargo.toml"));
        let lock = read(lockfile);
        let locked: Vec<(String, Option<String>)> = lock
            .split("[[package]]")
            .skip(1)
            .filter_map(|entry| {
                let field = |key: &str| {
                    entry.lines().find_map(|l| {
                        l.strip_prefix(&format!("{key} = "))
                            .map(|v| v.trim_matches('"').to_string())
                    })
                };
                (field("name")? == "opensrv-mysql")
                    .then(|| (field("version").unwrap(), field("source")))
            })
            .collect();
        assert!(!locked.is_empty(), "Cargo.lock has no opensrv-mysql at all");
        for (version, source) in &locked {
            assert!(
                source.is_none() && *version == vendored,
                "Cargo.lock resolves opensrv-mysql {version} from {} but vendor/opensrv-mysql is \
                 {vendored}: the patched crate is not the one being built. Re-vendor and \
                 re-apply the patch as vendor/opensrv-mysql/README.md describes, or restore the \
                 [patch.crates-io] entry.",
                source.as_deref().unwrap_or("a path")
            );
        }
        let unused = lock.split("[[patch.unused]]").skip(1).any(|entry| {
            entry
                .lines()
                .take_while(|l| !l.starts_with("[["))
                .any(|l| l.trim() == r#"name = "opensrv-mysql""#)
        });
        assert!(
            !unused,
            "Cargo.lock lists vendor/opensrv-mysql under [[patch.unused]]: Cargo is building \
             crates.io's opensrv-mysql, which parses pipelined packets out of freed memory."
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The crate over an in-memory pipe
// ---------------------------------------------------------------------------------------------

/// What the shim saw of one execute: statement, and each parameter's bytes (`None` for NULL).
type Seen = Arc<Mutex<Vec<(u32, Vec<Option<Vec<u8>>>)>>>;

/// Prepares every statement with two parameters and answers every execute OK with
/// affected_rows 9, recording the parameters. Every block sent here is well formed, so the
/// crate's `Params` iterator — which panics on malformed ones — is safe to use in this test.
struct RecordingShim {
    seen: Seen,
    next_id: u32,
}

static TWO_PARAMS: std::sync::LazyLock<Vec<Column>> = std::sync::LazyLock::new(|| {
    (0..2)
        .map(|_| Column {
            table: String::new(),
            column: "?".into(),
            coltype: ColumnType::MYSQL_TYPE_VAR_STRING,
            colflags: ColumnFlags::empty(),
        })
        .collect()
});

#[async_trait::async_trait]
impl<W: tokio::io::AsyncWrite + Send + Unpin> AsyncMysqlShim<W> for RecordingShim {
    type Error = std::io::Error;

    async fn on_prepare<'a>(
        &'a mut self,
        _query: &'a str,
        info: StatementMetaWriter<'a, W>,
    ) -> std::io::Result<()> {
        self.next_id += 1;
        info.reply(self.next_id, &TWO_PARAMS[..], &[]).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        id: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> std::io::Result<()> {
        let values = params
            .into_iter()
            .map(|p| match p.value.into_inner() {
                ValueInner::NULL => None,
                ValueInner::Bytes(b) => Some(b.to_vec()),
                other => panic!("unexpected value {other:?}"),
            })
            .collect();
        self.seen.lock().unwrap().push((id, values));
        results
            .completed(OkResponse {
                affected_rows: 9,
                ..Default::default()
            })
            .await
    }

    async fn on_close(&mut self, _stmt: u32) {}

    async fn on_query<'a>(
        &'a mut self,
        _query: &'a str,
        results: QueryResultWriter<'a, W>,
    ) -> std::io::Result<()> {
        results.completed(OkResponse::default()).await
    }
}

fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, seq];
    p.extend_from_slice(payload);
    p
}

/// One packet, or `None` when nothing arrives within half a second.
async fn reply<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 4];
    tokio::time::timeout(Duration::from_millis(500), r.read_exact(&mut h))
        .await
        .ok()?
        .ok()?;
    let n = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
    let mut p = vec![0u8; n];
    r.read_exact(&mut p).await.ok()?;
    Some((h[3], p))
}

/// Every packet that arrives before the line goes quiet.
async fn replies<R: AsyncRead + Unpin>(r: &mut R) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(p) = reply(r).await {
        out.push(p);
    }
    out
}

struct Session {
    reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    seen: Seen,
}

impl Session {
    /// A bare opensrv-mysql server on an in-memory pipe, past its handshake. Nothing of
    /// NetGet's sits beneath it, so every read the crate makes may hold several packets.
    async fn start() -> Session {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (sr, sw) = tokio::io::split(server);
        let seen: Seen = Arc::default();
        let shim = RecordingShim {
            seen: seen.clone(),
            next_id: 0,
        };
        tokio::spawn(async move {
            let _ = AsyncMysqlIntermediary::run_on(shim, sr, sw).await;
        });
        let (mut reader, mut writer) = tokio::io::split(client);
        reply(&mut reader).await.expect("greeting");
        let caps: u32 = 0x1 | 0x200 | 0x2000 | 0x8000 | 0x8_0000 | 0x100_0000; // DEPRECATE_EOF
        let mut resp = caps.to_le_bytes().to_vec();
        resp.extend_from_slice(&(16u32 << 20).to_le_bytes());
        resp.push(33);
        resp.extend_from_slice(&[0u8; 23]);
        // The plugin the crate's default shim offers, so it sends no AuthSwitchRequest.
        resp.extend_from_slice(b"root\0\0mysql_native_password\0");
        writer.write_all(&packet(1, &resp)).await.unwrap();
        let (_, ok) = reply(&mut reader).await.expect("auth reply");
        assert_eq!(ok[0], 0x00, "auth OK");
        Session {
            reader,
            writer,
            seen,
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
    }

    /// Prepare a two-parameter statement; its id.
    async fn prepare(&mut self) -> u32 {
        self.send(&packet(0, b"\x16INSERT INTO t VALUES (?, ?)"))
            .await;
        let (_, ok) = reply(&mut self.reader).await.expect("prepare OK");
        assert_eq!(ok[0], 0x00);
        for _ in 0..2 {
            reply(&mut self.reader).await.expect("parameter definition");
        }
        u32::from_le_bytes([ok[1], ok[2], ok[3], ok[4]])
    }
}

fn long_data(stmt: u32, param: u16, data: &[u8]) -> Vec<u8> {
    let mut body = vec![0x18];
    body.extend_from_slice(&stmt.to_le_bytes());
    body.extend_from_slice(&param.to_le_bytes());
    body.extend_from_slice(data);
    packet(0, &body)
}

/// A two-parameter execute, both bound as VAR_STRING, with `block_values` after the types.
fn execute(stmt: u32, block_values: &[u8]) -> Vec<u8> {
    let mut body = vec![0x17];
    body.extend_from_slice(&stmt.to_le_bytes());
    body.extend_from_slice(&[0, 1, 0, 0, 0]);
    body.extend_from_slice(&[0x00, 0x01, 0xFD, 0x00, 0xFD, 0x00]);
    body.extend_from_slice(block_values);
    packet(0, &body)
}

/// Parameter 0 is `a`; parameter 1 is left to long data.
const ONLY_FIRST: &[u8] = &[0x01, b'a'];
/// Both parameters in the packet: `a` and `b`.
const BOTH: &[u8] = &[0x01, b'a', 0x01, b'b'];

fn assert_err(reply: &(u8, Vec<u8>), code: u16, what: &str) {
    let (seq, p) = reply;
    assert_eq!(p.first(), Some(&0xFF), "{what}: expected ERR, got {p:?}");
    assert_eq!(u16::from_le_bytes([p[1], p[2]]), code, "{what}");
    assert_eq!(*seq, 1, "{what}: sequence id");
}

const SHIM_OK: &[u8] = &[0, 9, 0, 0, 0, 0, 0];

/// Upstream `next_async` replaced `self.bytes` with a copy of the remainder before returning
/// the packet that borrowed the old buffer, whenever one read held more than one packet: the
/// first of two pipelined commands was parsed out of freed memory. Two long-data chunks and
/// their execute in one write came back as stray OK packets for commands that have no reply,
/// and every later reply one behind.
#[tokio::test]
async fn pipelined_packets_are_parsed_from_live_memory() {
    let mut s = Session::start().await;
    let stmt = s.prepare().await;

    let mut burst = long_data(stmt, 1, b"hello ");
    burst.extend(long_data(stmt, 1, b"world"));
    burst.extend(execute(stmt, ONLY_FIRST));
    s.send(&burst).await;

    assert_eq!(
        replies(&mut s.reader).await,
        vec![(1, SHIM_OK.to_vec())],
        "long data has no reply; only the execute is answered"
    );
    assert_eq!(
        s.seen.lock().unwrap().clone(),
        vec![(
            stmt,
            vec![Some(b"a".to_vec()), Some(b"hello world".to_vec())]
        )],
        "both chunks arrived intact"
    );
}

/// Upstream answered every packet it could not parse with OK. An execute too short to name
/// its statement then read as a successful write; a short long-data or close, which have no
/// reply, got one.
#[tokio::test]
async fn unparseable_commands_are_answered_as_mysqld_answers_them() {
    let mut s = Session::start().await;
    let stmt = s.prepare().await;

    s.send(&packet(0, &[0x17, 1, 0, 0])).await;
    let r = reply(&mut s.reader)
        .await
        .expect("a reply to the short execute");
    assert_err(&r, 1835, "an execute too short to parse");

    s.send(&packet(0, &[])).await;
    let r = reply(&mut s.reader)
        .await
        .expect("a reply to the empty packet");
    assert_err(&r, 1835, "an empty command packet");

    s.send(&packet(0, &[0x18, 1, 0])).await;
    s.send(&packet(0, &[0x19, 1])).await;
    assert!(
        replies(&mut s.reader).await.is_empty(),
        "a malformed long-data or close gets no reply, like a well-formed one"
    );

    // A command this crate does not implement keeps upstream's OK (COM_STATISTICS).
    s.send(&packet(0, &[0x09])).await;
    let (_, ok) = reply(&mut s.reader)
        .await
        .expect("a reply to COM_STATISTICS");
    assert_eq!(ok[0], 0x00);

    // The session is still in step, and nothing malformed reached the shim.
    s.send(&execute(stmt, BOTH)).await;
    assert_eq!(
        reply(&mut s.reader).await.map(|r| r.1),
        Some(SHIM_OK.to_vec())
    );
    assert_eq!(s.seen.lock().unwrap().len(), 1);
}

/// Upstream did not parse COM_STMT_RESET: it answered OK through its parse-failure path and
/// kept the long data, which the next execute then used in place of the value it sent.
#[tokio::test]
async fn reset_discards_long_data() {
    let mut s = Session::start().await;
    let stmt = s.prepare().await;
    s.send(&long_data(stmt, 1, b"stale")).await;
    let mut reset = vec![0x1A];
    reset.extend_from_slice(&stmt.to_le_bytes());
    s.send(&packet(0, &reset)).await;
    let (_, ok) = reply(&mut s.reader)
        .await
        .expect("a reply to COM_STMT_RESET");
    assert_eq!(ok[0], 0x00);

    s.send(&execute(stmt, BOTH)).await;
    assert_eq!(
        reply(&mut s.reader).await.map(|r| r.1),
        Some(SHIM_OK.to_vec())
    );
    assert_eq!(
        s.seen.lock().unwrap().clone(),
        vec![(stmt, vec![Some(b"a".to_vec()), Some(b"b".to_vec())])],
        "the execute's own value, not the discarded long data"
    );
}
