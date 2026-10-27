//! Shared harness for the HDFS server suites: an in-process NameNode and DataNode with a python
//! policy playing the model (the LLM endpoint is unreachable, so an event the policy does not
//! cover exercises the fail-closed path), every status line the server logs kept for the test
//! to read, and the two independent clients — Apache Hadoop's `hdfs dfs` (Java) and
//! colinmarc/hdfs (Go) — run as subprocesses with a deadline, their output printed when a test
//! fails.
#![allow(dead_code)]

use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// The model. The root holds a text file, a directory described inline, a three-block file of
/// 64 KiB blocks, a failing file, alice's home (asked about when first opened) and a directory
/// the model refuses to describe. alice, bob and the account running the tests may connect;
/// mallory may not. Changes under /user/alice and /tmp are allowed, except content holding the
/// word "forbidden"; anything else is refused with AccessControlException; /silent gets no
/// answer at all.
pub const POLICY: &str = r#"import json,sys,os
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
def allow(): return {'type':'hdfs_allow'}
def deny(x='AccessControlException',m='Permission denied by policy'): return {'type':'hdfs_deny','exception':x,'message':m}
if t=='hdfs_connect':
  a=[deny('AccessControlException','mallory is not welcome')] if e['user']=='mallory' else [allow()]
elif t=='hdfs_describe_directory':
  p=e['path']
  if p=='/':
    a=[{'type':'hdfs_directory','entries':[
      {'name':'README.txt','kind':'file','text':'hello from netget\n','mode':420,'owner':'alice','group':'analysts','mtime':1760000000},
      {'name':'data','kind':'dir','owner':'hdfs','entries':[
        {'name':'events.csv','kind':'file','text':'id,event\n1,start\n2,stop\n'},
        {'name':'empty.txt','kind':'file','text':''}]},
      {'name':'big.bin','kind':'file','size':180000,'block_size':65536,'replication':3,
       'extents':[{'offset':0,'text':'BEGIN'},{'offset':65536,'length':65536,'fill':66},{'offset':131072,'hex':'deadbeef'}]},
      {'name':'broken.bin','kind':'file','size':8192,'errors':[{'offset':4096,'length':4096}]},
      {'name':'user','kind':'dir','entries':[{'name':'alice','kind':'dir','owner':'alice','mode':493},{'name':'bob','kind':'dir','owner':'bob'}]},
      {'name':'tmp','kind':'dir','mode':1023,'entries':[]},
      {'name':'secret','kind':'dir'},
      {'name':'silent','kind':'dir'}]}]
  elif p=='/secret':
    a=[deny('AccessControlException','the model will not say what is in /secret')]
  elif p=='/silent':
    a=[]
  elif p=='/user/alice':
    a=[{'type':'hdfs_directory','entries':[{'name':'notes.txt','kind':'file','text':'alice notes\n','owner':'alice'}]}]
  else:
    a=[{'type':'hdfs_directory','entries':[]}]
elif t=='hdfs_write' and 'forbidden' in e.get('data',''):
  a=[deny('DSQuotaExceededException','the model refuses this content')]
elif e.get('path','').startswith(('/user/alice/','/tmp/')) and e.get('destination','/tmp/').startswith(('/user/alice/','/tmp/')):
  a=[allow()]
else:
  a=[deny()]
print(json.dumps({'actions':a}))"#;

pub fn policy(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

pub struct Started {
    pub state: AppState,
    pub id: ServerId,
    pub port: u16,
    pub datanode_port: u16,
    pub logs: Arc<Mutex<Vec<String>>>,
}

impl Started {
    /// Every line the server logged so far containing `needle`.
    pub fn lines(&self, needle: &str) -> Vec<String> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .cloned()
            .collect()
    }

    /// Wait for a logged line containing `needle`.
    pub async fn wait_line(&self, needle: &str, secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(l) = self.lines(needle).into_iter().next() {
                return Some(l);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The NameNode methods every closed connection called, summed: method -> count.
    pub fn methods(&self) -> std::collections::BTreeMap<String, u64> {
        let mut out = std::collections::BTreeMap::new();
        for l in self.lines("closed after") {
            if let Some((_, list)) = l.split_once(" calls: ") {
                for item in list.split_whitespace() {
                    if let Some((m, n)) = item.split_once('=') {
                        *out.entry(m.to_string()).or_insert(0) += n.parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }
        out
    }

    /// The DataNode ops every closed connection ran: op -> count.
    pub fn ops(&self) -> std::collections::BTreeMap<String, u64> {
        let mut out = std::collections::BTreeMap::new();
        for l in self.lines("HDFS DataNode connection") {
            if let Some((_, rest)) = l.split_once(" closed: ") {
                for item in rest.split(" (").next().unwrap_or("").split_whitespace() {
                    if let Some((m, n)) = item.split_once('=') {
                        *out.entry(m.to_string()).or_insert(0) += n.parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }
        out
    }

    pub fn dump_logs(&self) -> String {
        self.logs.lock().unwrap().join("\n")
    }
}

/// Start the HDFS server on loopback with an unreachable model, so only `handlers` answer.
pub async fn start(handlers: Option<Vec<Value>>, params: Option<Value>) -> Started {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = logs.clone();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            sink.lock().unwrap().push(line);
        }
    });
    let mut params = params.unwrap_or_else(|| json!({}));
    if params.get("datanode_port").is_none() {
        params["datanode_port"] = json!(0);
    }
    let id = ServerForm {
        protocol: "hdfs".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
        instruction: Some("Be a Hadoop cluster".into()),
        event_handlers: handlers,
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap_or_else(|e| panic!("starting hdfs: {e}"));
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = state.get_server(id).await {
                if let Some(a) = s.local_addr {
                    return a.port();
                }
                if let netget::state::server::ServerStatus::Error(e) = &s.status {
                    panic!("hdfs failed to start: {e}");
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server started");
    let started = Started {
        state,
        id,
        port,
        datanode_port: 0,
        logs,
    };
    let line = started
        .wait_line("DataNode on", 10)
        .await
        .expect("the server logs its DataNode address");
    let datanode_port = line
        .rsplit(':')
        .next()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .expect("a DataNode port");
    Started {
        datanode_port,
        ..started
    }
}

/// What the model was shown, per event type, oldest first.
pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    let mut all: Vec<Value> = state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect();
    all.reverse();
    all
}

// ------------------------------------------------------------------- the peers

/// The Apache Hadoop 3.5.0 installation `tests/client/yarn/install_peers.sh` makes.
pub fn hadoop_home() -> PathBuf {
    let home = std::env::var("NETGET_HADOOP_HOME").unwrap_or_else(|_| {
        panic!(
            "NETGET_HADOOP_HOME is not set: the HDFS server's first independent client is Apache \
             Hadoop 3.5.0's hdfs CLI. Install it with `sh tests/client/yarn/install_peers.sh \
             /tmp/hadoop-peers` and export NETGET_HADOOP_HOME=/tmp/hadoop-peers/hadoop-3.5.0 \
             (it needs a JDK 17 on JAVA_HOME)"
        )
    });
    let home = PathBuf::from(home);
    assert!(
        home.join("bin/hdfs").exists(),
        "{}/bin/hdfs does not exist; rerun tests/client/yarn/install_peers.sh",
        home.display()
    );
    home
}

/// colinmarc/hdfs's Go client, `go install github.com/colinmarc/hdfs/v2/cmd/hdfs@v2.4.0`.
pub fn go_hdfs() -> PathBuf {
    if let Ok(p) = std::env::var("NETGET_GO_HDFS") {
        let p = PathBuf::from(p);
        assert!(p.exists(), "NETGET_GO_HDFS={} does not exist", p.display());
        return p;
    }
    let gobin = std::env::var("GOBIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("GOPATH")
                .ok()
                .map(|p| PathBuf::from(p).join("bin"))
        })
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("go/bin"))
        });
    if let Some(p) = gobin.map(|d| d.join("hdfs")) {
        if p.exists() {
            return p;
        }
    }
    panic!(
        "colinmarc/hdfs is not installed: the HDFS server's second independent client is its Go \
         `hdfs` command. Install it with `go install github.com/colinmarc/hdfs/v2/cmd/hdfs@v2.4.0` \
         and export NETGET_GO_HDFS=$(go env GOPATH)/bin/hdfs"
    )
}

/// colinmarc/hdfs's own `Client.Append`, through the driver in `tests/server/hdfs/goappend`
/// (its `hdfs` command has no append subcommand). Built with
/// `go build -o $(go env GOPATH)/bin/netget-hdfs-append ./tests/server/hdfs/goappend`.
pub fn go_append() -> PathBuf {
    if let Ok(p) = std::env::var("NETGET_GO_HDFS_APPEND") {
        let p = PathBuf::from(p);
        assert!(
            p.exists(),
            "NETGET_GO_HDFS_APPEND={} does not exist",
            p.display()
        );
        return p;
    }
    let beside = go_hdfs().with_file_name("netget-hdfs-append");
    if beside.exists() {
        return beside;
    }
    panic!(
        "colinmarc/hdfs's append driver is not built: its hdfs command has no append, so the test \
         drives the library's Client.Append through tests/server/hdfs/goappend. Build it with \
         `(cd tests/server/hdfs/goappend && go build -o $(go env GOPATH)/bin/netget-hdfs-append .)` \
         and export NETGET_GO_HDFS_APPEND to that path"
    )
}

/// colinmarc/hdfs's `Client.Append` of `data` to `path` as `user`.
pub async fn go_append_to(server: &Started, user: &str, path: &str, data: Vec<u8>) -> Run {
    let env = vec![
        ("HADOOP_NAMENODE", format!("127.0.0.1:{}", server.port)),
        ("HADOOP_USER_NAME", user.to_string()),
    ];
    run(&go_append(), &[path], &env, Some(data), 60).await
}

/// `n` bytes of numbered lines, so a misplaced byte shows where it came from.
pub fn lines(n: usize, tag: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0usize;
    while out.len() < n {
        out.extend_from_slice(format!("{tag} line {i:06}\n").as_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

/// What a peer run produced.
#[derive(Debug)]
pub struct Run {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
    /// Panic with the peer's own output unless it succeeded.
    pub fn expect_ok(&self, what: &str, server: &Started) -> &Self {
        assert!(
            self.ok(),
            "{what} failed ({:?})\n--- stdout ---\n{}\n--- stderr ---\n{}\n--- server log ---\n{}",
            self.status,
            self.stdout,
            self.stderr,
            server.dump_logs()
        );
        self
    }
    pub fn expect_failure(&self, what: &str, server: &Started) -> &Self {
        assert!(
            !self.ok(),
            "{what} succeeded but should have failed\n--- stdout ---\n{}\n--- stderr ---\n{}\n--- server log ---\n{}",
            self.stdout,
            self.stderr,
            server.dump_logs()
        );
        self
    }
}

/// Run a peer with a deadline; it is killed if it overstays.
pub async fn run(
    program: &std::path::Path,
    args: &[&str],
    env: &[(&str, String)],
    stdin: Option<Vec<u8>>,
    secs: u64,
) -> Run {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("running {}: {e}", program.display()));
    if let Some(input) = stdin {
        use tokio::io::AsyncWriteExt;
        let mut si = child.stdin.take().unwrap();
        // A peer that fails early stops reading: its exit status and output say why, so a
        // broken pipe here is not the failure to report.
        let _ = si.write_all(&input).await;
        drop(si);
    }
    match tokio::time::timeout(Duration::from_secs(secs), child.wait_with_output()).await {
        Ok(Ok(o)) => Run {
            status: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Ok(Err(e)) => panic!("waiting for {}: {e}", program.display()),
        Err(_) => Run {
            status: None,
            stdout: String::new(),
            stderr: format!(
                "{} did not finish within {secs} s (killed)",
                program.display()
            ),
        },
    }
}

/// `hdfs dfs <args>` against the server as `user`.
pub async fn hdfs_dfs(server: &Started, user: &str, args: &[&str]) -> Run {
    let home = hadoop_home();
    let fs = format!("fs.defaultFS=hdfs://127.0.0.1:{}", server.port);
    let mut all: Vec<&str> = vec![
        "dfs",
        "-D",
        &fs,
        "-D",
        "dfs.client.use.datanode.hostname=false",
        "-D",
        "dfs.client.block.write.replace-datanode-on-failure.enable=false",
        "-D",
        "dfs.replication=1",
    ];
    all.extend_from_slice(args);
    let mut env = vec![
        ("HADOOP_USER_NAME", user.to_string()),
        ("HADOOP_ROOT_LOGGER", "WARN,console".to_string()),
        ("HADOOP_HOME", home.display().to_string()),
    ];
    if let Ok(j) = std::env::var("JAVA_HOME") {
        env.push(("JAVA_HOME", j));
    }
    run(&home.join("bin/hdfs"), &all, &env, None, 120).await
}

/// colinmarc/hdfs's `hdfs <args>` against the server as `user`.
pub async fn go(server: &Started, user: &str, args: &[&str], stdin: Option<Vec<u8>>) -> Run {
    let env = vec![
        ("HADOOP_NAMENODE", format!("127.0.0.1:{}", server.port)),
        ("HADOOP_USER_NAME", user.to_string()),
        (
            "HADOOP_CONF_DIR",
            "/nonexistent-netget-hdfs-conf".to_string(),
        ),
    ];
    run(&go_hdfs(), args, &env, stdin, 60).await
}

/// The user running the tests.
pub fn me() -> String {
    std::env::var("USER").unwrap_or_else(|_| "netget".into())
}

/// CRC32C of `bytes`, computed here bit by bit from the Castagnoli polynomial (reflected
/// 0x82F63B78) so the checksums a test checks are not NetGet's own computation.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The per-block MD5s of the chunk CRC32Cs of `content` in blocks of `block_size`, chunks of
/// 512 bytes: what each OP_BLOCK_CHECKSUM answers, computed here.
pub fn block_md5s(content: &[u8], block_size: usize) -> Vec<[u8; 16]> {
    use md5::{Digest, Md5};
    content
        .chunks(block_size)
        .map(|block| {
            let mut sums = Vec::new();
            for chunk in block.chunks(512) {
                sums.extend_from_slice(&crc32c(chunk).to_be_bytes());
            }
            Md5::digest(&sums).into()
        })
        .collect()
}

/// Hadoop's MD5-of-MD5-of-CRC32C file checksum, as `hdfs dfs -checksum` prints its MD5.
///
/// Java's FileChecksumHelper writes the block MD5s into a `DataOutputBuffer` and digests
/// `getData()` — the whole backing array, not just what was written. The buffer starts at 32
/// bytes and doubles, so three blocks (48 bytes) are digested with 16 zero bytes after them.
/// That quirk is Hadoop's, reproduced here so the comparison is exact.
pub fn md5md5crc32c(content: &[u8], block_size: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut buf: Vec<u8> = block_md5s(content, block_size).concat();
    let mut capacity = 32usize;
    while capacity < buf.len() {
        capacity *= 2;
    }
    buf.resize(capacity, 0);
    Md5::digest(&buf).to_vec()
}

/// The bytes of /big.bin as POLICY describes them.
pub fn big_bin() -> Vec<u8> {
    let mut v = vec![0u8; 180000];
    v[..5].copy_from_slice(b"BEGIN");
    for b in &mut v[65536..131072] {
        *b = 66;
    }
    v[131072..131076].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    v
}
