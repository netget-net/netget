//! The HDFS client against a real single-node HDFS from Apache Hadoop 3.5.0: `hdfs namenode
//! -format`, then a NameNode and a DataNode on probed loopback ports, all state in temporary
//! directories. What the client reads is seeded with `hdfs dfs -put`; what it writes is read
//! back with `hdfs dfs -cat`; and every change the model's actions asked for is asserted from the
//! NameNode's own audit log (`cmd=mkdirs`, `cmd=create`, …), which records what reached it on
//! the wire.
//!
//!   sh tests/client/yarn/install_peers.sh /tmp/hadoop-peers && export NETGET_HADOOP_HOME=...
//!   export JAVA_HOME=<a JDK 17>
//!   ./cargo-isolated.sh test --no-default-features --test client -- client::hdfs:: --test-threads=2

use crate::helpers::common::E2EResult;
use crate::helpers::real_server::{InstallHint, RealServer};
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const HADOOP: InstallHint = InstallHint {
    brew: "openjdk@17, then `sh tests/client/yarn/install_peers.sh <dir>`, and export the \
           NETGET_HADOOP_HOME it prints and JAVA_HOME for the JDK 17",
    apt: "openjdk-17-jre-headless, then `sh tests/client/yarn/install_peers.sh <dir>`, and \
          export the NETGET_HADOOP_HOME it prints",
};

fn hadoop_home() -> E2EResult<PathBuf> {
    let home = std::env::var_os("NETGET_HADOOP_HOME")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_HADOOP_HOME is not set. The HDFS client's evidence is Apache Hadoop's own \
         NameNode and DataNode, and this test FAILS rather than skipping without them: run \
         `sh tests/client/yarn/install_peers.sh /some/dir` (needs a JDK 17) and export the \
         NETGET_HADOOP_HOME it prints.",
        )?;
    if !home.join("bin/hdfs").is_file() {
        return Err(format!(
            "{}/bin/hdfs is missing; re-run tests/client/yarn/install_peers.sh",
            home.display()
        )
        .into());
    }
    Ok(home)
}

const CORE_SITE: &str = r#"<?xml version="1.0"?>
<configuration>
  <property><name>fs.defaultFS</name><value>hdfs://127.0.0.1:{port}</value></property>
  <property><name>hadoop.tmp.dir</name><value>{dir}/tmp</value></property>
</configuration>
"#;

/// Every service on 127.0.0.1 and a probed port; the name and data directories in the
/// NameNode's temporary directory; no safe-mode wait; 64 KiB blocks allowed, so a write of a
/// few hundred KiB crosses block boundaries.
const HDFS_SITE: &str = r#"<?xml version="1.0"?>
<configuration>
  <property><name>dfs.namenode.name.dir</name><value>{dir}/name</value></property>
  <property><name>dfs.datanode.data.dir</name><value>{dir}/data</value></property>
  <property><name>dfs.replication</name><value>1</value></property>
  <property><name>dfs.namenode.rpc-address</name><value>127.0.0.1:{port}</value></property>
  <property><name>dfs.namenode.http-address</name><value>127.0.0.1:{port1}</value></property>
  <property><name>dfs.datanode.address</name><value>127.0.0.1:{port2}</value></property>
  <property><name>dfs.datanode.http.address</name><value>127.0.0.1:{port3}</value></property>
  <property><name>dfs.datanode.ipc.address</name><value>127.0.0.1:{port4}</value></property>
  <property><name>dfs.namenode.secondary.http-address</name><value>127.0.0.1:{port5}</value></property>
  <property><name>dfs.namenode.datanode.registration.ip-hostname-check</name><value>false</value></property>
  <property><name>dfs.namenode.safemode.extension</name><value>0</value></property>
  <property><name>dfs.namenode.fs-limits.min-block-size</name><value>65536</value></property>
  <property><name>dfs.datanode.du.reserved</name><value>0</value></property>
</configuration>
"#;

/// A NameNode and a DataNode sharing the NameNode's configuration. Fields drop in order: the
/// DataNode stops before the directory holding its data is removed.
struct Cluster {
    dn: RealServer,
    nn: RealServer,
}

impl Cluster {
    async fn start() -> E2EResult<Cluster> {
        let home = hadoop_home()?;
        let hdfs = home.join("bin/hdfs").to_string_lossy().into_owned();
        let log4j = std::fs::read_to_string(home.join("etc/hadoop/log4j.properties"))?;
        let nn = RealServer::builder(&hdfs, HADOOP)
            .config_file("conf/core-site.xml", CORE_SITE)
            .config_file("conf/hdfs-site.xml", HDFS_SITE)
            .config_file("conf/log4j.properties", &log4j)
            .extra_ports(5)
            .setup_env("HADOOP_CONF_DIR", "{dir}/conf")
            .setup_env("HADOOP_LOG_DIR", "{dir}/logs/format")
            .setup_command(
                &hdfs,
                HADOOP,
                ["namenode", "-format", "-force", "-nonInteractive"],
            )
            .args(["namenode"])
            .env("HADOOP_CONF_DIR", "{dir}/conf")
            .env("HADOOP_LOG_DIR", "{dir}/logs/nn")
            .env("HADOOP_PID_DIR", "{dir}/pids/nn")
            .env("HADOOP_HEAPSIZE_MAX", "512m")
            // The audit log, on the NameNode's stdout: one line per call that reached it.
            .env("HDFS_AUDIT_LOGGER", "INFO,console")
            .ready_when_log_matches(r"NameNode RPC up at")
            .startup_timeout(Duration::from_secs(120))
            .start()
            .await?;
        let conf = nn.dir().join("conf");
        let dn = RealServer::builder(&hdfs, HADOOP)
            .args(["datanode"])
            .env("HADOOP_CONF_DIR", &conf.to_string_lossy())
            .env("HADOOP_LOG_DIR", "{dir}/logs")
            .env("HADOOP_PID_DIR", "{dir}/pids")
            .env("HADOOP_HEAPSIZE_MAX", "512m")
            // Its ports are in the shared configuration; the probed one is unused.
            .without_tcp_readiness()
            .ready_when_log_matches(r"successfully registered with NN")
            .startup_timeout(Duration::from_secs(120))
            .start()
            .await;
        let dn = nn.with_log(dn)?;
        let cluster = Cluster { dn, nn };
        // Out of safe mode before anything writes.
        let (ok, out, err) = cluster.dfsadmin(&["-safemode", "wait"]).await?;
        if !ok {
            return Err(format!("dfsadmin -safemode wait failed:\n{out}\n{err}").into());
        }
        Ok(cluster)
    }

    fn rpc(&self) -> String {
        self.nn.addr()
    }

    async fn hdfs(&self, args: &[&str]) -> E2EResult<(bool, String, String)> {
        let home = hadoop_home()?;
        let mut cmd = tokio::process::Command::new(home.join("bin/hdfs"));
        cmd.args(args)
            .env("HADOOP_CONF_DIR", self.nn.dir().join("conf"))
            .env("HADOOP_LOG_DIR", self.nn.dir().join("logs/cli"))
            .env("HADOOP_ROOT_LOGGER", "WARN,console")
            .env("HADOOP_HEAPSIZE_MAX", "256m")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let out = tokio::time::timeout(Duration::from_secs(120), cmd.output())
            .await
            .map_err(|_| "an hdfs command did not finish in 120 s")?
            .map_err(|e| crate::helpers::real_server::missing_binary("hdfs", HADOOP, e))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    async fn dfs(&self, args: &[&str]) -> E2EResult<String> {
        let mut all = vec!["dfs"];
        all.extend_from_slice(args);
        let (ok, out, err) = self.hdfs(&all).await?;
        if !ok {
            return Err(format!(
                "`hdfs dfs {}` failed\nstdout:\n{out}\nstderr:\n{err}\n--- NameNode ---\n{}",
                args.join(" "),
                self.nn.log()
            )
            .into());
        }
        Ok(out)
    }

    async fn dfsadmin(&self, args: &[&str]) -> E2EResult<(bool, String, String)> {
        let mut all = vec!["dfsadmin"];
        all.extend_from_slice(args);
        self.hdfs(&all).await
    }

    /// The audit log's `cmd=` entries for `user`: (cmd, src, dst).
    fn audited(&self, user: &str) -> Vec<(String, String, String)> {
        let ugi = format!("ugi={user} ");
        self.nn
            .log()
            .lines()
            .filter(|l| l.contains("allowed=") && l.contains(&ugi) && !l.contains("cmd=safemode"))
            .filter_map(|l| {
                let field = |k: &str| {
                    l.split('\t')
                        .flat_map(|f| f.split(' '))
                        .find_map(|f| f.strip_prefix(k))
                        .map(str::to_string)
                };
                Some((
                    field("cmd=")?,
                    field("src=").unwrap_or_default(),
                    field("dst=").unwrap_or_default(),
                ))
            })
            .collect()
    }

    fn print_logs(&self) {
        println!("--- NameNode ---\n{}", self.nn.log());
        println!("--- DataNode ---\n{}", self.dn.log());
    }
}

fn me() -> String {
    std::env::var("USER").unwrap_or_else(|_| "netget".into())
}

fn chain(code: &str) -> Option<Vec<Value>> {
    Some(vec![
        json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":code}}),
    ])
}

struct Client {
    state: AppState,
    id: ClientId,
    logs: Arc<Mutex<Vec<String>>>,
}

async fn client(
    remote: String,
    user: &str,
    handlers: Option<Vec<Value>>,
) -> anyhow::Result<Client> {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = logs.clone();
    tokio::spawn(async move {
        while let Some(l) = rx.recv().await {
            sink.lock().unwrap().push(l);
        }
    });
    let id = ClientForm {
        protocol: "hdfs".into(),
        remote_addr: Some(remote),
        instruction: Some("Use the cluster as you are asked".into()),
        startup_params: Some(json!({"user": user})),
        event_handlers: handlers,
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
        tx,
    )
    .await?;
    Ok(Client { state, id, logs })
}

impl Client {
    async fn events(&self, event_type: &str) -> Vec<Value> {
        let mut all: Vec<Value> = self
            .state
            .list_access_logs_for(Some(AccessLogOwner::Client(self.id.as_u32())), None)
            .await
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .filter(|e| e["event_type"] == event_type)
            .map(|e| e["request"].clone())
            .collect();
        all.reverse();
        all
    }

    /// Wait for the `nth` (from 0) event of a type.
    async fn wait(&self, event_type: &str, nth: usize, cluster: &Cluster) -> Value {
        let found = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Some(e) = self.events(event_type).await.get(nth) {
                    return e.clone();
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        match found {
            Ok(e) => e,
            Err(_) => {
                cluster.print_logs();
                println!("--- client ---\n{}", self.logs.lock().unwrap().join("\n"));
                panic!("no {event_type} #{nth}: was the model's action dropped?")
            }
        }
    }

    async fn wait_log(&self, needle: &str) -> bool {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if self.logs.lock().unwrap().iter().any(|l| l.contains(needle)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok()
    }
}

const SEED_TEXT: &str = "hello from apache hadoop\n";

/// 150 000 bytes over three 64 KiB blocks: every byte its offset modulo 251.
fn seed_binary() -> Vec<u8> {
    (0..150_000u32).map(|i| (i % 251) as u8).collect()
}

/// 140 000 bytes of text the client writes in 64 KiB blocks, crossing two block boundaries.
fn written_big() -> String {
    (0..9000)
        .map(|i| format!("line {i:05} netget\n"))
        .collect::<String>()[..140_000]
        .to_string()
}

/// The model for a whole session, one step per event.
const SESSION: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
BIG=''.join('line %05d netget\n' % n for n in range(9000))[:140000]
a=[]
if t=='hdfs_connected':
  a=[{'type':'hdfs_list','path':'/seed'}]
elif t=='hdfs_listing':
  a=[{'type':'hdfs_stat','path':'/seed/hello.txt'}]
elif t=='hdfs_file_status' and e['path']=='/seed/hello.txt':
  a=[{'type':'hdfs_read','path':'/seed/hello.txt'}]
elif t=='hdfs_read_result' and e['path']=='/seed/hello.txt':
  a=[{'type':'hdfs_read','path':'/seed/bin.dat','offset':65000,'length':2000,'encoding':'hex'}]
elif t=='hdfs_read_result':
  a=[{'type':'hdfs_mkdir','path':'/out/tmp'}]
elif t=='hdfs_mutation_result' and e['operation']=='mkdir':
  a=[{'type':'hdfs_write','path':'/out/netget.txt','data':'written by the netget client\n'}]
elif t=='hdfs_write_result' and e['path']=='/out/netget.txt':
  a=[{'type':'hdfs_write','path':'/out/big.txt','data':BIG,'block_size':65536}]
elif t=='hdfs_write_result':
  a=[{'type':'hdfs_rename','path':'/out/netget.txt','destination':'/out/renamed.txt'}]
elif t=='hdfs_mutation_result' and e['operation']=='rename':
  a=[{'type':'hdfs_set_permission','path':'/out/renamed.txt','mode':416}]
elif t=='hdfs_mutation_result' and e['operation']=='set_permission':
  a=[{'type':'hdfs_delete','path':'/out/tmp','recursive':True}]
elif t=='hdfs_mutation_result' and e['operation']=='delete':
  a=[{'type':'hdfs_stat','path':'/out/tmp'}]
elif t=='hdfs_file_status' and e['path']=='/out/tmp':
  a=[{'type':'hdfs_read','path':'/missing.txt'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hdfs_client_drives_a_real_cluster() -> E2EResult<()> {
    let cluster = Cluster::start().await?;
    let seed_dir = cluster.nn.dir().join("seed-files");
    std::fs::create_dir_all(&seed_dir)?;
    std::fs::write(seed_dir.join("hello.txt"), SEED_TEXT)?;
    std::fs::write(seed_dir.join("bin.dat"), seed_binary())?;
    let seed = seed_dir.to_string_lossy().into_owned();
    cluster.dfs(&["-mkdir", "-p", "/seed"]).await?;
    cluster
        .dfs(&[
            "-D",
            "dfs.blocksize=65536",
            "-put",
            &format!("{seed}/hello.txt"),
            &format!("{seed}/bin.dat"),
            "/seed/",
        ])
        .await?;

    let user = me();
    let c = client(cluster.rpc(), &user, chain(SESSION)).await?;

    let connected = c.wait("hdfs_connected", 0, &cluster).await;
    assert_eq!(connected["server_defaults"]["checksum_type"], "CRC32C");
    let listing = c.wait("hdfs_listing", 0, &cluster).await;
    let names: Vec<&str> = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["bin.dat", "hello.txt"], "{listing}");
    assert_eq!(listing["entries"][0]["length"], 150_000);
    assert_eq!(listing["entries"][0]["block_size"], 65536);
    assert_eq!(listing["entries"][1]["owner"], user.as_str());

    let status = c.wait("hdfs_file_status", 0, &cluster).await;
    assert_eq!(status["exists"], true);
    assert_eq!(status["status"]["length"], SEED_TEXT.len());
    assert_eq!(status["status"]["kind"], "file");

    let text = c.wait("hdfs_read_result", 0, &cluster).await;
    assert_eq!(text["data"], SEED_TEXT);
    assert_eq!(text["encoding"], "utf8");
    assert_eq!(text["eof"], true);
    // 65000..67000 straddles the first block boundary (65536): two DataNode reads.
    let bin = c.wait("hdfs_read_result", 1, &cluster).await;
    assert_eq!(bin["encoding"], "hex");
    assert_eq!(bin["data"], hex::encode(&seed_binary()[65000..67000]));
    assert_eq!(bin["datanodes"].as_array().unwrap().len(), 2, "{bin}");

    let written = c.wait("hdfs_write_result", 0, &cluster).await;
    assert_eq!(written["bytes"], 29);
    let big = c.wait("hdfs_write_result", 1, &cluster).await;
    assert_eq!(big["blocks"], 3, "{big}");
    let gone = c.wait("hdfs_file_status", 1, &cluster).await;
    assert_eq!(
        gone["exists"], false,
        "the recursive delete took /out/tmp: {gone}"
    );
    let error = c.wait("hdfs_error", 0, &cluster).await;
    assert_eq!(error["operation"], "read");
    assert_eq!(
        error["exception_class"], "java.io.FileNotFoundException",
        "{error}"
    );
    assert!(error["message"].as_str().unwrap().contains("/missing.txt"));

    // What the client wrote, read back by Hadoop's own client.
    assert_eq!(
        cluster.dfs(&["-cat", "/out/renamed.txt"]).await?,
        "written by the netget client\n"
    );
    assert_eq!(cluster.dfs(&["-cat", "/out/big.txt"]).await?, written_big());
    assert_eq!(
        cluster
            .dfs(&["-stat", "%a %o", "/out/renamed.txt"])
            .await?
            .trim(),
        "640 134217728"
    );
    assert_eq!(
        cluster.dfs(&["-stat", "%o", "/out/big.txt"]).await?.trim(),
        "65536"
    );
    let ls = cluster.dfs(&["-ls", "/out"]).await?;
    assert!(
        !ls.contains("/out/tmp") && !ls.contains("/out/netget.txt"),
        "{ls}"
    );

    // Every change the model asked for reached the NameNode, as the NameNode recorded it.
    let audit = cluster.audited(&user);
    println!("audit: {audit:?}");
    let has = |cmd: &str, src: &str, dst: &str| {
        audit
            .iter()
            .any(|(c, s, d)| c == cmd && s == src && (dst.is_empty() || d == dst))
    };
    assert!(has("listStatus", "/seed", ""), "{audit:?}");
    assert!(has("mkdirs", "/out/tmp", ""), "{audit:?}");
    assert!(has("create", "/out/netget.txt", ""), "{audit:?}");
    assert!(has("create", "/out/big.txt", ""), "{audit:?}");
    assert!(
        has("rename", "/out/netget.txt", "/out/renamed.txt"),
        "{audit:?}"
    );
    assert!(has("setPermission", "/out/renamed.txt", ""), "{audit:?}");
    assert!(has("delete", "/out/tmp", ""), "{audit:?}");
    assert!(has("open", "/seed/bin.dat", ""), "{audit:?}");
    Ok(())
}

/// A refusal by the real NameNode reaches the model as its exception class and message.
const REFUSED: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='hdfs_connected':
  a=[{'type':'hdfs_mkdir','path':'/locked/inside'}]
elif t=='hdfs_error' and e['operation']=='mkdir':
  a=[{'type':'hdfs_write','path':'/locked/a.txt','data':'x'}]
print(json.dumps({'actions':a}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_namenodes_refusal_reaches_the_model() -> E2EResult<()> {
    let cluster = Cluster::start().await?;
    cluster.dfs(&["-mkdir", "/locked"]).await?;
    cluster.dfs(&["-chmod", "755", "/locked"]).await?;
    let c = client(cluster.rpc(), "mallory", chain(REFUSED)).await?;
    let mkdir = c.wait("hdfs_error", 0, &cluster).await;
    assert_eq!(
        mkdir["exception_class"], "org.apache.hadoop.security.AccessControlException",
        "{mkdir}"
    );
    assert!(
        mkdir["message"].as_str().unwrap().contains("user=mallory"),
        "{mkdir}"
    );
    let write = c.wait("hdfs_error", 1, &cluster).await;
    assert_eq!(write["operation"], "write");
    assert_eq!(
        write["exception_class"],
        "org.apache.hadoop.security.AccessControlException"
    );
    let audit = cluster.audited("mallory");
    assert!(
        audit
            .iter()
            .any(|(c, s, _)| c == "mkdirs" && s == "/locked/inside"),
        "{audit:?}"
    );
    Ok(())
}

/// A model that asks for the same stat after every result: the chain stops at the bound.
const LOOP: &str = r#"import json,sys
print(json.dumps({'actions':[{'type':'hdfs_stat','path':'/'}]}))"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn followup_chain_stops_at_the_bound() -> E2EResult<()> {
    let cluster = Cluster::start().await?;
    let c = client(cluster.rpc(), &me(), chain(LOOP)).await?;
    assert!(
        c.wait_log("decision=followup_depth").await,
        "the chain did not stop"
    );
    let stats = c.events("hdfs_file_status").await.len();
    assert_eq!(
        stats,
        netget::client::hdfs::MAX_FOLLOWUP_DEPTH,
        "one stat per allowed follow-up"
    );
    let audited = cluster
        .audited(&me())
        .iter()
        .filter(|(c, _, _)| c == "getfileinfo")
        .count();
    assert_eq!(
        audited,
        netget::client::hdfs::MAX_FOLLOWUP_DEPTH,
        "{:?}",
        cluster.audited(&me())
    );
    Ok(())
}

/// The model backend is unreachable and no handler answers: nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn llm_failure_sends_nothing() -> E2EResult<()> {
    let cluster = Cluster::start().await?;
    let c = client(cluster.rpc(), &me(), None).await?;
    assert!(
        c.wait_log("decision=fail_closed_llm_error").await,
        "no fail-closed line"
    );
    let audited = cluster.audited(&me());
    assert!(
        audited.is_empty(),
        "the client acted without an answer: {audited:?}"
    );
    Ok(())
}
