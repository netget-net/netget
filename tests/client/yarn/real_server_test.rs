//! The YARN client with the model in the loop, against **Apache Hadoop's own ResourceManager
//! and NodeManager** — never NetGet's own YARN server.
//!
//! [`Cluster::start`] runs the official Hadoop distribution (`install_peers.sh`) as a
//! single-node pseudo-distributed YARN on loopback ports, with a minimal configuration written
//! into a temporary directory (`fs.defaultFS` is `file:///`, so no HDFS) and two queues,
//! `default` and `netget`. The test then runs real **distributed-shell** applications on it —
//! one that succeeds, one whose container exits non-zero, and one that sleeps until the model
//! kills it — so the client reads a real application, attempt, queue and node.
//!
//! Every result the client hands the model is checked against what YARN itself reports through
//! its **RPC** command line (`yarn application -list`, `-status`, `yarn applicationattempt
//! -list`, `yarn node -list`), which is not the REST layer under test, and against the
//! configuration the test wrote.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire —
//! is asserted through [`WireTap`], a recording TCP relay between NetGet and the
//! ResourceManager: the requests YARN received (method, target and body) are compared with the
//! requests the model's actions name, including the application the model picked out of a list
//! and the one it killed; the kill is then confirmed by YARN's own CLI.
//!
//! **No test here skips.** Without `NETGET_HADOOP_HOME` (from `install_peers.sh`), or without a
//! JDK, every test fails and says how to install them.
//!
//! LLM calls: 14 (the cluster chain), 8 (follow-up bound), 2 (kill refused), 1 (LLM failure).
//!
//!   sh tests/client/yarn/install_peers.sh /tmp/hadoop-peers && export NETGET_HADOOP_HOME=...
//!   export JAVA_HOME=<a JDK 17>
//!   ./cargo-isolated.sh test --no-default-features --features tcp,yarn --test client -- client::yarn:: --test-threads=4

use crate::helpers::real_server::{InstallHint, RealServer, ToolProcess};
use crate::helpers::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HADOOP: InstallHint = InstallHint {
    brew: "openjdk@17, then `sh tests/client/yarn/install_peers.sh <dir>`, and export the \
           NETGET_HADOOP_HOME it prints and JAVA_HOME for the JDK 17",
    apt: "openjdk-17-jre-headless, then `sh tests/client/yarn/install_peers.sh <dir>`, and \
          export the NETGET_HADOOP_HOME it prints",
};

/// The distribution `install_peers.sh` unpacked.
fn hadoop_home() -> E2EResult<PathBuf> {
    let home = std::env::var_os("NETGET_HADOOP_HOME")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_HADOOP_HOME is not set. The YARN client's evidence is Apache Hadoop's own \
             ResourceManager and NodeManager, and this test FAILS rather than skipping without \
             it: run `sh tests/client/yarn/install_peers.sh /some/dir` (needs a JDK 17) and \
             export the NETGET_HADOOP_HOME it prints.",
        )?;
    if !home.join("etc/hadoop/log4j.properties").is_file() {
        return Err(format!(
            "{} is not a Hadoop binary distribution (no etc/hadoop/log4j.properties); re-run \
             tests/client/yarn/install_peers.sh",
            home.display()
        )
        .into());
    }
    Ok(home)
}

/// `$NETGET_HADOOP_HOME/bin/<name>`.
fn hadoop_tool(name: &str) -> E2EResult<String> {
    let path = hadoop_home()?.join("bin").join(name);
    if !path.is_file() {
        return Err(format!(
            "{} is missing; re-run tests/client/yarn/install_peers.sh",
            path.display()
        )
        .into());
    }
    Ok(path.to_string_lossy().into_owned())
}

/// The distributed-shell example application's jar.
fn distributed_shell_jar() -> E2EResult<String> {
    let dir = hadoop_home()?.join("share/hadoop/yarn");
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with("hadoop-yarn-applications-distributedshell-") && name.ends_with(".jar")
        {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    Err(format!("no distributed-shell jar under {}", dir.display()).into())
}

const CORE_SITE: &str = r#"<?xml version="1.0"?>
<configuration>
  <property><name>fs.defaultFS</name><value>file:///</value></property>
  <property><name>hadoop.tmp.dir</name><value>{dir}/tmp</value></property>
</configuration>
"#;

/// Every service on 127.0.0.1 and a probed port; every state directory inside the temporary
/// directory — the node-attribute store defaults to `/tmp/hadoop-yarn-${user}/node-attribute`
/// whatever `hadoop.tmp.dir` says, so two ResourceManagers started at once (`--test-threads`)
/// trample each other's mirror file and one fails to become active; the NodeManager's disk
/// health checker off
/// (a nearly full developer disk would mark the node unhealthy and nothing would run); no
/// memory enforcement (the containers are `echo`, `false` and `sleep`).
const YARN_SITE: &str = r#"<?xml version="1.0"?>
<configuration>
  <property><name>yarn.resourcemanager.hostname</name><value>127.0.0.1</value></property>
  <property><name>yarn.resourcemanager.webapp.address</name><value>127.0.0.1:{port}</value></property>
  <property><name>yarn.resourcemanager.address</name><value>127.0.0.1:{port1}</value></property>
  <property><name>yarn.resourcemanager.scheduler.address</name><value>127.0.0.1:{port2}</value></property>
  <property><name>yarn.resourcemanager.resource-tracker.address</name><value>127.0.0.1:{port3}</value></property>
  <property><name>yarn.resourcemanager.admin.address</name><value>127.0.0.1:{port4}</value></property>
  <property><name>yarn.nodemanager.hostname</name><value>127.0.0.1</value></property>
  <property><name>yarn.nodemanager.address</name><value>127.0.0.1:{port5}</value></property>
  <property><name>yarn.nodemanager.localizer.address</name><value>127.0.0.1:{port6}</value></property>
  <property><name>yarn.nodemanager.webapp.address</name><value>127.0.0.1:{port7}</value></property>
  <property><name>yarn.nodemanager.local-dirs</name><value>{dir}/nm-local</value></property>
  <property><name>yarn.nodemanager.log-dirs</name><value>{dir}/nm-logs</value></property>
  <property><name>yarn.nodemanager.resource.memory-mb</name><value>4096</value></property>
  <property><name>yarn.nodemanager.resource.cpu-vcores</name><value>4</value></property>
  <property><name>yarn.scheduler.minimum-allocation-mb</name><value>128</value></property>
  <property><name>yarn.nodemanager.pmem-check-enabled</name><value>false</value></property>
  <property><name>yarn.nodemanager.vmem-check-enabled</name><value>false</value></property>
  <property><name>yarn.nodemanager.disk-health-checker.enable</name><value>false</value></property>
  <property><name>yarn.nodemanager.disk-health-checker.max-disk-utilization-per-disk-percentage</name><value>100.0</value></property>
  <property><name>yarn.log-aggregation-enable</name><value>false</value></property>
  <property><name>yarn.node-attribute.fs-store.root-dir</name><value>file://{dir}/node-attribute</value></property>
  <property><name>yarn.node-labels.fs-store.root-dir</name><value>file://{dir}/node-labels</value></property>
</configuration>
"#;

/// Two queues, so a queue filter and a queue answer mean something.
const CAPACITY_SCHEDULER: &str = r#"<?xml version="1.0"?>
<configuration>
  <property><name>yarn.scheduler.capacity.root.queues</name><value>default,netget</value></property>
  <property><name>yarn.scheduler.capacity.root.default.capacity</name><value>60</value></property>
  <property><name>yarn.scheduler.capacity.root.netget.capacity</name><value>40</value></property>
  <property><name>yarn.scheduler.capacity.root.default.maximum-capacity</name><value>100</value></property>
  <property><name>yarn.scheduler.capacity.root.netget.maximum-capacity</name><value>100</value></property>
  <property><name>yarn.scheduler.capacity.maximum-am-resource-percent</name><value>0.8</value></property>
</configuration>
"#;

/// A single-node YARN: a ResourceManager and, for the tests that run applications, a
/// NodeManager. Fields drop in order, so the NodeManager stops before the ResourceManager's
/// directory (which holds the configuration and the NodeManager's local dirs) is removed.
struct Cluster {
    nm: Option<RealServer>,
    rm: RealServer,
}

impl Cluster {
    async fn start(with_node: bool) -> E2EResult<Cluster> {
        let home = hadoop_home()?;
        let log4j = std::fs::read_to_string(home.join("etc/hadoop/log4j.properties"))?;
        let yarn = hadoop_tool("yarn")?;
        let rm = RealServer::builder(&yarn, HADOOP)
            .args(["resourcemanager"])
            .config_file("conf/core-site.xml", CORE_SITE)
            .config_file("conf/yarn-site.xml", YARN_SITE)
            .config_file("conf/capacity-scheduler.xml", CAPACITY_SCHEDULER)
            .config_file("conf/log4j.properties", &log4j)
            .extra_ports(7)
            .env("HADOOP_CONF_DIR", "{dir}/conf")
            .env("HADOOP_LOG_DIR", "{dir}/logs/rm")
            .env("HADOOP_PID_DIR", "{dir}/pids/rm")
            .env("HADOOP_HEAPSIZE_MAX", "512m")
            .ready_when_log_matches(r"Transitioned to active state")
            .startup_timeout(Duration::from_secs(120))
            .start()
            .await?;
        let nm = if with_node {
            let conf = rm.dir().join("conf");
            let started = RealServer::builder(&yarn, HADOOP)
                .args(["nodemanager"])
                .env("HADOOP_CONF_DIR", &conf.to_string_lossy())
                .env("HADOOP_LOG_DIR", "{dir}/logs")
                .env("HADOOP_PID_DIR", "{dir}/pids")
                .env("HADOOP_HEAPSIZE_MAX", "512m")
                // Its ports are in the shared configuration; the probed one is unused.
                .without_tcp_readiness()
                .ready_when_log_matches(r"Registered with ResourceManager as")
                .startup_timeout(Duration::from_secs(120))
                .start()
                .await;
            Some(rm.with_log(started)?)
        } else {
            None
        };
        Ok(Cluster { nm, rm })
    }

    fn conf(&self) -> PathBuf {
        self.rm.dir().join("conf")
    }

    /// `yarn <args>` against this cluster, with the configuration the daemons read.
    fn yarn(&self, args: &[&str]) -> E2EResult<Command> {
        let mut cmd = Command::new(&hadoop_tool("yarn")?);
        cmd.args(args)
            .env("HADOOP_CONF_DIR", self.conf())
            .env("HADOOP_LOG_DIR", self.rm.dir().join("logs/cli"))
            .env("HADOOP_HEAPSIZE_MAX", "256m");
        Ok(cmd)
    }

    /// Run `yarn <args>` to completion: `(exit success, stdout, stderr)`.
    async fn run(&self, args: &[&str]) -> E2EResult<(bool, String, String)> {
        let mut cmd = self.yarn(args)?;
        let out =
            tokio::task::spawn_blocking(move || cmd.stdin(std::process::Stdio::null()).output())
                .await
                .map_err(|e| format!("yarn task failed: {e}"))?
                .map_err(|e| crate::helpers::real_server::missing_binary("yarn", HADOOP, e))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// A YARN CLI query that must succeed; its stdout.
    async fn query(&self, args: &[&str]) -> E2EResult<String> {
        let (ok, out, err) = self.run(args).await?;
        if !ok {
            return Err(format!(
                "`yarn {}` failed.\nstdout:\n{out}\nstderr:\n{err}",
                args.join(" ")
            )
            .into());
        }
        Ok(out)
    }

    /// The distributed-shell client's arguments for one application.
    fn shell_args(name: &str, queue: &str, command: &str, args: &str) -> E2EResult<Vec<String>> {
        let jar = distributed_shell_jar()?;
        let mut v: Vec<String> = [
            "jar",
            &jar,
            "org.apache.hadoop.yarn.applications.distributedshell.Client",
            "-jar",
            &jar,
            "-shell_command",
            command,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if !args.is_empty() {
            v.extend(["-shell_args".to_string(), args.to_string()]);
        }
        v.extend(
            [
                "-num_containers",
                "1",
                "-master_memory",
                "256",
                "-container_memory",
                "128",
                "-appname",
                name,
                "-queue",
                queue,
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        Ok(v)
    }

    /// Run a distributed-shell application to completion: its id and whether it succeeded.
    async fn run_app(
        &self,
        name: &str,
        queue: &str,
        command: &str,
        args: &str,
    ) -> E2EResult<(String, bool)> {
        let argv = Self::shell_args(name, queue, command, args)?;
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let (ok, out, err) = self.run(&argv).await?;
        let id = submitted_id(&format!("{out}\n{err}")).ok_or_else(|| {
            format!("the distributed shell never submitted {name}.\nstdout:\n{out}\nstderr:\n{err}")
        })?;
        Ok((id, ok))
    }

    /// Start a distributed-shell application that keeps running, and wait until YARN reports it
    /// RUNNING. The client process stays alive with it.
    async fn start_app(
        &self,
        name: &str,
        queue: &str,
        command: &str,
        args: &str,
    ) -> E2EResult<(String, ToolProcess)> {
        let argv = Self::shell_args(name, queue, command, args)?;
        let cmd = self.yarn(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
        let client = ToolProcess::spawn(cmd, "yarn", HADOOP)?;
        let line = client
            .wait_for_line("Submitted application", Duration::from_secs(120), |l| {
                submitted_id(l).is_some()
            })
            .await?;
        let id = submitted_id(&line).ok_or("no application id")?;
        self.wait_for_state(&id, "RUNNING", Duration::from_secs(120))
            .await?;
        Ok((id, client))
    }

    /// Poll the ResourceManager until `id` is in `state`. The harness waiting for its peer,
    /// not evidence: the evidence is what NetGet and the CLI read afterwards.
    async fn wait_for_state(&self, id: &str, state: &str, timeout: Duration) -> E2EResult<()> {
        let url = format!("http://{}/ws/v1/cluster/apps/{id}/state", self.rm.addr());
        let http = reqwest::Client::builder().no_proxy().build()?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(resp) = http.get(&url).send().await {
                if let Ok(v) = resp.json::<Value>().await {
                    if v["state"] == state {
                        return Ok(());
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("{id} never reached {state}").into());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn with_log<T>(&self, result: E2EResult<T>) -> E2EResult<T> {
        let result = self.rm.with_log(result);
        match &self.nm {
            Some(nm) => nm.with_log(result),
            None => result,
        }
    }
}

/// `Submitted application application_…` in the distributed shell's log.
fn submitted_id(text: &str) -> Option<String> {
    let rest = text.split("Submitted application ").nth(1)?;
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    id.starts_with("application_").then_some(id)
}

/// `yarn application -list -appStates ALL`: id → [name, type, user, queue, state, final state].
fn cli_apps(out: &str) -> BTreeMap<String, Vec<String>> {
    out.lines()
        .filter(|l| l.trim_start().starts_with("application_"))
        .map(|l| {
            let cols: Vec<String> = l.split('\t').map(|c| c.trim().to_string()).collect();
            (cols[0].clone(), cols[1..7].to_vec())
        })
        .collect()
}

/// `yarn application -status <id>`: each `Key : value` line, the first value of each key.
fn cli_report(out: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in out.lines() {
        if let Some((k, v)) = line.split_once(" : ") {
            map.entry(k.trim().to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    map
}

/// A recording TCP relay: NetGet talks to it, it talks to the ResourceManager, and it keeps
/// every HTTP request that crossed it as `METHOD target` plus its body. The ResourceManager
/// keeps no request log of its own, so this is where "what did the client actually ask for"
/// is read from the wire.
struct WireTap {
    addr: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

/// Every complete request in `pending`, drained: `(request line minus the version, body)`.
fn take_requests(pending: &mut Vec<u8>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = String::from_utf8_lossy(&pending[..end]).to_string();
        let length = head
            .lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if pending.len() < end + 4 + length {
            break;
        }
        let body = String::from_utf8_lossy(&pending[end + 4..end + 4 + length]).to_string();
        pending.drain(..end + 4 + length);
        let line = head.lines().next().unwrap_or_default();
        out.push((line.trim_end_matches(" HTTP/1.1").to_string(), body));
    }
    out
}

impl WireTap {
    async fn start(target: String) -> E2EResult<WireTap> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut relays = tokio::task::JoinSet::new();
            while let Ok((mut down, _)) = listener.accept().await {
                let target = target.clone();
                let seen = Arc::clone(&seen);
                relays.spawn(async move {
                    let Ok(up) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let (mut up_r, mut up_w) = up.into_split();
                    let (mut down_r, mut down_w) = down.split();
                    let to_yarn = async {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending = Vec::new();
                        loop {
                            let n = match down_r.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            let done = take_requests(&mut pending);
                            seen.lock().unwrap().extend(done);
                            if up_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = up_w.shutdown().await;
                    };
                    // When the ResourceManager closes (or dies), close NetGet's side too, so a
                    // pooled connection fails at once instead of carrying a request nobody
                    // will answer.
                    let from_yarn = async {
                        let _ = tokio::io::copy(&mut up_r, &mut down_w).await;
                        let _ = down_w.shutdown().await;
                    };
                    let _ = tokio::join!(to_yarn, from_yarn);
                });
            }
        });
        Ok(WireTap {
            addr,
            requests,
            task,
        })
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.requests.lock().unwrap().clone()
    }

    fn lines(&self) -> Vec<String> {
        self.requests().into_iter().map(|(l, _)| l).collect()
    }
}

impl Drop for WireTap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Events the mock model saw, by a key the rule names.
type Seen = Arc<Mutex<BTreeMap<String, Value>>>;

fn keep(seen: &Seen, key: &str, e: &Value) {
    seen.lock().unwrap().insert(key.to_string(), e.clone());
}

/// A real cluster with real applications: the model reads the metrics, the scheduler, the
/// node, the finished applications and the one running in queue `netget`; it then picks the
/// failed application out of the list (read with its attempts and queue), asks for one that
/// does not exist, and kills the running one. Every answer is checked against YARN's CLI and
/// every request against what crossed the wire.
#[tokio::test]
async fn yarn_client_reads_and_kills_on_a_real_cluster() -> E2EResult<()> {
    let cluster = Cluster::start(true).await?;
    let result = cluster_chain(&cluster).await;
    cluster.with_log(result)
}

async fn cluster_chain(cluster: &Cluster) -> E2EResult<()> {
    let (ok_id, ok_success) = cluster
        .run_app("netget-ok", "default", "echo", "netget")
        .await?;
    assert!(ok_success, "the succeeding application must succeed");
    let (failed_id, failed_success) = cluster
        .run_app("netget-fail", "netget", "false", "")
        .await?;
    assert!(!failed_success, "the failing application must fail");
    let (sleep_id, _sleeper) = cluster
        .start_app("netget-sleep", "netget", "sleep", "600")
        .await?;
    let ts = ok_id
        .strip_prefix("application_")
        .and_then(|r| r.split('_').next())
        .ok_or("no cluster timestamp in the application id")?
        .to_string();
    let unknown = format!("application_{ts}_999999");

    // YARN's own view before NetGet reads anything, over RPC rather than REST.
    let before = cli_apps(
        &cluster
            .query(&["application", "-list", "-appStates", "ALL"])
            .await?,
    );
    assert_eq!(before.len(), 3, "{before:?}");
    let failed_report = cli_report(
        &cluster
            .query(&["application", "-status", &failed_id])
            .await?,
    );
    let attempts_cli = cluster
        .query(&["applicationattempt", "-list", &failed_id])
        .await?;
    let nodes_cli = cluster.query(&["node", "-list", "-all"]).await?;

    let tap = WireTap::start(cluster.rm.addr()).await?;
    let addr = tap.addr.clone();
    let seen: Seen = Arc::default();
    let s = |key: &'static str| {
        let seen = Arc::clone(&seen);
        move |e: &Value| keep(&seen, key, e)
    };
    let (k_conn, k_metrics, k_sched, k_nodes, k_node) = (
        s("connected"),
        s("get_cluster_metrics"),
        s("get_scheduler"),
        s("list_nodes"),
        s("get_node"),
    );
    let (k_apps, k_app, k_attempts, k_queue, k_state, k_kill, k_err) = (
        Arc::clone(&seen),
        s("get_application"),
        s("list_app_attempts"),
        s("get_app_queue"),
        s("get_app_state"),
        s("kill_application"),
        s("error"),
    );
    let unknown_for_model = unknown.clone();
    let config = NetGetConfig::new(format!(
        "Look at the YARN cluster whose ResourceManager is at {addr}. YARN-CLUSTER-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("YARN-CLUSTER-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "YARN",
                "remote_addr": addr,
                "startup_params": {"allow_kill": true, "request_timeout_secs": 60},
                "instruction": "Find out why an application failed, and kill the one sleeping in queue netget."
            }]))
            .expect_calls(1)
            .and()
            .on_event("yarn_connected")
            .and_event_data_contains("resource_manager_version", "3.5.0")
            .respond_with_actions_from_event(move |e| {
                k_conn(e);
                json!([
                    {"type": "get_cluster_metrics"},
                    {"type": "get_scheduler"},
                    {"type": "list_nodes"},
                    {"type": "list_applications", "states": ["FINISHED"]},
                    {"type": "list_applications", "states": "running", "queue": "netget"}
                ])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_cluster_metrics")
            .respond_with_actions_from_event(move |e| {
                k_metrics(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_scheduler")
            .respond_with_actions_from_event(move |e| {
                k_sched(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_nodes")
            .and_event_data_contains("operation", "list_nodes")
            .respond_with_actions_from_event(move |e| {
                k_nodes(e);
                json!([{"type": "get_node", "node_id": e["nodes"][0]["id"]}])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_nodes")
            .and_event_data_contains("operation", "get_node")
            .respond_with_actions_from_event(move |e| {
                k_node(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_applications")
            .and_event_data_contains("operation", "list_applications")
            .respond_with_actions_from_event(move |e| {
                let apps = e["applications"].as_array().cloned().unwrap_or_default();
                if e["filters"]["queue"] == "netget" {
                    keep(&k_apps, "running_in_netget", e);
                    let id = apps.first().map(|a| a["id"].clone()).unwrap_or(json!("none"));
                    json!([
                        {"type": "get_app_state", "app_id": id},
                        {"type": "kill_application", "app_id": id}
                    ])
                } else {
                    keep(&k_apps, "finished", e);
                    // The model's choice: the application whose final status is FAILED.
                    let failed = apps
                        .iter()
                        .find(|a| a["finalStatus"] == "FAILED")
                        .map(|a| a["id"].clone())
                        .unwrap_or(json!("none"));
                    json!([
                        {"type": "get_application", "app_id": failed},
                        {"type": "list_app_attempts", "app_id": failed},
                        {"type": "get_app_queue", "app_id": failed},
                        {"type": "get_application", "app_id": unknown_for_model}
                    ])
                }
            })
            .expect_calls(2)
            .and()
            .on_event("yarn_applications")
            .and_event_data_contains("operation", "get_application")
            .respond_with_actions_from_event(move |e| {
                k_app(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_app_attempts")
            .respond_with_actions_from_event(move |e| {
                k_attempts(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_app_queue")
            .respond_with_actions_from_event(move |e| {
                k_queue(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_app_state")
            .and_event_data_contains("operation", "get_app_state")
            .respond_with_actions_from_event(move |e| {
                k_state(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_app_state")
            .and_event_data_contains("operation", "kill_application")
            .respond_with_actions_from_event(move |e| {
                k_kill(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_error")
            .respond_with_actions_from_event(move |e| {
                k_err(e);
                json!([])
            })
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(120).await;
    client.verify_mocks().await?;
    let seen = seen.lock().unwrap().clone();
    client.stop().await?;

    // The kill, as YARN's own CLI reports it once YARN has finished it.
    cluster
        .wait_for_state(&sleep_id, "KILLED", Duration::from_secs(60))
        .await?;
    let killed = cli_report(
        &cluster
            .query(&["application", "-status", &sleep_id])
            .await?,
    );
    assert_eq!(killed["State"], "KILLED", "{killed:?}");
    assert_eq!(killed["Final-State"], "KILLED", "{killed:?}");

    // The ResourceManager NetGet connected to.
    let conn = &seen["connected"];
    assert_eq!(conn["resource_manager_version"], "3.5.0");
    assert_eq!(conn["ha_state"], "ACTIVE");
    assert_eq!(conn["state"], "STARTED");
    assert_eq!(conn["kill_allowed"], true);
    assert_eq!(
        conn["cluster_id"].to_string(),
        ts,
        "the cluster id is the ids' timestamp"
    );

    // Metrics: three applications submitted, two completed, one running, on the one node of
    // the size the configuration gave it.
    let m = &seen["get_cluster_metrics"]["metrics"];
    assert_eq!(m["appsSubmitted"], 3, "{m}");
    assert_eq!(m["appsCompleted"], 2, "{m}");
    assert_eq!(m["appsRunning"], 1, "{m}");
    assert_eq!(m["totalNodes"], 1, "{m}");
    assert_eq!(m["activeNodes"], 1, "{m}");
    assert_eq!(m["totalMB"], 4096, "{m}");
    assert_eq!(m["totalVirtualCores"], 4, "{m}");

    // The scheduler: the queues capacity-scheduler.xml declares, with the running application
    // counted in netget.
    let sched = &seen["get_scheduler"];
    assert_eq!(sched["scheduler"]["type"], "capacityScheduler");
    let queues: BTreeMap<String, Value> = sched["queues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| {
            (
                q["queuePath"].as_str().unwrap_or_default().to_string(),
                q.clone(),
            )
        })
        .collect();
    assert_eq!(
        queues.keys().cloned().collect::<Vec<_>>(),
        ["root.default", "root.netget"],
        "{sched}"
    );
    assert_eq!(
        queues["root.default"]["capacity"].as_f64().map(f64::round),
        Some(60.0)
    );
    assert_eq!(
        queues["root.netget"]["capacity"].as_f64().map(f64::round),
        Some(40.0)
    );
    assert_eq!(queues["root.netget"]["numApplications"], 1);
    assert_eq!(queues["root.default"]["numApplications"], 0);

    // The node, as `yarn node -list -all` reports it, running the sleeper's AM (256 MB) and
    // shell container (128 MB).
    let cli_node: Vec<&str> = nodes_cli
        .lines()
        .find(|l| l.contains("RUNNING"))
        .ok_or("yarn node -list shows no running node")?
        .split_whitespace()
        .collect();
    let node = &seen["list_nodes"]["nodes"][0];
    assert_eq!(seen["list_nodes"]["count"], 1);
    assert_eq!(node["id"], cli_node[0]);
    assert_eq!(node["state"], cli_node[1]);
    assert_eq!(node["nodeHTTPAddress"], cli_node[2]);
    assert_eq!(node["numContainers"], 2, "{node}");
    assert_eq!(node["usedMemoryMB"], 384, "{node}");
    assert!(
        node.get("usedResource").is_none(),
        "nested resource maps are not read"
    );
    let one = &seen["get_node"];
    assert_eq!(one["node_id"], cli_node[0]);
    assert_eq!(one["nodes"][0]["id"], cli_node[0]);

    // Applications: every field the CLI shows, for every application, from the two lists.
    let row = |a: &Value| -> Vec<String> {
        [
            "name",
            "applicationType",
            "user",
            "queue",
            "state",
            "finalStatus",
        ]
        .iter()
        .map(|k| a[*k].as_str().unwrap_or_default().to_string())
        .collect()
    };
    let mut got: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for key in ["finished", "running_in_netget"] {
        for a in seen[key]["applications"].as_array().unwrap() {
            got.insert(a["id"].as_str().unwrap().to_string(), row(a));
        }
    }
    assert_eq!(
        got, before,
        "the applications NetGet decoded must be the ones YARN reports"
    );
    assert_eq!(seen["finished"]["filters"]["states"], json!(["FINISHED"]));
    assert_eq!(
        seen["finished"]["applications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([ok_id.as_str(), failed_id.as_str()])
    );
    let running = &seen["running_in_netget"];
    assert_eq!(running["count"], 1);
    assert_eq!(running["applications"][0]["id"], sleep_id.as_str());

    // The failed application the model picked, against `yarn application -status`.
    let app = &seen["get_application"]["applications"][0];
    assert_eq!(app["id"], failed_id.as_str());
    assert_eq!(app["finalStatus"], "FAILED");
    assert_eq!(app["queue"], failed_report["Queue"].as_str());
    assert_eq!(app["startedTime"].to_string(), failed_report["Start-Time"]);
    assert_eq!(
        app["finishedTime"].to_string(),
        failed_report["Finish-Time"]
    );
    let mb_seconds = failed_report["Aggregate Resource Allocation"]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    assert_eq!(app["memorySeconds"].to_string(), mb_seconds);
    let diagnostics = app["diagnostics"].as_str().unwrap_or_default();
    assert!(
        diagnostics.starts_with(failed_report["Diagnostics"].as_str()),
        "diagnostics {diagnostics:?} vs the CLI's {:?}",
        failed_report["Diagnostics"]
    );
    assert!(diagnostics.contains("failed = 1"), "{diagnostics}");

    // Its attempt, against `yarn applicationattempt -list`.
    let cli_attempt: Vec<&str> = attempts_cli
        .lines()
        .find(|l| l.trim_start().starts_with("appattempt_"))
        .ok_or("yarn applicationattempt -list shows no attempt")?
        .split('\t')
        .map(str::trim)
        .collect();
    let attempts = &seen["list_app_attempts"];
    assert_eq!(attempts["app_id"], failed_id.as_str());
    assert_eq!(attempts["count"], 1);
    let attempt = &attempts["attempts"][0];
    assert_eq!(attempt["appAttemptId"], cli_attempt[0]);
    assert_eq!(attempt["appAttemptState"], cli_attempt[1]);
    assert_eq!(attempt["containerId"], cli_attempt[2]);
    assert_eq!(attempt["id"], 1);

    // Its queue, the running one's state, the kill, and YARN's 404.
    assert_eq!(seen["get_app_queue"]["queue"], "root.netget");
    assert_eq!(seen["get_app_state"]["app_id"], sleep_id.as_str());
    assert_eq!(seen["get_app_state"]["state"], "RUNNING");
    let kill = &seen["kill_application"];
    assert_eq!(kill["app_id"], sleep_id.as_str());
    match (kill["http_status"].as_u64(), kill["state"].as_str()) {
        (Some(202), Some("KILLING")) | (Some(200), Some("KILLED")) => {}
        other => panic!("YARN answers a kill 202 KILLING or 200 KILLED, not {other:?}"),
    }
    let err = &seen["error"];
    assert_eq!(err["operation"], "get_application");
    assert_eq!(err["app_id"], unknown.as_str());
    assert_eq!(err["http_status"], 404);
    assert_eq!(err["exception"], "NotFoundException");
    assert_eq!(
        err["message"],
        format!("app with id: {unknown} not found").as_str()
    );

    // On the wire: exactly the requests the model's actions name, and nothing else.
    let b = "/ws/v1/cluster";
    let node_id = cli_node[0];
    let want: BTreeSet<String> = [
        format!("GET {b}/info"),
        format!("GET {b}/metrics"),
        format!("GET {b}/scheduler"),
        format!("GET {b}/nodes"),
        format!("GET {b}/nodes/{node_id}"),
        format!("GET {b}/apps?states=FINISHED"),
        format!("GET {b}/apps?states=RUNNING&queue=netget"),
        format!("GET {b}/apps/{failed_id}"),
        format!("GET {b}/apps/{failed_id}/appattempts"),
        format!("GET {b}/apps/{failed_id}/queue"),
        format!("GET {b}/apps/{unknown}"),
        format!("GET {b}/apps/{sleep_id}/state"),
        format!("PUT {b}/apps/{sleep_id}/state"),
    ]
    .into_iter()
    .collect();
    let wire = tap.requests();
    assert_eq!(wire.len(), want.len(), "requests on the wire: {wire:#?}");
    assert_eq!(tap.lines().into_iter().collect::<BTreeSet<_>>(), want);
    let put: Vec<&(String, String)> = wire.iter().filter(|(l, _)| l.starts_with("PUT ")).collect();
    assert_eq!(
        serde_json::from_str::<Value>(&put[0].1)?,
        json!({"state": "KILLED"}),
        "the kill's body"
    );
    for (line, body) in &wire {
        if line.starts_with("GET ") {
            assert!(body.is_empty(), "{line} carried a body");
        }
    }
    Ok(())
}

/// Opened without `allow_kill`, a kill the model asks for is refused before anything is sent:
/// the ResourceManager sees the connect probe and nothing else.
#[tokio::test]
async fn kill_is_refused_without_allow_kill() -> E2EResult<()> {
    let cluster = Cluster::start(false).await?;
    let result = kill_refused(&cluster).await;
    cluster.with_log(result)
}

async fn kill_refused(cluster: &Cluster) -> E2EResult<()> {
    let tap = WireTap::start(cluster.rm.addr()).await?;
    let addr = tap.addr.clone();
    let seen: Seen = Arc::default();
    let k_err = {
        let seen = Arc::clone(&seen);
        move |e: &Value| keep(&seen, "error", e)
    };
    let config = NetGetConfig::new(format!(
        "Look at the ResourceManager at {addr}. YARN-NOKILL-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("YARN-NOKILL-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "YARN",
                "remote_addr": addr,
                "instruction": "Kill the first application."
            }]))
            .expect_calls(1)
            .and()
            .on_event("yarn_connected")
            .respond_with_actions_from_event(|e| {
                json!([{"type": "kill_application",
                        "app_id": format!("application_{}_0001", e["cluster_id"])}])
            })
            .expect_calls(1)
            .and()
            .on_event("yarn_error")
            .respond_with_actions_from_event(move |e| {
                k_err(e);
                json!([])
            })
            .expect_calls(1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_mocks(90).await;
    client.verify_mocks().await?;
    assert!(
        client
            .output_contains("decision=refused_kill_not_allowed")
            .await,
        "the refusal must be logged"
    );
    let err = seen.lock().unwrap()["error"].clone();
    assert_eq!(err["operation"], "kill_application");
    assert!(err.get("http_status").is_none(), "{err}");
    assert!(
        err["message"]
            .as_str()
            .unwrap_or_default()
            .contains("allow_kill"),
        "{err}"
    );
    assert_eq!(
        tap.lines(),
        vec!["GET /ws/v1/cluster/info".to_string()],
        "nothing but the connect probe may reach the ResourceManager"
    );
    client.stop().await?;
    Ok(())
}

/// A model that answers every result with another request stops at MAX_FOLLOWUP_DEPTH: the
/// connected turn and seven follow-ups, so the ResourceManager sees the connect probe and eight
/// more.
#[tokio::test]
async fn followup_chain_stops_at_the_bound() -> E2EResult<()> {
    let cluster = Cluster::start(false).await?;
    let result = followup_bound(&cluster).await;
    cluster.with_log(result)
}

async fn followup_bound(cluster: &Cluster) -> E2EResult<()> {
    let tap = WireTap::start(cluster.rm.addr()).await?;
    let addr = tap.addr.clone();
    let depth = ::netget::client::yarn::MAX_FOLLOWUP_DEPTH as usize;
    let config = NetGetConfig::new(format!(
        "Look at the ResourceManager at {addr}. YARN-LOOP-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("YARN-LOOP-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "YARN",
                "remote_addr": addr,
                "instruction": "Ask for the cluster info forever."
            }]))
            .expect_calls(1)
            .and()
            .on_event("yarn_connected")
            .respond_with_actions(json!([{"type": "get_cluster_info"}]))
            .expect_calls(1)
            .and()
            .on_event("yarn_cluster_info")
            .respond_with_actions(json!([{"type": "get_cluster_info"}]))
            .expect_calls(depth - 1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_any(&["decision=followup_depth"], 90).await;
    assert!(
        client.output_contains("decision=followup_depth").await,
        "the chain must stop at the bound and say so"
    );
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    assert_eq!(
        tap.lines(),
        vec!["GET /ws/v1/cluster/info".to_string(); 1 + depth],
        "the connect probe and one request per model turn, then nothing"
    );
    client.stop().await?;
    Ok(())
}

/// When the model cannot be asked, nothing is read on its behalf: the ResourceManager sees the
/// connect probe and nothing after it.
#[tokio::test]
async fn llm_failure_reads_nothing() -> E2EResult<()> {
    let cluster = Cluster::start(false).await?;
    let result = llm_failure(&cluster).await;
    cluster.with_log(result)
}

async fn llm_failure(cluster: &Cluster) -> E2EResult<()> {
    let tap = WireTap::start(cluster.rm.addr()).await?;
    let addr = tap.addr.clone();
    let config = NetGetConfig::new(format!(
        "Look at the ResourceManager at {addr}. YARN-FAIL-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("YARN-FAIL-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "YARN",
                "remote_addr": addr,
                "startup_params": {"allow_kill": true},
                "instruction": "Read everything."
            }]))
            .expect_calls(1)
            .and()
        // No rule answers yarn_connected: the mock model fails that call.
    });
    let client = start_netget_client(config).await?;
    client
        .wait_for_any(&["decision=fail_closed_llm_error"], 90)
        .await;
    assert!(
        client
            .output_contains("decision=fail_closed_llm_error")
            .await,
        "the failed turn must be logged as failing closed"
    );
    assert_eq!(
        tap.lines(),
        vec!["GET /ws/v1/cluster/info".to_string()],
        "the ResourceManager received a request NetGet made without the model"
    );
    client.stop().await?;
    Ok(())
}

/// The relay's request parser, so the wire assertions above rest on something tested.
#[test]
fn the_tap_splits_requests_and_bodies() {
    let mut pending = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nPUT /b HTTP/1.1\r\ncontent-length: 18\r\n\r\n{\"state\":\"KILLED\"}GET /c HTTP/1.1\r\n".to_vec();
    let got = take_requests(&mut pending);
    assert_eq!(
        got,
        vec![
            ("GET /a".to_string(), String::new()),
            ("PUT /b".to_string(), "{\"state\":\"KILLED\"}".to_string())
        ]
    );
    assert_eq!(pending, b"GET /c HTTP/1.1\r\n");
}
