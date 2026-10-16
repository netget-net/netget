//! NetGet's OpenFlow controller against **Open vSwitch**, an independent OpenFlow 1.3 switch,
//! failing rather than skipping when it is absent (`apt-get install openvswitch-switch`; there
//! is no Homebrew formula, so this suite runs on Linux).
//!
//! Each test runs its own `ovsdb-server` and `ovs-vswitchd` unprivileged in a temporary
//! directory, with the userspace **dummy** datapath (`--enable-dummy=override`), so no kernel
//! module and no root are needed. The bridge has two dummy ports whose transmitted frames are
//! written to pcap files (`options:tx_pcap`), packets are injected with
//! `ovs-appctl netdev-dummy/receive`, and the flow table is read back with
//! `ovs-ofctl -O OpenFlow13 dump-flows`. OVS reaches NetGet through a recording relay, so
//! tshark's `openflow_v4` dissector reads every byte both ways.
//!
//! No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, ping, HOST_A, HOST_B};
use crate::helpers::real_server::{missing_binary, run_tool, InstallHint, ToolProcess};
use crate::helpers::recording_relay;
use crate::helpers::E2EResult;
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const OVS: InstallHint = InstallHint {
    brew: "openvswitch (no Homebrew formula exists; run this test on Linux)",
    apt: "openvswitch-switch",
};
const TSHARK: InstallHint = InstallHint {
    brew: "wireshark",
    apt: "tshark",
};

const SCHEMAS: &[&str] = &[
    "/usr/share/openvswitch/vswitch.ovsschema",
    "/usr/local/share/openvswitch/vswitch.ovsschema",
    "/opt/homebrew/share/openvswitch/vswitch.ovsschema",
];

/// A sandboxed Open vSwitch: ovsdb-server, ovs-vswitchd and bridge br0 with dummy ports p1
/// and p2, killed on drop.
struct Ovs {
    dir: tempfile::TempDir,
    _db: ToolProcess,
    vswitchd: ToolProcess,
}

impl Ovs {
    fn env(&self, cmd: &mut Command) {
        for k in ["OVS_RUNDIR", "OVS_LOGDIR", "OVS_DBDIR", "OVS_SYSCONFDIR"] {
            cmd.env(k, self.dir.path());
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    async fn start(controller: SocketAddr) -> E2EResult<Ovs> {
        let schema = SCHEMAS
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .ok_or_else(|| missing_binary("ovsdb-server", OVS, "vswitch.ovsschema not found"))?;
        let dir = tempfile::tempdir()?;
        let d = dir.path().to_path_buf();
        let env = |cmd: &mut Command| {
            for k in ["OVS_RUNDIR", "OVS_LOGDIR", "OVS_DBDIR", "OVS_SYSCONFDIR"] {
                cmd.env(k, &d);
            }
        };
        let mut create = Command::new("ovsdb-tool");
        env(&mut create);
        create.arg("create").arg(d.join("conf.db")).arg(schema);
        run_tool(create, "ovsdb-tool", OVS).await?;
        let mut db = Command::new("ovsdb-server");
        env(&mut db);
        db.arg(format!("--remote=punix:{}", d.join("db.sock").display()))
            .arg(format!(
                "--unixctl={}",
                d.join("ovsdb-server.ctl").display()
            ))
            .arg(d.join("conf.db"));
        let db = ToolProcess::spawn(db, "ovsdb-server", OVS)?;
        let sock = d.join("db.sock");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !sock.exists() {
            if std::time::Instant::now() > deadline {
                return Err(
                    format!("ovsdb-server never opened its socket: {:?}", db.lines()).into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let db_arg = format!("--db=unix:{}", sock.display());
        let mut init = Command::new("ovs-vsctl");
        env(&mut init);
        init.args([&db_arg, "--no-wait", "init"]);
        run_tool(init, "ovs-vsctl", OVS).await?;
        let mut vswitchd = Command::new("ovs-vswitchd");
        env(&mut vswitchd);
        vswitchd
            .arg("--enable-dummy=override")
            .arg(format!("unix:{}", sock.display()))
            .arg(format!(
                "--unixctl={}",
                d.join("ovs-vswitchd.ctl").display()
            ));
        let vswitchd = ToolProcess::spawn(vswitchd, "ovs-vswitchd", OVS)?;
        let ovs = Ovs {
            dir,
            _db: db,
            vswitchd,
        };
        let p1 = format!("options:tx_pcap={}", ovs.path("p1.pcap").display());
        let p2 = format!("options:tx_pcap={}", ovs.path("p2.pcap").display());
        let target = format!("tcp:{controller}");
        ovs.vsctl(&[
            "--timeout=30",
            "add-br",
            "br0",
            "--",
            "set",
            "bridge",
            "br0",
            "datapath_type=dummy",
            "fail-mode=secure",
            "protocols=OpenFlow13",
            "other-config:datapath-id=0000000000000abc",
            "--",
            "add-port",
            "br0",
            "p1",
            "--",
            "set",
            "interface",
            "p1",
            "type=dummy",
            "ofport_request=1",
            &p1,
            "--",
            "add-port",
            "br0",
            "p2",
            "--",
            "set",
            "interface",
            "p2",
            "type=dummy",
            "ofport_request=2",
            &p2,
            "--",
            "set-controller",
            "br0",
            &target,
        ])
        .await
        .map_err(|e| format!("{e}\novs-vswitchd: {:?}", ovs.vswitchd.lines()))?;
        Ok(ovs)
    }

    async fn vsctl(&self, args: &[&str]) -> E2EResult<String> {
        let mut cmd = Command::new("ovs-vsctl");
        self.env(&mut cmd);
        cmd.arg(format!("--db=unix:{}", self.path("db.sock").display()));
        cmd.args(args);
        run_tool(cmd, "ovs-vsctl", OVS).await
    }

    async fn ofctl(&self, args: &[&str]) -> E2EResult<String> {
        let mut cmd = Command::new("ovs-ofctl");
        self.env(&mut cmd);
        cmd.args(["-O", "OpenFlow13"]);
        cmd.args(args);
        run_tool(cmd, "ovs-ofctl", OVS).await
    }

    fn mgmt(&self) -> String {
        format!("unix:{}", self.path("br0.mgmt").display())
    }

    async fn dump_flows(&self) -> E2EResult<String> {
        self.ofctl(&["--no-names", "dump-flows", &self.mgmt()])
            .await
    }

    async fn wait_for_flow(&self, needle: &str) -> E2EResult<String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let flows = self.dump_flows().await?;
            if flows.contains(needle) {
                return Ok(flows);
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("no flow containing {needle:?}:\n{flows}").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Inject a frame as if it arrived on `port`.
    async fn receive(&self, port: &str, frame: &[u8]) -> E2EResult<String> {
        let mut cmd = Command::new("ovs-appctl");
        self.env(&mut cmd);
        cmd.arg("-t").arg(self.path("ovs-vswitchd.ctl"));
        cmd.args(["netdev-dummy/receive", port, &hex(frame)]);
        run_tool(cmd, "ovs-appctl", OVS).await
    }

    /// The frames a port transmitted, as tshark reads them: one row per frame.
    async fn transmitted(&self, port: &str) -> E2EResult<Vec<Vec<String>>> {
        let pcap = self.path(&format!("{port}.pcap"));
        if !pcap.exists() {
            return Ok(Vec::new());
        }
        let mut cmd = Command::new("tshark");
        cmd.arg("-r").arg(&pcap).args([
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-e",
            "eth.src",
            "-e",
            "eth.dst",
            "-e",
            "ip.dst",
            "-e",
            "icmp.checksum.status",
            "-e",
            "frame.len",
        ]);
        let out = run_tool(cmd, "tshark", TSHARK).await?;
        Ok(out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split('\t').map(str::to_string).collect())
            .collect())
    }

    async fn wait_transmitted(&self, port: &str, n: usize) -> E2EResult<Vec<Vec<String>>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let rows = self.transmitted(port).await?;
            if rows.len() >= n {
                return Ok(rows);
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("{port} transmitted {} frames, not {n}", rows.len()).into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn version() -> String {
        Command::new("ovs-vswitchd")
            .arg("--version")
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn open_vswitch_installs_the_models_flows_and_sends_its_packets() -> E2EResult<()> {
    let c = support::start(support::policy(), json!({})).await;
    let (relay, streams) = recording_relay::tcp_relay(c.addr()).await;
    let ovs = Ovs::start(relay).await?;
    println!("{}", Ovs::version());

    // The handshake: OVS reports its datapath id and its ports, LOCAL included.
    let ev = c.wait_for_events("openflow_switch_connected", 1).await;
    assert_eq!(ev.len(), 1, "{}", c.log_text());
    assert_eq!(ev[0]["datapath_id"], "0000000000000abc");
    let names: Vec<&str> = ev[0]["ports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    for want in ["br0", "p1", "p2"] {
        assert!(names.contains(&want), "{names:?}");
    }
    assert_eq!(ev[0]["description"]["mfr_desc"], "Nicira, Inc.");

    // The model's table-miss flow is in OVS's table.
    ovs.wait_for_flow("priority=0 actions=CONTROLLER:65535")
        .await?;

    // A packet for HOST_B on p1 reaches the model; its flow and its PACKET_OUT reach OVS.
    let frame = ping(HOST_B);
    ovs.receive("p1", &frame).await?;
    let pi = c.wait_for_events("openflow_packet_in", 1).await;
    assert_eq!(pi.len(), 1, "{}", c.log_text());
    assert_eq!(pi[0]["in_port"], 1);
    assert_eq!(
        pi[0]["buffered"], false,
        "SET_CONFIG asked for whole packets"
    );
    assert_eq!(pi[0]["packet"]["eth_src"], HOST_A);
    assert_eq!(pi[0]["packet"]["ipv4"]["dst"], "10.0.0.2");
    assert_eq!(pi[0]["total_len"], frame.len());
    ovs.wait_for_flow("priority=10,in_port=1,dl_dst=02:00:00:00:00:02 actions=output:2")
        .await?;
    let sent = ovs.wait_transmitted("p2", 1).await?;
    assert_eq!(sent[0][1], HOST_B);
    assert_eq!(sent[0][2], "10.0.0.2");
    assert_eq!(sent[0][3], "1", "tshark verified the ICMP checksum");
    assert_eq!(sent[0][4], frame.len().to_string());

    // The next packet for HOST_B is forwarded by OVS itself, through the model's flow.
    ovs.receive("p1", &frame).await?;
    ovs.wait_transmitted("p2", 2).await?;
    assert_eq!(c.events("openflow_packet_in").await.len(), 1);

    // An unknown destination is flooded: out of p1's peer, p2... and not back out of p2.
    ovs.receive("p2", &ping("02:00:00:00:00:77")).await?;
    let flooded = ovs.wait_transmitted("p1", 1).await?;
    assert_eq!(flooded[0][1], "02:00:00:00:00:77");

    // Statistics, through the operator's channel: the model's flow has counted the packet OVS
    // forwarded through it. OVS pushes datapath counters to its flow table periodically, so the
    // request is repeated until the count arrives.
    let conn = c.connections().await[0];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut asked = 0;
    let learned = loop {
        c.state
            .send_to_peer(
                c.id,
                conn,
                json!({"type": "openflow_request_stats", "kind": "flow"}),
                Duration::from_secs(10),
            )
            .await?;
        asked += 1;
        let stats = c.wait_for_events("openflow_stats_reply", asked).await;
        let entries = stats[asked - 1]["entries"].as_array().unwrap().clone();
        let learned = entries
            .iter()
            .find(|e| e["priority"] == 10)
            .cloned()
            .unwrap_or_else(|| panic!("{entries:?}"));
        if learned["packet_count"].as_u64().unwrap_or(0) >= 1 {
            break learned;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the flow never counted a packet: {learned}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(learned["match"]["eth_dst"], HOST_B);
    assert_eq!(learned["instructions"][0]["actions"][0]["port"], 2);

    // A FLOW_MOD OVS refuses comes back to the model as an error naming it.
    c.state
        .send_to_peer(
            c.id,
            conn,
            json!({"type": "openflow_flow_mod", "table_id": 3, "priority": 1, "match": {},
                   "instructions": [{"type": "goto_table", "table_id": 2}]}),
            Duration::from_secs(10),
        )
        .await?;
    let errors = c.wait_for_events("openflow_error", 1).await;
    assert_eq!(errors.len(), 1, "{}", c.log_text());
    assert_eq!(errors[0]["request"]["type"], "FLOW_MOD", "{errors:?}");
    assert_eq!(errors[0]["error_type"], "BAD_INSTRUCTION", "{errors:?}");
    assert_eq!(errors[0]["error_code"], "BAD_TABLE_ID", "{errors:?}");
    assert!(
        errors[0]["request"]["what"]
            .as_str()
            .unwrap()
            .contains("table 3"),
        "{errors:?}"
    );
    println!(
        "OVS refused the backwards goto_table with {}/{}",
        errors[0]["error_type"], errors[0]["error_code"]
    );

    // tshark's openflow_v4 dissector over everything that crossed, both ways.
    let streams = streams.lock().unwrap().clone();
    assert!(!streams.is_empty());
    for rec in streams {
        let chunks = rec.lock().unwrap().clone();
        if chunks.is_empty() {
            continue;
        }
        support::oracle(&chunks).assert_clean();
    }
    drop(ovs);
    Ok(())
}

#[tokio::test]
async fn with_no_answer_from_the_model_open_vswitch_forwards_nothing() -> E2EResult<()> {
    // Every event goes to a model that is not there.
    let c = support::start(None, json!({})).await;
    let ovs = Ovs::start(c.addr()).await?;
    let ev = c.wait_for_events("openflow_switch_connected", 1).await;
    assert_eq!(ev.len(), 1, "{}", c.log_text());
    // No table-miss flow was installed: the switch_connected failed closed.
    assert!(c.wait_for_log("decision=fail_closed_llm_error").await);
    let flows = ovs.dump_flows().await?;
    assert!(!flows.contains("priority="), "{flows}");
    // Install the table-miss by hand so a packet does reach NetGet, then watch it go nowhere.
    ovs.ofctl(&[
        "add-flow",
        &ovs.mgmt(),
        "priority=0,actions=CONTROLLER:65535",
    ])
    .await?;
    ovs.receive("p1", &ping(HOST_B)).await?;
    c.wait_for_events("openflow_packet_in", 1).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while c
        .log_text()
        .matches("decision=fail_closed_llm_error")
        .count()
        < 2
    {
        assert!(std::time::Instant::now() < deadline, "{}", c.log_text());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // A probe the switch does forward (a flow added by hand to p2) proves the pcap is live,
    // and the packet NetGet failed closed on is not in it: nothing was flooded or sent.
    ovs.ofctl(&[
        "add-flow",
        &ovs.mgmt(),
        "priority=5,in_port=1,dl_src=02:00:00:00:00:09,actions=output:2",
    ])
    .await?;
    let mut probe = ping(HOST_B);
    probe[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    ovs.receive("p1", &probe).await?;
    let sent = ovs.wait_transmitted("p2", 1).await?;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0][0], "02:00:00:00:00:09", "only the probe left p2");
    assert!(ovs.transmitted("p1").await?.is_empty());
    let flows = ovs.dump_flows().await?;
    assert!(!flows.contains("priority=10"), "{flows}");
    Ok(())
}
