//! NetGet's OpenFlow switch against two independent controllers, each failing rather than
//! skipping when absent:
//!
//! - **os-ken** (`pip install os-ken`, the OpenStack-maintained Ryu) running a learning switch
//!   written against its OpenFlow 1.3 API below: os-ken parses every message NetGet sends with
//!   its own `ofproto_v1_3_parser`, runs the handshake (FEATURES, PORT_DESC) itself, and
//!   prints what it decoded from each PACKET_IN.
//! - **Open vSwitch's `ovs-testcontroller`** (`apt-get install openvswitch-testcontroller`),
//!   OVS's C learning switch, speaking OpenFlow 1.3.
//!
//! In both, the controller installs a table-miss flow (a FLOW_MOD event at NetGet), the policy
//! answers with a PACKET_IN from HOST_A to HOST_B, the controller floods it (a PACKET_OUT
//! event), the policy answers with HOST_B's reply on the other port, and the controller —
//! having learned HOST_A — installs a flow to port 1 and sends the reply there. That is the
//! model's answers asserted on the wire, from the controller's side. tshark's `openflow_v4`
//! dissector reads both directions.
//!
//! No LLM calls: the python policy in `support.rs` plays the model.
use super::support::{self, HOST_A, HOST_B};
use crate::helpers::pcap_oracle::PcapOracle;
use crate::helpers::real_server::{InstallHint, RealServer};
use crate::helpers::recording_relay;
use crate::helpers::E2EResult;
use serde_json::json;
use std::time::Duration;

const OSKEN: InstallHint = InstallHint {
    brew: "python@3.12 && python3 -m pip install 'os-ken==4.2.2'",
    apt: "python3-pip && python3 -m pip install 'os-ken==4.2.2'",
};
const OVS_TESTCONTROLLER: InstallHint = InstallHint {
    brew: "openvswitch (no Homebrew formula exists; run this test on Linux)",
    apt: "openvswitch-testcontroller",
};

/// A learning switch on os-ken's OpenFlow 1.3 API: a table-miss flow on connect; each
/// PACKET_IN learns its source and is forwarded to the learned port (with a flow) or flooded.
const OSKEN_PY: &str = r#"
import sys
from os_ken import cfg
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ethernet, packet
from os_ken.ofproto import ofproto_v1_3


class LearningSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, dp, priority, match, actions):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        print("OSKEN table-miss installed on %016x n_tables=%d" % (dp.id, ev.msg.n_tables), flush=True)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        # dp.ports is what os-ken's own handshake read from the PORT_DESC reply.
        print("OSKEN ports %s" % sorted(p.name.decode() for p in dp.ports.values()), flush=True)
        eth = packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0]
        ports = self.mac_to_port.setdefault(dp.id, {})
        ports[eth.src] = in_port
        out_port = ports.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            self.add_flow(dp, 1, parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src), actions)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                        actions=actions, data=data))
        print("OSKEN packet-in in_port=%d src=%s dst=%s out=%d" % (in_port, eth.src, eth.dst, out_port), flush=True)


if __name__ == "__main__":
    cfg.CONF(args=["--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port", sys.argv[1]], project="os_ken")
    print("OSKEN starting on port %s" % sys.argv[1], flush=True)
    app_manager.AppManager.run_apps(["__main__"])
"#;

async fn osken() -> E2EResult<RealServer> {
    RealServer::builder("python3", OSKEN)
        .config_file("osken_switch.py", OSKEN_PY)
        .args(["{dir}/osken_switch.py", "{port}"])
        .ready_when_log_matches("OSKEN starting")
        .startup_timeout(Duration::from_secs(60))
        .start()
        .await
}

async fn testcontroller() -> E2EResult<RealServer> {
    RealServer::builder("ovs-testcontroller", OVS_TESTCONTROLLER)
        .args([
            "-O",
            "OpenFlow13",
            "--unixctl={dir}/testcontroller.ctl",
            "ptcp:{port}:127.0.0.1",
        ])
        .start()
        .await
}

/// The exchange both controllers are put through, and what NetGet's events must show.
async fn learning_switch_exchange(
    controller_addr: std::net::SocketAddr,
) -> E2EResult<(support::Switch, Vec<Vec<(bool, Vec<u8>)>>)> {
    let (relay, streams) = recording_relay::tcp_relay(controller_addr).await;
    let sw = support::connect(&relay.to_string(), Some(support::policy()), support::params())
        .await?;
    let connected = sw.wait_for_events("openflow_controller_connected", 1).await;
    assert_eq!(connected.len(), 1, "{}", sw.log_text());

    // The controller's table-miss flow.
    let flows = sw.wait_for_events("openflow_flow_mod_received", 1).await;
    let miss = flows
        .iter()
        .find(|f| f["priority"] == 0 && f["command"] == "add")
        .unwrap_or_else(|| panic!("no table-miss flow: {flows:?}\n{}", sw.log_text()));
    assert_eq!(miss["match"], json!({}));
    assert_eq!(miss["instructions"][0]["actions"][0]["port"], "controller");

    // The model's ping was flooded, and its reply was sent to HOST_A's learned port with a flow.
    let outs = sw.wait_for_events("openflow_packet_out_received", 2).await;
    assert!(outs.len() >= 2, "{outs:?}\n{}", sw.log_text());
    assert_eq!(outs[0]["in_port"], 1);
    assert_eq!(outs[0]["packet"]["eth_dst"], HOST_B);
    assert_eq!(outs[0]["actions"][0]["port"], "flood");
    assert_eq!(outs[0]["packet"]["payload_text"], "netget switch");
    assert_eq!(outs[1]["in_port"], 2);
    assert_eq!(outs[1]["packet"]["eth_dst"], HOST_A);
    assert_eq!(outs[1]["actions"][0]["port"], 1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let learned = loop {
        let flows = sw.events("openflow_flow_mod_received").await;
        if let Some(f) = flows
            .iter()
            .find(|f| f["command"] == "add" && f["priority"] != 0 && f["match"]["eth_dst"] == HOST_A)
        {
            break f.clone();
        }
        assert!(tokio::time::Instant::now() < deadline, "no learned flow: {flows:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(learned["match"]["in_port"], 2);
    assert_eq!(learned["instructions"][0]["actions"][0]["port"], 1);
    let streams = streams
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.lock().unwrap().clone())
        .collect();
    Ok((sw, streams))
}

fn assert_wire_is_openflow(streams: &[Vec<(bool, Vec<u8>)>]) {
    assert!(!streams.is_empty());
    for chunks in streams {
        let mut o = PcapOracle::tcp("openflow").also_named("openflow_v4");
        for (to_controller, bytes) in chunks {
            o = if *to_controller {
                o.to_server(bytes)
            } else {
                o.from_server(bytes)
            };
        }
        o.assert_clean();
    }
}

#[tokio::test]
async fn os_ken_learns_through_the_models_packets() -> E2EResult<()> {
    let ctl = osken().await?;
    let result = async {
        let addr: std::net::SocketAddr = ctl.addr().parse()?;
        let (sw, streams) = learning_switch_exchange(addr).await?;
        // os-ken decoded the switch and both of the model's packets itself.
        ctl.wait_for_log("OSKEN table-miss installed on 0000000000000abc n_tables=254", Duration::from_secs(30))
            .await?;
        ctl.wait_for_log("OSKEN ports ['eth1', 'eth2']", Duration::from_secs(30))
            .await?;
        ctl.wait_for_log(
            "OSKEN packet-in in_port=1 src=02:00:00:00:00:01 dst=02:00:00:00:00:02 out=4294967291",
            Duration::from_secs(30),
        )
        .await?;
        ctl.wait_for_log(
            "OSKEN packet-in in_port=2 src=02:00:00:00:00:02 dst=02:00:00:00:00:01 out=1",
            Duration::from_secs(30),
        )
        .await?;
        assert_wire_is_openflow(&streams);
        drop(sw);
        Ok(())
    }
    .await;
    ctl.with_log(result)
}

#[tokio::test]
async fn ovs_testcontroller_learns_through_the_models_packets() -> E2EResult<()> {
    let ctl = testcontroller().await?;
    let result = async {
        let addr: std::net::SocketAddr = ctl.addr().parse()?;
        let (sw, streams) = learning_switch_exchange(addr).await?;
        assert_wire_is_openflow(&streams);
        drop(sw);
        Ok(())
    }
    .await;
    ctl.with_log(result)
}

#[tokio::test]
async fn with_no_answer_from_the_model_os_ken_sees_no_packet() -> E2EResult<()> {
    let ctl = osken().await?;
    let result = async {
        let sw = support::connect(&ctl.addr(), None, support::params()).await?;
        ctl.wait_for_log("OSKEN table-miss installed", Duration::from_secs(30))
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while sw.log_text().matches("decision=fail_closed_llm_error").count() < 2 {
            assert!(tokio::time::Instant::now() < deadline, "{}", sw.log_text());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!ctl.log().contains("OSKEN packet-in"), "{}", ctl.log());
        Ok(())
    }
    .await;
    ctl.with_log(result)
}
