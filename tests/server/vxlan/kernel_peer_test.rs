//! NetGet's tunnel endpoint against the **Linux kernel's own tunnel drivers**: its vxlan
//! driver, the VTEP every Linux overlay (Docker, Flannel, OVS's kernel datapath) is built on,
//! and its gretap driver carried over a fou port (GRE-in-UDP, RFC 8086). Each lives in a
//! network namespace joined to the host by a veth, so NetGet holds the tunnel port on the
//! host side. Needs root or passwordless sudo, iproute2 and ethtool (and the vxlan, fou and
//! ip_gre modules); fails rather than skips without them.
//!
//! The namespace is 10.99.0.1/24 on VNI (or GRE key) 42; a python policy makes NetGet host
//! 10.99.0.2 (MAC 02:4e:47:00:00:02), answering ping and replying `pong:<data>` to UDP. The
//! kernel's own tools judge it: `ping` exits 0 only on valid echo replies (checksums and all),
//! the neighbour table holds the MAC from the model's ARP reply, and a python UDP socket in
//! the namespace reads the reply. 10.99.0.3 has no host, so it is silence. No LLM calls.
use crate::helpers::netns::Netns;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use tokio::sync::mpsc;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='vxlan_arp_request' and e['target_ip']=='10.99.0.2':
  a=[{'type':'vxlan_arp_reply','mac':'02:4e:47:00:00:02'}]
elif t=='vxlan_icmp_echo_request' and e['dst_ip']=='10.99.0.2':
  a=[{'type':'vxlan_icmp_echo_reply'}]
elif t=='vxlan_udp_datagram' and e['dst_port']==7777:
  a=[{'type':'vxlan_udp_reply','data':'pong:'+e['data']}]
print(json.dumps({'actions':a}))"#;

const UDP_ASK: &str = r#"import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10)
s.bind(('10.99.0.1',0)); s.sendto(b'hello',('10.99.0.2',7777))
print(s.recvfrom(2048)[0].decode())"#;

async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

/// `dev` is the namespace's tunnel link, already created; this addresses it, starts NetGet
/// on the host end at `port` with `params`, and runs the kernel's side of the exchange.
async fn kernel_pings_and_talks_udp(ns: &Netns, dev: &str, port: u16, params: Value) {
    // Across a veth nothing completes an offloaded (CHECKSUM_PARTIAL) inner UDP checksum, so
    // the kernel computes it itself, as a physical NIC would.
    ns.exec(&["ethtool", "-K", dev, "tx", "off"]);
    ns.exec(&["ip", "addr", "add", "10.99.0.1/24", "dev", dev]);
    ns.exec(&["ip", "link", "set", dev, "up"]);

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "vxlan".into(),
        port: Some(port),
        host: Some(ns.host_ip.to_string()),
        instruction: Some("Be 10.99.0.2".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
        ]),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .unwrap();

    let out = ns
        .output(&["ping", "-c", "2", "-W", "5", "10.99.0.2"])
        .await;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success() && text.contains("2 received"),
        "{text}{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&ns.try_exec(&["ip", "-s", "-d", "link", "show", dev]).stdout)
    );

    // The neighbour entry is the MAC the model's ARP reply gave.
    let neigh = String::from_utf8_lossy(
        &ns.exec(&["ip", "neigh", "show", "10.99.0.2", "dev", dev])
            .stdout,
    )
    .to_string();
    assert!(neigh.contains("lladdr 02:4e:47:00:00:02"), "{neigh}");

    let out = ns.output(&["python3", "-I", "-c", UDP_ASK]).await;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "pong:hello",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let udp = &events(&state, id, "vxlan_udp_datagram").await[0];
    assert_eq!(
        (
            udp["vni"].as_u64(),
            udp["src_ip"].as_str(),
            udp["dst_port"].as_u64()
        ),
        (Some(42), Some("10.99.0.1"), Some(7777)),
        "{udp}"
    );

    // No host at 10.99.0.3: the model says nothing, and the kernel never resolves it.
    let out = ns
        .output(&["ping", "-c", "1", "-W", "2", "10.99.0.3"])
        .await;
    assert!(!out.status.success());
    assert!(events(&state, id, "vxlan_arp_request")
        .await
        .iter()
        .any(|e| e["target_ip"] == "10.99.0.3"));
    state.remove_server(id).await;
}

#[tokio::test]
async fn linux_vxlan_pings_and_talks_udp_to_netget() {
    let ns = Netns::create("vs", 61);
    let (remote, local) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    ns.exec(&[
        "ip", "link", "add", "vx0", "type", "vxlan", "id", "42", "remote", &remote, "local",
        &local, "dstport", "4789", "dev", &ns.ns_if,
    ]);
    kernel_pings_and_talks_udp(&ns, "vx0", 4789, json!({"vni": 42})).await;
}

/// The kernel's gretap with every optional GRE field on: key 42 (ikey/okey), checksums
/// (icsum/ocsum: it drops a frame without one or with a wrong one) and sequence numbers
/// (iseq/oseq: it drops a frame without one or with one that goes backwards). It reaches NetGet
/// through fou, which puts GRE in UDP to port 4754 and takes it back off the same port.
#[tokio::test]
async fn linux_gretap_over_fou_pings_and_talks_udp_to_netget() {
    let ns = Netns::create("gs", 63);
    let (remote, local) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    // The GRE checksum is offloaded to the underlay device, and across a veth nothing ever
    // computes it: the kernel would send 0, which NetGet (rightly) refuses. Off, it is computed
    // in software, as a physical NIC would compute it in hardware.
    ns.exec(&["ethtool", "-K", &ns.ns_if, "tx", "off"]);
    ns.exec(&["ip", "fou", "add", "port", "4754", "ipproto", "47"]);
    ns.exec(&[
        "ip",
        "link",
        "add",
        "gt0",
        "type",
        "gretap",
        "remote",
        &remote,
        "local",
        &local,
        "key",
        "42",
        "csum",
        "seq",
        "encap",
        "fou",
        "encap-sport",
        "auto",
        "encap-dport",
        "4754",
    ]);
    kernel_pings_and_talks_udp(
        &ns,
        "gt0",
        4754,
        json!({"encapsulation": "gretap", "vni": 42}),
    )
    .await;
}
