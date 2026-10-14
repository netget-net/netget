//! NetGet's VXLAN client against the **Linux kernel's vxlan driver**, and its GRE (gretap)
//! client against the kernel's **gretap driver over a fou port**, each in a network namespace
//! (root or passwordless sudo, iproute2 and ethtool; fails rather than skips without them).
//! The namespace is 10.99.0.1/24 on VNI (or GRE key) 42 with a python UDP service on 9999;
//! NetGet is 10.99.0.2.
//!
//! The chain: on `vxlan_ready` the model pings 10.99.0.1, which the kernel answers once NetGet
//! has answered the kernel's own ARP for 10.99.0.2. On the echo reply the model sends UDP to
//! the service, built from that reply, and to a closed port. The service's answer and the
//! kernel's ICMP port unreachable both come back as events. The namespace's own `ping` of
//! NetGet is answered too. No LLM calls.
use crate::helpers::netns::Netns;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::{AccessLogOwner, ClientId};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

const SERVICE: &str = r#"import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.99.0.1',9999)); s.settimeout(60)
print('READY',flush=True)
d,a=s.recvfrom(2048); print('GOT',d.decode(),flush=True); s.sendto(b'ack:'+d,a)"#;

const ON_ECHO: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
print(json.dumps({'actions':[
  {'type':'vxlan_send_udp','ip':e['src_ip'],'port':9999,'data':'echo %d %s' % (e['sequence'],e['data'])},
  {'type':'vxlan_send_udp','ip':e['src_ip'],'port':9998,'data':'nobody'}]}))"#;

async fn wait_event(
    state: &AppState,
    id: ClientId,
    event_type: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hit = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .filter(|e| e["event_type"] == event_type)
                .map(|e| e["request"].clone())
                .find(|r| pred(r));
            if let Some(e) = hit {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no matching {event_type} event"))
}

#[tokio::test]
async fn netget_pings_and_talks_udp_through_linux_vxlan() {
    let ns = Netns::create("vc", 62);
    let (host, peer) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    ns.exec(&[
        "ip", "link", "add", "vx0", "type", "vxlan", "id", "42", "remote", &host, "local", &peer,
        "dstport", "4789", "dev", &ns.ns_if,
    ]);
    netget_pings_and_talks_udp(&ns, "vx0", json!({"vni": 42})).await;
}

/// The kernel's gretap over a fou port with key 42, checksums and sequence numbers, which it
/// demands on input (ikey, icsum, iseq): a frame from NetGet without the key, with a wrong or
/// missing checksum, or with a missing or backwards sequence number is dropped, and the ping
/// below would go unanswered.
#[tokio::test]
async fn netget_pings_and_talks_udp_through_linux_gretap_over_fou() {
    let ns = Netns::create("gc", 64);
    let (host, peer) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
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
        &host,
        "local",
        &peer,
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
    netget_pings_and_talks_udp(
        &ns,
        "gt0",
        json!({"encapsulation": "gretap", "vni": 42, "gre_checksum": true, "gre_sequence": true}),
    )
    .await;
}

/// `dev` is the namespace's tunnel link, already created. NetGet joins it as 10.99.0.2 with
/// `params` (plus its overlay IP and underlay address) and runs the whole chain.
async fn netget_pings_and_talks_udp(ns: &Netns, dev: &str, params: Value) {
    let (host, peer) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    // Checksum offload: across a veth nothing ever completes a CHECKSUM_PARTIAL inner UDP
    // checksum, so the kernel would hand NetGet datagrams whose checksum field holds only the
    // pseudo-header sum. On a physical NIC the hardware fills it in; here the kernel must.
    ns.exec(&["ethtool", "-K", dev, "tx", "off"]);
    ns.exec(&["ip", "addr", "add", "10.99.0.1/24", "dev", dev]);
    ns.exec(&["ip", "link", "set", dev, "up"]);
    let mut startup_params = params;
    startup_params["overlay_ip"] = json!("10.99.0.2");
    startup_params["local_address"] = json!(host);
    let mut service = tokio::process::Command::from(ns.command(&["python3", "-I", "-c", SERVICE]))
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(service.stdout.take().unwrap()).lines();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("READY"));

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let id = ClientForm {
        protocol: "vxlan".into(),
        remote_addr: Some(peer.clone()),
        instruction: Some("Ping 10.99.0.1, then tell its service".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"vxlan_ready","handler":{"type":"static","actions":[{"type":"vxlan_ping","ip":"10.99.0.1","data":"netget"}]}}),
            json!({"event_pattern":"vxlan_icmp_echo_reply","handler":{"type":"script","language":"python","code":ON_ECHO}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
        startup_params: Some(startup_params),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect");

    let echo = wait_event(&state, id, "vxlan_icmp_echo_reply", |_| true).await;
    assert_eq!(
        (
            echo["src_ip"].as_str(),
            echo["data"].as_str(),
            echo["sequence"].as_u64()
        ),
        (Some("10.99.0.1"), Some("netget"), Some(1)),
        "{echo}"
    );
    assert!(echo["rtt_ms"].is_number(), "{echo}");
    // The service got what the model built from the echo reply, and answered it.
    let got = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.as_deref(), Some("GOT echo 1 netget"));
    let ack = wait_event(&state, id, "vxlan_udp_datagram", |_| true).await;
    assert_eq!(
        (ack["src_port"].as_u64(), ack["data"].as_str()),
        (Some(9999), Some("ack:echo 1 netget")),
        "{ack}"
    );
    let closed = wait_event(&state, id, "vxlan_icmp_error", |_| true).await;
    assert_eq!(
        (
            closed["meaning"].as_str(),
            closed["original_dst_port"].as_u64()
        ),
        (Some("port_unreachable"), Some(9998)),
        "{closed}"
    );

    // The kernel pings NetGet's host, which answers in Rust.
    let out = ns
        .output(&["ping", "-c", "1", "-W", "5", "10.99.0.2"])
        .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Injected: an IP nobody has is reported unreachable after the ARP wait.
    let outcome = state
        .send_to_client(
            id,
            json!({"type":"vxlan_resolve","ip":"10.99.0.77"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("no ARP reply")),
        "{outcome:?}"
    );
    wait_event(&state, id, "vxlan_unreachable", |e| e["ip"] == "10.99.0.77").await;
    let resolved = state
        .send_to_client(
            id,
            json!({"type":"vxlan_resolve","ip":"10.99.0.1"}),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(
        matches!(&resolved, ClientSendOutcome::Executed { .. }),
        "{resolved:?}"
    );
}
