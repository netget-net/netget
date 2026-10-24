//! NetGet's GRE client (IP protocol 47, a raw socket) against the **Linux kernel's own GRE
//! driver**, `ip_gre`, in a network namespace: a `gre` link (IPv4 in GRE) and a `gretap` link
//! (Ethernet in GRE), each with key 42, checksums and sequence numbers on. The kernel demands
//! all three on input (ikey, icsum, iseq), so a packet from NetGet without the key, with a
//! missing or wrong checksum, or with a missing or backwards sequence number is dropped, and
//! the first echo reply is already the evidence for all three. The namespace is 10.99.0.1/24
//! with a python UDP service on 9999; NetGet is 10.99.0.2.
//!
//! The chain: on `gre_ready` the model pings 10.99.0.1 (on gretap the kernel first ARPs for
//! 10.99.0.2, which NetGet answers in Rust). On the echo reply the model sends UDP to the
//! service, built from that reply, and to a closed port. The service's answer and the
//! kernel's ICMP port unreachable both come back as events, and the namespace's own `ping` of
//! NetGet is answered. On the gre link the model also sends a Cisco-style keepalive, which the
//! kernel reflects once forwarding is on (`ip_forward`, `accept_local`, no `rp_filter`: the
//! known Linux recipe for answering Cisco keepalives). On gretap an injected Ethernet frame
//! arrives on the kernel's link, read by a packet socket there.
//!
//! Needs Linux, root (a raw socket in this process), iproute2, ethtool, ping and python3, and
//! the ip_gre module; fails rather than skips without them. No LLM calls.
use crate::helpers::live_capture::{outer_src, LiveCapture};
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

/// A packet socket on the namespace's gretap link, for EtherType 0x88b5.
const FRAMES: &str = r#"import socket,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5)); s.bind((sys.argv[1],0)); s.settimeout(60)
print('READY',flush=True)
f=s.recv(4096); print('GOT',f[6:12].hex(':'),f[14:].rstrip(b'\x00').decode(errors='replace'),flush=True)"#;

const ON_ECHO: &str = r#"import json,sys
e=json.load(sys.stdin)['event']
print(json.dumps({'actions':[
  {'type':'gre_send_udp','ip':e['src_ip'],'port':9999,'data':'echo %d %s' % (e['sequence'],e['data'])},
  {'type':'gre_send_udp','ip':e['src_ip'],'port':9998,'data':'nobody'}]}))"#;

async fn wait_events(
    state: &AppState,
    id: ClientId,
    event_type: &str,
    count: usize,
    pred: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let hits: Vec<Value> = state
                .list_access_logs_for(Some(AccessLogOwner::Client(id.as_u32())), None)
                .await
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .filter(|e| e["event_type"] == event_type)
                .map(|e| e["request"].clone())
                .filter(|r| pred(r))
                .collect();
            if hits.len() >= count {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fewer than {count} matching {event_type} events"))
}

async fn wait_event(
    state: &AppState,
    id: ClientId,
    event_type: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    wait_events(state, id, event_type, 1, pred).await.remove(0)
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A python helper in the namespace, once it has said READY.
async fn helper(
    ns: &Netns,
    args: &[&str],
) -> (
    tokio::process::Child,
    tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
) {
    let mut child = tokio::process::Command::from(ns.command(args))
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("READY"));
    (child, lines)
}

async fn send(state: &AppState, id: ClientId, action: Value) -> ClientSendOutcome {
    state
        .send_to_client(id, action, Duration::from_secs(10))
        .await
        .unwrap()
}

/// `dev` is the namespace's tunnel link, already created with key 42, csum and seq.
async fn netget_through_linux(
    ns: &Netns,
    dev: &str,
    gretap: bool,
) -> (AppState, ClientId, LiveCapture) {
    // The GRE checksum is offloaded to the underlay device and the inner UDP checksum to the
    // tunnel link, and across a veth nothing computes either: off, the kernel does it in
    // software, as a physical NIC would in hardware.
    ns.exec(&["ethtool", "-K", &ns.ns_if, "tx", "off"]);
    ns.exec(&["ethtool", "-K", dev, "tx", "off"]);
    ns.exec(&["ip", "addr", "add", "10.99.0.1/24", "dev", dev]);
    ns.exec(&["ip", "link", "set", dev, "up"]);
    let (_service, mut lines) = helper(ns, &["python3", "-I", "-c", SERVICE]).await;
    let capture = LiveCapture::start_filtered(&ns.host_if, Some("ip proto 47"));

    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let (tx, _) = mpsc::unbounded_channel();
    let mut on_ready = vec![json!({"type":"gre_ping","ip":"10.99.0.1","data":"netget"})];
    if !gretap {
        on_ready.push(json!({"type":"gre_send_keepalive"}));
    }
    let id = ClientForm {
        protocol: "gre".into(),
        remote_addr: Some(ns.ns_ip.to_string()),
        instruction: Some("Ping 10.99.0.1, then tell its service".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"gre_ready","handler":{"type":"static","actions":on_ready}}),
            json!({"event_pattern":"gre_icmp_echo_reply","handler":{"type":"script","language":"python","code":ON_ECHO}}),
            json!({"event_pattern":"*","handler":{"type":"static","actions":[]}}),
        ]),
        startup_params: Some(json!({
            "overlay_ip": "10.99.0.2",
            "overlay_mac": "02:4e:47:00:00:02",
            "tunnel": if gretap { "gretap" } else { "gre" },
            "key": 42,
            "gre_checksum": true,
            "gre_sequence": true,
            "local_address": ns.host_ip.to_string(),
        })),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new("http://127.0.0.1:1"), tx)
    .await
    .expect("connect (as root)");

    let echo = wait_event(&state, id, "gre_icmp_echo_reply", |_| true).await;
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
    let ack = wait_event(&state, id, "gre_udp_datagram", |_| true).await;
    assert_eq!(
        (ack["src_port"].as_u64(), ack["data"].as_str()),
        (Some(9999), Some("ack:echo 1 netget")),
        "{ack}"
    );
    let closed = wait_event(&state, id, "gre_icmp_error", |_| true).await;
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
        "{}{}",
        text(&out),
        text(&ns.try_exec(&["ip", "-s", "-d", "link", "show", dev]))
    );
    (state, id, capture)
}

fn tunnel(ns: &Netns, dev: &str, kind: &str) {
    let (remote, local) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    ns.exec(&[
        "ip", "link", "add", dev, "type", kind, "remote", &remote, "local", &local, "key", "42",
        "csum", "seq",
    ]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_pings_talks_udp_and_keeps_alive_through_linux_gre() {
    let ns = Netns::create("gcl", 75);
    tunnel(&ns, "gr0", "gre");
    // A keepalive's inner packet is from the namespace's own address to NetGet: forwarding it
    // back out needs forwarding on, a source that is local accepted, and no reverse-path
    // filter (the route to that source is the veth, not the tunnel).
    for setting in [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0",
        "net.ipv4.conf.all.accept_local=1",
    ] {
        ns.exec(&["sysctl", "-qw", setting]);
    }
    ns.exec(&["sysctl", "-qw", "net.ipv4.conf.gr0.rp_filter=0"]);
    ns.exec(&["sysctl", "-qw", "net.ipv4.conf.gr0.accept_local=1"]);
    let (state, id, capture) = netget_through_linux(&ns, "gr0", false).await;

    // The keepalive the model sent on gre_ready came back through the kernel.
    let reply = wait_event(&state, id, "gre_keepalive_reply", |_| true).await;
    assert!(reply["rtt_ms"].is_number(), "{reply}");
    // And one injected by hand.
    let outcome = send(&state, id, json!({"type":"gre_send_keepalive"})).await;
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
    wait_events(&state, id, "gre_keepalive_reply", 2, |_| true).await;

    // A gre tunnel has no link layer: ARP and Ethernet frames are refused, not sent.
    for action in [
        json!({"type":"gre_resolve","ip":"10.99.0.1"}),
        json!({"type":"gre_send_ethernet","dst_mac":"ff:ff:ff:ff:ff:ff","ethertype":34997,"data":"x"}),
    ] {
        let outcome = send(&state, id, action.clone()).await;
        assert!(
            matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("gretap tunnel")),
            "{action}: {outcome:?}"
        );
    }
    oracle(capture, &ns, false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn netget_arps_pings_talks_udp_and_sends_frames_through_linux_gretap() {
    let ns = Netns::create("gct", 76);
    tunnel(&ns, "gt0", "gretap");
    let (state, id, capture) = netget_through_linux(&ns, "gt0", true).await;

    // An Ethernet frame the operator injects arrives on the kernel's gretap link, from
    // NetGet's MAC, carrying the data.
    let (_frames, mut lines) = helper(&ns, &["python3", "-I", "-c", FRAMES, "gt0"]).await;
    let outcome = send(
        &state,
        id,
        json!({"type":"gre_send_ethernet","dst_mac":"ff:ff:ff:ff:ff:ff","ethertype":34997,
               "data":"frame-from-netget","encoding":"utf8"}),
    )
    .await;
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
    let got = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        got.as_deref(),
        Some("GOT 02:4e:47:00:00:02 frame-from-netget")
    );

    // An IP nobody has is reported unreachable after the ARP wait; one that exists resolves.
    let outcome = send(&state, id, json!({"type":"gre_resolve","ip":"10.99.0.77"})).await;
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("no ARP reply")),
        "{outcome:?}"
    );
    wait_event(&state, id, "gre_unreachable", |e| e["ip"] == "10.99.0.77").await;
    let outcome = send(&state, id, json!({"type":"gre_resolve","ip":"10.99.0.1"})).await;
    assert!(
        matches!(&outcome, ClientSendOutcome::Executed { .. }),
        "{outcome:?}"
    );
    // A keepalive is a gre (IPv4) tunnel's; a gretap link would not know what to do with it.
    let outcome = send(&state, id, json!({"type":"gre_send_keepalive"})).await;
    assert!(
        matches!(&outcome, ClientSendOutcome::Rejected { error } if error.contains("gre tunnel")),
        "{outcome:?}"
    );
    oracle(capture, &ns, true);
}

fn mac_of(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The pcap oracle over the veth: tshark's gre dissector (and what it hands the payload to)
/// reads every GRE packet both sides sent, clean. NetGet's carry key 42, a checksum tshark
/// verified, and sequence numbers from 0 going up by one, since every packet leaves from the
/// client's one task.
fn oracle(mut capture: LiveCapture, ns: &Netns, gretap: bool) {
    capture.stop();
    let ours = mac_of(&ns.host_if);
    let chains = capture.assert_clean_from(&ours);
    let inner = if gretap { "gre:eth" } else { "gre:ip" };
    assert!(
        chains.iter().all(|c| c.contains(inner)),
        "NetGet's packets: {chains:?}"
    );
    let rows: Vec<Vec<String>> = capture
        .fields(&["gre.key", "gre.checksum.status", "gre.sequence_number"])
        .into_iter()
        .filter(|r| outer_src(&r[0]) == ours)
        .collect();
    for (n, r) in rows.iter().enumerate() {
        assert_eq!(
            (r[1].as_str(), r[2].as_str(), r[3].as_str()),
            ("0x0000002a", "1", n.to_string().as_str()),
            "NetGet's packet {n} (key 42, checksum good, sequence {n}): {rows:?}"
        );
    }
    assert!(rows.len() >= 4, "{rows:?}");
}
