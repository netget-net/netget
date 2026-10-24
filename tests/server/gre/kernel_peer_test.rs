//! NetGet's GRE endpoint (IP protocol 47, a raw socket) against the **Linux kernel's own GRE
//! driver**, `ip_gre`: a `gre` link (IPv4 in GRE) and a `gretap` link (Ethernet in GRE), each
//! in a network namespace joined to the host by a veth, with key 42, checksums and sequence
//! numbers on, which the kernel demands on input (ikey, icsum, iseq): a packet from NetGet
//! without the key, with a missing or wrong checksum, or with a missing or backwards sequence
//! number is dropped, so every reply the kernel accepts is evidence for all three. NetGet's raw
//! socket is bound to the host end of the veth, the kernel's tunnel to the namespace end, so
//! the two GRE stacks never see the same packets.
//!
//! The namespace is 10.99.0.1/24; a python policy makes NetGet host 10.99.0.2 (MAC
//! 02:4e:47:00:00:02 on gretap), answering ping and replying `pong:<data>` to UDP. The
//! kernel's own tools judge it: `ping` exits 0 only on valid echo replies, `arping` and the
//! neighbour table hold the MAC from the model's ARP reply, and `nc -u` prints the reply.
//! tshark captures the veth and reads every GRE packet both sides sent (the pcap oracle).
//! 10.99.0.3 has no host, so it is silence. No LLM calls.
//!
//! Needs Linux, root (NetGet opens a raw socket in this process), iproute2, ethtool, ping,
//! arping, nc and tshark, and the ip_gre module; fails rather than skips without them.
use crate::helpers::live_capture::{outer_src, LiveCapture};
use crate::helpers::netns::Netns;
use netget::cli::management::ServerForm;
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use tokio::sync::mpsc;

pub const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='gre_arp_request' and e['target_ip']=='10.99.0.2':
  a=[{'type':'gre_arp_reply','mac':'02:4e:47:00:00:02'}]
elif t=='gre_icmp_echo_request' and e['dst_ip']=='10.99.0.2':
  a=[{'type':'gre_icmp_echo_reply'}]
elif t=='gre_udp_datagram' and e['dst_port']==7777:
  a=[{'type':'gre_udp_reply','data':'pong:'+e['data']}]
print(json.dumps({'actions':a}))"#;

pub async fn events(state: &AppState, id: ServerId, event_type: &str) -> Vec<Value> {
    state
        .list_access_logs_for(Some(AccessLogOwner::Server(id.as_u32())), None)
        .await
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .filter(|e| e["event_type"] == event_type)
        .map(|e| e["request"].clone())
        .collect()
}

/// A NetGet GRE server on `host` answering with `POLICY`, and its status lines.
pub async fn start(
    state: &AppState,
    host: &str,
    params: Value,
) -> (ServerId, mpsc::UnboundedReceiver<String>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "gre".into(),
        host: Some(host.into()),
        instruction: Some("Be 10.99.0.2".into()),
        event_handlers: Some(vec![
            json!({"event_pattern":"*","handler":{"type":"script","language":"python","code":POLICY}}),
        ]),
        startup_params: Some(params),
        ..Default::default()
    }
    .create(state, tx)
    .await
    .expect("the GRE server starts (as root)");
    (id, rx)
}

/// State whose model backend is nothing at all, so anything a script does not answer fails
/// closed.
pub async fn state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    state
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The peers' own view, for a failure message: the tunnel link with its counters, and the
/// kernel's log.
fn diagnostics(ns: &Netns, dev: &str) -> String {
    let link = text(&ns.try_exec(&["ip", "-s", "-d", "link", "show", dev]));
    let dmesg = std::process::Command::new("dmesg")
        .output()
        .map(|o| {
            let all = String::from_utf8_lossy(&o.stdout).to_string();
            all.lines().rev().take(20).collect::<Vec<_>>().join("\n")
        })
        .unwrap_or_default();
    format!("\n--- ip -s -d link show {dev}\n{link}\n--- dmesg (newest first)\n{dmesg}")
}

fn mac_of(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// `dev` is the namespace's tunnel link, already created with key 42, csum and seq. This
/// addresses it, starts NetGet on the host end of the veth, and runs the kernel's side.
async fn kernel_pings_and_talks_udp(ns: &Netns, dev: &str, gretap: bool) {
    // The GRE checksum is offloaded to the underlay device and nothing across a veth computes
    // it, and the same for the inner UDP checksum on the tunnel link: off, the kernel computes
    // both in software, as a physical NIC would in hardware.
    ns.exec(&["ethtool", "-K", &ns.ns_if, "tx", "off"]);
    ns.exec(&["ethtool", "-K", dev, "tx", "off"]);
    ns.exec(&["ip", "addr", "add", "10.99.0.1/24", "dev", dev]);
    ns.exec(&["ip", "link", "set", dev, "up"]);

    let mut capture = LiveCapture::start_filtered(&ns.host_if, Some("ip proto 47"));
    let state = state().await;
    let host = ns.host_ip.to_string();
    let (id, _status) = start(
        &state,
        &host,
        json!({"peers": [ns.ns_ip.to_string()], "key": 42}),
    )
    .await;

    let out = ns
        .output(&["ping", "-c", "2", "-W", "5", "10.99.0.2"])
        .await;
    assert!(
        out.status.success() && text(&out).contains("2 received"),
        "{}{}",
        text(&out),
        diagnostics(ns, dev)
    );

    if gretap {
        // The neighbour entry is the MAC the model's ARP reply gave, and arping hears it.
        let neigh = text(&ns.exec(&["ip", "neigh", "show", "10.99.0.2", "dev", dev]));
        assert!(neigh.contains("lladdr 02:4e:47:00:00:02"), "{neigh}");
        let out = ns
            .output(&["arping", "-c", "1", "-w", "5", "-I", dev, "10.99.0.2"])
            .await;
        assert!(
            out.status.success() && text(&out).to_lowercase().contains("02:4e:47:00:00:02"),
            "arping: {}{}",
            text(&out),
            diagnostics(ns, dev)
        );
    }

    // nc sends one datagram and prints what comes back until it has been idle for 3 s.
    let out = ns
        .output(&["sh", "-c", "printf hello | nc -u -w 3 10.99.0.2 7777"])
        .await;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "pong:hello",
        "nc: {}{}",
        text(&out),
        diagnostics(ns, dev)
    );
    let udp = &events(&state, id, "gre_udp_datagram").await[0];
    assert_eq!(
        (
            udp["tunnel"].as_str(),
            udp["key"].as_u64(),
            udp["peer"].as_str(),
            udp["src_ip"].as_str(),
            udp["dst_port"].as_u64()
        ),
        (
            Some(if gretap { "gretap" } else { "gre" }),
            Some(42),
            Some(ns.ns_ip.to_string().as_str()),
            Some("10.99.0.1"),
            Some(7777)
        ),
        "{udp}"
    );

    // No host at 10.99.0.3: the model says nothing, and the kernel never hears an answer.
    let out = ns
        .output(&["ping", "-c", "1", "-W", "2", "10.99.0.3"])
        .await;
    assert!(!out.status.success(), "{}", text(&out));
    let asked = if gretap {
        events(&state, id, "gre_arp_request").await
    } else {
        events(&state, id, "gre_icmp_echo_request").await
    };
    assert!(
        asked
            .iter()
            .any(|e| e["target_ip"] == "10.99.0.3" || e["dst_ip"] == "10.99.0.3"),
        "{asked:?}"
    );
    state.remove_server(id).await;

    // The pcap oracle: tshark's gre dissector reads every packet on the veth, both ways.
    capture.stop();
    let ours = mac_of(&ns.host_if);
    let theirs = mac_of_in(ns, &ns.ns_if);
    let chains = capture.assert_clean_from(&ours);
    let inner = if gretap { "gre:eth" } else { "gre:ip" };
    assert!(
        chains.iter().all(|c| c.contains(inner)),
        "NetGet's packets: {chains:?}"
    );
    capture.assert_clean_from(&theirs);
    let rows = capture.fields(&[
        "gre.key",
        "gre.checksum.status",
        "gre.sequence_number",
        "gre.proto",
    ]);
    let mine: Vec<&Vec<String>> = rows.iter().filter(|r| outer_src(&r[0]) == ours).collect();
    // Two echo replies and a UDP reply at least (gretap adds the ARP replies).
    assert!(mine.len() >= 3, "{rows:?}");
    let mut last_sequence = None;
    for r in &mine {
        assert_eq!(r[1], "0x0000002a", "key 42: {r:?}");
        // 1 is PROTO_CHECKSUM_E_GOOD: tshark computed the GRE checksum and it matched.
        assert_eq!(r[2], "1", "checksum status: {r:?}");
        let s: u32 = r[3].parse().unwrap_or_else(|_| panic!("sequence: {r:?}"));
        if let Some(prev) = last_sequence {
            assert!(s > prev, "sequence numbers go forward: {mine:?}");
        }
        last_sequence = Some(s);
        assert_eq!(
            r[4],
            if gretap { "0x6558" } else { "0x0800" },
            "protocol type: {r:?}"
        );
    }
}

fn mac_of_in(ns: &Netns, iface: &str) -> String {
    text(&ns.exec(&["cat", &format!("/sys/class/net/{iface}/address")]))
        .trim()
        .to_string()
}

fn tunnel(ns: &Netns, dev: &str, kind: &str) {
    let (remote, local) = (ns.host_ip.to_string(), ns.ns_ip.to_string());
    ns.exec(&[
        "ip", "link", "add", dev, "type", kind, "remote", &remote, "local", &local, "key", "42",
        "csum", "seq",
    ]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linux_gre_pings_and_talks_udp_to_netget() {
    let ns = Netns::create("grl", 71);
    tunnel(&ns, "gr0", "gre");
    kernel_pings_and_talks_udp(&ns, "gr0", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linux_gretap_arps_pings_and_talks_udp_to_netget() {
    let ns = Netns::create("grt", 72);
    tunnel(&ns, "gt0", "gretap");
    kernel_pings_and_talks_udp(&ns, "gt0", true).await;
}
