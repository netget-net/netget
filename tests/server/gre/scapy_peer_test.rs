//! NetGet's GRE endpoint against **scapy**, a second GRE implementation independent of both
//! NetGet and the Linux kernel (`scapy_peer.py`, run inside a network namespace). scapy builds
//! each request with the key, checksum and sequence number the case asks for, and reads every
//! reply with its own GRE layer; the reply's checksum is recomputed over the bytes as they
//! crossed the wire. tshark reads the same packets on the veth (the pcap oracle).
//!
//! Covered here and not by the kernel: replies mirror each request's own header (a keyed,
//! checksummed, numbered request and a bare one in the same run), Cisco-style keepalives, and
//! every refusal and bound before the model: a bad checksum, GRE version 1, an RFC 1701 bit,
//! packets ending inside a field, a truncated inner frame, a keepalive that is not addressed
//! back to its sender, another key, no key, a peer not on the allowlist, the packet rate, the
//! payload size, and silence when the model backend fails.
//!
//! Needs Linux, root, iproute2, python3 with scapy (apt-get install python3-scapy) and tshark;
//! fails rather than skips without them. No LLM calls.
use super::kernel_peer_test::{events, start, state};
use crate::helpers::live_capture::{outer_src, LiveCapture};
use crate::helpers::netns::Netns;
use netget::cli::management::ServerForm;
use netget::server::gre::actions::MAX_INNER_BYTES;
use serde_json::{json, Value};
use std::time::Duration;

const SCAPY: &str = include_str!("scapy_peer.py");
const TEB: u64 = 0x6558;
const IPV4: u64 = 0x0800;

/// Send `packets` from inside the namespace and return what came back within `wait` seconds.
async fn scapy(ns: &Netns, packets: Value, wait: f64) -> Vec<Value> {
    let cfg = json!({"netget": ns.host_ip.to_string(), "me": ns.ns_ip.to_string(),
        "iface": ns.ns_if, "wait": wait, "packets": packets});
    let out = tokio::time::timeout(
        Duration::from_secs(90),
        ns.output(&["python3", "-I", "-c", SCAPY, &cfg.to_string()]),
    )
    .await
    .expect("scapy ran for 90 s");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "scapy failed (it needs python3-scapy: apt-get install python3-scapy): {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout.lines().last().unwrap_or_default();
    let v: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    v["replies"].as_array().cloned().unwrap_or_default()
}

fn arp() -> Value {
    json!({"kind": "arp", "target": "10.99.0.2"})
}

fn mac_of(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scapy_reads_mirrored_headers_keepalives_and_refusals() {
    let ns = Netns::create("grs", 73);
    let mut capture = LiveCapture::start_filtered(&ns.host_if, Some("ip proto 47"));
    let state = state().await;
    let (id, _status) = start(
        &state,
        &ns.host_ip.to_string(),
        json!({"peers": [ns.ns_ip.to_string()]}),
    )
    .await;

    // Keyed, checksummed and numbered: the reply carries the same key, a checksum that
    // verifies, and the server's own first sequence number.
    let r = scapy(
        &ns,
        json!([{"proto": TEB, "key": 7, "csum": true, "seq": 500, "inner": arp()}]),
        2.0,
    )
    .await;
    assert_eq!(r.len(), 1, "{r:?}");
    let a = &r[0];
    assert_eq!(
        (
            a["proto"].as_u64(),
            a["key"].as_u64(),
            a["csum"].as_bool(),
            a["csum_ok"].as_bool(),
            a["seq"].as_u64()
        ),
        (Some(TEB), Some(7), Some(true), Some(true), Some(0)),
        "{a}"
    );
    assert_eq!(
        a["arp"],
        json!({"op": 2, "hwsrc": "02:4e:47:00:00:02", "psrc": "10.99.0.2",
               "hwdst": "02:00:00:00:00:01", "pdst": "10.99.0.1"}),
        "{a}"
    );

    // Bare IPv4 in GRE: no key, no checksum, no sequence number back.
    let r = scapy(
        &ns,
        json!([{"proto": IPV4, "inner": {"kind": "ping", "id": 4660, "seq": 9, "data": "abc"}}]),
        2.0,
    )
    .await;
    assert_eq!(r.len(), 1, "{r:?}");
    let p = &r[0];
    assert_eq!(
        (
            p["proto"].as_u64(),
            p["key"].is_null(),
            p["csum"].as_bool(),
            p["seq"].is_null(),
            p["len"].as_u64()
        ),
        (Some(IPV4), true, Some(false), true, Some(4 + 20 + 8 + 3)),
        "{p}"
    );
    assert_eq!(
        p["icmp"],
        json!({"type": 0, "id": 4660, "seq": 9, "load": "abc", "src": "10.99.0.2",
               "dst": "10.99.0.1", "ok": true}),
        "{p}"
    );

    // Keyed and numbered without a checksum; the server's counter has moved on by one.
    let r = scapy(
        &ns,
        json!([{"proto": IPV4, "key": 9, "seq": 1, "inner": {"kind": "udp", "port": 7777, "data": "hi"}}]),
        2.0,
    )
    .await;
    assert_eq!(r.len(), 1, "{r:?}");
    let u = &r[0];
    assert_eq!(
        (
            u["key"].as_u64(),
            u["csum"].as_bool(),
            u["seq"].as_u64(),
            &u["udp"]
        ),
        (
            Some(9),
            Some(false),
            Some(1),
            &json!({"sport": 7777, "dport": 5000, "load": "pong:hi", "src": "10.99.0.2", "dst": "10.99.0.1"})
        ),
        "{u}"
    );

    // A Cisco keepalive comes back as the bare GRE header it carried, without the model.
    let r = scapy(
        &ns,
        json!([{"proto": IPV4, "key": 7, "inner": {"kind": "keepalive"}}]),
        2.0,
    )
    .await;
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        (
            r[0]["proto"].as_u64(),
            r[0]["key"].is_null(),
            r[0]["len"].as_u64()
        ),
        (Some(0), true, Some(4)),
        "{r:?}"
    );

    // Refusals: each is a request the policy would answer, so a check that stopped refusing
    // shows up as a reply, and as an event the model was asked about.
    let asked_before = events(&state, id, "gre_arp_request").await.len()
        + events(&state, id, "gre_icmp_echo_request").await.len();
    let other = "203.0.113.9";
    let r = scapy(
        &ns,
        json!([
            {"proto": TEB, "key": 7, "csum": true, "bad_csum": true, "inner": arp()},
            {"proto": TEB, "version": 1, "inner": arp()},
            {"proto": TEB, "flags_or": 64, "inner": arp()},
            {"proto": TEB, "key": 7, "seq": 1, "truncate": 10, "inner": arp()},
            {"proto": TEB, "csum": true, "truncate": 6, "inner": arp()},
            {"proto": TEB, "inner": {"kind": "short"}},
            {"proto": 0x86dd, "inner": arp()},
            {"proto": IPV4, "inner": {"kind": "keepalive", "dst": other}},
            {"proto": IPV4, "inner": {"kind": "keepalive", "src": other}},
        ]),
        3.0,
    )
    .await;
    assert!(r.is_empty(), "refused packets were answered: {r:?}");
    let asked_after = events(&state, id, "gre_arp_request").await.len()
        + events(&state, id, "gre_icmp_echo_request").await.len();
    assert_eq!(
        asked_before, asked_after,
        "a refused packet reached the model"
    );
    state.remove_server(id).await;

    // The pcap oracle over everything NetGet sent: clean to tshark, with the header fields
    // scapy also read.
    capture.stop();
    let ours = mac_of(&ns.host_if);
    capture.assert_clean_from(&ours);
    let rows: Vec<Vec<String>> = capture
        .fields(&[
            "gre.key",
            "gre.checksum.status",
            "gre.sequence_number",
            "gre.proto",
        ])
        .into_iter()
        .filter(|r| outer_src(&r[0]) == ours)
        .collect();
    let cells = |i: usize| rows.iter().map(|r| r[i].clone()).collect::<Vec<_>>();
    assert_eq!(
        cells(1),
        ["0x00000007", "", "0x00000009", ""],
        "keys: {rows:?}"
    );
    assert_eq!(cells(2), ["1", "", "", ""], "checksum status: {rows:?}");
    assert_eq!(cells(3), ["0", "", "1", ""], "sequence numbers: {rows:?}");
    assert_eq!(
        cells(4),
        ["0x6558", "0x0800", "0x0800", "0x0000"],
        "protocol types: {rows:?}"
    );
}

/// Each bound with its own server on the same address, one after another (two raw sockets on
/// one address would both answer).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_peers_rate_size_and_backend_failure_are_bounded_before_the_model() {
    let ns = Netns::create("grb", 74);
    let host = ns.host_ip.to_string();
    let state = state().await;

    // Only key 7: another key and no key are dropped.
    let (id, _s) = start(&state, &host, json!({"key": 7})).await;
    let r = scapy(
        &ns,
        json!([
            {"proto": TEB, "key": 7, "inner": arp()},
            {"proto": TEB, "key": 8, "inner": arp()},
            {"proto": TEB, "inner": arp()},
        ]),
        2.0,
    )
    .await;
    assert_eq!(
        r.iter().map(|x| x["key"].clone()).collect::<Vec<_>>(),
        [json!(7)],
        "{r:?}"
    );
    assert_eq!(events(&state, id, "gre_arp_request").await.len(), 1);
    state.remove_server(id).await;

    // A peer that is not on the allowlist is never answered and never reaches the model.
    let (id, _s) = start(&state, &host, json!({"peers": ["198.18.74.99"]})).await;
    let r = scapy(&ns, json!([{"proto": TEB, "inner": arp()}]), 2.0).await;
    assert!(r.is_empty(), "{r:?}");
    assert!(events(&state, id, "gre_arp_request").await.is_empty());
    state.remove_server(id).await;

    // Three packets a second: a burst of ten gets three answers.
    let (id, _s) = start(&state, &host, json!({"max_packets_per_second": 3})).await;
    let burst: Vec<Value> = (0..10)
        .map(|_| json!({"proto": TEB, "inner": arp()}))
        .collect();
    let r = scapy(&ns, json!(burst), 3.0).await;
    assert_eq!(r.len(), 3, "{r:?}");
    state.remove_server(id).await;

    // A payload of exactly MAX_INNER_BYTES is answered; one byte more is not (the outer packet
    // is fragmented on the way, and reassembled before NetGet reads it).
    let (id, _s) = start(&state, &host, json!({})).await;
    let pad = MAX_INNER_BYTES - 42; // 14 bytes of Ethernet and 28 of ARP
    let r = scapy(
        &ns,
        json!([{"proto": TEB, "pad": pad, "inner": arp()}]),
        2.0,
    )
    .await;
    assert_eq!(r.len(), 1, "a {MAX_INNER_BYTES}-byte payload: {r:?}");
    let r = scapy(
        &ns,
        json!([{"proto": TEB, "pad": pad + 1, "inner": arp()}]),
        2.0,
    )
    .await;
    assert!(
        r.is_empty(),
        "a {}-byte payload: {r:?}",
        MAX_INNER_BYTES + 1
    );
    assert_eq!(events(&state, id, "gre_arp_request").await.len(), 1);
    state.remove_server(id).await;

    // No script, and a model backend that is not there: silence on the wire, and the log says
    // why.
    let (tx, mut status) = tokio::sync::mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "gre".into(),
        host: Some(host.clone()),
        instruction: Some("Be 10.99.0.2".into()),
        ..Default::default()
    }
    .create(&state, tx)
    .await
    .expect("start");
    let r = scapy(&ns, json!([{"proto": TEB, "inner": arp()}]), 3.0).await;
    assert!(r.is_empty(), "{r:?}");
    let failed = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(line) = status.recv().await {
            if line.contains("decision=fail_closed_llm_error") {
                return line;
            }
        }
        String::new()
    })
    .await
    .expect("no decision=fail_closed_llm_error line");
    assert!(failed.contains("gre_arp_request"), "{failed}");
    state.remove_server(id).await;
}
