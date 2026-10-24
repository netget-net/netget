//! NetGet's VXLAN/Geneve/GRE endpoint against a tunnel endpoint written in the test, for every
//! encapsulation, what the kernel test cannot cover (Geneve, GRE without a key), and the
//! refusals. tshark's VXLAN, Geneve and GRE dissectors read every frame both sides sent (the
//! pcap oracle). Unprivileged; no LLM calls.
use crate::helpers::pcap_oracle::PcapOracle;
use netget::cli::management::ServerForm;
use netget::server::vxlan::frame::{self, Encap, Header, Payload};
use netget::state::app_state::AppState;
use netget::state::{AccessLogOwner, ServerId};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const POLICY: &str = r#"import json,sys
i=json.load(sys.stdin); t=i['event_type_id']; e=i['event']
a=[]
if t=='vxlan_arp_request' and e['target_ip']=='10.99.0.2':
  a=[{'type':'vxlan_arp_reply','mac':'02:4e:47:00:00:02'}]
elif t=='vxlan_icmp_echo_request':
  a=[{'type':'vxlan_icmp_echo_reply'}]
elif t=='vxlan_udp_datagram':
  a=[{'type':'vxlan_udp_reply','data':'pong:'+e['data']}]
print(json.dumps({'actions':a}))"#;

const PEER_MAC: frame::Mac = [0x02, 0, 0, 0, 0, 0x01];
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
const HOST_MAC: frame::Mac = [0x02, 0x4e, 0x47, 0, 0, 0x02];

async fn start(params: Value) -> (AppState, ServerId, u16) {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    let (tx, _) = mpsc::unbounded_channel();
    let id = ServerForm {
        protocol: "vxlan".into(),
        port: Some(0),
        host: Some("127.0.0.1".into()),
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
    let port = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(a) = state.get_server(id).await.and_then(|s| s.local_addr) {
                break a.port();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (state, id, port)
}

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

/// The test's tunnel endpoint, on 127.0.0.9 at the server's own port: where NetGet replies.
struct Vtep {
    socket: UdpSocket,
    port: u16,
    encap: Encap,
    /// What every frame is sent with; a GRE sequence number counts up from its value.
    header: Header,
    sent: Vec<Vec<u8>>,
    received: Vec<Vec<u8>>,
    /// The GRE sequence numbers NetGet's replies carried.
    sequences: Vec<u32>,
}

impl Vtep {
    async fn new(port: u16, encap: Encap, header: Header) -> Self {
        Self {
            socket: UdpSocket::bind(("127.0.0.9", port)).await.unwrap(),
            port,
            encap,
            header,
            sent: vec![],
            received: vec![],
            sequences: vec![],
        }
    }
    async fn send(&mut self, inner: &[u8]) {
        let d = frame::encap(self.encap, &self.header, inner);
        if let Some(s) = &mut self.header.sequence {
            *s += 1;
        }
        self.socket
            .send_to(&d, ("127.0.0.1", self.port))
            .await
            .unwrap();
        self.sent.push(d);
    }
    async fn send_raw(&mut self, d: &[u8]) {
        self.socket
            .send_to(d, ("127.0.0.1", self.port))
            .await
            .unwrap();
    }
    async fn recv(&mut self, secs: u64) -> Option<frame::Frame> {
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(secs), self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap()
            .0;
        self.received.push(buf[..n].to_vec());
        let (header, inner) = frame::decap(self.encap, &buf[..n])
            .expect("NetGet's encapsulation (a GRE checksum included)");
        // The reply is encapsulated as the request was: same VNI or key (or none), and for GRE
        // a checksum and a sequence number exactly when the request had them.
        assert_eq!(header.vni, self.header.vni);
        assert_eq!(header.checksum, self.header.checksum);
        assert_eq!(header.sequence.is_some(), self.header.sequence.is_some());
        self.sequences.extend(header.sequence);
        Some(frame::parse_frame(inner).expect("NetGet's inner frame (checksums included)"))
    }
}

/// ARP, ping and UDP through the tunnel, then the oracle over every datagram.
async fn exchange(encap: Encap, header: Header, params: Value, dissector: &str) -> Vtep {
    let (state, id, port) = start(params).await;
    let mut v = Vtep::new(port, encap, header).await;

    v.send(&frame::arp_frame(true, PEER_MAC, PEER_IP, [0; 6], HOST_IP))
        .await;
    let arp = v.recv(20).await.expect("no ARP reply");
    let Payload::Arp(a) = &arp.payload else {
        panic!("{arp:?}")
    };
    assert!(!a.request);
    assert_eq!(
        (a.sender_mac, a.sender_ip, a.target_mac, a.target_ip),
        (HOST_MAC, HOST_IP, PEER_MAC, PEER_IP)
    );
    assert_eq!(arp.dst_mac, PEER_MAC);

    let ping = frame::ipv4(
        PEER_IP,
        HOST_IP,
        1,
        7,
        &frame::icmp_echo(true, 0x1234, 1, b"abcdefgh"),
    );
    v.send(&frame::ethernet(
        HOST_MAC,
        PEER_MAC,
        frame::ETHERTYPE_IPV4,
        &ping,
    ))
    .await;
    let reply = v.recv(20).await.expect("no echo reply");
    assert_eq!(
        (reply.src_ip, reply.dst_ip, reply.src_mac),
        (Some(HOST_IP), Some(PEER_IP), HOST_MAC)
    );
    assert_eq!(
        reply.payload,
        Payload::Echo {
            request: false,
            identifier: 0x1234,
            sequence: 1,
            data: b"abcdefgh".to_vec()
        }
    );

    let udp = frame::ipv4(
        PEER_IP,
        HOST_IP,
        17,
        8,
        &frame::udp(PEER_IP, HOST_IP, 5000, 7777, b"hello"),
    );
    v.send(&frame::ethernet(
        HOST_MAC,
        PEER_MAC,
        frame::ETHERTYPE_IPV4,
        &udp,
    ))
    .await;
    let answer = v.recv(20).await.expect("no UDP reply");
    assert_eq!(
        answer.payload,
        Payload::Udp {
            src_port: 7777,
            dst_port: 5000,
            data: b"pong:hello".to_vec()
        }
    );

    let mut oracle = PcapOracle::udp(dissector).port(encap.port());
    for d in &v.sent {
        oracle = oracle.to_server(d);
    }
    for d in &v.received {
        oracle = oracle.from_server(d);
    }
    oracle.assert_clean();
    assert_eq!(
        events(&state, id, "vxlan_udp_datagram").await[0]["vni"],
        json!(header.vni)
    );
    v
}

#[tokio::test]
async fn vxlan_arp_ping_udp_and_oracle() {
    exchange(
        Encap::Vxlan,
        Header::vni(42),
        json!({"encapsulation": "vxlan", "vni": 42}),
        "vxlan",
    )
    .await;
}

#[tokio::test]
async fn geneve_arp_ping_udp_and_oracle() {
    exchange(
        Encap::Geneve,
        Header::vni(42),
        json!({"encapsulation": "geneve", "vni": 42}),
        "geneve",
    )
    .await;
}

/// Every optional GRE field on: key 42, a checksum, and sequence numbers. NetGet's replies
/// carry the key and a valid checksum, and number themselves 0, 1, 2 in the order they left.
#[tokio::test]
async fn gretap_with_key_checksum_and_sequence_and_oracle() {
    let header = Header {
        vni: Some(42),
        checksum: true,
        sequence: Some(100),
    };
    let v = exchange(
        Encap::Gretap,
        header,
        json!({"encapsulation": "gretap", "vni": 42}),
        "gretap",
    )
    .await;
    assert_eq!(v.sequences, [0, 1, 2]);
}

/// Plain GRE: no key, no checksum, no sequence number, and a server with no key filter.
#[tokio::test]
async fn gretap_without_a_key_and_oracle() {
    exchange(
        Encap::Gretap,
        Header::default(),
        json!({"encapsulation": "gretap"}),
        "gretap",
    )
    .await;
}

/// The GRE codec on its own: each optional field round-trips, a corrupted byte fails the
/// checksum, and renumbering keeps the checksum valid.
#[test]
fn gre_header_round_trip_and_sequence_stamping() {
    let inner = frame::arp_frame(true, PEER_MAC, PEER_IP, [0; 6], HOST_IP);
    for checksum in [false, true] {
        for vni in [None, Some(0), Some(u32::MAX)] {
            for sequence in [None, Some(7)] {
                let h = Header {
                    vni,
                    checksum,
                    sequence,
                };
                let mut d = frame::encap(Encap::Gretap, &h, &inner);
                assert_eq!(
                    frame::decap(Encap::Gretap, &d).unwrap(),
                    (h, &inner[..]),
                    "{h:?}"
                );
                assert_eq!(
                    frame::stamp_sequence(Encap::Gretap, &mut d, 9),
                    sequence.is_some()
                );
                let (after, _) = frame::decap(Encap::Gretap, &d).expect("checksum redone");
                assert_eq!(after.sequence, sequence.map(|_| 9));
                if checksum {
                    let last = d.len() - 1;
                    d[last] ^= 1;
                    let e = frame::decap(Encap::Gretap, &d).unwrap_err();
                    assert!(e.to_string().contains("bad GRE checksum"), "{e}");
                }
            }
        }
    }
}

#[tokio::test]
async fn refusals_and_the_vni_filter() {
    let (state, id, port) = start(json!({"vni": 42})).await;
    let mut v = Vtep::new(port, Encap::Vxlan, Header::vni(42)).await;
    let arp = frame::arp_frame(true, PEER_MAC, PEER_IP, [0; 6], HOST_IP);

    // The I flag clear: no valid VNI, dropped.
    let mut no_i = frame::encap(Encap::Vxlan, &Header::vni(42), &arp);
    no_i[0] = 0;
    v.send_raw(&no_i).await;
    // Another VNI: not this server's overlay.
    v.send_raw(&frame::encap(Encap::Vxlan, &Header::vni(43), &arp))
        .await;
    // A truncated inner frame, and an IPv4 header with a wrong checksum.
    v.send_raw(&frame::encap(Encap::Vxlan, &Header::vni(42), &arp[..20]))
        .await;
    let mut bad = frame::ipv4(PEER_IP, HOST_IP, 1, 7, &frame::icmp_echo(true, 1, 1, b"x"));
    bad[10] ^= 0xff;
    v.send_raw(&frame::encap(
        Encap::Vxlan,
        &Header::vni(42),
        &frame::ethernet(HOST_MAC, PEER_MAC, frame::ETHERTYPE_IPV4, &bad),
    ))
    .await;
    assert!(
        v.recv(2).await.is_none(),
        "answered something it should have dropped"
    );
    // None of them reached the model; and the server still answers.
    assert!(events(&state, id, "vxlan_arp_request").await.is_empty());
    assert!(events(&state, id, "vxlan_icmp_echo_request")
        .await
        .is_empty());
    v.send(&arp).await;
    assert!(v.recv(20).await.is_some());

    // An IP with no host: silence (the policy answers ARP for 10.99.0.2 only).
    v.send(&frame::arp_frame(
        true,
        PEER_MAC,
        PEER_IP,
        [0; 6],
        Ipv4Addr::new(10, 99, 0, 3),
    ))
    .await;
    assert!(v.recv(2).await.is_none());
}

/// Each datagram below is an ARP request for 10.99.0.2 that the policy would answer, broken in
/// exactly one way, so a check that stopped refusing it shows up as a reply (or, for the
/// truncated header, as a server whose receive loop died and answers nothing afterwards).
#[tokio::test]
async fn gre_refusals_before_the_model() {
    let (state, id, port) = start(json!({"encapsulation": "gretap", "vni": 42})).await;
    let mut v = Vtep::new(port, Encap::Gretap, Header::vni(42)).await;
    let arp = frame::arp_frame(true, PEER_MAC, PEER_IP, [0; 6], HOST_IP);
    let plain = frame::encap(Encap::Gretap, &Header::vni(42), &arp);

    // Version 1 is PPTP's enhanced GRE, a different header.
    let mut version = plain.clone();
    version[1] |= 0x01;
    v.send_raw(&version).await;
    // Protocol type IPv4 (0x0800), not Transparent Ethernet Bridging (0x6558).
    let mut protocol = plain.clone();
    protocol[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    v.send_raw(&protocol).await;
    // RFC 1701's routing-present bit, which RFC 2784 receivers discard.
    let mut routing = plain.clone();
    routing[0] |= 0x40;
    v.send_raw(&routing).await;
    // A checksum that no longer matches: one bit of the inner source MAC flipped after it was
    // computed (header: 4 + checksum 4 + key 4 bytes).
    let mut corrupted = frame::encap(
        Encap::Gretap,
        &Header {
            vni: Some(42),
            checksum: true,
            sequence: None,
        },
        &arp,
    );
    corrupted[12 + 11] ^= 0x02;
    v.send_raw(&corrupted).await;
    // Another key, and no key at all: not this server's overlay.
    v.send_raw(&frame::encap(Encap::Gretap, &Header::vni(43), &arp))
        .await;
    v.send_raw(&frame::encap(Encap::Gretap, &Header::default(), &arp))
        .await;
    // K and S set, but the datagram ends after the key: the sequence number is missing.
    v.send_raw(&[0x30, 0, 0x65, 0x58, 0, 0, 0, 42]).await;
    // C set on a four-byte datagram: the checksum field itself is missing.
    v.send_raw(&[0x80, 0, 0x65, 0x58]).await;
    // A truncated inner frame.
    v.send_raw(&frame::encap(Encap::Gretap, &Header::vni(42), &arp[..20]))
        .await;
    assert!(
        v.recv(2).await.is_none(),
        "answered a GRE datagram it should have dropped"
    );
    assert!(events(&state, id, "vxlan_arp_request").await.is_empty());

    // The server is still up and answers the same request sent properly.
    v.send(&arp).await;
    assert!(v.recv(20).await.is_some(), "the server stopped answering");
}
