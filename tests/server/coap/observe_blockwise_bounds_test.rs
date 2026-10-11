//! Every bound Observe and Block-wise transfer added to the CoAP server, from a UDP socket.
//!
//! "A bound nobody tested is a comment." Each test here holds a limit at its edge and one
//! past it, and where the server is supposed to answer without the model, counts the handler
//! calls rather than inferring them. Requests are built with **coap-lite**, an independent
//! codec, never with `netget::server::coap::codec`; the Block values are packed by hand below
//! from RFC 7959 §2.2 so they are not the server's own encoder either. Every exchange is also
//! read by the pcap oracle (tshark's CoAP dissector), which decodes Observe, Block1, Block2,
//! Size1 and Size2 itself.
//!
//! | bound | where | test |
//! |---|---|---|
//! | `observe::MAX_OBSERVERS_PER_IP` (4) | registration served without Observe | `one_ip_holds_at_most_…_observations_…` |
//! | `blockwise::MAX_UPLOADS_PER_IP` (2) | that IP's oldest upload evicted | `one_ip_holds_at_most_…_uploads_…` |
//! | `codec::MAX_REPRESENTATION_LEN` inbound (64 KiB) | 4.13 + Size1, announced or reached | `an_upload_of_exactly_…` |
//! | Block1 order | 4.08 | `an_out_of_order_block_…` |
//! | Block1 size | 4.00 | `a_short_block_that_says_more_…` |
//! | `blockwise::MAX_TRANSFERS` (32) | oldest evicted, re-asked | `the_transfer_cache_…` |
//! | `blockwise::TRANSFER_SERVE_FACTOR` (2×) | entry evicted, re-asked | `a_cached_representation_serves_…` |
//! | Block2 past the end | 4.02 | `a_block_past_the_end_…` |
//! | RST ends an observation | RFC 7641 §3.6 | `a_reset_ends_the_observation` |
//! | `NOTIFICATION_MAX_RETRANSMIT` (4) | then the observer is removed | `an_unacknowledged_confirmable_…` |
//! | `observe::RECENT_NOTIFICATIONS` (256) does not end a wait for an ACK | resent, then removed | `a_confirmable_notification_pushed_out_…` |
//! | non-2.xx notification ends observations | RFC 7641 §4.2 | `an_error_notification_…` |
//!
//! The shared caps — `observe::MAX_OBSERVERS` (64) and `blockwise::MAX_UPLOADS` (16) — sit
//! above the per-IP caps, so reaching them on the wire needs more source IPs than loopback has
//! on every platform the suite runs on. They are held at the table in
//! `observe_blockwise_table_test.rs`, with distinct addresses, along with the rules that need
//! a clock: the Block2 TTL that a hit does not renew, and an observer's 24-hour expiry.

use super::observe_support::{body, Device};
use crate::helpers::pcap_oracle::PcapOracle;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
use netget::server::coap::blockwise::{
    Representation, MAX_TRANSFERS, MAX_UPLOADS_PER_IP, TRANSFER_SERVE_FACTOR,
};
use netget::server::coap::codec::{CODE_CONTENT, CODE_NOT_FOUND, MAX_REPRESENTATION_LEN};
use netget::server::coap::observe::{MAX_OBSERVERS_PER_IP, RECENT_NOTIFICATIONS};
use netget::server::coap::NOTIFICATION_MAX_RETRANSMIT;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// A Block option value, packed from RFC 7959 §2.2: `NUM << 4 | M << 3 | SZX`, minimum length.
fn block(num: u32, more: bool, szx: u8) -> Vec<u8> {
    let v = (num << 4) | (u32::from(more) << 3) | u32::from(szx);
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(4);
    bytes[first..].to_vec()
}

fn uint(v: u32) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(4);
    bytes[first..].to_vec()
}

fn read_uint(v: &[u8]) -> u32 {
    v.iter().fold(0, |acc, b| (acc << 8) | u32::from(*b))
}

/// A Confirmable request built with coap-lite.
fn request(
    method: RequestType,
    mid: u16,
    token: &[u8],
    path: &str,
    options: &[(CoapOption, Vec<u8>)],
    payload: &[u8],
) -> Vec<u8> {
    let mut p = Packet::new();
    p.header.set_version(1);
    p.header.set_type(MessageType::Confirmable);
    p.header.code = MessageClass::Request(method);
    p.header.message_id = mid;
    p.set_token(token.to_vec());
    for segment in path.trim_start_matches('/').split('/') {
        p.add_option(CoapOption::UriPath, segment.as_bytes().to_vec());
    }
    for (o, v) in options {
        p.add_option(*o, v.clone());
    }
    p.payload = payload.to_vec();
    p.to_bytes().expect("coap-lite encodes")
}

/// An empty ACK or RST.
fn empty(mtype: MessageType, mid: u16) -> Vec<u8> {
    let mut p = Packet::new();
    p.header.set_version(1);
    p.header.set_type(mtype);
    p.header.code = MessageClass::Empty;
    p.header.message_id = mid;
    p.to_bytes().unwrap()
}

/// One UDP endpoint, recording every datagram for the pcap oracle.
struct Peer {
    socket: UdpSocket,
    server: SocketAddr,
    wire: Vec<(bool, Vec<u8>)>,
}

impl Peer {
    async fn new(port: u16) -> Peer {
        Peer {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            server: format!("127.0.0.1:{port}").parse().unwrap(),
            wire: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: Vec<u8>) {
        self.socket.send_to(&bytes, self.server).await.unwrap();
        self.wire.push((true, bytes));
    }

    async fn recv_within(&mut self, wait: Duration) -> Option<Packet> {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(wait, self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        buf.truncate(n);
        let packet = Packet::from_bytes(&buf).expect("coap-lite decodes what NetGet sent");
        self.wire.push((false, buf));
        Some(packet)
    }

    async fn recv(&mut self) -> Packet {
        self.recv_within(Duration::from_secs(15))
            .await
            .expect("no reply from the CoAP server")
    }

    async fn exchange(&mut self, bytes: Vec<u8>) -> Packet {
        self.send(bytes).await;
        self.recv().await
    }

    /// The pcap oracle over everything this peer sent and received.
    fn assert_wire_clean(&self) {
        let mut oracle = PcapOracle::udp("coap");
        for (to_server, bytes) in &self.wire {
            oracle = if *to_server {
                oracle.to_server(bytes)
            } else {
                oracle.from_server(bytes)
            };
        }
        oracle.assert_clean();
    }
}

/// `(class, detail)` of a reply.
fn code(p: &Packet) -> (u8, u8) {
    let byte: u8 = p.header.code.into();
    (byte >> 5, byte & 0x1F)
}

fn option(p: &Packet, o: CoapOption) -> Option<Vec<u8>> {
    p.get_option(o).and_then(|l| l.front().cloned())
}

/// A registration of /temp under `token`, Confirmable, with message id `mid`.
fn register(mid: u16, token: &[u8]) -> Vec<u8> {
    request(
        RequestType::Get,
        mid,
        token,
        "/temp",
        &[(CoapOption::Observe, vec![])],
        b"",
    )
}

#[tokio::test]
async fn one_ip_holds_at_most_four_observations_across_its_ports() {
    assert_eq!(
        MAX_OBSERVERS_PER_IP % 2,
        0,
        "split evenly over two sockets below"
    );
    let device = Device::start(None).await;
    // Two sockets on 127.0.0.1: two endpoints, one IP. The cap is the IP's.
    let mut a = Peer::new(device.port).await;
    let mut b = Peer::new(device.port).await;
    for i in 0..MAX_OBSERVERS_PER_IP {
        let peer = if i % 2 == 0 { &mut a } else { &mut b };
        let reply = peer.exchange(register(i as u16, &[i as u8])).await;
        assert_eq!(code(&reply), (2, 5));
        assert!(
            option(&reply, CoapOption::Observe).is_some(),
            "registration {i} of {MAX_OBSERVERS_PER_IP} from this IP is accepted"
        );
    }
    let reply = a.exchange(register(100, b"over")).await;
    assert_eq!(code(&reply), (2, 5), "still served");
    assert!(
        option(&reply, CoapOption::Observe).is_none(),
        "one past MAX_OBSERVERS_PER_IP is answered without Observe: not registered"
    );
    assert_eq!(
        device.handle().await.observers().len(),
        MAX_OBSERVERS_PER_IP
    );

    // Re-registering a token this endpoint already holds replaces it (RFC 7641 §4.1): not a
    // new registration, so the cap does not refuse it.
    let reply = a.exchange(register(101, &[0])).await;
    assert!(option(&reply, CoapOption::Observe).is_some());
    assert_eq!(
        device.handle().await.observers().len(),
        MAX_OBSERVERS_PER_IP
    );

    // Deregistering with Observe 1 frees a place for this IP.
    let reply = b
        .exchange(request(
            RequestType::Get,
            102,
            &[1],
            "/temp",
            &[(CoapOption::Observe, vec![1])],
            b"",
        ))
        .await;
    assert!(option(&reply, CoapOption::Observe).is_none());
    assert_eq!(
        device.handle().await.observers().len(),
        MAX_OBSERVERS_PER_IP - 1
    );
    let reply = a.exchange(register(103, b"over")).await;
    assert!(
        option(&reply, CoapOption::Observe).is_some(),
        "the freed place is taken"
    );
    assert_eq!(
        device.handle().await.observers().len(),
        MAX_OBSERVERS_PER_IP
    );
    let mut wire = a.wire.clone();
    wire.extend(b.wire.clone());
    a.wire = wire;
    a.assert_wire_clean();
}

#[tokio::test]
async fn one_ip_holds_at_most_two_uploads_and_a_third_evicts_its_oldest() {
    assert_eq!(
        MAX_UPLOADS_PER_IP, 2,
        "the paths below name two uploads and a third"
    );
    let device = Device::start(None).await;
    let mut first = Peer::new(device.port).await;
    let mut second = Peer::new(device.port).await;
    let chunk = vec![b'u'; 64];
    let start = |mid: u16, path: &str| {
        request(
            RequestType::Put,
            mid,
            b"u",
            path,
            &[(CoapOption::Block1, block(0, true, 2))],
            &chunk,
        )
    };
    for (mid, path) in [(1, "/upload/0"), (2, "/upload/1")] {
        let reply = first.exchange(start(mid, path)).await;
        assert_eq!(code(&reply), (2, 31), "{path} continues");
    }
    assert_eq!(device.handle().await.uploads_in_progress(), 2);

    // A third upload from the same IP — another port — is taken, not refused, and the IP's
    // least recently advanced upload makes room for it.
    let reply = second.exchange(start(3, "/upload/2")).await;
    assert_eq!(code(&reply), (2, 31), "the third upload continues");
    assert_eq!(
        device.handle().await.uploads_in_progress(),
        MAX_UPLOADS_PER_IP,
        "the IP still holds only its cap"
    );

    // /upload/0 was the oldest: its next block finds no upload in progress.
    let reply = first
        .exchange(request(
            RequestType::Put,
            4,
            b"u",
            "/upload/0",
            &[(CoapOption::Block1, block(1, false, 2))],
            b"end",
        ))
        .await;
    assert_eq!(code(&reply), (4, 8), "the evicted upload is gone");

    // The other two are intact and finish at the handler.
    for (mid, path, peer) in [(5, "/upload/1", &mut first), (6, "/upload/2", &mut second)] {
        let reply = peer
            .exchange(request(
                RequestType::Put,
                mid,
                b"u",
                path,
                &[(CoapOption::Block1, block(1, false, 2))],
                b"end",
            ))
            .await;
        assert_eq!(code(&reply), (2, 4), "{path}");
        assert_eq!(reply.payload, b"got 67 bytes in 2 blocks");
    }
    let asked: Vec<String> = device
        .requests()
        .await
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(asked, ["/upload/1", "/upload/2"]);
    let mut wire = first.wire.clone();
    wire.extend(second.wire.clone());
    first.wire = wire;
    first.assert_wire_clean();
}

#[tokio::test]
async fn an_upload_of_exactly_the_representation_limit_is_taken_and_one_byte_more_is_4_13() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let full = vec![b'a'; 1024];
    let blocks = MAX_REPRESENTATION_LEN / 1024;

    // Exactly MAX_REPRESENTATION_LEN, in 1024-byte blocks: taken.
    for num in 0..blocks {
        let last = num + 1 == blocks;
        let reply = peer
            .exchange(request(
                RequestType::Put,
                num as u16,
                b"a",
                "/upload/at",
                &[(CoapOption::Block1, block(num as u32, !last, 6))],
                &full,
            ))
            .await;
        if !last {
            assert_eq!(code(&reply), (2, 31), "block {num}");
        } else {
            assert_eq!(code(&reply), (2, 4));
            assert_eq!(
                reply.payload,
                format!("got {MAX_REPRESENTATION_LEN} bytes in {blocks} blocks").into_bytes()
            );
        }
    }

    // Announced one byte over in Size1: refused on the first block, nothing held.
    let reply = peer
        .exchange(request(
            RequestType::Put,
            500,
            b"b",
            "/upload/announced",
            &[
                (CoapOption::Block1, block(0, true, 6)),
                (CoapOption::Size1, uint(MAX_REPRESENTATION_LEN as u32 + 1)),
            ],
            &full,
        ))
        .await;
    assert_eq!(code(&reply), (4, 13));
    assert_eq!(
        option(&reply, CoapOption::Size1).map(|v| read_uint(&v)),
        Some(MAX_REPRESENTATION_LEN as u32),
        "a 4.13 says what the server takes"
    );

    // Not announced, reached: the block that crosses the limit is refused.
    for num in 0..blocks {
        let reply = peer
            .exchange(request(
                RequestType::Put,
                600 + num as u16,
                b"c",
                "/upload/over",
                &[(CoapOption::Block1, block(num as u32, true, 6))],
                &full,
            ))
            .await;
        assert_eq!(code(&reply), (2, 31), "block {num}");
    }
    let reply = peer
        .exchange(request(
            RequestType::Put,
            700,
            b"c",
            "/upload/over",
            &[(CoapOption::Block1, block(blocks as u32, false, 6))],
            b"x",
        ))
        .await;
    assert_eq!(
        code(&reply),
        (4, 13),
        "one byte past MAX_REPRESENTATION_LEN"
    );
    assert_eq!(
        option(&reply, CoapOption::Size1).map(|v| read_uint(&v)),
        Some(MAX_REPRESENTATION_LEN as u32)
    );

    let asked: Vec<String> = device
        .requests()
        .await
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        asked,
        ["/upload/at"],
        "the refused uploads never reached the handler"
    );
    peer.assert_wire_clean();
}

#[tokio::test]
async fn an_out_of_order_block_is_4_08_and_ends_the_upload() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let chunk = vec![b'o'; 32];
    let reply = peer
        .exchange(request(
            RequestType::Put,
            1,
            b"o",
            "/upload",
            &[(CoapOption::Block1, block(0, true, 1))],
            &chunk,
        ))
        .await;
    assert_eq!(code(&reply), (2, 31));
    let reply = peer
        .exchange(request(
            RequestType::Put,
            2,
            b"o",
            "/upload",
            &[(CoapOption::Block1, block(2, true, 1))],
            &chunk,
        ))
        .await;
    assert_eq!(code(&reply), (4, 8), "block 2 after block 0");
    // The upload is gone: even the block that would have been next is incomplete now.
    let reply = peer
        .exchange(request(
            RequestType::Put,
            3,
            b"o",
            "/upload",
            &[(CoapOption::Block1, block(1, false, 1))],
            &chunk,
        ))
        .await;
    assert_eq!(code(&reply), (4, 8));
    assert_eq!(device.handle().await.uploads_in_progress(), 0);
    assert!(device.requests().await.is_empty());
    peer.assert_wire_clean();
}

#[tokio::test]
async fn a_short_block_that_says_more_is_4_00() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let reply = peer
        .exchange(request(
            RequestType::Put,
            1,
            b"s",
            "/upload",
            &[(CoapOption::Block1, block(0, true, 2))],
            b"only ten b",
        ))
        .await;
    assert_eq!(code(&reply), (4, 0), "a 64-byte block carrying 10 bytes");
    assert!(device.requests().await.is_empty());
}

#[tokio::test]
async fn the_transfer_cache_evicts_the_oldest_and_re_asks_for_it() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let ask_block = |mid: u16, path: &str, num: u32| {
        request(
            RequestType::Get,
            mid,
            b"t",
            path,
            &[(CoapOption::Block2, block(num, false, 6))],
            b"",
        )
    };
    // MAX_TRANSFERS + 1 representations, each left after its first block.
    for i in 0..=MAX_TRANSFERS {
        let reply = peer
            .exchange(ask_block(i as u16, &format!("/big/{i}"), 0))
            .await;
        assert_eq!(option(&reply, CoapOption::Block2), Some(block(0, true, 6)));
        assert!(device.handle().await.cached_transfers() <= MAX_TRANSFERS);
    }
    assert_eq!(device.handle().await.cached_transfers(), MAX_TRANSFERS);

    // The newest is still cached: its second block costs no handler call.
    let last = format!("/big/{MAX_TRANSFERS}");
    let reply = peer.exchange(ask_block(200, &last, 1)).await;
    assert_eq!(reply.payload, body().as_bytes()[1024..2048]);
    assert_eq!(device.asked(&last).await, 1);

    // The oldest was evicted: its second block is asked again, and still right.
    let reply = peer.exchange(ask_block(201, "/big/0", 1)).await;
    assert_eq!(reply.payload, body().as_bytes()[1024..2048]);
    assert_eq!(device.asked("/big/0").await, 2);
    peer.assert_wire_clean();
}

#[tokio::test]
async fn a_cached_representation_serves_at_most_twice_its_length_then_goes_back_to_the_model() {
    // The cache answers a source address the server cannot verify, without the model. Each
    // entry may serve TRANSFER_SERVE_FACTOR times its length, counting block 0; the block that
    // would pass that evicts the entry, and the request is asked again.
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let ask = |mid: u16, num: u32| {
        request(
            RequestType::Get,
            mid,
            b"r",
            "/big",
            &[(CoapOption::Block2, block(num, false, 6))],
            b"",
        )
    };
    let budget = body().len() * TRANSFER_SERVE_FACTOR;
    let reply = peer.exchange(ask(1, 0)).await;
    assert_eq!(option(&reply, CoapOption::Block2), Some(block(0, true, 6)));
    let mut served = reply.payload.len();
    assert_eq!(device.asked("/big").await, 1);

    // Block 1 over and over, as a reflector would ask for it.
    let mut mid = 2;
    let mut hits = 0;
    while served + 1024 <= budget {
        let reply = peer.exchange(ask(mid, 1)).await;
        mid += 1;
        assert_eq!(reply.payload, body().as_bytes()[1024..2048]);
        served += reply.payload.len();
        hits += 1;
        assert_eq!(
            device.asked("/big").await,
            1,
            "hit {hits}: {served} of {budget} bytes, still from the cache"
        );
    }
    assert!(hits >= 2, "the budget allows a whole transfer at least");

    // The next one would pass the budget: the entry is gone and the model is asked.
    let reply = peer.exchange(ask(mid, 1)).await;
    assert_eq!(code(&reply), (2, 5));
    assert_eq!(
        reply.payload,
        body().as_bytes()[1024..2048],
        "still the right block"
    );
    assert_eq!(
        device.asked("/big").await,
        2,
        "past {budget} bytes the cache stops answering for the model"
    );
    peer.assert_wire_clean();
}

#[tokio::test]
async fn a_block_past_the_end_is_4_02() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    let reply = peer
        .exchange(request(
            RequestType::Get,
            1,
            b"e",
            "/big",
            &[(CoapOption::Block2, block(0, false, 6))],
            b"",
        ))
        .await;
    assert_eq!(code(&reply), (2, 5));
    assert_eq!(option(&reply, CoapOption::Block2), Some(block(0, true, 6)));
    assert_eq!(
        option(&reply, CoapOption::Size2).map(|v| read_uint(&v)),
        Some(3000)
    );
    // 3000 bytes are blocks 0-2 at 1024; block 3 starts past the end.
    let reply = peer
        .exchange(request(
            RequestType::Get,
            2,
            b"e",
            "/big",
            &[(CoapOption::Block2, block(3, false, 6))],
            b"",
        ))
        .await;
    assert_eq!(code(&reply), (4, 2));
    peer.assert_wire_clean();
}

/// Register `peer` as an observer of /temp under `token`, returning the response.
async fn observe(peer: &mut Peer, token: &[u8]) -> Packet {
    let reply = peer
        .exchange(request(
            RequestType::Get,
            7,
            token,
            "/temp",
            &[(CoapOption::Observe, vec![])],
            b"",
        ))
        .await;
    assert!(option(&reply, CoapOption::Observe).is_some());
    reply
}

#[tokio::test]
async fn a_reset_ends_the_observation() {
    let device = Device::start(None).await;
    let mut observer = Peer::new(device.port).await;
    let mut writer = Peer::new(device.port).await;
    observe(&mut observer, b"obs").await;

    // A PUT whose handler answers and notifies.
    let reply = writer
        .exchange(request(RequestType::Put, 1, b"w", "/temp", &[], b"30"))
        .await;
    assert_eq!(code(&reply), (2, 4));
    let note = observer.recv().await;
    assert_eq!(note.payload, b"t=30");
    assert_eq!(note.get_token(), b"obs");
    assert!(option(&note, CoapOption::Observe).is_some());

    // RST in reply to the notification: the client has forgotten it.
    observer
        .send(empty(MessageType::Reset, note.header.message_id))
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !device.handle().await.observers().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the RST removed the observer");

    writer
        .exchange(request(RequestType::Put, 2, b"w", "/temp", &[], b"31"))
        .await;
    assert!(
        observer.recv_within(Duration::from_secs(1)).await.is_none(),
        "no notification after the RST"
    );
    let mut wire = observer.wire.clone();
    wire.extend(writer.wire.clone());
    observer.wire = wire;
    observer.assert_wire_clean();
}

#[tokio::test]
async fn an_unacknowledged_confirmable_notification_is_resent_four_times_then_dropped() {
    let device = Device::start(Some(
        serde_json::json!({"notification_ack_timeout_ms": 100}),
    ))
    .await;
    let mut silent = Peer::new(device.port).await;
    let mut polite = Peer::new(device.port).await;
    observe(&mut silent, b"silent").await;
    observe(&mut polite, b"polite").await;

    let handle = device.handle().await;
    let report = handle
        .notify(
            &device.state,
            "/temp",
            Representation::new(CODE_CONTENT, b"t=40".to_vec(), Some(0)),
            true,
        )
        .await;
    assert_eq!(report.sent, 2);

    // The polite observer ACKs and hears it once.
    let note = polite.recv().await;
    assert_eq!(note.header.get_type(), MessageType::Confirmable);
    polite
        .send(empty(MessageType::Acknowledgement, note.header.message_id))
        .await;

    // The silent one hears the same message id 1 + NOTIFICATION_MAX_RETRANSMIT times.
    // 100 ms doubling four times is 3.1 s at least, 4.65 s at most.
    let mut copies = Vec::new();
    while let Some(p) = silent.recv_within(Duration::from_secs(8)).await {
        copies.push(p.header.message_id);
    }
    assert_eq!(
        copies.len(),
        1 + NOTIFICATION_MAX_RETRANSMIT as usize,
        "{copies:?}"
    );
    assert!(
        copies.iter().all(|m| *m == copies[0]),
        "the same message: {copies:?}"
    );

    let left: Vec<Vec<u8>> = handle.observers().into_iter().map(|o| o.token).collect();
    assert_eq!(
        left,
        [b"polite".to_vec()],
        "the silent observer was dropped"
    );
    assert!(
        polite
            .recv_within(Duration::from_millis(500))
            .await
            .is_none(),
        "an acknowledged notification is not resent"
    );
    silent.assert_wire_clean();
}

#[tokio::test]
async fn a_confirmable_notification_pushed_out_of_the_window_is_still_resent_and_its_observer_removed(
) {
    // RECENT_NOTIFICATIONS bounds the message ids kept for matching a RST. A Confirmable
    // notification still waiting for its ACK must not be forgotten when later notifications
    // push it out of that window: forgetting it reads as "acknowledged", and an observer that
    // never answers would be kept, and notified, forever.
    let device = Device::start(Some(
        serde_json::json!({"notification_ack_timeout_ms": 100}),
    ))
    .await;
    let mut silent = Peer::new(device.port).await;
    observe(&mut silent, b"silent").await;
    let handle = device.handle().await;

    let flood = async {
        let report = handle
            .notify(
                &device.state,
                "/temp",
                Representation::new(CODE_CONTENT, b"t=con".to_vec(), Some(0)),
                true,
            )
            .await;
        assert_eq!(report.sent, 1);
        for i in 0..RECENT_NOTIFICATIONS + 44 {
            handle
                .notify(
                    &device.state,
                    "/temp",
                    Representation::new(CODE_CONTENT, format!("t={i}").into_bytes(), Some(0)),
                    false,
                )
                .await;
        }
    };
    // Read while the flood is sent, so no retransmission is lost to a full receive buffer.
    let drain = async {
        let mut confirmable = Vec::new();
        let mut non = 0usize;
        while let Some(p) = silent.recv_within(Duration::from_secs(8)).await {
            match p.header.get_type() {
                MessageType::Confirmable => confirmable.push(p.header.message_id),
                _ => non += 1,
            }
        }
        (confirmable, non)
    };
    let ((), (confirmable, non)) = tokio::join!(flood, drain);
    assert!(
        non > RECENT_NOTIFICATIONS,
        "the window was overrun: {non} NON"
    );
    assert_eq!(
        confirmable.len(),
        1 + NOTIFICATION_MAX_RETRANSMIT as usize,
        "the Confirmable notification was resent after leaving the window: {confirmable:?}"
    );
    assert!(confirmable.iter().all(|m| *m == confirmable[0]));
    assert!(
        handle.observers().is_empty(),
        "the observer that never acknowledged was removed"
    );
    assert_eq!(handle.pending_notifications(), 0, "nothing left waiting");
}

#[tokio::test]
async fn an_error_notification_goes_out_without_observe_and_ends_every_observation() {
    let device = Device::start(None).await;
    let mut a = Peer::new(device.port).await;
    let mut b = Peer::new(device.port).await;
    observe(&mut a, b"a").await;
    observe(&mut b, b"b").await;
    let handle = device.handle().await;
    let report = handle
        .notify(
            &device.state,
            "/temp",
            Representation::new(CODE_NOT_FOUND, Vec::new(), None),
            false,
        )
        .await;
    assert_eq!((report.sent, report.ended), (2, 2));
    for peer in [&mut a, &mut b] {
        let note = peer.recv().await;
        assert_eq!(code(&note), (4, 4));
        assert!(option(&note, CoapOption::Observe).is_none());
    }
    assert!(handle.observers().is_empty());
    a.assert_wire_clean();
}

#[tokio::test]
async fn a_notification_over_one_block_is_its_first_block_and_the_rest_come_from_the_cache() {
    let device = Device::start(None).await;
    let mut peer = Peer::new(device.port).await;
    observe(&mut peer, b"big").await;
    let handle = device.handle().await;
    handle
        .notify(
            &device.state,
            "/temp",
            Representation::new(CODE_CONTENT, body().into_bytes(), Some(0)),
            false,
        )
        .await;
    let note = peer.recv().await;
    assert_eq!(option(&note, CoapOption::Block2), Some(block(0, true, 6)));
    let etag = option(&note, CoapOption::ETag).expect("an ETag ties the blocks together");
    let mut whole = note.payload.clone();
    // RFC 7959 §2.6: the rest is fetched with ordinary GETs, without Observe.
    for num in 1..3 {
        let reply = peer
            .exchange(request(
                RequestType::Get,
                100 + num as u16,
                b"rest",
                "/temp",
                &[(CoapOption::Block2, block(num, false, 6))],
                b"",
            ))
            .await;
        assert_eq!(option(&reply, CoapOption::ETag), Some(etag.clone()));
        whole.extend_from_slice(&reply.payload);
    }
    assert_eq!(whole, body().into_bytes());
    assert_eq!(
        device.asked("/temp").await,
        1,
        "only the registration was asked"
    );
    peer.assert_wire_clean();
}
