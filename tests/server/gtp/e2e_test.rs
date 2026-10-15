//! E2E tests for the GTP-C / GTP-U server.
//!
//! **The transport genuinely executes here.** Both GTP ports are above 1023, so unlike every
//! raw-socket protocol in this tier there is no privilege to stand in the way: these tests
//! bind real UDP sockets on 127.0.0.1, send real GTP datagrams into the real server, and
//! decode what comes back. Nothing is mocked except the model.
//!
//! **The peer is hand-written, and that is exactly the limit on the maturity rating.** No
//! third-party GTP implementation is used anywhere below: the builders and parsers in this
//! file were written from TS 29.060 and TS 29.274, and they share no code with
//! `src/server/gtp/codec.rs`. That makes them an independent *reading* of the specification —
//! which is worth something, and is the same evidence `dhcp` and the USB/IP family have — but
//! not an independent *implementation*, so the protocol stays `Experimental`. See
//! `tests/server/gtp/CLAUDE.md`.
//!
//! Every mock rule uses `respond_with_actions_from_event` and takes the sequence number from
//! the event, which is the rule the root `CLAUDE.md` states for UDP protocols: a hardcoded
//! transaction identifier is the documented cause of timeouts in every UDP suite here.


use crate::helpers::server::NetGetServer;
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// ===========================================================================
// A GTP peer, written from the specification and sharing no code with the server
// ===========================================================================

/// GTPv1 flags with PT=1 and S=1: version 1, GTP (not GTP'), sequence number present.
const V1_FLAGS_WITH_SEQUENCE: u8 = 0x32;

/// Build a GTPv1 message. The Length field counts the four optional octets as well as the
/// body, which is the part implementations get wrong.
fn v1_message(message_type: u8, teid: u32, sequence: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![V1_FLAGS_WITH_SEQUENCE, message_type];
    out.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&teid.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(0); // N-PDU number: absent, but the octet is still there
    out.push(0); // next extension header type
    out.extend_from_slice(body);
    out
}

/// A GTPv1 information element below type 128: type octet then the value, no length.
fn tv(ie_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![ie_type];
    out.extend_from_slice(value);
    out
}

/// A GTPv1 information element at type 128 or above: type, two-octet length, value.
fn tlv(ie_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![ie_type];
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Telephony BCD: two digits per octet, low nibble first, 0xF filler.
fn tbcd(digits: &str) -> Vec<u8> {
    let nibbles: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
    nibbles
        .chunks(2)
        .map(|pair| (pair.get(1).copied().unwrap_or(0x0F) << 4) | pair[0])
        .collect()
}

/// An APN as DNS-style labels.
fn apn_labels(apn: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in apn.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out
}

struct V1Packet {
    message_type: u8,
    teid: u32,
    sequence: Option<u16>,
    ies: Vec<(u8, Vec<u8>)>,
    body: Vec<u8>,
}

impl V1Packet {
    fn ie(&self, ie_type: u8) -> Option<&[u8]> {
        self.ies
            .iter()
            .find(|(t, _)| *t == ie_type)
            .map(|(_, v)| v.as_slice())
    }

    fn u32_ie(&self, ie_type: u8) -> Option<u32> {
        self.ie(ie_type)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes)
    }
}

/// Parse a GTPv1 datagram. Independent of the server's decoder, including the all-or-nothing
/// rule: any of E/S/PN means four optional octets, not just the flagged field.
fn parse_v1(bytes: &[u8], parse_ies: bool) -> V1Packet {
    assert!(bytes.len() >= 8, "GTPv1 reply is shorter than a header");
    assert_eq!(bytes[0] >> 5, 1, "expected a GTPv1 reply");
    let message_type = bytes[1];
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let teid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    assert_eq!(
        declared,
        bytes.len() - 8,
        "the Length field must describe the rest of the datagram exactly"
    );

    let e = bytes[0] & 0x04 != 0;
    let s = bytes[0] & 0x02 != 0;
    let pn = bytes[0] & 0x01 != 0;
    let (sequence, mut offset) = if e || s || pn {
        assert!(bytes.len() >= 12, "the optional block is four octets");
        (
            if s {
                Some(u16::from_be_bytes([bytes[8], bytes[9]]))
            } else {
                None
            },
            12,
        )
    } else {
        (None, 8)
    };

    // Extension headers, if any.
    if e {
        let mut next = bytes[11];
        while next != 0 {
            let units = bytes[offset] as usize;
            assert!(units > 0, "an extension header cannot be zero units long");
            next = bytes[offset + units * 4 - 1];
            offset += units * 4;
        }
    }

    let body = bytes[offset..].to_vec();
    let ies = if parse_ies {
        parse_v1_ies(&body)
    } else {
        Vec::new()
    };
    V1Packet {
        message_type,
        teid,
        sequence,
        ies,
        body,
    }
}

/// The fixed lengths this test needs, read off TS 29.060 §7.7 independently of the server.
fn fixed_len(ie_type: u8) -> usize {
    match ie_type {
        1 => 1,   // Cause
        8 => 1,   // Reordering Required
        14 => 1,  // Recovery
        16 => 4,  // TEID Data I
        17 => 4,  // TEID Control Plane
        19 => 1,  // Teardown Ind
        20 => 1,  // NSAPI
        127 => 4, // Charging ID
        other => panic!("this test does not know the fixed length of GTPv1 IE {other}"),
    }
}

fn parse_v1_ies(body: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let ie_type = body[pos];
        if ie_type < 128 {
            let len = fixed_len(ie_type);
            out.push((ie_type, body[pos + 1..pos + 1 + len].to_vec()));
            pos += 1 + len;
        } else {
            let len = u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
            out.push((ie_type, body[pos + 3..pos + 3 + len].to_vec()));
            pos += 3 + len;
        }
    }
    out
}

/// Build a GTPv2-C message. `teid` present sets the T flag; the sequence is 24 bits and is
/// followed by one spare octet.
fn v2_message(message_type: u8, teid: Option<u32>, sequence: u32, ies: &[u8]) -> Vec<u8> {
    let mut rest = Vec::new();
    if let Some(t) = teid {
        rest.extend_from_slice(&t.to_be_bytes());
    }
    rest.extend_from_slice(&sequence.to_be_bytes()[1..4]);
    rest.push(0);
    rest.extend_from_slice(ies);

    let mut out = vec![if teid.is_some() { 0x48 } else { 0x40 }, message_type];
    out.extend_from_slice(&(rest.len() as u16).to_be_bytes());
    out.extend_from_slice(&rest);
    out
}

/// A GTPv2 TLIV information element: type, two-octet length, spare+instance, value.
fn v2_ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![ie_type];
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.push(instance & 0x0F);
    out.extend_from_slice(value);
    out
}

struct V2Packet {
    message_type: u8,
    teid: Option<u32>,
    sequence: u32,
    ies: Vec<(u8, u8, Vec<u8>)>,
}

impl V2Packet {
    fn ie(&self, ie_type: u8) -> Option<&[u8]> {
        self.ies
            .iter()
            .find(|(t, _, _)| *t == ie_type)
            .map(|(_, _, v)| v.as_slice())
    }

    fn ie_instance(&self, ie_type: u8, instance: u8) -> Option<&[u8]> {
        self.ies
            .iter()
            .find(|(t, i, _)| *t == ie_type && *i == instance)
            .map(|(_, _, v)| v.as_slice())
    }
}

fn parse_v2(bytes: &[u8]) -> V2Packet {
    assert!(bytes.len() >= 8, "GTPv2 reply is shorter than a header");
    assert_eq!(bytes[0] >> 5, 2, "expected a GTPv2 reply");
    let has_teid = bytes[0] & 0x08 != 0;
    let message_type = bytes[1];
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(declared, bytes.len() - 4, "GTPv2 Length must be exact");

    let mut pos = 4;
    let teid = if has_teid {
        let t = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        pos = 8;
        Some(t)
    } else {
        None
    };
    let sequence = u32::from_be_bytes([0, bytes[pos], bytes[pos + 1], bytes[pos + 2]]);
    pos += 4;

    V2Packet {
        message_type,
        teid,
        sequence,
        ies: parse_v2_ies(&bytes[pos..]),
    }
}

fn parse_v2_ies(bytes: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        let ie_type = bytes[pos];
        let len = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
        let instance = bytes[pos + 3] & 0x0F;
        out.push((ie_type, instance, bytes[pos + 4..pos + 4 + len].to_vec()));
        pos += 4 + len;
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Send one datagram and wait for exactly one reply.
async fn exchange(socket: &UdpSocket, server: SocketAddr, out: &[u8]) -> Vec<u8> {
    socket
        .send_to(out, server)
        .await
        .expect("failed to send a GTP datagram");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for a GTP reply")
        .expect("failed to receive a GTP reply");
    buf.truncate(n);

    // The pcap oracle. Wireshark's `gtp` dissector reads the flags byte — version,
    // protocol type, and the three optional-field bits that decide whether a sequence
    // number, N-PDU number and extension header type follow — and then checks the
    // 16-bit Length against what actually follows the fixed header. Those bits are
    // exactly the kind of thing this suite's hand-written helpers index past rather
    // than verify.
    //
    // The capture is framed on GTP-C's own port. `wire_for("gtp")` warns that the two
    // planes are different protocols on different ports; both are named `gtp` in the
    // decode-as table and the dissector reads the version out of the header, so one
    // port serves for the oracle even though it would not for a live capture.
    //
    // `peer_input_is_context` is required here and the reason is worth keeping: GTP-U
    // tunnels arbitrary user traffic, and tshark recurses into it. This suite's G-PDU
    // fixture carries an inner IPv4/UDP packet addressed to port 53 with a one-byte
    // body, so the DNS dissector is handed one byte and reports a malformed packet —
    // a true statement about the test's own fixture and nothing at all about the
    // server. The reply, which is what the oracle is here for, is judged in full.
    crate::helpers::pcap_oracle::PcapOracle::udp("gtp")
        .port(2123)
        .peer_input_is_context()
        .to_server(out)
        .from_server(&buf)
        .assert_clean();

    buf
}

/// The GTP-U port the server chose, read off its own startup line.
async fn user_plane_port(server: &NetGetServer) -> u16 {
    let line = server
        .wait_for_pattern("GTP-U user plane bound to", Duration::from_secs(15))
        .await
        .expect("the server must announce its user-plane port");
    let addr = line.rsplit("bound to ").next().unwrap_or_default().trim();
    addr.rsplit(':')
        .next()
        .unwrap_or_default()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("could not read a port out of {line:?}"))
}

// ===========================================================================
// GTPv1: echo, session creation, user-plane traffic and deletion
// ===========================================================================

/// The subscriber identifiers below are **invented for this test**. IMSI and MSISDN identify
/// real people when they are real; nothing in netget reads any subscriber source, and this
/// file is where that promise has to be visible.
const TEST_IMSI: &str = "262011234567890";
const TEST_MSISDN: &str = "15551234567";

#[tokio::test]
async fn test_gtpv1_session_lifecycle_over_real_udp() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a GTP server on port {AVAILABLE_PORT} acting as a GGSN for the internet APN",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // 1. Server startup.
            .on_instruction_containing("GTP server")
            .and_instruction_containing("on port")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "gtp",
                "instruction": "Act as a GGSN for the internet APN"
            }]))
            .expect_calls(1)
            .and()
            // 2. Path management. The sequence comes from the event, never a literal.
            .on_event("gtp_echo_request")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_gtp_echo_response",
                    "sequence": event["sequence"],
                    "recovery": 3
                }])
            })
            .expect_calls(1)
            .and()
            // 3. The session decision. Matching on the decoded IMSI, MSISDN and APN is the
            //    assertion that they reached the model: if any of them failed to decode the
            //    rule does not match, the request falls through to the fail-closed refusal,
            //    and the assertions below fail loudly rather than passing on a coincidence.
            .on_event("gtp_create_session_request")
            .and_event_data_contains("imsi", TEST_IMSI)
            .and_event_data_contains("msisdn", TEST_MSISDN)
            .and_event_data_contains("apn", "internet")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_gtp_create_session_response",
                    "cause": "request_accepted",
                    "sequence": event["sequence"],
                    "assigned_address": "10.45.0.2",
                    "control_teid": 48879,
                    "data_teid": 48880,
                    "dns_servers": ["8.8.8.8", "1.1.1.1"],
                    "charging_id": 7
                }])
            })
            .expect_calls(1)
            .and()
            // 4. User-plane traffic. The reply is built out of the decoded inner IP header,
            //    so it can only be right if that header really was parsed into fields.
            .on_event("gtp_gpdu_received")
            .respond_with_actions_from_event(|event| {
                let inner = &event["inner_ip"];
                let text = format!(
                    "reply to {} proto {} dport {}",
                    inner["source"].as_str().unwrap_or("?"),
                    inner["protocol_name"].as_str().unwrap_or("?"),
                    inner["destination_port"].as_u64().unwrap_or(0)
                );
                let hex: String = text.bytes().map(|b| format!("{b:02x}")).collect();
                json!([{
                    "type": "send_gtp_gpdu",
                    "teid": 286331153,
                    "payload": hex,
                    "encoding": "hex"
                }])
            })
            .expect_calls(1)
            .and()
            // 5. Tearing the session down.
            .on_event("gtp_delete_session_request")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_gtp_delete_session_response",
                    "cause": "request_accepted",
                    "sequence": event["sequence"],
                    "teid": 572662306
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("GTP control plane receive loop started", 15)
        .await?;
    let gtpu_port = user_plane_port(&server).await;

    let control: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let user: SocketAddr = format!("127.0.0.1:{gtpu_port}").parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // --- Echo Request -------------------------------------------------------
    let reply = parse_v1(
        &exchange(&socket, control, &v1_message(1, 0, 0x1234, &[])).await,
        true,
    );
    assert_eq!(
        reply.message_type, 2,
        "an Echo Request must get an Echo Response"
    );
    assert_eq!(
        reply.sequence,
        Some(0x1234),
        "the Echo Response must carry the request's sequence number, or the peer decides the \
         path is dead"
    );
    assert_eq!(reply.teid, 0, "an Echo Response carries no tunnel");
    assert_eq!(
        reply.ie(14),
        Some([3u8].as_slice()),
        "the Recovery IE is mandatory in an Echo Response and must carry the restart counter \
         the model chose"
    );

    // --- Create PDP Context Request ----------------------------------------
    // Information elements in ascending type order, as TS 29.060 §7.7 requires.
    let mut body = Vec::new();
    body.extend(tv(2, &tbcd(TEST_IMSI))); // IMSI
    body.extend(tv(16, &0x1111_1111u32.to_be_bytes())); // TEID Data I (ours)
    body.extend(tv(17, &0x2222_2222u32.to_be_bytes())); // TEID Control Plane (ours)
    body.extend(tv(20, &[5])); // NSAPI
    body.extend(tlv(128, &[0xF1, 0x21])); // End User Address: assign me one
    body.extend(tlv(131, &apn_labels("internet"))); // APN
    body.extend(tlv(133, &[127, 0, 0, 1])); // GSN Address, control plane
    body.extend(tlv(133, &[127, 0, 0, 1])); // GSN Address, user plane
    let mut msisdn = vec![0x91]; // international, ISDN numbering
    msisdn.extend(tbcd(TEST_MSISDN));
    body.extend(tlv(134, &msisdn)); // MSISDN

    let reply = parse_v1(
        &exchange(&socket, control, &v1_message(16, 0, 1, &body)).await,
        true,
    );
    assert_eq!(
        reply.message_type, 17,
        "a Create PDP Context Request must get a Create PDP Context Response"
    );
    assert_eq!(reply.sequence, Some(1));
    assert_eq!(
        reply.teid, 0x2222_2222,
        "the response header must carry the control TEID WE advertised, taken from IE 17 of \
         the request - the request header's own TEID was 0"
    );
    assert_eq!(
        reply.ie(1),
        Some([128u8].as_slice()),
        "cause 128 is Request accepted; anything else means the model's decision was lost"
    );
    assert_eq!(
        reply.ie(8),
        Some([0xFEu8].as_slice()),
        "Reordering Required is mandatory in an accepted Create PDP Context Response"
    );
    assert_eq!(
        reply.u32_ie(16),
        Some(48880),
        "the data TEID the model assigned"
    );
    assert_eq!(
        reply.u32_ie(17),
        Some(48879),
        "the control TEID the model assigned"
    );
    assert_eq!(
        reply.u32_ie(127),
        Some(7),
        "the charging id the model chose"
    );
    assert_eq!(
        reply.ie(128),
        Some([0xF1, 0x21, 10, 45, 0, 2].as_slice()),
        "the End User Address must carry the address the model assigned, IETF/IPv4 encoded"
    );
    assert_eq!(
        reply.ie(132),
        Some([0x80, 0x00, 0x0D, 0x04, 8, 8, 8, 8, 0x00, 0x0D, 0x04, 1, 1, 1, 1].as_slice()),
        "both DNS servers must appear as PCO containers, in order"
    );
    assert_eq!(
        reply.ies.iter().filter(|(t, _)| *t == 133).count(),
        2,
        "an accepted response carries a GSN Address for each plane"
    );
    // Ascending information element order is a real requirement, not decoration.
    let order: Vec<u8> = reply.ies.iter().map(|(t, _)| *t).collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(
        order, sorted,
        "GTPv1 information elements must ascend by type"
    );

    // --- A subscriber's own packet, through the tunnel ----------------------
    // 10.45.0.2:40000 -> 1.1.1.1:53, one octet of payload.
    let inner: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1D, 0x00, 0x02, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 45, 0, 2, 1, 1,
        1, 1, 0x9C, 0x40, 0x00, 0x35, 0x00, 0x09, 0x00, 0x00, 0x71,
    ];
    // A G-PDU with no sequence number: flags 0x30, and the Length is the body alone.
    let mut gpdu = vec![0x30, 0xFF];
    gpdu.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    gpdu.extend_from_slice(&48880u32.to_be_bytes()); // the data TEID we were given
    gpdu.extend_from_slice(&inner);

    let reply = parse_v1(&exchange(&socket, user, &gpdu).await, false);
    assert_eq!(reply.message_type, 0xFF, "the answer to a G-PDU is a G-PDU");
    assert_eq!(
        reply.teid, 0x1111_1111,
        "the returning G-PDU must carry the TEID the peer said it would accept"
    );
    assert_eq!(
        String::from_utf8_lossy(&reply.body),
        "reply to 10.45.0.2 proto UDP dport 53",
        "the inner IP header must have reached the model as decoded fields - and the hex \
         payload the model sent must have been decoded rather than put on the wire literally"
    );

    // --- Delete PDP Context Request ----------------------------------------
    let mut body = Vec::new();
    body.extend(tv(19, &[0xFF])); // Teardown Ind
    body.extend(tv(20, &[5])); // NSAPI
    let reply = parse_v1(
        &exchange(&socket, control, &v1_message(20, 48879, 3, &body)).await,
        true,
    );
    assert_eq!(reply.message_type, 21);
    assert_eq!(reply.sequence, Some(3));
    assert_eq!(
        reply.teid, 0x2222_2222,
        "the model's explicit teid override must be honoured"
    );
    assert_eq!(reply.ie(1), Some([128u8].as_slice()));

    // Every decision must be recorded, and none of them as a fail-closed one.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    // Same race as the `model_reject` case further down: `wait_for_mocks` proves the
    // model was called, and `decision=` is written after its answer is handled. Waiting
    // for the positive line does not weaken the negative one below — giving
    // model_accept time to appear gives fail_closed the same time.
    server.wait_for_any(&["decision=model_accept"], 30).await;
    assert!(
        server.output_contains("decision=model_accept").await,
        "an accepted session must be logged with a decision token"
    );
    assert!(
        !server.output_contains("decision=fail_closed").await,
        "nothing in this exchange should have fallen through to the fail-closed path"
    );
    server.stop().await?;
    Ok(())
}

// ===========================================================================
// GTPv2-C: the same port, a different header, and a refusal
// ===========================================================================

#[tokio::test]
async fn test_gtpv2_create_session_accepted_and_refused() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a GTP server on port {AVAILABLE_PORT} acting as a PGW that only serves the \
         internet APN",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("GTP server")
            .and_instruction_containing("on port")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "gtp",
                // Control plane only: this test never sends user traffic, and it proves the
                // startup parameter is read rather than merely declared.
                "startup_params": { "enable_user_plane": false },
                "instruction": "Act as a PGW that only serves the internet APN"
            }]))
            .expect_calls(1)
            .and()
            .on_event("gtp_create_session_request")
            .and_event_data_contains("apn", "internet")
            .and_event_data_contains("rat_type", "EUTRAN")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_gtp_create_session_response",
                    "cause": "request_accepted",
                    "sequence": event["sequence"],
                    "assigned_address": "10.45.0.7",
                    "control_teid": 2596069104u32,
                    "data_teid": 2596069105u32,
                    "dns_servers": ["8.8.4.4"]
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("gtp_create_session_request")
            .and_event_data_contains("apn", "forbidden")
            .respond_with_actions_from_event(|event| {
                json!([{
                    "type": "send_gtp_create_session_response",
                    "cause": "missing_or_unknown_apn",
                    "sequence": event["sequence"]
                }])
            })
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("GTP control plane receive loop started", 15)
        .await?;
    assert!(
        server
            .output_contains("GTP-U disabled by enable_user_plane")
            .await,
        "enable_user_plane: false must actually suppress the user-plane socket"
    );

    let control: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    let create_session = |apn: &str, sequence: u32| {
        let mut ies = Vec::new();
        ies.extend(v2_ie(1, 0, &tbcd(TEST_IMSI))); // IMSI
        ies.extend(v2_ie(71, 0, &apn_labels(apn))); // APN
        ies.extend(v2_ie(76, 0, &tbcd(TEST_MSISDN))); // MSISDN
        ies.extend(v2_ie(82, 0, &[6])); // RAT Type: EUTRAN
                                        // Sender F-TEID for the control plane: V4 flag, interface type 10 (S11 MME GTP-C).
        let mut fteid = vec![0x80 | 10];
        fteid.extend_from_slice(&0x3333_3333u32.to_be_bytes());
        fteid.extend_from_slice(&[127, 0, 0, 1]);
        ies.extend(v2_ie(87, 0, &fteid));
        // Bearer Context to be created: EBI 5 and the eNB's user-plane F-TEID.
        let mut bearer = v2_ie(73, 0, &[5]);
        let mut u_fteid = vec![0x80 | 1]; // interface type 1: S1-U eNodeB GTP-U
        u_fteid.extend_from_slice(&0x4444_4444u32.to_be_bytes());
        u_fteid.extend_from_slice(&[127, 0, 0, 1]);
        bearer.extend(v2_ie(87, 0, &u_fteid));
        ies.extend(v2_ie(93, 0, &bearer));
        v2_message(32, Some(0), sequence, &ies)
    };

    // --- Accepted ----------------------------------------------------------
    let reply = parse_v2(&exchange(&socket, control, &create_session("internet", 0x0A0B0C)).await);
    assert_eq!(
        reply.message_type, 33,
        "a Create Session Request must get a Create Session Response"
    );
    assert_eq!(
        reply.sequence, 0x0A0B0C,
        "the 24-bit sequence number must come back intact"
    );
    assert_eq!(
        reply.teid,
        Some(0x3333_3333),
        "the response header must carry the TEID from the peer's Sender F-TEID, not the \
         request header's zero"
    );
    assert_eq!(
        reply.ie(2),
        Some([16u8, 0].as_slice()),
        "GTPv2 cause 16 is Request accepted, and the Cause IE is two octets"
    );
    assert_eq!(
        reply.ie(79),
        Some([0x01, 10, 45, 0, 7].as_slice()),
        "the PDN Address Allocation must carry the address the model assigned"
    );
    assert_eq!(
        reply.ie(78),
        Some([0x80, 0x00, 0x0D, 0x04, 8, 8, 4, 4].as_slice()),
        "the DNS server must be delivered inside Protocol Configuration Options"
    );

    let control_fteid = reply
        .ie_instance(87, 1)
        .expect("an accepted Create Session Response carries the PGW's control F-TEID");
    assert_eq!(
        &control_fteid[1..5],
        &2596069104u32.to_be_bytes(),
        "the control F-TEID must carry the TEID the model assigned"
    );
    assert_eq!(
        control_fteid[0] & 0x3F,
        7,
        "interface type 7 is PGW S5/S8 GTP-C"
    );

    let bearer = reply
        .ie(93)
        .expect("an accepted Create Session Response carries a Bearer Context");
    let inner = parse_v2_ies(bearer);
    assert_eq!(
        inner
            .iter()
            .find(|(t, _, _)| *t == 73)
            .map(|(_, _, v)| v.clone()),
        Some(vec![5]),
        "the Bearer Context must name the EPS Bearer Identity from the request"
    );
    let bearer_fteid = inner
        .iter()
        .find(|(t, _, _)| *t == 87)
        .map(|(_, _, v)| v.clone())
        .expect("the Bearer Context must carry the user-plane F-TEID");
    assert_eq!(&bearer_fteid[1..5], &2596069105u32.to_be_bytes());
    assert_eq!(
        bearer_fteid[0] & 0x3F,
        5,
        "interface type 5 is PGW S5/S8 GTP-U"
    );

    // --- Refused -----------------------------------------------------------
    let reply = parse_v2(&exchange(&socket, control, &create_session("forbidden", 0x0A0B0D)).await);
    assert_eq!(reply.message_type, 33);
    assert_eq!(reply.sequence, 0x0A0B0D);
    assert_eq!(
        reply.ie(2),
        Some([77u8, 0].as_slice()),
        "GTPv2 cause 77 is Missing or unknown APN"
    );
    assert!(
        reply.ie(79).is_none(),
        "a refusal must not hand out an address"
    );
    assert!(
        reply.ie_instance(87, 1).is_none(),
        "a refusal must not hand out a tunnel endpoint"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    // `wait_for_mocks` only proves the model was *called*; `decision=` is written after its
    // answer is handled, so under a full-suite run at --test-threads=100 the line can still be
    // in flight here. Wait for the line itself. This does not weaken the negative assertion
    // below - giving model_reject time to appear gives fail_closed the same time.
    server.wait_for_any(&["decision=model_reject"], 30).await;
    assert!(
        server.output_contains("decision=model_reject").await,
        "a refusal the model chose must be logged as model_reject, never as a fail-closed one"
    );
    assert!(
        !server.output_contains("decision=fail_closed").await,
        "neither request should have reached the fail-closed path"
    );
    server.stop().await?;
    Ok(())
}

/// A datagram announcing a GTP version this server does not speak is answered mechanically
/// with Version Not Supported — no LLM call at all, because there is nothing to decide.
///
/// This is also the cheapest possible check that the socket is really bound and really
/// serving: it costs one datagram and zero model calls.
#[tokio::test]
async fn test_unsupported_version_is_answered_without_consulting_the_model() -> E2EResult<()> {
    let config = NetGetConfig::new("Start a GTP server on port {AVAILABLE_PORT}")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("GTP server")
                .and_instruction_containing("on port")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "gtp",
                    "startup_params": { "user_plane_port": 0 },
                    "instruction": "Act as a GGSN"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("GTP control plane receive loop started", 15)
        .await?;

    let control: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // Version 0 in the top three bits: GTPv0, which 3GPP withdrew.
    let v0 = vec![
        0x1E, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let reply = parse_v1(&exchange(&socket, control, &v0).await, false);
    assert_eq!(
        reply.message_type, 3,
        "TS 29.060 §11.1.1: an unsupported version is answered with Version Not Supported"
    );
    assert_eq!(
        reply.body,
        Vec::<u8>::new(),
        "Version Not Supported carries no information elements"
    );

    // The whole point: the model was consulted exactly once, at startup.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    assert!(
        !server.output_contains("gtp_echo_request").await,
        "a version this server cannot parse must not be turned into an event"
    );
    server.stop().await?;

    // Sanity: the hex helper this file uses is the one the assertions above depend on.
    assert_eq!(to_hex(&[0x0A, 0xFF]), "0aff");
    Ok(())
}

// ===========================================================================
// A sequence number the header cannot hold refuses the session, it does not wrap
// ===========================================================================

/// A model answer with a sequence number wider than the header field must **fail closed**,
/// and the refusal must be a refusing cause rather than a wrapped accept.
///
/// This is two properties in one exchange, and neither had a test.
///
/// The first is the narrowing cast. GTPv1's header sequence is 16 bits while the action's
/// `sequence` parameter is validated as a `u32`, so `sequence as u16` turned 70000 into
/// 4464 silently. That is worse than it sounds: the peer matches a response to its request
/// by sequence number, so a wrapped one is discarded and the request times out - a failure
/// that reads as a lost packet, sending whoever debugs it to the network rather than to the
/// field.
///
/// The second is `synthesised_refusal`, the protocol's most important safety property:
/// every path that cannot produce a real answer must still put a *refusing* cause on the
/// wire. The mock below asks for `request_accepted` and supplies every field an accepted
/// session needs; the only thing wrong with it is the sequence. If the bound were missing
/// the client would receive cause 128 and believe a session existed.
#[tokio::test]
async fn test_a_sequence_wider_than_the_header_field_fails_closed() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "Start a GTP server on port {AVAILABLE_PORT} acting as a GGSN for the internet APN",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_instruction_containing("GTP server")
            .and_instruction_containing("on port")
            .respond_with_actions(json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "gtp",
                "instruction": "Act as a GGSN for the internet APN"
            }]))
            .expect_calls(1)
            .and()
            // Everything here is a valid, accepting answer except the sequence: 70000 needs
            // 17 bits and the GTPv1 field has 16.
            .on_event("gtp_create_session_request")
            .respond_with_actions(json!([{
                "type": "send_gtp_create_session_response",
                "cause": "request_accepted",
                "sequence": 70000,
                "assigned_address": "10.45.0.2",
                "control_teid": 48879,
                "data_teid": 48880,
                "charging_id": 7
            }]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    server
        .wait_for_log("GTP control plane receive loop started", 15)
        .await?;

    let control: SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    let mut body = Vec::new();
    body.extend(tv(2, &tbcd(TEST_IMSI)));
    body.extend(tv(16, &0x1111_1111u32.to_be_bytes()));
    body.extend(tv(17, &0x2222_2222u32.to_be_bytes()));
    body.extend(tv(20, &[5]));
    body.extend(tlv(128, &[0xF1, 0x21]));
    body.extend(tlv(131, &apn_labels("internet")));
    body.extend(tlv(133, &[127, 0, 0, 1]));
    body.extend(tlv(133, &[127, 0, 0, 1]));

    let reply = parse_v1(
        &exchange(&socket, control, &v1_message(16, 0, 1, &body)).await,
        true,
    );

    assert_eq!(
        reply.message_type, 17,
        "the refusal must still be a Create PDP Context Response, not silence - a peer that \
         hears nothing retransmits rather than releasing the session"
    );
    assert_eq!(
        reply.sequence,
        Some(1),
        "the synthesised refusal must carry the request's own sequence, which is the one \
         value we know fits"
    );

    let cause = reply
        .ie(1)
        .expect("a Create PDP Context Response carries a Cause IE");
    assert_ne!(
        cause,
        [128u8].as_slice(),
        "cause 128 is Request accepted: the model's accepting answer must NOT have reached \
         the wire, because the sequence it came with could not be encoded"
    );
    assert!(
        !(128..=191).contains(&cause[0]),
        "GTPv1 causes 128-191 are the acceptance range (TS 29.060 §7.7.1); a synthesised \
         refusal must fall outside it, got {cause:?}"
    );
    assert_eq!(
        reply.u32_ie(17),
        None,
        "a refusal must not carry the control TEID the model tried to assign - a refusal \
         that hands out tunnel endpoints is an accept wearing a rejection's cause"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    // Wait for the line rather than checking once. The refusal reaches the socket
    // before the harness's reader task has necessarily drained the server's stdout into
    // `output_lines`, so a bare `output_contains` here is a race — green on a quiet
    // machine, intermittently red at `--test-threads=100`, and reproduced at unmodified
    // HEAD as often as anywhere else. This still asserts the line must appear; it only
    // stops asserting *when*.
    server
        .wait_for_log("decision=fail_closed", 20)
        .await
        .map_err(|e| {
            format!(
                "the fail-closed path must be recorded with its own decision token, because \
                 the wire cannot distinguish it from a refusal the model chose deliberately: {e}"
            )
        })?;
    server.stop().await?;
    Ok(())
}
