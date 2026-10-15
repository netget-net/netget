//! End-to-end DHCP tests for NetGet.
//!
//! Every reply is decoded by the RFC 2131 / RFC 2132 decoder in this file, which is written
//! from the wire format and deliberately does **not** use `dhcproto` — the codec the server
//! encodes with. Using the same library on both sides would hide any bug in it, and a DHCP
//! client on the other end of the wire is a decoder like this one, not a shared codec.
//!
//! There is no usable real DHCP client to point at these servers: `dhclient`/`ipconfig` bind
//! UDP/68, need root, and cannot be aimed at an ephemeral port on loopback. So the peer here
//! is an independent implementation of the packet format rather than a real binary.


use super::super::super::helpers::{self, E2EResult};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// RFC 2132 option codes
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS_SERVERS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_MESSAGE: u8 = 56;
const OPT_END: u8 = 255;

// RFC 2131 message types (option 53)
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;

const CLIENT_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Build a BOOTREQUEST carrying the given DHCP message type, per RFC 2131 section 2.
fn build_request(msg_type: u8, xid: u32, options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut packet = vec![0u8; 240];

    packet[0] = 1; // op: BOOTREQUEST
    packet[1] = 1; // htype: Ethernet
    packet[2] = 6; // hlen
    packet[3] = 0; // hops
    packet[4..8].copy_from_slice(&xid.to_be_bytes());
    packet[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
    packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
                                                              // ciaddr/yiaddr/siaddr/giaddr stay 0.0.0.0
    packet[28..34].copy_from_slice(&CLIENT_MAC);
    packet[236..240].copy_from_slice(&MAGIC_COOKIE);

    packet.push(OPT_MESSAGE_TYPE);
    packet.push(1);
    packet.push(msg_type);

    for (code, value) in options {
        packet.push(*code);
        packet.push(value.len() as u8);
        packet.extend_from_slice(value);
    }

    packet.push(OPT_END);

    // Real clients pad to the 300-byte BOOTP minimum.
    while packet.len() < 300 {
        packet.push(0);
    }

    packet
}

/// A decoded BOOTP/DHCP message.
#[derive(Debug)]
struct DhcpMessage {
    op: u8,
    htype: u8,
    hlen: u8,
    xid: u32,
    flags: u16,
    yiaddr: Ipv4Addr,
    chaddr: Vec<u8>,
    options: HashMap<u8, Vec<u8>>,
}

impl DhcpMessage {
    /// Decode straight from the wire format (RFC 2131 section 2, RFC 2132 section 2).
    fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 240 {
            return Err(format!(
                "reply is {} bytes, shorter than the 240-byte BOOTP header + magic cookie",
                data.len()
            ));
        }
        if data[236..240] != MAGIC_COOKIE {
            return Err(format!(
                "reply has no DHCP magic cookie at bytes 236..240, got {:02x?}",
                &data[236..240]
            ));
        }

        let hlen = data[2];
        if hlen as usize > 16 {
            return Err(format!("reply declares hlen {} (max 16)", hlen));
        }

        let mut options: HashMap<u8, Vec<u8>> = HashMap::new();
        let mut offset = 240;
        loop {
            if offset >= data.len() {
                return Err("options ran off the end of the datagram without an End option".into());
            }
            let code = data[offset];
            if code == OPT_END {
                break;
            }
            if code == 0 {
                // Pad
                offset += 1;
                continue;
            }
            if offset + 1 >= data.len() {
                return Err(format!("option {} has no length byte", code));
            }
            let len = data[offset + 1] as usize;
            if offset + 2 + len > data.len() {
                return Err(format!(
                    "option {} declares {} bytes but only {} remain",
                    code,
                    len,
                    data.len() - offset - 2
                ));
            }
            options.insert(code, data[offset + 2..offset + 2 + len].to_vec());
            offset += 2 + len;
        }

        Ok(DhcpMessage {
            op: data[0],
            htype: data[1],
            hlen,
            xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            flags: u16::from_be_bytes([data[10], data[11]]),
            yiaddr: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            chaddr: data[28..28 + hlen as usize].to_vec(),
            options,
        })
    }

    fn message_type(&self) -> Option<u8> {
        self.options
            .get(&OPT_MESSAGE_TYPE)
            .and_then(|v| v.first())
            .copied()
    }

    fn ipv4_option(&self, code: u8) -> Option<Ipv4Addr> {
        let v = self.options.get(&code)?;
        if v.len() < 4 {
            return None;
        }
        Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
    }

    fn u32_option(&self, code: u8) -> Option<u32> {
        let v = self.options.get(&code)?;
        if v.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    fn string_option(&self, code: u8) -> Option<String> {
        self.options
            .get(&code)
            .map(|v| String::from_utf8_lossy(v).to_string())
    }

    /// Fields RFC 2131 section 4.1 requires every server reply to echo from the request.
    fn assert_echoes_request(&self, xid: u32) {
        assert_eq!(
            self.op, 2,
            "reply op must be BOOTREPLY (2), got {}",
            self.op
        );
        assert_eq!(self.htype, 1, "reply htype must be 1 (Ethernet)");
        assert_eq!(self.hlen, 6, "reply hlen must be 6");
        assert_eq!(
            self.xid, xid,
            "reply xid 0x{:08x} does not match the request's 0x{:08x}; a client silently \
             discards a reply whose transaction id differs",
            self.xid, xid
        );
        assert_eq!(
            self.chaddr, CLIENT_MAC,
            "reply chaddr must echo the client hardware address"
        );
        assert_eq!(
            self.flags & 0x8000,
            0x8000,
            "the request set the broadcast flag, so RFC 2131 4.1 requires the reply to set it too"
        );
    }
}

/// Send one datagram and decode the reply, failing the test on timeout.
async fn exchange(
    socket: &UdpSocket,
    server_addr: std::net::SocketAddr,
    packet: &[u8],
    what: &str,
) -> DhcpMessage {
    socket
        .send_to(packet, server_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to send {}: {}", what, e));

    let mut buffer = vec![0u8; 1500];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buffer))
        .await
        .unwrap_or_else(|_| panic!("no reply to {} within 10s", what))
        .unwrap_or_else(|e| panic!("socket error awaiting reply to {}: {}", what, e));

    // The pcap oracle. `src/server/dhcp/CLAUDE.md` records that no real DHCP client
    // can be pointed at this server — dhclient and ipconfig bind UDP/68, need root and
    // cannot target an ephemeral loopback port — so the only independent reading of
    // RFC 2131 in this suite is `DhcpMessage::decode` below, which is an in-test
    // decoder written by the same hand as the test. Wireshark's `dhcp` dissector is
    // the genuinely independent one: it checks the magic cookie, walks the option list
    // by code-and-length to the End option, and reports an option whose length runs
    // past the datagram. That is the closest this protocol can get to a third-party
    // peer, and it costs a line.
    crate::helpers::pcap_oracle::PcapOracle::udp("dhcp")
        .to_server(packet)
        .from_server(&buffer[..n])
        .assert_clean();

    DhcpMessage::decode(&buffer[..n])
        .unwrap_or_else(|e| panic!("reply to {} is not a valid DHCP message: {}", what, e))
}

/// Assert that nothing arrives on the socket within `secs`.
async fn expect_no_reply(socket: &UdpSocket, secs: u64, what: &str) {
    let mut buffer = vec![0u8; 1500];
    if let Ok(Ok((n, from))) =
        tokio::time::timeout(Duration::from_secs(secs), socket.recv_from(&mut buffer)).await
    {
        panic!(
            "expected no reply to {}, but got {} bytes from {}: {:02x?}",
            what,
            n,
            from,
            &buffer[..n.min(64)]
        );
    }
}

/// DISCOVER → OFFER, REQUEST → ACK, and a malformed datagram in between.
///
/// One server handles all of it: 1 startup call + 2 DISCOVERs + 1 REQUEST = 4 LLM calls.
#[tokio::test]
async fn test_dhcp_discover_offer_and_request_ack() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dhcp. Offer and assign 192.168.1.100 \
        with subnet mask 255.255.255.0, gateway 192.168.1.1, DNS 8.8.8.8 and 9.9.9.9, \
        lease time 86400 seconds, server identifier 127.0.0.1";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCP",
                        "instruction": "DHCP server: OFFER on DISCOVER, ACK on REQUEST"
                    }
                ]))
                .expect_calls(1)
                .and()
                // dhcproto spells message types in PascalCase ("Discover", not "DISCOVER").
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "Discover")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_offer",
                        "offered_ip": "192.168.1.100",
                        "server_ip": "127.0.0.1",
                        "subnet_mask": "255.255.255.0",
                        "router": "192.168.1.1",
                        "dns_servers": ["8.8.8.8", "9.9.9.9"],
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(2)
                .and()
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "Request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_ack",
                        "assigned_ip": "192.168.1.100",
                        "server_ip": "127.0.0.1",
                        "subnet_mask": "255.255.255.0",
                        "router": "192.168.1.1",
                        "dns_servers": ["8.8.8.8", "9.9.9.9"],
                        "lease_time": 86400
                    }
                ]))
                .expect_calls(1)
                .and()
                // A datagram the server cannot decode must never reach the model: the event
                // would carry "unknown" in every field and no reply could be built from it.
                // This rule exists to fail the run if such a call is ever made.
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "unknown")
                .respond_with_actions(serde_json::json!([{"type": "ignore_request"}]))
                .expect_calls(0)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // ---- DISCOVER → OFFER -------------------------------------------------------------
    let discover_xid = 0x12345678u32;
    let offer = exchange(
        &socket,
        server_addr,
        &build_request(DHCP_DISCOVER, discover_xid, &[]),
        "DISCOVER",
    )
    .await;

    offer.assert_echoes_request(discover_xid);
    assert_eq!(
        offer.message_type(),
        Some(DHCP_OFFER),
        "DISCOVER must be answered with option 53 = DHCPOFFER (2), got {:?}",
        offer.message_type()
    );
    assert_eq!(
        offer.yiaddr,
        Ipv4Addr::new(192, 168, 1, 100),
        "yiaddr must carry the offered address"
    );
    assert_eq!(
        offer.ipv4_option(OPT_SUBNET_MASK),
        Some(Ipv4Addr::new(255, 255, 255, 0)),
        "option 1 (subnet mask)"
    );
    assert_eq!(
        offer.ipv4_option(OPT_ROUTER),
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        "option 3 (router)"
    );
    assert_eq!(
        offer.options.get(&OPT_DNS_SERVERS).map(|v| v.as_slice()),
        Some([8, 8, 8, 8, 9, 9, 9, 9].as_slice()),
        "option 6 must carry both DNS servers, in order"
    );
    assert_eq!(
        offer.u32_option(OPT_LEASE_TIME),
        Some(86400),
        "option 51 (lease time)"
    );
    assert_eq!(
        offer.ipv4_option(OPT_SERVER_ID),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
        "RFC 2131 table 3 requires option 54 (server identifier) in a DHCPOFFER; a client \
         addresses its REQUEST with it"
    );

    // ---- REQUEST → ACK ----------------------------------------------------------------
    let request_xid = 0x87654321u32;
    let ack = exchange(
        &socket,
        server_addr,
        &build_request(
            DHCP_REQUEST,
            request_xid,
            &[
                (OPT_REQUESTED_IP, vec![192, 168, 1, 100]),
                (OPT_SERVER_ID, vec![127, 0, 0, 1]),
            ],
        ),
        "REQUEST",
    )
    .await;

    ack.assert_echoes_request(request_xid);
    assert_eq!(
        ack.message_type(),
        Some(DHCP_ACK),
        "REQUEST must be answered with option 53 = DHCPACK (5), got {:?}",
        ack.message_type()
    );
    assert_eq!(
        ack.yiaddr,
        Ipv4Addr::new(192, 168, 1, 100),
        "the ACK must assign the address the client requested"
    );
    assert_eq!(
        ack.ipv4_option(OPT_SERVER_ID),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
        "option 54 (server identifier) is required in a DHCPACK too"
    );
    assert_eq!(ack.u32_option(OPT_LEASE_TIME), Some(86400));

    // ---- A malformed datagram must be dropped, not forwarded to the model -------------
    // hlen = 0xff is the shape that panics inside dhcproto's `Message::chaddr()`.
    let mut malformed = build_request(DHCP_DISCOVER, 0xdeadbeef, &[]);
    malformed[2] = 0xff;
    socket.send_to(&malformed, server_addr).await?;
    expect_no_reply(&socket, 2, "a datagram with hlen=255").await;

    // ---- The server survived it and still answers -------------------------------------
    let after_xid = 0x0badf00du32;
    let offer2 = exchange(
        &socket,
        server_addr,
        &build_request(DHCP_DISCOVER, after_xid, &[]),
        "the DISCOVER following the malformed datagram",
    )
    .await;
    offer2.assert_echoes_request(after_xid);
    assert_eq!(
        offer2.message_type(),
        Some(DHCP_OFFER),
        "the server must keep serving after dropping a malformed datagram"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A REQUEST the model rejects must produce a DHCPNAK, not a silent drop and not an ACK.
///
/// 1 startup call + 1 REQUEST = 2 LLM calls.
#[tokio::test]
async fn test_dhcp_nak_rejects_request() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dhcp. Reject every REQUEST with a NAK \
        saying 'Address not on this network'";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcp")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCP",
                        "instruction": "DHCP server that NAKs every REQUEST"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("dhcp_request")
                .and_event_data_contains("message_type", "Request")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_dhcp_nak",
                        "server_ip": "127.0.0.1",
                        "message": "Address not on this network"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", server.port).parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    let xid = 0x0000abcdu32;
    let nak = exchange(
        &socket,
        server_addr,
        &build_request(DHCP_REQUEST, xid, &[(OPT_REQUESTED_IP, vec![10, 0, 0, 5])]),
        "REQUEST for an address the server rejects",
    )
    .await;

    nak.assert_echoes_request(xid);
    assert_eq!(
        nak.message_type(),
        Some(DHCP_NAK),
        "a rejected REQUEST must be answered with option 53 = DHCPNAK (6), got {:?}",
        nak.message_type()
    );
    assert_eq!(
        nak.yiaddr,
        Ipv4Addr::UNSPECIFIED,
        "RFC 2131 table 3: yiaddr must be zero in a DHCPNAK"
    );
    assert!(
        !nak.options.contains_key(&OPT_LEASE_TIME),
        "RFC 2131 table 3: a DHCPNAK must not carry option 51 (lease time)"
    );
    assert_eq!(
        nak.string_option(OPT_MESSAGE).as_deref(),
        Some("Address not on this network"),
        "option 56 must carry the reason the model gave"
    );
    assert_eq!(
        nak.ipv4_option(OPT_SERVER_ID),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
        "option 54 (server identifier) is required in a DHCPNAK"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
