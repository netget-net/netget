//! End-to-end DHCPv6 (RFC 8415) tests for NetGet.
//!
//! The client half is written from the wire format **in this file** and deliberately does not
//! use `dhcproto`, which is the codec the server encodes with. Encoding and decoding with the
//! same library on both sides proves only that it round-trips with itself; a real DHCPv6 client
//! is an independent decoder like this one.
//!
//! There is no usable real DHCPv6 client to point at these servers. `dhclient -6`, `dhcpcd` and
//! `odhcp6c` bind UDP/546, need root, and drive a kernel interface rather than an ephemeral
//! loopback port; macOS ships no DHCPv6 client binary at all (`ipconfig` asks configd to run
//! DHCPv6 on a real interface). So the peer here is an independent reading of the spec, not an
//! independent implementation — which is why the protocol is rated Experimental.

use super::super::super::helpers::{self, E2EResult};
use std::net::Ipv6Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

// RFC 8415 §7.3 message types
const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_CONFIRM: u8 = 4;
const MSG_REPLY: u8 = 7;
const MSG_RELEASE: u8 = 8;
const MSG_INFORMATION_REQUEST: u8 = 11;

// RFC 8415 §21 option codes
const OPT_CLIENT_ID: u16 = 1;
const OPT_SERVER_ID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IA_ADDR: u16 = 5;
const OPT_ORO: u16 = 6;
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_DOMAIN_SEARCH: u16 = 24;
const OPT_IA_PD: u16 = 25;
const OPT_IA_PREFIX: u16 = 26;

/// DUID-LL (type 3) over Ethernet (hardware type 1) for MAC 00:11:22:33:44:55.
const CLIENT_DUID: [u8; 10] = [0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// The DUID NetGet uses when the model does not supply one: DUID-EN (type 2) carrying IANA's
/// reserved documentation enterprise number 32473 (0x7ED9) and the identifier `netget`.
///
/// Asserted rather than merely tolerated. A client sends its REQUEST to the Server Identifier
/// it saw in the ADVERTISE and rejects a REPLY carrying a different one, so this value has to
/// be stable across two model calls that share no state.
const DEFAULT_SERVER_DUID: [u8; 12] = [
    0x00, 0x02, 0x00, 0x00, 0x7E, 0xD9, b'n', b'e', b't', b'g', b'e', b't',
];

const CLIENT_IAID: u32 = 0x2701_C0FF;
const CLIENT_PD_IAID: u32 = 0x51EB_0001;

// ============================================================================
// An independent RFC 8415 codec
// ============================================================================

/// `option-code | option-len | option-data`, RFC 8415 §21.1.
fn option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// IA_NA / IA_PD share a layout: `IAID | T1 | T2 | encapsulated options`.
fn identity_association(code: u16, iaid: u32, t1: u32, t2: u32, sub_options: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&iaid.to_be_bytes());
    data.extend_from_slice(&t1.to_be_bytes());
    data.extend_from_slice(&t2.to_be_bytes());
    data.extend_from_slice(sub_options);
    option(code, &data)
}

/// IA Address, RFC 8415 §21.6: `address | preferred | valid | options`.
fn ia_addr_option(addr: Ipv6Addr, preferred: u32, valid: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&addr.octets());
    data.extend_from_slice(&preferred.to_be_bytes());
    data.extend_from_slice(&valid.to_be_bytes());
    option(OPT_IA_ADDR, &data)
}

fn oro_option(codes: &[u16]) -> Vec<u8> {
    let mut data = Vec::with_capacity(codes.len() * 2);
    for code in codes {
        data.extend_from_slice(&code.to_be_bytes());
    }
    option(OPT_ORO, &data)
}

/// `msg-type | transaction-id (THREE octets) | options`, RFC 8415 §8.
fn build_message(msg_type: u8, xid: [u8; 3], options: &[Vec<u8>]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(msg_type);
    packet.extend_from_slice(&xid);
    for opt in options {
        packet.extend_from_slice(opt);
    }
    packet
}

/// Walk a `code | len | data` option stream, rejecting anything truncated.
fn parse_options(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if offset + 4 > data.len() {
            return Err(format!(
                "option header at byte {} is truncated ({} bytes left)",
                offset,
                data.len() - offset
            ));
        }
        let code = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        if offset + 4 + len > data.len() {
            return Err(format!(
                "option {} declares {} bytes but only {} remain",
                code,
                len,
                data.len() - offset - 4
            ));
        }
        out.push((code, data[offset + 4..offset + 4 + len].to_vec()));
        offset += 4 + len;
    }
    Ok(out)
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn read_ipv6(data: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&data[at..at + 16]);
    Ipv6Addr::from(octets)
}

#[derive(Debug, PartialEq, Eq)]
struct IaAddress {
    address: Ipv6Addr,
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct IaPrefix {
    prefix: Ipv6Addr,
    prefix_length: u8,
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

#[derive(Debug)]
struct IdentityAssociation {
    iaid: u32,
    t1: u32,
    t2: u32,
    addresses: Vec<IaAddress>,
    prefixes: Vec<IaPrefix>,
}

#[derive(Debug)]
struct Dhcpv6Message {
    msg_type: u8,
    xid: [u8; 3],
    options: Vec<(u16, Vec<u8>)>,
}

impl Dhcpv6Message {
    fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err(format!(
                "reply is {} bytes, shorter than the 4-byte DHCPv6 header",
                data.len()
            ));
        }
        Ok(Dhcpv6Message {
            msg_type: data[0],
            xid: [data[1], data[2], data[3]],
            options: parse_options(&data[4..])?,
        })
    }

    fn first(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    fn has(&self, code: u16) -> bool {
        self.options.iter().any(|(c, _)| *c == code)
    }

    /// Decode an IA_NA or IA_PD together with the addresses/prefixes it encapsulates.
    fn identity_association(&self, code: u16) -> Option<IdentityAssociation> {
        let data = self.first(code)?;
        assert!(
            data.len() >= 12,
            "option {} is {} bytes; IAID + T1 + T2 alone is 12",
            code,
            data.len()
        );
        let sub = parse_options(&data[12..]).unwrap_or_else(|e| {
            panic!(
                "option {} has a malformed encapsulated option list: {}",
                code, e
            )
        });

        let mut addresses = Vec::new();
        let mut prefixes = Vec::new();
        for (sub_code, sub_data) in &sub {
            match *sub_code {
                OPT_IA_ADDR => {
                    assert!(
                        sub_data.len() >= 24,
                        "IA Address is {} bytes; RFC 8415 §21.6 needs at least 24",
                        sub_data.len()
                    );
                    addresses.push(IaAddress {
                        address: read_ipv6(sub_data, 0),
                        preferred_lifetime: read_u32(sub_data, 16),
                        valid_lifetime: read_u32(sub_data, 20),
                    });
                }
                OPT_IA_PREFIX => {
                    assert!(
                        sub_data.len() >= 25,
                        "IA Prefix is {} bytes; RFC 8415 §21.22 needs at least 25",
                        sub_data.len()
                    );
                    prefixes.push(IaPrefix {
                        preferred_lifetime: read_u32(sub_data, 0),
                        valid_lifetime: read_u32(sub_data, 4),
                        prefix_length: sub_data[8],
                        prefix: read_ipv6(sub_data, 9),
                    });
                }
                _ => {}
            }
        }

        Some(IdentityAssociation {
            iaid: read_u32(data, 0),
            t1: read_u32(data, 4),
            t2: read_u32(data, 8),
            addresses,
            prefixes,
        })
    }

    fn dns_servers(&self) -> Vec<Ipv6Addr> {
        let Some(data) = self.first(OPT_DNS_SERVERS) else {
            return Vec::new();
        };
        assert_eq!(
            data.len() % 16,
            0,
            "option 23 is {} bytes, which is not a whole number of IPv6 addresses",
            data.len()
        );
        (0..data.len() / 16)
            .map(|i| read_ipv6(data, i * 16))
            .collect()
    }

    /// Decode option 24 as the sequence of RFC 1035 wire-format names it is, compression
    /// pointers included — a real client has to handle them, so this decoder does too.
    fn domain_search(&self) -> Vec<String> {
        let Some(data) = self.first(OPT_DOMAIN_SEARCH) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let (name, next) = decode_name(data, offset, 0)
                .unwrap_or_else(|e| panic!("option 24 is not a valid name list: {}", e));
            if !name.is_empty() {
                names.push(name);
            }
            assert!(
                next > offset,
                "name decoding made no progress at byte {}",
                offset
            );
            offset = next;
        }
        names
    }

    fn status_code(&self) -> Option<(u16, String)> {
        let data = self.first(OPT_STATUS_CODE)?;
        assert!(
            data.len() >= 2,
            "option 13 is {} bytes; the status code alone is 2",
            data.len()
        );
        Some((
            u16::from_be_bytes([data[0], data[1]]),
            String::from_utf8_lossy(&data[2..]).to_string(),
        ))
    }

    /// What RFC 8415 §16 requires of every server message: the client's own transaction id,
    /// the Client Identifier it sent, and a Server Identifier. A client silently drops
    /// anything else, so a mismatch here would present as a timeout, never as an error.
    fn assert_echoes_request(&self, xid: [u8; 3]) {
        assert_eq!(
            self.xid, xid,
            "reply transaction id {:02x?} does not match the request's {:02x?}; a client \
             silently discards a message whose id differs",
            self.xid, xid
        );
        assert_eq!(
            self.first(OPT_CLIENT_ID),
            Some(CLIENT_DUID.as_slice()),
            "RFC 8415 §16.10: the reply must carry back the client's own DUID (option 1)"
        );
        assert_eq!(
            self.first(OPT_SERVER_ID),
            Some(DEFAULT_SERVER_DUID.as_slice()),
            "the reply must identify the server (option 2), and with no server_duid given that \
             is NetGet's stable placeholder DUID-EN"
        );
    }
}

/// One RFC 1035 name; returns the name and the offset just past it.
fn decode_name(data: &[u8], mut offset: usize, depth: usize) -> Result<(String, usize), String> {
    if depth > 8 {
        return Err("compression pointers nested more than 8 deep".into());
    }
    let mut labels: Vec<String> = Vec::new();
    loop {
        if offset >= data.len() {
            return Err(format!("name ran off the end at byte {}", offset));
        }
        let len = data[offset];
        if len == 0 {
            return Ok((labels.join("."), offset + 1));
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return Err("truncated compression pointer".into());
            }
            let target = (((len & 0x3F) as usize) << 8) | data[offset + 1] as usize;
            let (suffix, _) = decode_name(data, target, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            return Ok((labels.join("."), offset + 2));
        }
        let start = offset + 1;
        let end = start + len as usize;
        if end > data.len() {
            return Err(format!("label at byte {} runs off the end", offset));
        }
        labels.push(String::from_utf8_lossy(&data[start..end]).to_string());
        offset = end;
    }
}

// ============================================================================
// Wire helpers
// ============================================================================

async fn exchange(
    socket: &UdpSocket,
    server_addr: std::net::SocketAddr,
    packet: &[u8],
    what: &str,
) -> Dhcpv6Message {
    socket
        .send_to(packet, server_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to send {}: {}", what, e));

    let mut buffer = vec![0u8; 1500];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buffer))
        .await
        .unwrap_or_else(|_| panic!("no reply to {} within 15s", what))
        .unwrap_or_else(|e| panic!("socket error awaiting reply to {}: {}", what, e));

    Dhcpv6Message::decode(&buffer[..n])
        .unwrap_or_else(|e| panic!("reply to {} is not a valid DHCPv6 message: {}", what, e))
}

/// Assert nothing arrives within `secs`. This is the assertion the fail-closed rule needs:
/// "sent nothing" is only visible as an absence.
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

async fn client_socket() -> E2EResult<UdpSocket> {
    Ok(UdpSocket::bind("[::1]:0").await?)
}

// ============================================================================
// Tests
// ============================================================================

/// The core four-message exchange, with prefix delegation alongside the address, then the
/// RELEASE that gives the lease back.
///
/// 1 startup call + 1 SOLICIT + 1 REQUEST + 1 RELEASE = 4 LLM calls.
#[tokio::test]
async fn test_dhcpv6_solicit_advertise_request_reply() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dhcpv6. Advertise and assign \
        2001:db8:1::100 with a 3600 second preferred and 7200 second valid lifetime, delegate \
        2001:db8:100::/56, DNS 2001:4860:4860::8888, search domain lab.example.com";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcpv6")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCPv6",
                        "instruction": "DHCPv6 server: ADVERTISE on SOLICIT, REPLY on REQUEST"
                    }
                ]))
                .expect_calls(1)
                .and()
                // The transaction id is echoed here explicitly, from the event, which is what
                // exercises the `transaction_id` override. The REQUEST rule below omits it and
                // exercises the automatic echo from the per-datagram request context. Both
                // replies are asserted against the id the client actually sent.
                .on_event("dhcpv6_solicit")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dhcpv6_advertise",
                        "transaction_id": e["transaction_id"],
                        "addresses": [{
                            "address": "2001:db8:1::100",
                            "preferred_lifetime": 3600,
                            "valid_lifetime": 7200
                        }],
                        "prefixes": [{
                            "prefix": "2001:db8:100::",
                            "prefix_length": 56,
                            "preferred_lifetime": 3600,
                            "valid_lifetime": 7200
                        }],
                        "dns_servers": ["2001:4860:4860::8888"],
                        "domain_search": ["lab.example.com"],
                        "t1": 1800,
                        "t2": 2880,
                        "preference": 255
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dhcpv6_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_dhcpv6_reply",
                    "addresses": [{
                        "address": "2001:db8:1::100",
                        "preferred_lifetime": 3600,
                        "valid_lifetime": 7200
                    }],
                    "prefixes": [{
                        "prefix": "2001:db8:100::",
                        "prefix_length": 56,
                        "preferred_lifetime": 3600,
                        "valid_lifetime": 7200
                    }],
                    "dns_servers": ["2001:4860:4860::8888"],
                    "domain_search": ["lab.example.com"],
                    "t1": 1800,
                    "t2": 2880
                }]))
                .expect_calls(1)
                .and()
                .on_event("dhcpv6_release")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_dhcpv6_reply",
                    "status_code": {"code": "Success", "message": "Lease released"}
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("[::1]:{}", server.port).parse()?;
    let socket = client_socket().await?;

    // ---- SOLICIT → ADVERTISE ----------------------------------------------------------
    let solicit_xid = [0x10, 0x08, 0x74];
    let solicit = build_message(
        MSG_SOLICIT,
        solicit_xid,
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            oro_option(&[OPT_DNS_SERVERS, OPT_DOMAIN_SEARCH]),
            identity_association(OPT_IA_NA, CLIENT_IAID, 0, 0, &[]),
            identity_association(OPT_IA_PD, CLIENT_PD_IAID, 0, 0, &[]),
        ],
    );

    let advertise = exchange(&socket, server_addr, &solicit, "SOLICIT").await;

    assert_eq!(
        advertise.msg_type, MSG_ADVERTISE,
        "a SOLICIT with no Rapid Commit must be answered with ADVERTISE (2), got {}",
        advertise.msg_type
    );
    advertise.assert_echoes_request(solicit_xid);

    let ia = advertise
        .identity_association(OPT_IA_NA)
        .expect("the ADVERTISE must carry an IA_NA (option 3) holding the offered address");
    assert_eq!(
        ia.iaid, CLIENT_IAID,
        "the IA_NA must use the IAID the client sent; a client ignores addresses offered under \
         an identity association it never asked about"
    );
    assert_eq!((ia.t1, ia.t2), (1800, 2880), "T1/T2 from the model");
    assert_eq!(
        ia.addresses,
        vec![IaAddress {
            address: "2001:db8:1::100".parse::<Ipv6Addr>()?,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        }],
        "IA Address (option 5) with the lifetimes the model gave"
    );

    let pd = advertise
        .identity_association(OPT_IA_PD)
        .expect("the client sent an IA_PD, so the delegated prefix belongs in one (option 25)");
    assert_eq!(
        pd.iaid, CLIENT_PD_IAID,
        "the IA_PD must use the client's IAID"
    );
    assert_eq!(
        pd.prefixes,
        vec![IaPrefix {
            prefix: "2001:db8:100::".parse::<Ipv6Addr>()?,
            prefix_length: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        }],
        "IA Prefix (option 26)"
    );

    assert_eq!(
        advertise.dns_servers(),
        vec!["2001:4860:4860::8888".parse::<Ipv6Addr>()?],
        "option 23 (DNS Recursive Name Server), which the client's ORO asked for"
    );
    assert_eq!(
        advertise.domain_search(),
        vec!["lab.example.com".to_string()],
        "option 24 (Domain Search List)"
    );
    assert_eq!(
        advertise.first(7),
        Some([255u8].as_slice()),
        "option 7 (Preference) must carry the value the model chose"
    );
    assert!(
        !advertise.has(OPT_RAPID_COMMIT),
        "the client did not ask for Rapid Commit, so option 14 must not appear"
    );

    // ---- REQUEST → REPLY --------------------------------------------------------------
    let request_xid = [0x49, 0x17, 0x4e];
    let request = build_message(
        MSG_REQUEST,
        request_xid,
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_SERVER_ID, &DEFAULT_SERVER_DUID),
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            oro_option(&[OPT_DNS_SERVERS, OPT_DOMAIN_SEARCH]),
            identity_association(
                OPT_IA_NA,
                CLIENT_IAID,
                0,
                0,
                &ia_addr_option("2001:db8:1::100".parse()?, 3600, 7200),
            ),
            identity_association(OPT_IA_PD, CLIENT_PD_IAID, 0, 0, &[]),
        ],
    );

    let reply = exchange(&socket, server_addr, &request, "REQUEST").await;

    assert_eq!(
        reply.msg_type, MSG_REPLY,
        "a REQUEST must be answered with REPLY (7), got {}",
        reply.msg_type
    );
    // The Server Identifier is asserted inside this call, and it matters here specifically:
    // the client addressed its REQUEST to the DUID it saw in the ADVERTISE and rejects a REPLY
    // carrying a different one. NetGet holds no state between the two model calls, so the
    // default DUID being constant is what makes the exchange complete at all.
    reply.assert_echoes_request(request_xid);
    assert_eq!(
        advertise.first(OPT_SERVER_ID),
        reply.first(OPT_SERVER_ID),
        "the ADVERTISE and the REPLY must claim the same server identity"
    );

    let ia = reply
        .identity_association(OPT_IA_NA)
        .expect("the REPLY must confirm the address in an IA_NA");
    assert_eq!(ia.iaid, CLIENT_IAID);
    assert_eq!(
        ia.addresses,
        vec![IaAddress {
            address: "2001:db8:1::100".parse::<Ipv6Addr>()?,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        }],
        "the REPLY must confirm the address that was advertised"
    );
    assert_eq!(
        reply.dns_servers(),
        vec!["2001:4860:4860::8888".parse::<Ipv6Addr>()?]
    );

    // ---- RELEASE → REPLY with a Success status code ------------------------------------
    //
    // RFC 8415 §18.3.7 requires a Reply to a Release, and the status code is the whole content
    // of it. This is also the only place a status code is a *correct* thing for this server to
    // send: it is a statement about the client's lease, never about NetGet's health.
    let release_xid = [0x5e, 0x1e, 0xa5];
    let release = build_message(
        MSG_RELEASE,
        release_xid,
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_SERVER_ID, &DEFAULT_SERVER_DUID),
            identity_association(
                OPT_IA_NA,
                CLIENT_IAID,
                0,
                0,
                &ia_addr_option("2001:db8:1::100".parse()?, 3600, 7200),
            ),
        ],
    );

    let release_reply = exchange(&socket, server_addr, &release, "RELEASE").await;
    assert_eq!(release_reply.msg_type, MSG_REPLY);
    release_reply.assert_echoes_request(release_xid);
    assert_eq!(
        release_reply.status_code(),
        Some((0, "Lease released".to_string())),
        "option 13 must carry Success (0) and the model's message"
    );
    assert!(
        !release_reply.has(OPT_IA_NA),
        "the model sent no addresses, so no IA_NA should be fabricated for the acknowledgement"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The Rapid Commit two-message exchange, and the stateless INFORMATION-REQUEST.
///
/// 1 startup call + 1 SOLICIT + 1 INFORMATION-REQUEST = 3 LLM calls.
#[tokio::test]
async fn test_dhcpv6_rapid_commit_and_information_request() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via dhcpv6. Honour Rapid Commit by replying \
        immediately with 2001:db8:2::50, and answer INFORMATION-REQUEST with DNS only";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcpv6")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCPv6",
                        "instruction": "DHCPv6 server honouring Rapid Commit"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("dhcpv6_solicit")
                .and_event_data_contains("rapid_commit", "true")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "send_dhcpv6_reply",
                        "transaction_id": e["transaction_id"],
                        "rapid_commit": true,
                        "addresses": [{
                            "address": "2001:db8:2::50",
                            "preferred_lifetime": 600,
                            "valid_lifetime": 900
                        }]
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dhcpv6_information_request")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_dhcpv6_reply",
                    "dns_servers": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
                    "domain_search": ["lab.example.com", "corp.example.net"]
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("[::1]:{}", server.port).parse()?;
    let socket = client_socket().await?;

    // ---- SOLICIT with Rapid Commit → REPLY (no ADVERTISE at all) -----------------------
    let solicit_xid = [0x00, 0x00, 0x07];
    let solicit = build_message(
        MSG_SOLICIT,
        solicit_xid,
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_RAPID_COMMIT, &[]),
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            identity_association(OPT_IA_NA, CLIENT_IAID, 0, 0, &[]),
        ],
    );

    let reply = exchange(&socket, server_addr, &solicit, "SOLICIT with Rapid Commit").await;

    assert_eq!(
        reply.msg_type, MSG_REPLY,
        "a SOLICIT carrying Rapid Commit is answered with REPLY (7), not ADVERTISE; got {}",
        reply.msg_type
    );
    reply.assert_echoes_request(solicit_xid);
    assert!(
        reply.has(OPT_RAPID_COMMIT),
        "RFC 8415 §21.14: the REPLY that replaces an ADVERTISE must carry option 14, which is \
         what tells the client the assignment is committed"
    );
    assert_eq!(
        reply.first(OPT_RAPID_COMMIT),
        Some([].as_slice()),
        "option 14 has no data"
    );

    let ia = reply
        .identity_association(OPT_IA_NA)
        .expect("the rapid-commit REPLY must carry the assigned address");
    assert_eq!(
        ia.addresses,
        vec![IaAddress {
            address: "2001:db8:2::50".parse::<Ipv6Addr>()?,
            preferred_lifetime: 600,
            valid_lifetime: 900,
        }]
    );

    // ---- INFORMATION-REQUEST → REPLY with configuration only ---------------------------
    //
    // No Client Identifier: RFC 8415 §18.2.6 makes it optional here, and a server that only
    // works when it is present would fail against a real stateless client.
    let info_xid = [0xab, 0xcd, 0xef];
    let info_request = build_message(
        MSG_INFORMATION_REQUEST,
        info_xid,
        &[
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            oro_option(&[OPT_DNS_SERVERS, OPT_DOMAIN_SEARCH]),
        ],
    );

    let info_reply = exchange(&socket, server_addr, &info_request, "INFORMATION-REQUEST").await;

    assert_eq!(info_reply.msg_type, MSG_REPLY);
    assert_eq!(
        info_reply.xid, info_xid,
        "the INFORMATION-REQUEST transaction id must be echoed"
    );
    assert_eq!(
        info_reply.first(OPT_SERVER_ID),
        Some(DEFAULT_SERVER_DUID.as_slice()),
        "a REPLY always identifies the server"
    );
    assert!(
        !info_reply.has(OPT_CLIENT_ID),
        "the request carried no Client Identifier, so the reply must not invent one"
    );
    assert!(
        !info_reply.has(OPT_IA_NA),
        "RFC 8415 §18.3.5: a Reply to an Information-request carries no IA options — this \
         client already has an address and did not ask for one"
    );
    assert_eq!(
        info_reply.dns_servers(),
        vec![
            "2001:4860:4860::8888".parse::<Ipv6Addr>()?,
            "2001:4860:4860::8844".parse::<Ipv6Addr>()?
        ],
        "both resolvers, in the order the model gave them"
    );
    assert_eq!(
        info_reply.domain_search(),
        vec![
            "lab.example.com".to_string(),
            "corp.example.net".to_string()
        ],
        "both search domains, decoded from the RFC 1035 name list"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// When the model cannot answer, DHCPv6 puts **nothing** on the wire.
///
/// This is the property the protocol's silence rule exists for, and it is only observable as
/// an absence — so the test provokes a real LLM failure (the mock answers with something the
/// action parser cannot use) and asserts no datagram comes back at all, not even a status code.
/// A CONFIRM checks the other silent path: it is dropped before the model is consulted, because
/// it asks about a binding and NetGet keeps none.
///
/// 1 startup call + the failing SOLICIT = 2 or more LLM calls (the failing one is retried).
#[tokio::test]
async fn test_dhcpv6_llm_failure_sends_nothing() -> E2EResult<()> {
    let prompt =
        "listen on port {AVAILABLE_PORT} via dhcpv6. Assign addresses from 2001:db8:3::/64";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcpv6")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCPv6",
                        "instruction": "DHCPv6 server"
                    }
                ]))
                .expect_calls(1)
                .and()
                // A reply the action parser cannot turn into anything. This is what a backend
                // failure looks like from inside NetGet, and the rule's own call count proves
                // the model really was consulted — so the silence below is the fail-closed
                // path, not a datagram that never reached the server.
                .on_event("dhcpv6_solicit")
                .respond_with_raw("the backend is having a bad day and this is not an action")
                .expect_at_least(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("[::1]:{}", server.port).parse()?;
    let socket = client_socket().await?;

    let solicit = build_message(
        MSG_SOLICIT,
        [0x0b, 0xad, 0x00],
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            identity_association(OPT_IA_NA, CLIENT_IAID, 0, 0, &[]),
        ],
    );
    socket.send_to(&solicit, server_addr).await?;
    expect_no_reply(&socket, 8, "a SOLICIT the model could not answer").await;

    // The absence above is only meaningful next to the log line saying why. `decision=` is the
    // stable token; `grep decision=fail_closed_` finds every message NetGet dropped.
    server.wait_for_any(&["decision=fail_closed_"], 30).await;
    assert!(
        server.output_contains("decision=fail_closed_").await,
        "a failed model call must be recorded with a fail-closed decision token, so an operator \
         can tell it apart from a client that never sent anything"
    );

    // ---- CONFIRM is dropped before the model is consulted ------------------------------
    //
    // CONFIRM asks "are these addresses still appropriate for this link?". NetGet keeps no
    // bindings, so it cannot know — and RFC 8415 §18.3.3 says a server that cannot perform
    // that test MUST NOT send a Reply. Answering it would mean the model inventing an answer
    // to a question about state that does not exist.
    let confirm = build_message(
        MSG_CONFIRM,
        [0x0c, 0x0f, 0x11],
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            identity_association(
                OPT_IA_NA,
                CLIENT_IAID,
                0,
                0,
                &ia_addr_option("2001:db8:3::9".parse()?, 3600, 7200),
            ),
        ],
    );
    socket.send_to(&confirm, server_addr).await?;
    expect_no_reply(&socket, 5, "a CONFIRM").await;
    server.wait_for_any(&["Dropping DHCPv6 Confirm"], 15).await;
    assert!(
        server.output_contains("Dropping DHCPv6 Confirm").await,
        "a CONFIRM must be dropped with a log line saying so, rather than silently vanishing"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A REQUEST the model cannot answer gets the protocol's own "the server failed".
///
/// RFC 8415 answers a REQUEST with a REPLY, and §18.2.10 defines a REPLY whose Status Code is
/// **UnspecFail** as the server being "unable to process the client's message" — the client
/// may retry, rate-limited. It is the one status that asserts nothing about the lease
/// (NoAddrsAvail and NoBinding would both be false statements about the client's
/// configuration), so it is what a fail-closed REQUEST receives instead of silence. The reply
/// must echo the transaction id and Client Identifier, name the server the client addressed
/// (its own option 2, here a DUID NetGet never uses), carry no IA_NA, and put only the fixed
/// category text in the status message — never the error.
///
/// 1 startup call + the failing REQUEST (unmocked, answered HTTP 500).
#[tokio::test]
async fn test_dhcpv6_llm_failure_on_a_request_answers_unspecfail() -> E2EResult<()> {
    let prompt =
        "listen on port {AVAILABLE_PORT} via dhcpv6. Assign addresses from 2001:db8:4::/64";

    let config = helpers::NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("listen on port")
                .and_instruction_containing("dhcpv6")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DHCPv6",
                        "instruction": "DHCPv6 server"
                    }
                ]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for dhcpv6_request: the mock answers 500, which is what
            // drives the server down its LLM-failure path.
        });

    let server = helpers::start_netget_server(config).await?;
    let server_addr: std::net::SocketAddr = format!("[::1]:{}", server.port).parse()?;
    let socket = client_socket().await?;

    // A server DUID the client learned from some ADVERTISE — deliberately not NetGet's
    // placeholder, so echoing it proves the reply names the server the client asked.
    let addressed_server: [u8; 10] = [0x00, 0x03, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let xid = [0x5e, 0x4f, 0x01];
    let request = build_message(
        MSG_REQUEST,
        xid,
        &[
            option(OPT_CLIENT_ID, &CLIENT_DUID),
            option(OPT_SERVER_ID, &addressed_server),
            option(OPT_ELAPSED_TIME, &0u16.to_be_bytes()),
            identity_association(
                OPT_IA_NA,
                CLIENT_IAID,
                0,
                0,
                &ia_addr_option("2001:db8:4::20".parse()?, 3600, 7200),
            ),
        ],
    );

    let reply = exchange(
        &socket,
        server_addr,
        &request,
        "a REQUEST the model could not answer (the server went silent on LLM failure if this \
         times out)",
    )
    .await;

    assert_eq!(
        reply.msg_type, MSG_REPLY,
        "a REQUEST is answered by a REPLY"
    );
    assert_eq!(reply.xid, xid, "the transaction id must be echoed");
    assert_eq!(
        reply.first(OPT_CLIENT_ID),
        Some(CLIENT_DUID.as_slice()),
        "the client's own DUID must be echoed"
    );
    assert_eq!(
        reply.first(OPT_SERVER_ID),
        Some(addressed_server.as_slice()),
        "the reply must name the server the client addressed, not NetGet's placeholder"
    );
    let (code, message) = reply
        .status_code()
        .expect("a fail-closed REPLY must carry a top-level Status Code");
    assert_eq!(
        code, 1,
        "the status must be UnspecFail (1) — NoAddrsAvail (2) or NoBinding (3) would be false \
         statements about the lease; got {code} {message:?}"
    );
    assert_eq!(
        message, "request could not be processed",
        "the status message must be the fixed WireFailure category text, never the error"
    );
    assert!(
        !reply.has(OPT_IA_NA),
        "a failure reply must hand out nothing — no IA_NA"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    assert!(
        server
            .output_contains("decision=fail_closed_llm_error")
            .await,
        "the UnspecFail reply is still the fail-closed outcome and must be tagged as one"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
