//! NetBIOS Name Service server tests.
//!
//! Two layers, weakest evidence first.
//!
//! 1. **Codec against literal bytes a third party produced.** The two request literals below
//!    were captured off loopback with `tcpdump` while **Samba 4.24.6 `nmblookup`** sent them.
//!    Nothing in NetGet wrote those bytes, so they pin the first-level name encoding — the one
//!    part of NBNS that implementations get wrong — against a real client's idea of it.
//! 2. **End to end through the real binary**, driven by a raw UDP socket with the LLM mocked,
//!    including the two silence tests: an LLM failure must put *no datagram* on the wire, and
//!    that must be distinguishable in the log from the model choosing silence.
//!
//! There is no third layer, and the reason is recorded in `tests/server/netbios_ns/CLAUDE.md`:
//! `nmblookup` is hard-wired to UDP port 137 and offers no way to change it, so driving it
//! against a NetGet server needs a privileged run.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use netget::server::netbios_ns::packet::{self, NodeType};
use std::time::Duration;
use tokio::net::UdpSocket;

// ===========================================================================================
// Literals captured from Samba 4.24.6 nmblookup
// ===========================================================================================

/// `nmblookup -U 127.0.0.1 NETGETTEST`, captured with `tcpdump -i lo0 -X udp`.
///
/// TRN_ID 0x047f, FLAGS 0 (a plain broadcast-style query with RD clear), QDCOUNT 1, question
/// name `NETGETTEST` padded to 15 with spaces and suffix 0x00, QTYPE `NB`, QCLASS `IN`.
const SAMBA_NAME_QUERY: &str = "047f000000010000000000002045\
4f4546464545484546464546454546464446454341434143414341434141410000200001";

/// `nmblookup -A 127.0.0.1`, same capture method.
///
/// TRN_ID 0x3326, question name is the wildcard `*` — `'*'` followed by fifteen **NUL**
/// octets, encoding to `CKAAAA…` — and QTYPE is `NBSTAT`.
const SAMBA_NODE_STATUS_QUERY: &str = "33260000000100000000000020434b41\
41414141414141414141414141414141414141414141414141414141410000210001";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(['\n', ' '], "")).expect("test literal is not valid hex")
}

// ===========================================================================================
// Layer 1 — codec, no network, no LLM
// ===========================================================================================

/// **The single thing most NBNS implementations get wrong.**
///
/// Each of the 16 name octets becomes two characters: `'A' + high nibble`, `'A' + low nibble`.
/// The wildcard `*` (0x2A followed by fifteen NULs) is the canonical published example, and it
/// is also exactly what the captured `nmblookup -A` put on the wire.
#[test]
fn first_level_encoding_matches_the_published_wildcard() {
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    assert_eq!(
        &packet::encode_first_level(&raw)[..],
        b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "'*' is 0x2A -> nibbles 2 and 10 -> 'C','K'; fifteen NULs are thirty 'A's"
    );

    // And the same name built through the padding helper, which must choose NUL padding for
    // the wildcard rather than the space padding every other name uses.
    assert_eq!(
        packet::pad_netbios_name("*", 0x00).unwrap(),
        raw,
        "the wildcard pads with NUL, not space"
    );
}

/// Every octet, both directions, plus the rejection that keeps a bad name from being invented.
#[test]
fn first_level_encoding_round_trips_every_octet() {
    for byte in 0u16..=255 {
        let mut raw = [0u8; 16];
        raw[3] = byte as u8;
        let encoded = packet::encode_first_level(&raw);
        assert!(
            encoded.iter().all(|c| (b'A'..=b'P').contains(c)),
            "every encoded character must land in A..=P; {byte} produced {:?}",
            String::from_utf8_lossy(&encoded)
        );
        assert_eq!(packet::decode_first_level(&encoded).unwrap(), raw);
    }

    // 'Q' is one past 'P' and cannot have come from a nibble.
    let mut bad = *b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    bad[5] = b'Q';
    assert!(
        packet::decode_first_level(&bad).is_err(),
        "a character outside A-P must be refused, not silently masked into a name"
    );
    assert!(
        packet::decode_first_level(b"CKAA").is_err(),
        "a short field must be refused"
    );
}

/// The suffix is the 16th octet, not text. `FILESERVER<0x20>` and `FILESERVER<0x00>` are
/// different names and must encode differently, in the last two characters only.
#[test]
fn the_suffix_is_the_sixteenth_octet_and_never_part_of_the_name() {
    let workstation = packet::pad_netbios_name("FILESERVER", 0x00).unwrap();
    let file_server = packet::pad_netbios_name("FILESERVER", 0x20).unwrap();

    assert_eq!(&workstation[..15], &file_server[..15]);
    assert_eq!(workstation[15], 0x00);
    assert_eq!(file_server[15], 0x20);

    let a = packet::encode_first_level(&workstation);
    let b = packet::encode_first_level(&file_server);
    assert_eq!(&a[..30], &b[..30], "only the suffix differs");
    assert_eq!(&a[30..], b"AA", "0x00 -> 'A','A'");
    assert_eq!(&b[30..], b"CA", "0x20 -> 'C','A'");

    // Round trip, and the padding is invisible to the model.
    let (name, suffix) = packet::split_netbios_name(&file_server);
    assert_eq!((name.as_str(), suffix), ("FILESERVER", 0x20));

    // 16 characters cannot fit: the 16th octet belongs to the suffix.
    assert!(packet::pad_netbios_name("SIXTEENCHARSXXXX", 0).is_err());
}

/// The query Samba actually sent, decoded field by field. The header is **12** octets, so the
/// question begins at offset 12 — miscounting it as 16 shifts every field.
#[test]
fn decodes_the_name_query_samba_sent() {
    let bytes = unhex(SAMBA_NAME_QUERY);
    assert_eq!(bytes.len(), 50);

    let request = packet::parse_request(&bytes).expect("a real nmblookup query must decode");

    assert_eq!(request.header.trn_id, 0x047f);
    assert_eq!(request.header.opcode(), packet::OPCODE_QUERY);
    assert!(!request.header.is_response());
    assert_eq!(request.header.qdcount, 1);
    assert_eq!(request.qtype, packet::QTYPE_NB);
    assert_eq!(request.qclass, packet::CLASS_IN);
    assert_eq!(request.question_name.name, "NETGETTEST");
    assert_eq!(request.question_name.suffix, 0x00);
    assert_eq!(request.question_name.scope, None);
    assert_eq!(
        request.question_name.end,
        packet::HEADER_LEN + 34,
        "length octet + 32 encoded characters + root terminator"
    );

    // Re-encoding the name must reproduce the bytes Samba sent, terminator included.
    assert_eq!(
        packet::encode_name_field("NETGETTEST", 0x00, None).unwrap(),
        request.question_name.raw
    );
}

/// The node status query Samba sent, which is where the wildcard name comes from.
#[test]
fn decodes_the_node_status_query_samba_sent() {
    let bytes = unhex(SAMBA_NODE_STATUS_QUERY);
    let request = packet::parse_request(&bytes).expect("a real nmblookup -A query must decode");

    assert_eq!(request.header.trn_id, 0x3326);
    assert_eq!(request.qtype, packet::QTYPE_NBSTAT);
    assert_eq!(
        request.question_name.name, "*",
        "the wildcard must arrive as '*', not '*' followed by NULs"
    );
    assert_eq!(request.question_name.suffix, 0x00);
    assert_eq!(
        packet::encode_name_field("*", 0x00, None).unwrap(),
        request.question_name.raw
    );
}

/// A positive name response is one NB answer RR of six octets per address.
#[test]
fn encodes_a_positive_name_response() {
    let name_field = packet::encode_name_field("FILESERVER", 0x20, None).unwrap();
    let addresses = vec![
        packet::AddressEntry {
            flags: NodeType::B.ont_bits(),
            address: "192.168.1.10".parse().unwrap(),
        },
        packet::AddressEntry {
            flags: NodeType::B.ont_bits(),
            address: "192.168.1.11".parse().unwrap(),
        },
    ];

    let bytes = packet::encode_name_query_response(
        0xbeef,
        packet::OPCODE_QUERY,
        false,
        &name_field,
        &addresses,
        3600,
    )
    .unwrap();

    let header = packet::Header::parse(&bytes).unwrap();
    assert_eq!(header.trn_id, 0xbeef);
    assert!(header.is_response());
    assert_eq!(header.opcode(), packet::OPCODE_QUERY);
    assert_eq!(header.rcode(), packet::RCODE_OK);
    assert_ne!(header.flags & packet::NM_FLAG_AA, 0, "AA must be set");
    assert_eq!(header.qdcount, 0);
    assert_eq!(header.ancount, 1);

    let rr = &bytes[packet::HEADER_LEN..];
    assert_eq!(&rr[..name_field.len()], &name_field[..]);
    let after = &rr[name_field.len()..];
    assert_eq!(u16::from_be_bytes([after[0], after[1]]), packet::QTYPE_NB);
    assert_eq!(u16::from_be_bytes([after[2], after[3]]), packet::CLASS_IN);
    assert_eq!(
        u32::from_be_bytes([after[4], after[5], after[6], after[7]]),
        3600
    );
    assert_eq!(
        u16::from_be_bytes([after[8], after[9]]),
        12,
        "6 octets per address"
    );
    assert_eq!(&after[10..14], &[0x00, 0x00, 192, 168], "B-node, unique");
    assert_eq!(&after[14..16], &[1, 10]);

    // A group name sets the top bit of NB_FLAGS; an M-node sets ONT.
    let grouped = packet::encode_name_query_response(
        1,
        packet::OPCODE_QUERY,
        false,
        &name_field,
        &[packet::AddressEntry {
            flags: packet::NB_FLAG_GROUP | NodeType::M.ont_bits(),
            address: "10.0.0.1".parse().unwrap(),
        }],
        0,
    )
    .unwrap();
    let flags_offset = packet::HEADER_LEN + name_field.len() + 10;
    assert_eq!(
        u16::from_be_bytes([grouped[flags_offset], grouped[flags_offset + 1]]),
        0x8000 | (2 << 13)
    );

    // Nothing may claim to be a positive answer while carrying no address.
    assert!(packet::encode_name_query_response(
        1,
        packet::OPCODE_QUERY,
        false,
        &name_field,
        &[],
        0
    )
    .is_err());
}

/// RFC 1002 §4.2.14: the negative answer is a NULL RR with zero RDATA and a non-zero RCODE.
#[test]
fn encodes_a_negative_response_as_a_null_rr() {
    let name_field = packet::encode_name_field("NOSUCHHOST", 0x00, None).unwrap();
    let bytes = packet::encode_negative_response(
        0x1234,
        packet::OPCODE_QUERY,
        true,
        &name_field,
        packet::RCODE_NAM_ERR,
    )
    .unwrap();

    let header = packet::Header::parse(&bytes).unwrap();
    assert_eq!(header.trn_id, 0x1234);
    assert!(header.is_response());
    assert_eq!(header.rcode(), packet::RCODE_NAM_ERR);
    assert_ne!(header.flags & packet::NM_FLAG_RD, 0, "RD is echoed");
    assert_ne!(header.flags & packet::NM_FLAG_RA, 0);
    assert_eq!(header.ancount, 1);

    let after = &bytes[packet::HEADER_LEN + name_field.len()..];
    assert_eq!(
        u16::from_be_bytes([after[0], after[1]]),
        packet::RRTYPE_NULL
    );
    assert_eq!(u16::from_be_bytes([after[8], after[9]]), 0, "RDLENGTH is 0");
    assert_eq!(after.len(), 10);

    // RCODE 0 would make this a *positive* answer carrying nothing.
    assert!(packet::encode_negative_response(
        1,
        packet::OPCODE_QUERY,
        false,
        &name_field,
        packet::RCODE_OK
    )
    .is_err());
}

/// Node status RDATA is `NUM_NAMES` + 18 octets per name + a fixed 46-octet statistics block
/// whose first six octets are the adapter MAC. The names in that list are **not** first-level
/// encoded — encoding them is a classic way to make every real client render gibberish.
#[test]
fn encodes_a_node_status_response_with_a_raw_name_list() {
    let name_field = packet::encode_name_field("*", 0x00, None).unwrap();
    let names = vec![
        packet::NodeName {
            raw: packet::pad_netbios_name("FILESERVER", 0x00).unwrap(),
            flags: packet::NAME_FLAG_ACTIVE,
        },
        packet::NodeName {
            raw: packet::pad_netbios_name("WORKGROUP", 0x00).unwrap(),
            flags: packet::NAME_FLAG_GROUP | packet::NAME_FLAG_ACTIVE,
        },
    ];
    let mac = packet::parse_mac("00:11:22:33:44:55").unwrap();

    let bytes = packet::encode_node_status_response(0x4242, &name_field, &names, mac).unwrap();

    let header = packet::Header::parse(&bytes).unwrap();
    assert_eq!(header.trn_id, 0x4242);
    assert!(header.is_response());
    assert_eq!(header.ancount, 1);

    let after = &bytes[packet::HEADER_LEN + name_field.len()..];
    assert_eq!(
        u16::from_be_bytes([after[0], after[1]]),
        packet::QTYPE_NBSTAT
    );
    let rdlength = u16::from_be_bytes([after[8], after[9]]) as usize;
    assert_eq!(rdlength, 1 + 2 * 18 + 46);
    let rdata = &after[10..10 + rdlength];

    assert_eq!(rdata[0], 2, "NUM_NAMES");
    assert_eq!(
        &rdata[1..17],
        b"FILESERVER     \x00",
        "the name list carries the raw 16 octets, not the encoded 32"
    );
    assert_eq!(
        u16::from_be_bytes([rdata[17], rdata[18]]),
        packet::NAME_FLAG_ACTIVE
    );
    assert_eq!(&rdata[19..35], b"WORKGROUP      \x00");
    assert_eq!(
        u16::from_be_bytes([rdata[35], rdata[36]]),
        packet::NAME_FLAG_GROUP | packet::NAME_FLAG_ACTIVE
    );

    let statistics = &rdata[1 + 2 * 18..];
    assert_eq!(statistics.len(), 46);
    assert_eq!(&statistics[..6], &mac[..], "UNIT_ID is the adapter MAC");
    assert!(
        statistics[6..].iter().all(|b| *b == 0),
        "NetGet has no adapter counters and must not invent any"
    );
}

/// MAC addresses reach the model as formatted strings, never byte arrays.
#[test]
fn parses_and_formats_mac_addresses() {
    assert_eq!(
        packet::parse_mac("00:11:22:33:44:55").unwrap(),
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    );
    assert_eq!(
        packet::parse_mac("AA-BB-CC-DD-EE-FF").unwrap(),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert_eq!(
        packet::format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        "00:11:22:33:44:55"
    );
    assert!(packet::parse_mac("001122334455").is_err());
    assert!(packet::parse_mac("00:11:22:33:44:zz").is_err());
}

/// Malformed and hostile datagrams must be refused, not half-parsed.
#[test]
fn refuses_datagrams_that_are_not_answerable_requests() {
    // Already a response: answering one turns this server into a reflector.
    let mut response = unhex(SAMBA_NAME_QUERY);
    response[2] = 0x80;
    assert!(packet::parse_request(&response).is_err());

    // Truncated inside the name.
    assert!(packet::parse_request(&unhex(SAMBA_NAME_QUERY)[..20]).is_err());

    // Header only.
    assert!(packet::parse_request(&[0u8; 12]).is_err());

    // Shorter than a header.
    assert!(packet::parse_request(&[0u8; 5]).is_err());

    // First label is not 32 octets, so it cannot be a first-level encoded name.
    let mut bad_label = unhex(SAMBA_NAME_QUERY);
    bad_label[12] = 4;
    assert!(packet::parse_request(&bad_label).is_err());

    // Compression pointer in a question: refused rather than followed.
    let mut pointer = unhex(SAMBA_NAME_QUERY);
    pointer[12] = 0xc0;
    assert!(packet::parse_request(&pointer).is_err());

    // Over the RFC 1002 §4.1 size cap.
    assert!(packet::parse_request(&vec![0u8; packet::MAX_DATAGRAM + 1]).is_err());
}

/// A positive answer always carries the *queried* name, so an answer that names a different
/// one is refused rather than silently corrected.
///
/// This is a fail-open hole that was open: `name` and `suffix` are declared **required** on
/// `send_netbios_name_response`, but the NAME field on the wire comes from the request, so
/// the executor read them and threw them away (`let _ = parse_name(&action)`). A model
/// answering a query for `FILESERVER<0x20>` with `{"name": "PRINTER", "suffix": 0}` therefore
/// emitted a perfectly valid positive answer **for FILESERVER<0x20>**, carrying PRINTER's
/// addresses, while the action's own log template printed `-> NetBIOS name PRINTER<0x00>`.
/// The querier caches that for the TTL. Guessing which of the two the model meant is not
/// available to us, so the answer is refused and nothing goes on the wire.
#[test]
fn a_positive_answer_may_not_name_a_different_name_than_the_query() {
    use netget::llm::actions::protocol_trait::Server;
    use netget::server::netbios_ns::actions::{NetbiosNsProtocol, RequestContext};

    let context = |name: &str, suffix: u8| RequestContext {
        trn_id: 0x1234,
        opcode: packet::OPCODE_QUERY,
        recursion_desired: false,
        name_field: packet::encode_name_field(name, suffix, None).unwrap(),
        question_name: name.to_string(),
        question_suffix: suffix,
        default_ttl: 3600,
        default_node_type: NodeType::B,
    };
    let answer = |name: &str, suffix: serde_json::Value| {
        serde_json::json!({
            "type": "send_netbios_name_response",
            "name": name,
            "suffix": suffix,
            "addresses": ["10.1.2.3"],
        })
    };

    let protocol = NetbiosNsProtocol::for_request(context("FILESERVER", 0x20));

    // Matching name and suffix: answered.
    protocol
        .execute_action(answer("FILESERVER", serde_json::json!(0x20)))
        .expect("an answer naming the queried name is the normal case");

    // A different name entirely.
    let wrong_name = protocol
        .execute_action(answer("PRINTER", serde_json::json!(0x20)))
        .expect_err("answering for a different host must not produce a datagram");
    let message = format!("{wrong_name:#}");
    assert!(
        message.contains("FILESERVER") && message.contains("PRINTER"),
        "the refusal must name both the question and what the model said: {message}"
    );

    // Same name, different service. `FILESERVER<0x00>` and `FILESERVER<0x20>` are two names.
    protocol
        .execute_action(answer("FILESERVER", serde_json::json!(0x00)))
        .expect_err("a different suffix is a different name, not a detail");

    // The suffix must be unambiguous, for the same reason: a bare "20" spells both 32 (hex,
    // the conventional NetBIOS notation) and 20 (decimal), and those are two names.
    let ambiguous = protocol
        .execute_action(answer("FILESERVER", serde_json::json!("20")))
        .expect_err("a bare digit string must be refused rather than guessed at");
    assert!(
        format!("{ambiguous:#}").contains("0x20"),
        "the refusal must name the unambiguous spelling"
    );
    protocol
        .execute_action(answer("FILESERVER", serde_json::json!("0x20")))
        .expect("an explicit hex spelling is accepted");
}

// ===========================================================================================
// Layer 2 — end to end through the real binary, LLM mocked
// ===========================================================================================

/// Send one datagram and wait for a reply.
async fn exchange(port: u16, request: &[u8]) -> E2EResult<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(request, format!("127.0.0.1:{}", port))
        .await?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out waiting for a NetBIOS-NS reply")??;
    buf.truncate(n);
    Ok(buf)
}

/// Send one datagram and assert that **nothing** comes back within `secs`.
async fn expect_silence(port: u16, request: &[u8], secs: u64) -> E2EResult<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(request, format!("127.0.0.1:{}", port))
        .await?;

    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(secs), socket.recv_from(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok((n, _))) => Err(format!(
            "expected silence, got a {n}-byte datagram: {}",
            hex::encode(&buf[..n])
        )
        .into()),
        Ok(Err(e)) => Err(e.into()),
    }
}

/// The reply lands on the socket before the harness has necessarily drained the server's
/// stdout, so waiting is required; the assertion is still that the line appears.
async fn wait_for_log(server: &helpers::server::NetGetServer, needle: &str) -> bool {
    for _ in 0..100 {
        if server.output_contains(needle).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Split a response into (header, name field bytes, everything after the name field).
fn dissect(bytes: &[u8]) -> (packet::Header, &[u8], &[u8]) {
    let header = packet::Header::parse(bytes).expect("reply must have a well-formed header");
    let name = packet::read_name_field(bytes, packet::HEADER_LEN)
        .expect("reply must carry a well-formed NAME field");
    (
        header,
        &bytes[packet::HEADER_LEN..name.end],
        &bytes[name.end..],
    )
}

fn open_server_action(instruction: &str) -> serde_json::Value {
    serde_json::json!([{
        "type": "open_server",
        "port": 0,
        "base_stack": "netbios_ns",
        "startup_params": {"default_ttl": 3600, "node_type": "b"},
        "instruction": instruction
    }])
}

/// One server, three requests: a name it holds, a name it does not, and a registration it
/// refuses. All three are answered by the model, and the transaction id, opcode and question
/// name are echoed by the server on every one of them.
#[tokio::test]
async fn answers_queries_and_registrations_the_model_decides() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via netbios_ns. Resolve NETGETTEST to 10.1.2.3 and \
         refuse everything else.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // ONE rule for both queries, branching on the event. Two rules on the same event
            // would be first-match-wins and the second would report zero calls.
            .on_event("netbios_name_query")
            .respond_with_actions_from_event(|event| {
                let name = event["name"].as_str().unwrap_or("");
                if name == "NETGETTEST" {
                    serde_json::json!([{
                        "type": "send_netbios_name_response",
                        "name": name,
                        "suffix": event["suffix"].as_u64().unwrap_or(0),
                        "addresses": ["10.1.2.3"],
                        "ttl": 1200,
                        "group": false
                    }])
                } else {
                    serde_json::json!([{
                        "type": "send_netbios_negative_response",
                        "rcode": "name_not_found"
                    }])
                }
            })
            .expect_calls(2)
            .and()
            .on_event("netbios_name_registration")
            .respond_with_actions_from_event(|_| {
                serde_json::json!([{
                    "type": "send_netbios_negative_response",
                    "rcode": "name_active"
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("netbios_ns")
            .respond_with_actions(open_server_action(
                "Resolve NETGETTEST to 10.1.2.3, refuse everything else",
            ))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- 1. The query Samba really sent, replayed byte for byte -----------------------------
    let query = unhex(SAMBA_NAME_QUERY);
    let reply = exchange(server.port, &query).await?;
    let (header, name_field, rest) = dissect(&reply);

    assert_eq!(
        header.trn_id, 0x047f,
        "the transaction id must be echoed or the querier discards the reply"
    );
    assert!(header.is_response(), "R bit must be set");
    assert_eq!(header.opcode(), packet::OPCODE_QUERY);
    assert_eq!(header.rcode(), packet::RCODE_OK);
    assert_ne!(header.flags & packet::NM_FLAG_AA, 0);
    assert_eq!(header.qdcount, 0);
    assert_eq!(header.ancount, 1);
    assert_eq!(
        name_field,
        &query[packet::HEADER_LEN..packet::HEADER_LEN + 34],
        "the answer RR must name exactly what was asked about, byte for byte"
    );
    assert_eq!(u16::from_be_bytes([rest[0], rest[1]]), packet::QTYPE_NB);
    assert_eq!(
        u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]),
        1200,
        "the model's ttl, not the server's default_ttl"
    );
    assert_eq!(u16::from_be_bytes([rest[8], rest[9]]), 6);
    assert_eq!(
        u16::from_be_bytes([rest[10], rest[11]]) & packet::NB_FLAG_GROUP,
        0,
        "group=false must produce a unique name"
    );
    assert_eq!(&rest[12..16], &[10, 1, 2, 3], "the address the model chose");

    assert!(
        wait_for_log(&server, "decision=model_answer").await,
        "Output: {:?}",
        server.get_output().await
    );

    // --- 2. A name the model does not hold --------------------------------------------------
    let mut unknown = packet::Header {
        trn_id: 0x0abc,
        flags: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    }
    .encode()
    .to_vec();
    unknown.extend_from_slice(&packet::encode_name_field("NOSUCHHOST", 0x20, None).unwrap());
    unknown.extend_from_slice(&packet::QTYPE_NB.to_be_bytes());
    unknown.extend_from_slice(&packet::CLASS_IN.to_be_bytes());

    let reply = exchange(server.port, &unknown).await?;
    let (header, _, rest) = dissect(&reply);
    assert_eq!(header.trn_id, 0x0abc);
    assert_eq!(
        header.rcode(),
        packet::RCODE_NAM_ERR,
        "'name_not_found' must reach the wire as RCODE 3"
    );
    assert_eq!(u16::from_be_bytes([rest[0], rest[1]]), packet::RRTYPE_NULL);
    assert!(
        wait_for_log(&server, "decision=model_reject").await,
        "an explicit refusal must be logged as the model's, not as fail-closed. Output: {:?}",
        server.get_output().await
    );

    // --- 3. A registration, refused ---------------------------------------------------------
    let mut registration = packet::Header {
        trn_id: 0x5150,
        // OPCODE 5 (registration), RD set as a real claimant sets it.
        flags: (packet::OPCODE_REGISTRATION << 11) | packet::NM_FLAG_RD | packet::NM_FLAG_B,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 1,
    }
    .encode()
    .to_vec();
    let claim_name = packet::encode_name_field("CLAIMANT", 0x00, None).unwrap();
    registration.extend_from_slice(&claim_name);
    registration.extend_from_slice(&packet::QTYPE_NB.to_be_bytes());
    registration.extend_from_slice(&packet::CLASS_IN.to_be_bytes());
    // ADDITIONAL: the NB record carrying the address being claimed.
    registration.extend_from_slice(&claim_name);
    registration.extend_from_slice(&packet::QTYPE_NB.to_be_bytes());
    registration.extend_from_slice(&packet::CLASS_IN.to_be_bytes());
    registration.extend_from_slice(&300u32.to_be_bytes());
    registration.extend_from_slice(&6u16.to_be_bytes());
    registration.extend_from_slice(&0u16.to_be_bytes());
    registration.extend_from_slice(&[192, 168, 5, 55]);

    let reply = exchange(server.port, &registration).await?;
    let (header, _, _) = dissect(&reply);
    assert_eq!(header.trn_id, 0x5150);
    assert_eq!(
        header.opcode(),
        packet::OPCODE_REGISTRATION,
        "a registration response differs from a query response only in the OPCODE, and the \
         server — not the model — supplies it"
    );
    assert_eq!(header.rcode(), packet::RCODE_ACT_ERR);
    assert!(
        wait_for_log(&server, "netbios_name_registration").await,
        "Output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A node status listing: the names are the model's invention, and the adapter MAC reaches the
/// wire as six octets from the formatted string it supplied.
#[tokio::test]
async fn node_status_lists_the_names_the_model_invented() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via netbios_ns. Report two names on node status.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("netbios_node_status_request")
            .respond_with_actions_from_event(|event| {
                // Derived from the event: a server that mis-decoded the wildcard would send
                // the wrong list and this assertion would fail.
                let asked = event["name"].as_str().unwrap_or("");
                serde_json::json!([{
                    "type": "send_netbios_node_status_response",
                    "names": [
                        {"name": "NETGETHOST", "suffix": 0, "group": false, "active": true},
                        {"name": if asked == "*" { "WORKGROUP" } else { "UNEXPECTED" },
                         "suffix": 0, "group": true, "active": true}
                    ],
                    "mac_address": "02:00:5e:10:00:01"
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("netbios_ns")
            .respond_with_actions(open_server_action("Report NETGETHOST and WORKGROUP"))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let query = unhex(SAMBA_NODE_STATUS_QUERY);
    let reply = exchange(server.port, &query).await?;
    let (header, name_field, rest) = dissect(&reply);

    assert_eq!(header.trn_id, 0x3326, "transaction id echoed");
    assert!(header.is_response());
    assert_eq!(
        name_field,
        &query[packet::HEADER_LEN..packet::HEADER_LEN + 34],
        "the wildcard name must be echoed exactly as it arrived"
    );
    assert_eq!(u16::from_be_bytes([rest[0], rest[1]]), packet::QTYPE_NBSTAT);

    let rdlength = u16::from_be_bytes([rest[8], rest[9]]) as usize;
    let rdata = &rest[10..10 + rdlength];
    assert_eq!(rdata[0], 2, "NUM_NAMES");
    assert_eq!(&rdata[1..17], b"NETGETHOST     \x00");
    assert_eq!(
        u16::from_be_bytes([rdata[17], rdata[18]]),
        packet::NAME_FLAG_ACTIVE
    );
    assert_eq!(
        &rdata[19..35],
        b"WORKGROUP      \x00",
        "the model saw '*' and answered for it"
    );
    assert_eq!(
        u16::from_be_bytes([rdata[35], rdata[36]]),
        packet::NAME_FLAG_GROUP | packet::NAME_FLAG_ACTIVE
    );
    assert_eq!(
        &rdata[37..43],
        &[0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
        "the MAC string became six octets of UNIT_ID"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// **The silence test.**
///
/// No mock rule matches `netbios_name_query`, so the mock answers HTTP 500 and `call_llm`
/// returns `Err` — the same shape as a backend outage. NBNS must then put **nothing** on the
/// wire: a fabricated answer would be cached by the querier for its TTL and would redirect
/// that host's traffic long after the backend recovered.
#[tokio::test]
async fn an_llm_failure_produces_no_datagram_at_all() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via netbios_ns.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("netbios_ns")
                .respond_with_actions(open_server_action("Answer NetBIOS name queries"))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for netbios_name_query: the mock answers 500, which is
            // what drives the server down its failure path.
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    expect_silence(server.port, &unhex(SAMBA_NAME_QUERY), 8).await?;

    assert!(
        wait_for_log(&server, "decision=fail_closed_llm_error").await,
        "an outage must be recorded as the server's fail-closed silence. Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server.output_contains("decision=model_silent").await,
        "an outage must NOT be recorded as the model choosing silence — on this protocol the \
         wire cannot tell them apart, so the log is the only place the distinction exists"
    );
    assert!(
        !server.output_contains("decision=model_reject").await,
        "an outage must not be recorded as a refusal either"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// **The one answer that needs no model.** The same outage, but the query addresses this
/// server as its name server: RD set (RFC 1002 §4.2.1.1 — "may only be set on a request to
/// the NBNS") and B clear. RFC 1002 §4.2.14 gives the NBNS a word for "I cannot process this",
/// RCODE SRV_ERR, and it asserts nothing about the name — so the querier is told the server
/// failed instead of waiting out its retransmissions. The reply must echo the transaction id
/// and question name, carry the NULL RR of a negative response, and be tagged in the log as
/// the fail-closed outcome it is.
#[tokio::test]
async fn an_llm_failure_on_a_query_to_the_name_server_is_answered_srv_err() -> E2EResult<()> {
    let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via netbios_ns.")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("netbios_ns")
                .respond_with_actions(open_server_action("Answer NetBIOS name queries"))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for netbios_name_query: the mock answers 500.
        });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut query = unhex(SAMBA_NAME_QUERY);
    let flags = u16::from_be_bytes([query[2], query[3]]) | packet::NM_FLAG_RD;
    query[2..4].copy_from_slice(&flags.to_be_bytes());

    let reply = exchange(server.port, &query).await?;
    let (header, name, rest) = dissect(&reply);
    assert_eq!(header.trn_id, 0x047f, "the transaction id must be echoed");
    assert!(header.is_response(), "must be a response");
    assert_eq!(
        header.rcode(),
        packet::RCODE_SRV_ERR,
        "an outage on a query addressed to the NBNS must be answered SRV_ERR, not NAM_ERR \
         (which would assert the name does not exist) and not a positive answer"
    );
    assert_eq!(
        name,
        &query[packet::HEADER_LEN..packet::HEADER_LEN + name.len()]
    );
    assert_eq!(
        u16::from_be_bytes([rest[0], rest[1]]),
        packet::RRTYPE_NULL,
        "a negative response carries a NULL RR"
    );

    assert!(
        wait_for_log(&server, "decision=fail_closed_llm_error").await,
        "the SRV_ERR answer is still the fail-closed outcome and must be tagged as one. \
         Output: {:?}",
        server.get_output().await
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The mirror image: the model was reached and chose to say nothing. The wire is identical to
/// the test above — that is the point — so only the log distinguishes them.
#[tokio::test]
async fn model_chosen_silence_is_distinguishable_from_an_outage() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via netbios_ns. Say nothing about names you do not hold.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("netbios_name_query")
            .respond_with_actions(serde_json::json!([{"type": "no_response"}]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("netbios_ns")
            .respond_with_actions(open_server_action("Stay silent about unknown names"))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    expect_silence(server.port, &unhex(SAMBA_NAME_QUERY), 8).await?;

    assert!(
        wait_for_log(&server, "decision=model_silent").await,
        "Output: {:?}",
        server.get_output().await
    );
    assert!(
        !server.output_contains("decision=fail_closed").await,
        "a deliberate no_response is a real answer and must never be logged as fail-closed"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
