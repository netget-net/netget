//! NetBIOS Name Service **client** tests.
//!
//! Three layers, strongest evidence first, because the strength of the evidence is exactly
//! what this protocol's maturity rating turns on.
//!
//! 1. **The encode direction, against bytes Samba produced.** `SAMBA_NAME_QUERY` and
//!    `SAMBA_NODE_STATUS_QUERY` below were captured off loopback with `tcpdump` while Samba
//!    4.24.6's `nmblookup` sent them. This client's own encoder must reproduce them **byte for
//!    byte**, transaction id included. NetGet wrote none of those bytes, so this is genuinely
//!    independent evidence — for one direction.
//! 2. **The decode direction, against NetGet's own encoders.** Same-project evidence: it shows
//!    the two halves agree, not that either matches RFC 1002.
//! 3. **End to end through the real binary**, LLM mocked, against two different responders —
//!    NetGet's own NBNS server, and a raw UDP stand-in that can misbehave on purpose.
//!
//! Layer 1 is why `metadata()` says the encode direction is independently pinned; layers 2 and
//! 3 are why it still says **Experimental**. No third-party NBNS *responder* can be reached
//! here: `nmblookup` is hard-wired to UDP 137 and binding 137 needs root, so the decode
//! direction has never been checked against anything NetGet did not write.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

// Explicit imports rather than `use crate::helpers::*`: the helpers module contains a
// submodule literally called `netget`, and a glob import of it shadows the crate of the same
// name, so `netget::client::...` below stops resolving (E0659).
use crate::helpers::{start_netget_client, start_netget_server, E2EResult, NetGetConfig};
use netget::client::netbios_ns::wire;
use netget::server::netbios_ns::packet::{self, NodeType};

// ===========================================================================================
// Literals captured from Samba 4.24.6 nmblookup
// ===========================================================================================
//
//   tcpdump -i lo0 -n -w nbns.pcap 'udp port 137' &
//   nmblookup -U 127.0.0.1 NETGETTEST     # -> SAMBA_NAME_QUERY
//   nmblookup -A 127.0.0.1                # -> SAMBA_NODE_STATUS_QUERY
//
// Both were captured for this suite and both match, byte for byte after the transaction id,
// the independently captured literals in `tests/server/netbios_ns/e2e_test.rs`. That second
// capture matters: it means the encoding is pinned by two separate runs of a third-party
// client rather than by one transcription that could have been mis-copied.

/// `nmblookup -U 127.0.0.1 NETGETTEST`. TRN_ID 0x086d, `FLAGS` **0x0000** (a directed query
/// to a name server: RD clear, B clear), QDCOUNT 1, the name space-padded to 15 with suffix
/// 0x00, QTYPE `NB`, QCLASS `IN`.
const SAMBA_NAME_QUERY: &str = "086d0000000100000000000020454f454646454548454646454645454646\
4446454341434143414341434141410000200001";

/// `nmblookup -A 127.0.0.1`. TRN_ID 0x3908, the wildcard `*` — `'*'` followed by fifteen
/// **NUL** octets, encoding to `CKAAAA…` — and QTYPE `NBSTAT`.
const SAMBA_NODE_STATUS_QUERY: &str =
    "39080000000100000000000020434b414141414141414141414141414141\
4141414141414141414141414141410000210001";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(['\n', ' '], "")).expect("test literal is not valid hex")
}

// ===========================================================================================
// Layer 1 — the encode direction, pinned by a third party
// ===========================================================================================

/// **The strongest claim this suite can make.** A NAME QUERY this client builds is
/// indistinguishable from one Samba builds.
#[test]
fn the_name_query_this_client_builds_is_byte_identical_to_sambas() {
    let ours = wire::encode_name_query(0x086d, "NETGETTEST", 0x00, false)
        .expect("a 10-character ASCII name must encode");

    assert_eq!(
        hex::encode(&ours),
        SAMBA_NAME_QUERY,
        "our NAME QUERY must be byte-for-byte what nmblookup -U put on the wire"
    );
    assert_eq!(ours.len(), 50);

    // And it decodes, through the server half's parser, as the question we meant to ask.
    let parsed = packet::parse_request(&ours).expect("our own query must parse as a request");
    assert_eq!(parsed.header.trn_id, 0x086d);
    assert_eq!(
        parsed.header.flags, 0x0000,
        "a directed query sets no flags"
    );
    assert_eq!(parsed.qtype, packet::QTYPE_NB);
    assert_eq!(parsed.qclass, packet::CLASS_IN);
    assert_eq!(parsed.question_name.name, "NETGETTEST");
    assert_eq!(parsed.question_name.suffix, 0x00);
}

/// The node status question, and with it the wildcard's **NUL** padding.
///
/// Space padding would produce `CKCACACA…` here — a name no NBNS implementation recognises as
/// the wildcard, and the bug that cost real debugging on the server side until a captured
/// datagram disagreed with the code.
#[test]
fn the_node_status_query_this_client_builds_is_byte_identical_to_sambas() {
    let ours = wire::encode_node_status_query(0x3908, "*", 0x00).expect("the wildcard must encode");

    assert_eq!(
        hex::encode(&ours),
        SAMBA_NODE_STATUS_QUERY,
        "our NODE STATUS query must be byte-for-byte what nmblookup -A put on the wire"
    );

    // The encoded name label, spelled out: 0x2A -> 'C','K'; fifteen NULs -> thirty 'A's.
    let name_label = &ours[packet::HEADER_LEN + 1..packet::HEADER_LEN + 1 + 32];
    assert_eq!(name_label, b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_ne!(
        name_label, b"CKCACACACACACACACACACACACACACAAA",
        "the wildcard pads with NUL, not space (RFC 1001 §17)"
    );

    let parsed = packet::parse_request(&ours).expect("our own query must parse as a request");
    assert_eq!(parsed.qtype, packet::QTYPE_NBSTAT);
    assert_eq!(
        parsed.question_name.name, "*",
        "the wildcard must round-trip as '*', not '*' with fifteen NULs attached — \
         trim_end() alone does not strip NULs"
    );
}

/// The broadcast form differs from the directed one in the flag word and nothing else.
#[test]
fn broadcast_changes_only_the_flag_word() {
    let directed = wire::encode_name_query(0x1234, "HOST", 0x20, false).unwrap();
    let broadcast = wire::encode_name_query(0x1234, "HOST", 0x20, true).unwrap();

    assert_eq!(directed[..2], broadcast[..2], "same transaction id");
    assert_eq!(directed[4..], broadcast[4..], "same question");
    assert_eq!(u16::from_be_bytes([directed[2], directed[3]]), 0x0000);
    assert_eq!(
        u16::from_be_bytes([broadcast[2], broadcast[3]]),
        packet::NM_FLAG_B | packet::NM_FLAG_RD,
        "the broadcast form sets B and RD"
    );
}

/// The suffix is the 16th octet and never part of the name, in the queries we build too.
#[test]
fn the_suffix_is_a_field_and_changes_only_the_last_two_characters() {
    let workstation = wire::encode_name_query(1, "FILESERVER", 0x00, false).unwrap();
    let file_server = wire::encode_name_query(1, "FILESERVER", 0x20, false).unwrap();

    let name_at = packet::HEADER_LEN + 1;
    assert_eq!(
        workstation[name_at..name_at + 30],
        file_server[name_at..name_at + 30]
    );
    assert_eq!(&workstation[name_at + 30..name_at + 32], b"AA", "0x00");
    assert_eq!(&file_server[name_at + 30..name_at + 32], b"CA", "0x20");

    // And the action-level parser accepts both the number and the hex string the NBNS server's
    // own actions use, so a suffix seen in an event can be handed straight back.
    assert_eq!(
        wire::parse_suffix(Some(&serde_json::json!(32))).unwrap(),
        32
    );
    assert_eq!(
        wire::parse_suffix(Some(&serde_json::json!("0x20"))).unwrap(),
        0x20
    );
    assert_eq!(wire::parse_suffix(None).unwrap(), 0);
    assert!(wire::parse_suffix(Some(&serde_json::json!("beef"))).is_err());
    assert!(wire::parse_suffix(Some(&serde_json::json!(256))).is_err());

    // A BARE digit string is refused rather than guessed at. "20" is a valid spelling of
    // both 32 (hex, the conventional NetBIOS notation for the file server) and 20 (decimal),
    // and the two select DIFFERENT NAMES — FILESERVER<0x20> is not FILESERVER<0x14>. A
    // parser that picks one silently answers for, or asks about, a name nobody named.
    let ambiguous = wire::parse_suffix(Some(&serde_json::json!("20")));
    assert!(
        ambiguous.is_err(),
        "a bare '20' must be refused, not read as one of the two names it could mean"
    );
    let message = format!("{:#}", ambiguous.unwrap_err());
    assert!(
        message.contains("0x20"),
        "the refusal must name the unambiguous form the sender should have used: {message}"
    );
}

/// Client and server read a suffix through **one** function, so they cannot disagree.
///
/// This is the assertion that would have failed before the two were merged: the client read a
/// bare `"20"` as decimal 20 and the server read it as hex 0x20, while a doc comment in
/// `wire.rs` claimed they used "the same contract". Same input, two different NetBIOS names,
/// in the same session, on a protocol whose whole hazard is answering for the wrong name.
#[test]
fn the_two_halves_read_a_suffix_the_same_way() {
    for value in [
        serde_json::json!(0),
        serde_json::json!(32),
        serde_json::json!("0x1b"),
        serde_json::json!("0X20"),
        serde_json::json!("20"),
        serde_json::json!("beef"),
        serde_json::json!(256),
        serde_json::json!(true),
    ] {
        let via_client = wire::parse_suffix(Some(&value));
        let via_shared = packet::parse_suffix_value(Some(&value));
        assert_eq!(
            via_client.as_ref().ok().copied(),
            via_shared.as_ref().ok().copied(),
            "client and server must agree on suffix {value}"
        );
    }
}

// ===========================================================================================
// Layer 2 — the decode direction, against NetGet's own encoders
// ===========================================================================================

/// A positive name response, parsed into addresses with the suffix kept separate.
#[test]
fn parses_a_positive_name_response() {
    let name_field = packet::encode_name_field("FILESERVER", 0x20, None).unwrap();
    let addresses = vec![
        packet::AddressEntry {
            flags: NodeType::B.ont_bits(),
            address: "192.0.2.10".parse().unwrap(),
        },
        packet::AddressEntry {
            flags: NodeType::B.ont_bits(),
            address: "192.0.2.11".parse().unwrap(),
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

    let response = wire::parse_response(&bytes).expect("a positive NB answer must parse");
    assert_eq!(response.trn_id, 0xbeef);
    let wire::NbnsAnswer::Name(answer) = response.answer else {
        panic!("expected a name answer");
    };
    assert_eq!(answer.name, "FILESERVER");
    assert_eq!(answer.suffix, 0x20, "the suffix is its own field");
    assert_eq!(wire::suffix_label(answer.suffix), "file_server");
    assert_eq!(
        answer.addresses,
        vec![
            "192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap(),
            "192.0.2.11".parse().unwrap()
        ]
    );
    assert_eq!(answer.ttl, 3600);
    assert!(!answer.group);
    assert_eq!(answer.node_type, "b");

    // A group name with a mixed node type, so the flag decoding is not vacuously "all zero".
    let group = vec![packet::AddressEntry {
        flags: packet::NB_FLAG_GROUP | NodeType::M.ont_bits(),
        address: "192.0.2.255".parse().unwrap(),
    }];
    let bytes = packet::encode_name_query_response(
        1,
        packet::OPCODE_QUERY,
        false,
        &packet::encode_name_field("WORKGROUP", 0x00, None).unwrap(),
        &group,
        300,
    )
    .unwrap();
    let wire::NbnsAnswer::Name(answer) = wire::parse_response(&bytes).unwrap().answer else {
        panic!("expected a name answer");
    };
    assert!(answer.group);
    assert_eq!(answer.node_type, "m");
}

/// **The high-value one.** A node status reply must come apart into names with their suffixes
/// separated, their group and active flags decoded, and the adapter MAC as a formatted string.
#[test]
fn parses_a_node_status_response_into_names_with_suffixes_separated() {
    let names = vec![
        packet::NodeName {
            raw: packet::pad_netbios_name("NETGETHOST", 0x00).unwrap(),
            flags: packet::NAME_FLAG_ACTIVE,
        },
        packet::NodeName {
            raw: packet::pad_netbios_name("NETGETHOST", 0x20).unwrap(),
            flags: packet::NAME_FLAG_ACTIVE,
        },
        packet::NodeName {
            raw: packet::pad_netbios_name("WORKGROUP", 0x1e).unwrap(),
            flags: packet::NAME_FLAG_GROUP | packet::NAME_FLAG_ACTIVE,
        },
        packet::NodeName {
            // Deliberately not active, so `active` is not a constant `true`.
            raw: packet::pad_netbios_name("OLDNAME", 0x03).unwrap(),
            flags: 0,
        },
    ];
    let bytes = packet::encode_node_status_response(
        0x4242,
        &packet::encode_name_field("*", 0x00, None).unwrap(),
        &names,
        [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    )
    .unwrap();

    let response = wire::parse_response(&bytes).expect("a node status answer must parse");
    assert_eq!(response.trn_id, 0x4242);
    let wire::NbnsAnswer::NodeStatus(answer) = response.answer else {
        panic!("expected a node status answer");
    };

    assert_eq!(
        answer.name, "*",
        "the question is echoed back as the wildcard"
    );
    assert_eq!(answer.mac_address, "02:00:5e:10:00:01");
    assert_eq!(answer.names.len(), 4);

    // The same machine name at two different suffixes stays two entries, and neither carries
    // the suffix inside its name string.
    assert_eq!(answer.names[0].name, "NETGETHOST");
    assert_eq!(answer.names[0].suffix, 0x00);
    assert_eq!(wire::suffix_label(answer.names[0].suffix), "workstation");
    assert!(answer.names[0].active);
    assert!(!answer.names[0].group);

    assert_eq!(answer.names[1].name, "NETGETHOST");
    assert_eq!(answer.names[1].suffix, 0x20);
    assert_eq!(wire::suffix_label(answer.names[1].suffix), "file_server");

    assert_eq!(answer.names[2].name, "WORKGROUP");
    assert_eq!(answer.names[2].suffix, 0x1e);
    assert!(answer.names[2].group, "the workgroup is a group name");
    assert_eq!(
        wire::suffix_label(answer.names[2].suffix),
        "browser_service_elections"
    );

    assert_eq!(answer.names[3].name, "OLDNAME");
    assert!(!answer.names[3].active);
}

/// A refusal reaches the model as a named rcode, not as a bare number and not as a timeout.
#[test]
fn parses_a_negative_response() {
    let bytes = packet::encode_negative_response(
        0x1234,
        packet::OPCODE_QUERY,
        true,
        &packet::encode_name_field("NOSUCHHOST", 0x00, None).unwrap(),
        packet::RCODE_NAM_ERR,
    )
    .unwrap();

    let response = wire::parse_response(&bytes).expect("a negative response must parse");
    assert_eq!(response.trn_id, 0x1234);
    let wire::NbnsAnswer::Negative(answer) = response.answer else {
        panic!("expected a negative answer");
    };
    assert_eq!(answer.name, "NOSUCHHOST");
    assert_eq!(answer.rcode, packet::RCODE_NAM_ERR);
    assert_eq!(answer.rcode_name, "name_not_found");
}

/// The parser reports the transaction id so the caller can reject a mismatch, and refuses the
/// datagrams that must never be treated as an answer.
#[test]
fn refuses_datagrams_that_are_not_answers_and_reports_the_transaction_id() {
    // A request (R=0) is not an answer. Accepting one would let anything on the path inject a
    // name — and NBNS answers are cached, so that redirects the host's traffic for the TTL.
    assert!(
        wire::parse_response(&unhex(SAMBA_NAME_QUERY)).is_err(),
        "a request must not parse as a response"
    );

    let good = packet::encode_name_query_response(
        0x0aaa,
        packet::OPCODE_QUERY,
        false,
        &packet::encode_name_field("HOST", 0x00, None).unwrap(),
        &[packet::AddressEntry {
            flags: 0,
            address: "192.0.2.1".parse().unwrap(),
        }],
        60,
    )
    .unwrap();

    // The id is reported, not enforced here: matching is the caller's job (see `run_query` in
    // src/client/netbios_ns/mod.rs), and this is what makes a mismatch detectable at all.
    assert_eq!(wire::parse_response(&good).unwrap().trn_id, 0x0aaa);
    let mut wrong = good.clone();
    wrong[0] ^= 0xff;
    wrong[1] ^= 0xff;
    assert_eq!(wire::parse_response(&wrong).unwrap().trn_id, 0xf555);

    // Truncation at every interesting boundary.
    assert!(
        wire::parse_response(&good[..8]).is_err(),
        "header truncated"
    );
    assert!(
        wire::parse_response(&good[..good.len() - 3]).is_err(),
        "RDATA truncated"
    );

    // A success with nothing in it asserts nothing and must not read as an empty answer.
    let mut empty = good.clone();
    empty[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    assert!(wire::parse_response(&empty[..packet::HEADER_LEN]).is_err());
}

// ===========================================================================================
// Layer 3 — end to end through the real binary, LLM mocked
// ===========================================================================================

/// A raw UDP stand-in for an NBNS responder, so the tests can control exactly what comes back
/// — including the two things a real cooperating server will never do: answer with the wrong
/// transaction id, and say nothing at all.
///
/// It is spawned in the test process; the client runs in the NetGet binary and talks to it
/// over loopback.
/// Answers an NBSTAT question with `names` and `mac`; answers anything else with a
/// deliberately **mismatched** transaction id.
struct Responder {
    /// `(name, suffix, group)`
    names: Vec<(&'static str, u8, bool)>,
    mac: [u8; 6],
}

async fn start_responder(behaviour: Responder) -> E2EResult<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            let Ok(request) = packet::parse_request(&buffer[..n]) else {
                eprintln!("[RESPONDER] undecodable datagram of {n} octets from {peer}");
                continue;
            };
            let Responder { names, mac } = &behaviour;

            let reply = if request.qtype == packet::QTYPE_NBSTAT {
                let entries: Vec<packet::NodeName> = names
                    .iter()
                    .map(|(name, suffix, group)| packet::NodeName {
                        raw: packet::pad_netbios_name(name, *suffix).unwrap(),
                        flags: packet::NAME_FLAG_ACTIVE
                            | if *group { packet::NAME_FLAG_GROUP } else { 0 },
                    })
                    .collect();
                packet::encode_node_status_response(
                    request.header.trn_id,
                    &request.question_name.raw,
                    &entries,
                    *mac,
                )
            } else {
                // A well-formed answer to somebody else's question. The client must discard it
                // and go on waiting, which is what turns this into a timeout.
                packet::encode_name_query_response(
                    request.header.trn_id ^ 0xffff,
                    packet::OPCODE_QUERY,
                    false,
                    &request.question_name.raw,
                    &[packet::AddressEntry {
                        flags: 0,
                        address: "203.0.113.66".parse().unwrap(),
                    }],
                    3600,
                )
            };

            match reply {
                Ok(bytes) => {
                    let _ = socket.send_to(&bytes, peer).await;
                }
                Err(e) => eprintln!("[RESPONDER] could not build a reply: {e}"),
            }
        }
    });

    Ok(addr)
}

/// The two halves of NetGet, talking to each other: the client resolves a name against
/// NetGet's own NBNS server.
///
/// This is **same-project evidence** — it shows the encoder and the decoder agree, not that
/// either matches RFC 1002 — and it is why the client is rated Experimental. The independent
/// part of this suite is layer 1.
///
/// LLM calls: 2 on the server, 3 on the client.
#[tokio::test]
async fn resolves_a_name_against_netgets_own_nbns_server() -> E2EResult<()> {
    let server_config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via netbios_ns and answer name queries for NETGETTEST.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("listen on port")
            .and_instruction_containing("netbios_ns")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "netbios_ns",
                "instruction": "NETGETTEST<0x20> is 192.0.2.10. Refuse everything else."
            }]))
            .expect_calls(1)
            .and()
            // ONE rule that branches on the event. Two rules on `netbios_name_query` would be
            // first-match-wins: the first would answer everything and the second would report
            // zero calls.
            .on_event("netbios_name_query")
            .respond_with_actions_from_event(|e| {
                let name = e["name"].as_str().unwrap_or("");
                if name == "NETGETTEST" {
                    serde_json::json!([{
                        "type": "send_netbios_name_response",
                        "name": name,
                        // Echoed from the event: a server that mis-decoded the first-level
                        // encoding cannot produce the right suffix here.
                        "suffix": e["suffix"].as_u64().unwrap_or(0),
                        "addresses": ["192.0.2.10"],
                        "ttl": 3600,
                        "group": false
                    }])
                } else {
                    serde_json::json!([{
                        "type": "send_netbios_negative_response",
                        "rcode": "name_not_found"
                    }])
                }
            })
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;

    let remote = format!("127.0.0.1:{}", server.port);
    let client_config = NetGetConfig::new(format!(
        "Connect to {remote} via NetBIOS-NS and resolve NETGETTEST."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("NetBIOS-NS")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "NetBIOS-NS",
                "remote_addr": remote,
                "instruction": "Resolve NETGETTEST at suffix 0x20 and report the address."
            }]))
            .expect_calls(1)
            .and()
            .on_event("netbios_ns_connected")
            .respond_with_actions(serde_json::json!([{
                "type": "send_netbios_name_query",
                "name": "NETGETTEST",
                "suffix": 32
            }]))
            .expect_calls(1)
            .and()
            // This rule firing at all is the real assertion: it can only happen if a datagram
            // came back, carried the matching transaction id, and decoded.
            .on_event("netbios_name_response")
            .and_event_data_contains("addresses", "192.0.2.10")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(client_config).await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    client.stop().await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Node status parsed into names **with suffixes separated**, and — on the same client — a
/// reply carrying the wrong transaction id discarded, so the query times out normally.
///
/// The two are deliberately in one test: both need a responder that misbehaves on purpose, and
/// running them together keeps the whole file inside the LLM call budget.
///
/// LLM calls: 4 (open_client, connected, node status answer, timeout).
#[tokio::test]
async fn parses_a_node_status_reply_and_discards_a_mismatched_transaction_id() -> E2EResult<()> {
    let responder = start_responder(Responder {
        names: vec![
            ("NETGETHOST", 0x00, false),
            ("NETGETHOST", 0x20, false),
            ("WORKGROUP", 0x00, true),
        ],
        mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    })
    .await?;
    let remote = responder.to_string();

    let config = NetGetConfig::new(format!(
        "Connect to {remote} via NetBIOS-NS and enumerate the host."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("Connect to")
            .and_instruction_containing("NetBIOS-NS")
            .respond_with_actions(serde_json::json!([{
                "type": "open_client",
                "protocol": "NetBIOS-NS",
                "remote_addr": remote,
                "instruction": "List the host's NetBIOS names, then try to resolve MISSINGHOST.",
                // A short deadline so the timeout case does not dominate the run. Both keys
                // are declared by the protocol; an undeclared one would refuse to connect.
                "startup_params": {"query_timeout_secs": 2}
            }]))
            .expect_calls(1)
            .and()
            .on_event("netbios_ns_connected")
            .respond_with_actions(serde_json::json!([
                {"type": "send_netbios_node_status_query", "name": "*", "suffix": 0},
                {"type": "send_netbios_name_query", "name": "MISSINGHOST", "suffix": 0}
            ]))
            .expect_calls(1)
            .and()
            // The suffix must arrive as its own field. `"suffix":32` can only appear if the
            // raw 16-octet name list was split rather than rendered as text.
            .on_event("netbios_node_status_response")
            .and_event_data_contains("names", "\"suffix\":32")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
            // The responder DID answer this query — with somebody else's transaction id. A
            // client that failed to match on the id would raise `netbios_name_response` here
            // and this rule would report zero calls.
            .on_event("netbios_query_timeout")
            .and_event_data_contains("name", "MISSINGHOST")
            .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;

    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;

    // The discard is also visible directly: the client logs every datagram it throws away.
    client
        .wait_for_any(&["does not match the outstanding"], 10)
        .await;
    assert!(
        client
            .output_contains("does not match the outstanding")
            .await,
        "the mismatched reply must be logged as discarded, not silently dropped"
    );

    client.stop().await?;
    Ok(())
}

/// A sanity guard on the fixture itself: the stand-in responder really does answer a node
/// status question and really does mismatch anything else, without NetGet in the picture.
///
/// Without this, a bug in the fixture would look like a bug in the client.
#[tokio::test]
async fn the_stand_in_responder_behaves_as_the_tests_assume() -> E2EResult<()> {
    let responder = start_responder(Responder {
        names: vec![("PROBE", 0x00, false)],
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    })
    .await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut buffer = vec![0u8; 1500];

    socket
        .send_to(
            &wire::encode_node_status_query(0x7777, "*", 0).unwrap(),
            responder,
        )
        .await?;
    let (n, _) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await??;
    let response = wire::parse_response(&buffer[..n]).unwrap();
    assert_eq!(response.trn_id, 0x7777, "node status echoes the id");
    let wire::NbnsAnswer::NodeStatus(answer) = response.answer else {
        panic!("expected a node status answer");
    };
    assert_eq!(answer.names[0].name, "PROBE");
    assert_eq!(answer.mac_address, "00:11:22:33:44:55");

    socket
        .send_to(
            &wire::encode_name_query(0x7777, "ANYTHING", 0, false).unwrap(),
            responder,
        )
        .await?;
    let (n, _) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await??;
    assert_ne!(
        wire::parse_response(&buffer[..n]).unwrap().trn_id,
        0x7777,
        "a name query must come back with a deliberately wrong transaction id"
    );

    Ok(())
}
