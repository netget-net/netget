//! What an SNMP manager gets when the LLM backend fails: a Response PDU with genErr(5).
//!
//! SNMP runs over UDP, but it is not the `udp` case: every request carries a request-id, so a
//! reply is unambiguously the answer to *this* request and cannot be misread as some other
//! traffic. Silence means the manager retries until its own timeout and then reports the agent
//! as down, which is not what happened.
//!
//! The status has to be non-zero. A Response PDU with error-status 0 means "the varbinds are
//! the answer", so an empty one would read as "that OID has no value" - a statement about the
//! managed object rather than about the agent. genErr(5) is RFC 1157 / RFC 3416's generic
//! "could not produce this response".
//!
//! The request is built and the response decoded here from the ASN.1 BER structure in the
//! RFCs, not with our own codec: `SNMPv2-PDU ::= SEQUENCE { version INTEGER, community OCTET
//! STRING, data [2] IMPLICIT SEQUENCE { request-id, error-status, error-index, varbinds } }`.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

/// BER: tag, definite short-form length, value. Every field here is well under 128 bytes.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128, "short-form length only");
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

/// A v2c GetRequest for sysDescr.0 with community "public".
fn build_get_request(request_id: i32) -> Vec<u8> {
    // 1.3.6.1.2.1.1.1.0 - the first subidentifier packs 1.3 into 40*1+3 = 0x2B.
    let sys_descr = [0x2Bu8, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

    let mut varbind = Vec::new();
    varbind.extend_from_slice(&tlv(0x06, &sys_descr)); // OID
    varbind.extend_from_slice(&tlv(0x05, &[])); // NULL value
    let varbind = tlv(0x30, &varbind);
    let varbind_list = tlv(0x30, &varbind);

    let mut pdu = Vec::new();
    pdu.extend_from_slice(&tlv(0x02, &request_id.to_be_bytes())); // request-id
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-status
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-index
    pdu.extend_from_slice(&varbind_list);
    let pdu = tlv(0xA0, &pdu); // [0] GetRequest-PDU

    let mut message = Vec::new();
    message.extend_from_slice(&tlv(0x02, &[0x01])); // version 1 = v2c
    message.extend_from_slice(&tlv(0x04, b"public")); // community
    message.extend_from_slice(&pdu);
    tlv(0x30, &message)
}

/// Read one TLV at `pos`, returning (tag, value range start, value range end, next position).
fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *buf.get(pos)?;
    let len_byte = *buf.get(pos + 1)?;
    // Long-form lengths are legal BER but nothing this small emits one.
    if len_byte & 0x80 != 0 {
        return None;
    }
    let start = pos + 2;
    let end = start + len_byte as usize;
    if end > buf.len() {
        return None;
    }
    Some((tag, start, end, end))
}

/// Pull (request-id, error-status) out of an SNMP Response message.
fn decode_response(buf: &[u8]) -> Option<(i64, i64)> {
    let (tag, start, _end, _) = read_tlv(buf, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, _, after_version) = read_tlv(buf, start)?;
    let (_, _, _, after_community) = read_tlv(buf, after_version)?;
    let (pdu_tag, pdu_start, _pdu_end, _) = read_tlv(buf, after_community)?;
    // [2] IMPLICIT - GetResponse-PDU.
    if pdu_tag != 0xA2 {
        return None;
    }
    let (_, rid_s, rid_e, after_rid) = read_tlv(buf, pdu_start)?;
    let (_, st_s, st_e, _) = read_tlv(buf, after_rid)?;

    let as_int = |bytes: &[u8]| -> i64 {
        let mut v: i64 = if bytes.first().copied().unwrap_or(0) & 0x80 != 0 {
            -1
        } else {
            0
        };
        for b in bytes {
            v = (v << 8) | (*b as i64);
        }
        v
    };
    Some((as_int(&buf[rid_s..rid_e]), as_int(&buf[st_s..st_e])))
}

#[tokio::test]
async fn test_snmp_answers_gen_err_when_llm_fails() -> E2EResult<()> {
    let port = 0u16;
    let prompt = format!("listen on port {port} via snmp. Answer sysDescr");

    let config = NetGetConfig::new_no_scripts(&prompt).with_mock(|mock| {
        mock.on_instruction_containing("via snmp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": port,
                    "base_stack": "SNMP",
                    "instruction": "Answer sysDescr"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `snmp_request`.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(800)).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;

    const REQUEST_ID: i32 = 0x1234_5678;
    socket.send(&build_get_request(REQUEST_ID)).await?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(25), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No SNMP response within 25s - the agent went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    buf.truncate(n);
    println!("SNMP response ({n} bytes): {:02x?}", &buf);

    // The pcap oracle. `decode_response` below is this file's own BER walker and it
    // reads exactly the two fields it wants; Wireshark's `snmp` dissector decodes the
    // whole message and fails on a length byte that does not match its contents,
    // which is the characteristic defect of a hand-written BER encoder answering on
    // an error path nobody exercises.
    crate::helpers::pcap_oracle::PcapOracle::udp("snmp")
        .to_server(&build_get_request(REQUEST_ID))
        .from_server(&buf)
        .assert_clean();

    let (request_id, error_status) =
        decode_response(&buf).ok_or("the reply was not a decodable SNMP Response message")?;

    assert_eq!(
        request_id, REQUEST_ID as i64,
        "the Response must echo the request-id or the manager cannot correlate it"
    );
    assert_ne!(
        error_status, 0,
        "error-status 0 means the varbinds ARE the answer, so an empty one would report the \
         OID as having no value rather than the agent as having failed"
    );
    assert_eq!(error_status, 5, "expected genErr(5)");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
