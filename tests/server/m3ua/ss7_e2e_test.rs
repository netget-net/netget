//! The SS7 layer end to end through a real NetGet process and the mocked model, over the lab
//! TCP transport (so it runs on any host): jSS7's captured MAP and CAP requests go in, the
//! model's structured answers come out as TCAP, and for MAP the octets are jSS7's own answer.
//!
//! Five LLM calls: startup, ASPUP, ASPAC, the MAP dialogue, the CAP dialogue. The M3UA framing is
//! written here from RFC 4666; the SCCP payloads are jSS7's.

use super::ss7_support::{jss7, unhex};
use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

fn m3ua(class: u8, msg_type: u8, params: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, value) in params {
        body.extend_from_slice(&tag.to_be_bytes());
        body.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        body.extend_from_slice(value);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    let mut out = vec![1, 0, class, msg_type];
    out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// DATA from jSS7's point code 1 to 2, SI 3, NI 2, SLS 1, routing context 100.
fn data(sccp_hex: &str) -> Vec<u8> {
    let mut pd = vec![0, 0, 0, 1, 0, 0, 0, 2, 3, 2, 0, 1];
    pd.extend(unhex(sccp_hex));
    m3ua(
        1,
        1,
        &[(0x0006, 100u32.to_be_bytes().to_vec()), (0x0210, pd)],
    )
}

/// Read one message: (class, type, Protocol Data value if any).
async fn read(s: &mut TcpStream) -> E2EResult<(u8, u8, Option<Vec<u8>>)> {
    let mut h = [0u8; 8];
    timeout(Duration::from_secs(60), s.read_exact(&mut h)).await??;
    let len = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
    let mut body = vec![0u8; len - 8];
    s.read_exact(&mut body).await?;
    let mut pos = 0;
    let mut pd = None;
    while pos + 4 <= body.len() {
        let tag = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let l = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        if tag == 0x0210 {
            pd = Some(body[pos + 4..pos + l].to_vec());
        }
        pos += l.div_ceil(4) * 4;
    }
    Ok((h[2], h[3], pd))
}

#[tokio::test]
async fn the_model_answers_jss7s_map_and_camel_requests_through_netget() -> E2EResult<()> {
    let config = NetGetConfig::new(
        "listen on port 0 via m3ua over the tcp lab transport as an HLR and gsmSCF",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("m3ua")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server", "port": 0, "base_stack": "M3UA",
                "instruction": "You are an HLR and a gsmSCF behind this SGP.",
                "startup_params": {"transport": "tcp", "routing_context": 100}
            }]))
            .expect_calls(1)
            .and()
            .on_event("m3ua_asp_up_received")
            .respond_with_actions(serde_json::json!([{"type": "send_m3ua_asp_up_ack"}]))
            .expect_calls(1)
            .and()
            .on_event("m3ua_asp_active_received")
            .respond_with_actions(serde_json::json!([
                {"type": "send_m3ua_asp_active_ack", "routing_context": 100},
                {"type": "send_m3ua_notify", "status_type": "as_state_change",
                 "status_info": "as_active", "routing_context": 100}]))
            .expect_calls(1)
            .and()
            // The dialogue id and the decoded MSISDN come off the event: the model is answering
            // what jSS7 asked, not a canned dialogue.
            .on_event("m3ua_map_received")
            .respond_with_actions_from_event(|e| {
                let msisdn = e["components"][0]["argument"]["msisdn"]["digits"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(msisdn, "31628838002");
                serde_json::json!([{
                    "type": "send_map_result", "dialogue_id": e["dialogue_id"],
                    "invoke_id": e["awaiting_answer_to"][0],
                    "operation": "sendRoutingInfoForSM",
                    "result": {"imsi": "001010123456789", "network_node_number": "31600000001"}
                }])
            })
            .expect_calls(1)
            .and()
            .on_event("m3ua_cap_received")
            .respond_with_actions_from_event(|e| {
                serde_json::json!([{
                    "type": "send_cap_operations", "dialogue_id": e["dialogue_id"],
                    "operations": [{"operation": "connect",
                                    "destination_routing_address": "31677777777"}]
                }])
            })
            .expect_calls(1)
            .and()
    });
    let server = start_netget_server(config).await?;
    server.wait_for_log("M3UA SGP listening on", 15).await?;
    let mut asp = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;

    asp.write_all(&m3ua(3, 1, &[])).await?;
    let (c, t, _) = read(&mut asp).await?;
    assert_eq!((c, t), (3, 4), "ASPUP ACK");
    asp.write_all(&m3ua(4, 1, &[(0x0006, 100u32.to_be_bytes().to_vec())]))
        .await?;
    let (c, t, _) = read(&mut asp).await?;
    assert_eq!((c, t), (4, 3), "ASPAC ACK");
    let (c, t, _) = read(&mut asp).await?;
    assert_eq!((c, t), (0, 1), "NTFY AS-ACTIVE");

    asp.write_all(&data(jss7::SRI_SM_BEGIN)).await?;
    let (c, _, pd) = read(&mut asp).await?;
    assert_eq!(c, 1);
    let pd = pd.ok_or("DATA without Protocol Data")?;
    assert_eq!(
        &pd[..12],
        &[0, 0, 0, 2, 0, 0, 0, 1, 3, 2, 0, 1],
        "routing label swapped"
    );
    assert_eq!(
        hex::encode(&pd[12..]),
        jss7::SRI_SM_END,
        "jSS7's own answer, octet for octet"
    );

    asp.write_all(&data(jss7::IDP_BEGIN)).await?;
    let (_, _, pd) = read(&mut asp).await?;
    let ud = netget::server::m3ua::sccp::decode(&pd.ok_or("no Protocol Data")?[12..])
        .map_err(|e| e.to_string())?;
    let tc =
        netget::server::m3ua::tcap::TcMessage::decode(&ud.data).map_err(|(_, e)| e.to_string())?;
    assert_eq!(tc.kind, netget::server::m3ua::tcap::TcKind::End);
    // Connect, destinationRoutingAddress 31677777777 as an ISUP called party number.
    let comp = hex::encode(tc.components[0].encode());
    assert!(
        comp.contains("020114"),
        "operation code 20 (connect): {comp}"
    );
    // destinationRoutingAddress [0] { OCTET STRING: odd, international (0x84), ISDN (0x10),
    // 31677777777 in BCD with a 0 filler }.
    assert!(comp.contains("a00a04088410137677777707"), "{comp}");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
