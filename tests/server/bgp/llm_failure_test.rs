//! Regression test: when the operator has configured a dynamic peering policy and the backend
//! cannot be reached, BGP fails **closed** with a NOTIFICATION rather than admitting the peer.
//!
//! Two failure modes are being guarded against at once, and they are opposites:
//!
//! 1. **Fail open.** `bgp_open` used to collapse "the model answered nothing" and "the LLM call
//!    errored" into one `SendOutcome::Nothing`, which sends the *configured* OPEN and proceeds
//!    to OpenConfirm. With an admission policy in the instruction ("peer only with AS
//!    65000-65535"), a backend outage therefore admitted every neighbour the policy would have
//!    refused — the fail-open pattern the root CLAUDE.md calls the most dangerous in this
//!    codebase. Silence from a model that *was* consulted still takes the configured-OPEN path;
//!    only a failure to consult it at all refuses.
//!
//! 2. **Leaking the error.** A BGP NOTIFICATION has no free-text field at all, so the only thing
//!    the peer can be told is a `(code, subcode)` pair. The category is carried there and
//!    nowhere else; the error itself goes to the log and the status stream.
//!
//! The mock deliberately has **no rule for `bgp_open`**, so that request goes unmatched and the
//! harness answers HTTP 500 — a real backend failure as far as NetGet is concerned. The
//! unmatched request is recorded as a harness diagnostic, which is informational and does not
//! fail `verify_mocks()`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const BGP_MSG_OPEN: u8 = 1;
const BGP_MSG_NOTIFICATION: u8 = 3;
const BGP_MARKER: [u8; 16] = [0xff; 16];

fn build_bgp_open(
    my_as: u16,
    hold_time: u16,
    router_id: [u8; 4],
    four_octet_as: Option<u32>,
) -> Vec<u8> {
    let mut params = Vec::new();
    if let Some(asn) = four_octet_as {
        params.push(0x02); // Optional Parameter type 2: Capabilities
        params.push(0x06);
        params.push(0x41); // capability 65: four-octet AS
        params.push(0x04);
        params.extend_from_slice(&asn.to_be_bytes());
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&BGP_MARKER);
    msg.extend_from_slice(&[0, 0]); // length, patched below
    msg.push(BGP_MSG_OPEN);
    msg.push(4); // version
    msg.extend_from_slice(&my_as.to_be_bytes());
    msg.extend_from_slice(&hold_time.to_be_bytes());
    msg.extend_from_slice(&router_id);
    msg.push(params.len() as u8);
    msg.extend_from_slice(&params);
    let msg_len = msg.len() as u16;
    msg[16..18].copy_from_slice(&msg_len.to_be_bytes());
    msg
}

async fn read_bgp_message(stream: &mut TcpStream) -> E2EResult<(u8, Vec<u8>)> {
    let mut header = [0u8; 19];
    stream.read_exact(&mut header).await?;
    if header[..16] != BGP_MARKER {
        return Err("Invalid BGP marker".into());
    }
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    if !(19..=4096).contains(&length) {
        return Err(format!("BGP message length {length} out of range").into());
    }
    let mut full = vec![0u8; length];
    full[..19].copy_from_slice(&header);
    if length > 19 {
        stream.read_exact(&mut full[19..]).await?;
    }
    Ok((header[18], full))
}

/// RFC 4271 section 6.7 / RFC 4486 section 4.
const ERR_CEASE: u8 = 6;
const SUB_CEASE_CONNECTION_REJECTED: u8 = 5;

#[tokio::test]
async fn test_bgp_open_fails_closed_when_the_backend_errors() -> E2EResult<()> {
    let config =
        NetGetConfig::new_no_scripts("listen on port {AVAILABLE_PORT} via bgp").with_mock(|mock| {
            mock
                // Startup only. The instruction is a peering *policy*, which is what makes the
                // fail-open case dangerous: it must never be bypassed by an outage. It contains
                // no "bgp" substring, so this rule cannot also swallow the event request.
                .on_instruction_containing("bgp")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "BGP",
                    "instruction": "Peer only with neighbours in AS 65000-65535."
                }]))
                .expect_calls(1)
                .and()
            // No `bgp_open` rule on purpose: the request goes unmatched, the harness answers
            // HTTP 500, and NetGet sees a backend failure.
        });

    let server = start_netget_server(config).await?;

    let mut client = timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("127.0.0.1:{}", server.port)),
    )
    .await??;

    // A peer that the policy might well have accepted — the point is that nobody got to decide.
    client
        .write_all(&build_bgp_open(65000, 180, [192, 168, 1, 100], Some(65000)))
        .await?;

    // The backend is down, so the policy could not be evaluated. The peer must get a
    // NOTIFICATION, not our configured OPEN. Generous timeout: `call_llm` retries first.
    let (msg_type, msg) = timeout(Duration::from_secs(60), read_bgp_message(&mut client)).await??;
    assert_eq!(
        msg_type, BGP_MSG_NOTIFICATION,
        "the peering policy could not be evaluated, so the session must be refused; got message \
         type {msg_type} (type 1 would mean the configured OPEN went out and the peer was \
         admitted despite the policy never running)"
    );
    assert!(
        msg.len() >= 21,
        "a NOTIFICATION carries at least a code and a subcode, got {} octets",
        msg.len()
    );
    assert_eq!(msg[19], ERR_CEASE, "expected Cease");
    assert_eq!(
        msg[20], SUB_CEASE_CONNECTION_REJECTED,
        "a backend error that is not saturation is a rejection, not a resource condition; \
         RFC 4486 subcode 8 (Out of Resources) is reserved for the overloaded category so a \
         peer can tell the two apart and back off appropriately"
    );

    // The NOTIFICATION carries nothing but the two octets asserted above — there is no text
    // field in which an internal error could have been leaked.
    assert_eq!(
        msg.len(),
        21,
        "no data was supplied for this NOTIFICATION, so nothing derived from the error can be \
         on the wire; found {} extra octets",
        msg.len() - 21
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
