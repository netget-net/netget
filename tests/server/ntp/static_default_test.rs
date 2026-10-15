//! Regression test: an NTP time request is answered CORRECTLY with ZERO LLM calls.
//!
//! A normal time response is mechanical — stratum 2, current-time timestamps, and the client's
//! transmit timestamp echoed as the origin — so when the operator gives neither a server
//! instruction nor an event handler, the server must answer statically and never consult the
//! model. The mock has an `ntp_request` rule with `expect_calls(0)`: if the mechanical path
//! ever reaches the LLM, that rule fires and `verify_mocks()` fails.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

const CLIENT_TRANSMIT: u64 = 0xC1A2_B3C4_D5E6_F708;
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

#[tokio::test]
async fn test_ntp_time_response_needs_no_llm() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via ntp";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // Startup: the only legitimate LLM call. The resulting server has an EMPTY
            // instruction, so the request path is purely static.
            .on_instruction_containing("via ntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NTP",
                    "instruction": ""
                }
            ]))
            .expect_calls(1)
            .and()
            // If the mechanical time path ever calls the LLM, this rule fires and the
            // expect_calls(0) assertion fails.
            .on_event("ntp_request")
            .respond_with_actions(serde_json::json!([
                { "type": "send_ntp_time_response", "stratum": 2 }
            ]))
            .expect_calls(0)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A minimal NTPv4 client request: LI=0, VN=4, Mode=3.
    let mut request = vec![0u8; 48];
    request[0] = (4 << 3) | 3;
    request[40..48].copy_from_slice(&CLIENT_TRANSMIT.to_be_bytes());

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(&request).await?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
        .await
        .map_err(|_| "No static NTP response within 10s")??;

    assert_eq!(n, 48, "an NTP packet is 48 bytes");

    // The pcap oracle: Wireshark's own RFC 5905 decoder reads the packet this
    // server synthesised without asking the model. The fail-closed path is exactly
    // where a hand-built packet is least likely to have been looked at.
    crate::helpers::pcap_oracle::PcapOracle::udp("ntp")
        .to_server(&request)
        .from_server(&buf[..n])
        .assert_clean();

    let version = (buf[0] >> 3) & 0x07;
    let mode = buf[0] & 0x07;
    assert_eq!(mode, 4, "mode must be 4 (server)");
    assert_eq!(version, 4, "the reply must use the client's NTP version");
    assert_eq!(buf[1], 2, "the static default answers as stratum 2");

    let origin = u64::from_be_bytes(buf[24..32].try_into().expect("8 bytes"));
    assert_eq!(
        origin, CLIENT_TRANSMIT,
        "the client's transmit timestamp must be echoed as the origin timestamp"
    );

    let transmit = u64::from_be_bytes(buf[40..48].try_into().expect("8 bytes"));
    assert_ne!(
        transmit, 0,
        "the transmit timestamp must be a real clock reading"
    );
    let transmit_secs = (transmit >> 32) as u64;
    let now_ntp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + NTP_UNIX_OFFSET;
    assert!(
        transmit_secs.abs_diff(now_ntp) < 300,
        "the static default must report the true current time (transmit {transmit_secs} vs now {now_ntp})"
    );

    // Asserts the ntp_request rule was hit 0 times: the mechanical path took NO LLM call.
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
