//! What an NTP client gets when the LLM backend fails while the operator opted into LLM
//! control: a Kiss-o'-Death, not silence and not a usable time sample.
//!
//! This test used to assert the opposite — a stratum-2 answer carrying the true current time —
//! on the reasoning that the truth cannot be a lie in the operator's favour. That argument is
//! about the *content* of the reply and misses what the reply *is*: a stratum-2 packet is an
//! affirmative assertion that this server is a usable time source, and the client steps its
//! clock from it. An operator who pointed NTP at a model asked for the model to decide; when
//! the backend is unreachable, answering anyway on the server's own authority is a fail-open.
//!
//! RFC 5905 §7.4 gives NTP the one thing it needs here: a Kiss-o'-Death (stratum 0, LI 3, a
//! four-character kiss code) can never be mistaken for a time sample, so it fails closed —
//! while still being a *reply*, so the client backs off instead of polling a server it thinks
//! is merely slow. `RATE` says the backend is saturated, `INIT` that it is unavailable.
//!
//! The packet is decoded here byte by byte against the RFC's field layout rather than through
//! the server's own builder, so the test is evidence and not a tautology.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// The client's transmit timestamp, which must come back as the reply's origin timestamp.
const CLIENT_TRANSMIT: u64 = 0xE5F1_2345_89AB_CDEF;

/// NTP epoch (1900) is this many seconds before the Unix epoch (1970).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

#[tokio::test]
async fn test_ntp_answers_kiss_of_death_when_llm_fails() -> E2EResult<()> {
    // The instruction opts this server into LLM control; the mock then fails every request
    // (no matching rule -> HTTP 500), forcing the fail-closed path.
    let prompt = "listen on port {AVAILABLE_PORT} via ntp. Answer with the current time";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via ntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NTP",
                    "instruction": "Answer with the current time"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `ntp_request`: the mock answers 500, the LLM call fails, and the
        // server must fall back to the correct static time response.
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
    let n = tokio::time::timeout(Duration::from_secs(20), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "No NTP response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;

    assert_eq!(n, 48, "an NTP packet is 48 bytes");

    // The pcap oracle: Wireshark's own RFC 5905 decoder reads the packet this
    // server synthesised without asking the model. The fail-closed path is exactly
    // where a hand-built packet is least likely to have been looked at.
    crate::helpers::pcap_oracle::PcapOracle::udp("ntp")
        .to_server(&request)
        .from_server(&buf[..n])
        .assert_clean();

    let leap_indicator = (buf[0] >> 6) & 0x03;
    let version = (buf[0] >> 3) & 0x07;
    let mode = buf[0] & 0x07;
    assert_eq!(mode, 4, "mode must be 4 (server)");
    assert_eq!(version, 4, "the reply must use the client's NTP version");
    assert_eq!(
        leap_indicator, 3,
        "LI must be 3 (unsynchronised): together with stratum 0 this is what marks the packet \
         as a Kiss-o'-Death rather than a time sample"
    );
    assert_eq!(
        buf[1], 0,
        "stratum must be 0 - a Kiss-o'-Death. A stratum-2 reply here would be an affirmative, \
         usable time sample produced by a backend outage, which is the fail-open this test \
         exists to catch"
    );

    // The kiss code lives in the reference identifier (bytes 12-15). The mock returns HTTP
    // 500, which classifies as Unavailable rather than Overloaded, so INIT is the code.
    let kiss_code = std::str::from_utf8(&buf[12..16]).unwrap_or("????");
    assert_eq!(
        kiss_code, "INIT",
        "an unavailable backend must send the INIT kiss code (RATE is for saturation)"
    );

    // Origin timestamp (bytes 24-31) must be the client's transmit timestamp verbatim, or the
    // client discards the reply as unrelated to its request - which is silence again.
    let origin = u64::from_be_bytes(buf[24..32].try_into().expect("8 bytes"));
    assert_eq!(
        origin, CLIENT_TRANSMIT,
        "the client's transmit timestamp must be echoed as the origin timestamp"
    );

    // Transmit timestamp (bytes 40-47) must be a real, current clock reading.
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
        "the timestamps must still be real - a KoD with a garbage transmit time is a malformed \
         packet, and a client may drop it before reading the stratum \
         (transmit {transmit_secs} vs now {now_ntp})"
    );

    // The distinction has to survive in the log too: the wire says "do not use me" but not
    // *why*, so only the tag separates a saturated backend from a broken one.
    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "the backend failure must be tagged fail_closed_llm_error. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("decision=static_default_llm_error")),
        "static_default_llm_error named the old fail-open and must not reappear: the server no \
         longer answers a backend failure with a usable time sample"
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
