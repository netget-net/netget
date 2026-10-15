//! Every NTP request leaves a `decision=` token in the log, and the token tells the truth
//! about what the client received.
//!
//! This test was written to pin an awkwardness that no longer exists, and the history is the
//! useful part. NTP used to answer a backend failure with the mechanical stratum-2 time
//! response — an affirmative, usable time sample the client sets its clock from — so the
//! failure could not honestly be tagged `fail_closed_*` and was tagged
//! `decision=static_default_llm_error` instead. This file asserted that pairing, and said in
//! as many words that if the wire behaviour ever became a Kiss-o'-Death the stratum assertion
//! would fail first so the token had to be revisited in the same change. That is what
//! happened: `actions::build_kod_packet` was wired up, the fail-open closed, and the token
//! became `fail_closed_llm_error` / `fail_closed_llm_overloaded`.
//!
//! So what this test now pins is the *converse* obligation. `fail_closed_*` is a claim that
//! the peer was denied, and `grep decision=fail_closed` — the one diagnostic this repo
//! teaches — is only worth running if that claim is true. Both halves are asserted together
//! because either alone is meaningless: the log must carry the tag, and the wire must carry a
//! packet no client will take time from.
//!
//! See `src/server/ntp/CLAUDE.md`, "Failure behaviour".

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::net::UdpSocket;

/// The client's transmit timestamp, which must come back as the reply's origin timestamp or
/// a real client discards the reply as unrelated to its request.
const CLIENT_TRANSMIT: u64 = 0xD4C3_B2A1_1234_5678;

#[tokio::test]
async fn test_ntp_llm_failure_is_tagged_fail_closed_and_denies_on_the_wire() -> E2EResult<()> {
    // A non-empty instruction is what opts the server into LLM control; without it NTP
    // answers statically and never calls the model at all.
    let prompt = "listen on port {AVAILABLE_PORT} via ntp. Report the time as stratum 1";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via ntp")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NTP",
                    "instruction": "Report the time as stratum 1"
                }
            ]))
            .expect_calls(1)
            .and()
        // Deliberately NO rule for `ntp_request`: the mock answers HTTP 500, the
        // retry/repair loop exhausts and `call_llm` returns Err. That is the backend-failure
        // path, the same shape as a real outage.
    });

    let server = start_netget_server(config).await?;

    let mut request = vec![0u8; 48];
    request[0] = (4 << 3) | 3; // LI 0, VN 4, Mode 3 (client)
    request[40..48].copy_from_slice(&CLIENT_TRANSMIT.to_be_bytes());

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(format!("127.0.0.1:{}", server.port)).await?;
    socket.send(&request).await?;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(30), socket.recv(&mut buf))
        .await
        .map_err(|_| {
            "no NTP reply within 30s - failing closed means sending a Kiss-o'-Death, not going \
             silent; silence looks like a merely slow server and the client keeps polling"
        })??;
    assert_eq!(n, 48, "an NTP packet is 48 bytes");

    // The wire half: what came back really is a denial, which is what makes `fail_closed_*`
    // an honest token below.
    assert_eq!(buf[0] & 0x07, 4, "mode must be 4 (server)");
    assert_eq!(
        (buf[0] >> 6) & 0x03,
        3,
        "LI must be 3 (unsynchronised) - half of what marks a Kiss-o'-Death"
    );
    assert_eq!(
        buf[1], 0,
        "stratum must be 0 (Kiss-o'-Death). If this ever becomes 2 again the server is handing \
         out usable time samples on backend failure, and the fail_closed_* token asserted below \
         would be reporting a denial that never happened"
    );
    let origin = u64::from_be_bytes(buf[24..32].try_into().expect("8 bytes"));
    assert_eq!(
        origin, CLIENT_TRANSMIT,
        "the client's transmit timestamp must be echoed, or the client discards the reply as \
         unrelated to its request and the denial never lands"
    );

    // The log half. The wire says "do not use me" but not why, so only the tag separates a
    // saturated backend from a broken one.
    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;

    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure must be tagged so an operator can find it. Output was:\n{}",
        lines.join("\n")
    );

    // The old token named the fail-open. Its reappearance would mean the affirmative
    // stratum-2 fallback is back on this path.
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("decision=static_default_llm_error")),
        "static_default_llm_error named the behaviour where a backend outage still answered \
         with a usable time sample; it must not come back. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
