//! Wake-on-LAN against a real, independent third-party sender: the **`wakeonlan` Perl script**.
//!
//! # What this closes
//!
//! `src/server/wol/actions.rs` said, in as many words, that WOL is Experimental because "the
//! decoder has been validated only against packets this repository builds from the
//! specification - no third-party sender (wakeonlan, etherwake) was available to generate one".
//! `wakeonlan` is now on `PATH`, so that sentence is no longer true and this test is what makes
//! it false: the 102 bytes decoded below were assembled by a Perl script from 2000-odd that has
//! never seen NetGet, not by `magic_packet()` in the test next door.
//!
//! # What this does NOT close, and why WOL stays Experimental
//!
//! **Wake-on-LAN has no reply.** A magic packet is one datagram in one direction; the protocol
//! defines nothing to send back, and `wakeonlan` exits without reading. So this exercise can
//! only ever show that NetGet's *decoder* accepts a real sender's bytes — there is no session,
//! no round trip, and nothing NetGet emits that a third-party implementation ever inspects.
//!
//! That is a **codec test with a real generator**, not "works against real clients", and the
//! difference matters in the direction that bites: a decoder that is wrong by being too
//! *permissive* passes this test and every other test in this directory. `rss` was promoted on
//! a superficially similar argument — "fetch-and-parse *is* the protocol, so an independent
//! reader is the strongest evidence the protocol admits" — but there the independent
//! implementation was reading **NetGet's output**. Here it writes NetGet's input, and nothing
//! third-party ever judges anything NetGet produced. See `src/server/wol/CLAUDE.md`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// The MAC handed to `wakeonlan` on its command line, and the one the event must carry back.
const TARGET_MAC: &str = "00:11:22:33:44:55";

#[tokio::test]
async fn test_wol_decodes_a_packet_built_by_the_real_wakeonlan() -> E2EResult<()> {
    println!("\n=== E2E Test: Wake-on-LAN magic packet from the real `wakeonlan` ===");

    // The real sender IS the evidence — it is the whole reason this file exists separately
    // from `e2e_test.rs`, which builds its own packets. A machine without `wakeonlan` must say
    // so rather than report a silent pass, or this test quietly becomes a duplicate of the
    // synthetic one it was written to supersede.
    match std::process::Command::new("wakeonlan").arg("-v").output() {
        Ok(out) if out.status.success() => println!(
            "wakeonlan present: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ),
        Ok(out) => {
            return Err(format!(
                "`wakeonlan -v` exited {}: this test's whole point is driving the real \
                 third-party sender",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "wakeonlan not available ({e}): this test's whole point is having a real \
                 third-party implementation build the magic packet, and skipping it would \
                 leave WOL's decoder resting on packets this repository wrote for itself. \
                 Install it with `brew install wakeonlan` (or your distribution's wakeonlan \
                 package)."
            )
            .into())
        }
    }

    let prompt = "listen on port {AVAILABLE_PORT} via wol. Record every magic packet you see";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // The generator echoes the event's OWN fields back into the action, so the
            // assertions below are about what the server decoded out of wakeonlan's bytes
            // rather than about anything this test wrote.
            .on_event("wol_magic_packet_received")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "record_wake_request",
                    "target_mac": event["target_mac"].as_str().unwrap_or("missing"),
                    "host": "lab-nas",
                    "note": format!(
                        "transport={} offset={} password_length={}",
                        event["transport"].as_str().unwrap_or("missing"),
                        event["sync_offset"],
                        event["password_length"],
                    ),
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via wol")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "wol",
                    "instruction": "Record every magic packet you see"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("WOL listener on 127.0.0.1:{}", server.port);

    // `-i 127.0.0.1` overrides wakeonlan's 255.255.255.255 default (broadcast needs a route
    // and privileges we do not have and do not want); `-p` aims at the ephemeral test port,
    // since the real port 9 is privileged and `PrivilegedPort(9)` genuinely fires there.
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("wakeonlan")
            .arg("-i")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(server.port.to_string())
            .arg(TARGET_MAC)
            .output(),
    )
    .await
    .map_err(|_| "wakeonlan did not finish within 30s")??;

    println!(
        "wakeonlan said: {}{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    assert!(
        output.status.success(),
        "wakeonlan exited {} — it never put a packet on the wire, so nothing below is a \
         statement about NetGet",
        output.status
    );

    // The assertion: the model was handed OUR reading of THEIR bytes, and it matches. The
    // `target_mac` in the action came from the event, which came from `decode_magic_packet`
    // walking 102 bytes of Perl output.
    //
    // `sync_offset=0` and `transport=udp` are part of it: wakeonlan sends the magic packet as
    // the entire UDP payload with no header of its own, so a decoder that only ever found the
    // sync stream because the test had placed it at a known offset would show up here.
    server.wait_for_any(&["decision=model_accept"], 30).await;
    server.wait_for_mocks(30).await;

    let log = server.get_output().await.join("\n");
    assert!(
        log.contains(TARGET_MAC),
        "the MAC wakeonlan was asked to wake ({TARGET_MAC}) never appeared in the server's \
         output, so the decoder did not recover it from the real packet"
    );
    assert!(
        // The decoder's own INFO line (`src/server/wol/mod.rs`): offset, transport, password.
        log.contains("(offset 0, udp, password_length=0)"),
        "expected the event to describe wakeonlan's packet as a bare UDP payload at offset 0 \
         with no SecureON trailer"
    );

    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
