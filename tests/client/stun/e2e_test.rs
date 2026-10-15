//! E2E tests for the STUN client, through the real NetGet binary.
//!
//! These used to be three `#[ignore]`d tests pointed at `stun.l.google.com:19302`. Each was
//! wrong in three separate ways and none of them could fail: they contacted an external
//! endpoint (the repo's rule is localhost only), they called `verify_mocks()` having
//! configured **no** mocks so the call asserted nothing, and they were ignored — so the
//! whole file was, in the root CLAUDE.md's phrase, evidence of nothing.
//!
//! They are now one test against a NetGet **STUN server** on loopback, and it runs. The
//! server answers a Binding request mechanically with no LLM call of its own (see
//! `src/server/stun/`), so the only mocked calls are the two the client makes: the startup
//! command and the client's own `stun_connected` event, whose answer is what puts the
//! binding request on the wire.
//!
//! What this proves that `tests/client/stun/command_channel_test.rs` does not: the
//! instruction → `stun_connected` → `send_binding_request` chain works when the *model*
//! drives it, rather than when a test injects the action directly.

#![cfg(unix)]

mod stun_client_tests {
    use crate::helpers::*;

    /// The model is told to discover the external address; it answers `send_binding_request`;
    /// the client runs a real exchange against a local NetGet STUN server and reports back.
    ///
    /// LLM calls: 2 on the client (startup command, `stun_connected`), 1 on the server
    /// (startup command — its binding path is static and takes none).
    #[tokio::test]
    async fn stun_client_discovers_its_address_from_a_local_server() -> E2EResult<()> {
        // A NetGet STUN server with an EMPTY instruction: its binding responses are purely
        // mechanical, so nothing here depends on a second model answering correctly.
        let server_config = NetGetConfig::new_no_scripts(
            "listen on port {AVAILABLE_PORT} via stun",
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("via stun")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "STUN",
                        "instruction": ""
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(server_config).await?;
        server.wait_for_log("STUN receive loop started", 5).await?;
        let stun_addr = format!("127.0.0.1:{}", server.port);

        let client_config = NetGetConfig::new(format!(
            "Connect to {stun_addr} via STUN and discover my external address."
        ))
        .with_log_level("debug")
        .with_mock(move |mock| {
            mock.on_instruction_containing("via STUN")
                .and_instruction_containing("external address")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "protocol": "stun",
                        "remote_addr": stun_addr,
                        "instruction": "Discover the external address, then stop."
                    }
                ]))
                .expect_calls(1)
                .and()
                // The client's connected event. Answering it with send_binding_request is
                // what makes the exchange happen; a rule that never matched would leave the
                // client idle and the assertion below would fail on an empty log.
                .on_event("stun_connected")
                .respond_with_actions(serde_json::json!([
                    { "type": "send_binding_request" }
                ]))
                .expect_calls(1)
                .and()
                // The exchange's result comes back as stun_binding_response. Answer with
                // nothing: re-probing would loop, and first-match-wins means a second rule
                // on this event would never fire anyway.
                .on_event("stun_binding_response")
                .respond_with_actions(serde_json::json!([]))
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Wait for the condition, never a fixed sleep: the client logs the address it
        // discovered, and that line is the proof the whole chain ran.
        client
            .wait_for_any(&["discovered external address"], 30)
            .await;
        let output = client.get_output().await;
        assert!(
            output
                .iter()
                .any(|line| line.contains("discovered external address")),
            "the client should log the address it discovered from the local STUN server. \
             Output: {output:?}"
        );
        // The server reflects the client's own source address, which is on loopback.
        assert!(
            output
                .iter()
                .any(|line| line.contains("discovered external address: 127.0.0.1:")),
            "the discovered address must be the client's real source address as the local \
             server saw it. Output: {output:?}"
        );

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;

        Ok(())
    }
}
