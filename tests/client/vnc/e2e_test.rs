//! E2E tests for the VNC client
//!
//! Each test starts a mocked NetGet VNC **server** and points a mocked NetGet VNC **client** at
//! it, so the whole exchange is determined and nothing depends on an external VNC host.
//!
//! All four tests were broken in the same three ways, and had been since they were written —
//! the same copy-paste rot found in the UDP and DNS client suites:
//!
//! 1. The rule meant to start the **server** answered with `open_client`. Even when it matched,
//!    no listener was ever opened.
//! 2. That `open_client` carried no `remote_addr`, which is required, so it was rejected with
//!    "LLM returned malformed action: open_client" before anything could happen.
//! 3. The client configs carried **no mock at all**, while still calling `verify_mocks()`.
//!
//! The matcher was `on_instruction_containing("vnc")` against prompts reading "via VNC", and
//! that comparison is a case-sensitive substring match, so it matched nothing either.
//!
//! `vnc_connected` firing on the client is the real assertion in every test: it can only happen
//! if the RFB handshake against the server actually completed. The server-side event mocks are
//! the other half — they are reachable only if the client's request crossed the wire.

mod vnc_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// A mocked VNC server that answers one event, then stays quiet.
    fn server_awaiting(event: &'static str, response: serde_json::Value) -> NetGetConfig {
        NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via VNC. Accept connections with no password. \
             Provide a 800x600 framebuffer with name 'NetGet Test VNC'.",
        )
        .with_mock(move |mock| {
            mock.on_instruction_containing("Listen on port")
                .and_instruction_containing("VNC")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "VNC",
                    "instruction": "Answer the client",
                    "startup_params": {
                        "width": 800,
                        "height": 600,
                        "desktop_name": "NetGet Test VNC"
                    }
                }]))
                .expect_calls(1)
                .and()
                // Reachable only if the client's message actually arrived.
                .on_event(event)
                .respond_with_actions(serde_json::json!([response]))
                .expect_calls(1)
                .and()
        })
    }

    /// The client half: connect, then run `action` once the RFB handshake completes.
    fn connecting_client(
        remote: String,
        instruction: &str,
        action: serde_json::Value,
    ) -> NetGetConfig {
        let instruction = instruction.to_string();
        let prompt_instruction = instruction.clone();
        NetGetConfig::new(format!(
            "Connect to {remote} via VNC with no password. {prompt_instruction}"
        ))
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("VNC")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_client",
                    "remote_addr": remote,
                    "protocol": "VNC",
                    "instruction": instruction
                }]))
                .expect_calls(1)
                .and()
                // Firing at all is the assertion: the RFB handshake completed.
                .on_event("vnc_connected")
                .respond_with_actions(serde_json::json!([action]))
                .expect_calls(1)
                .and()
        })
    }

    /// The handshake completes and the client's framebuffer request reaches the server.
    #[tokio::test]
    async fn test_vnc_client_connect_to_server() -> E2EResult<()> {
        let mut server = start_netget_server(server_awaiting(
            "vnc_framebuffer_update_request",
            serde_json::json!({
                "type": "vnc_render_display",
                "commands": [
                    {"type": "rect", "x": 0, "y": 0, "width": 800, "height": 600,
                     "color": "#101020"}
                ]
            }),
        ))
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = start_netget_client(connecting_client(
            format!("127.0.0.1:{}", server.port),
            "Request a framebuffer update after connecting.",
            serde_json::json!({"type": "request_framebuffer_update", "incremental": false}),
        ))
        .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A pointer event reaches the server.
    #[tokio::test]
    async fn test_vnc_client_pointer_event() -> E2EResult<()> {
        let mut server = start_netget_server(server_awaiting(
            "vnc_pointer_event",
            serde_json::json!({"type": "vnc_no_change"}),
        ))
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = start_netget_client(connecting_client(
            format!("127.0.0.1:{}", server.port),
            "Click the left button at 150,120.",
            serde_json::json!({
                "type": "send_pointer_event", "x": 150, "y": 120, "button_mask": 1
            }),
        ))
        .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A key event reaches the server.
    #[tokio::test]
    async fn test_vnc_client_key_event() -> E2EResult<()> {
        let mut server = start_netget_server(server_awaiting(
            "vnc_key_event",
            serde_json::json!({"type": "vnc_no_change"}),
        ))
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = start_netget_client(connecting_client(
            format!("127.0.0.1:{}", server.port),
            "Press the 'a' key.",
            serde_json::json!({"type": "send_key_event", "key": "a", "down": true}),
        ))
        .await?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;
        client.stop().await?;
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// VNC password authentication.
    ///
    /// Ignored because the server implements security type `None` only — there is no VNC-Auth
    /// (DES challenge/response) path for a password to exercise, so a test asserting one would
    /// assert a feature that does not exist. This is a missing feature, not a broken test;
    /// `src/server/vnc/CLAUDE.md` lists it under limitations. The previous reason claimed the
    /// auth was "simplified" and "may fail with strict servers", which implied it existed.
    #[tokio::test]
    #[ignore = "Server implements security type None only; VNC-Auth is not implemented, so there is nothing to authenticate against."]
    async fn test_vnc_client_with_password() -> E2EResult<()> {
        Ok(())
    }
}
