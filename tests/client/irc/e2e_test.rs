//! E2E tests for the IRC client, against a NetGet IRC server.
//!
//! Two NetGet processes, each with its own mock Ollama: one runs the IRC server, the other the
//! IRC client. Both sides of every exchange are therefore observable, and the client's read
//! loop, registration detection, event emission and action execution are all exercised for
//! real.
//!
//! # These tests had never passed
//!
//! They were wired into `tests/client/mod.rs` in `1e842bf0` and failed at HEAD from that point
//! on, because every mock named an event or an action the code does not have:
//!
//! | Mock said | Code emits/accepts |
//! |---|---|
//! | server event `irc_data_received`, field `data` | `irc_message_received`, field `message` |
//! | client event `irc_client_connected` | `irc_connected` (the *static* is `IRC_CLIENT_CONNECTED_EVENT`; its `id` is not) |
//! | client event `irc_client_message_received` | `irc_message_received` |
//! | client action `register` | nothing — the client sends NICK/USER itself before the event fires |
//! | client `irc_..._message_received` with `message: "001"` | never fires: the 001 line is consumed to raise `irc_connected` |
//!
//! Nothing matched, so no mock ever answered, no `001` was ever sent, the client never
//! registered, and none of its events fired. The assertions could not see that — they checked
//! only that the output mentioned "connected" or "message", which the startup banner satisfies.
//! `verify_mocks()` was called and was the only thing that failed.
//!
//! The mocks below use the real vocabulary and the assertions now check the wire.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features irc \
//!     --test client -- client::irc --test-threads=100
//! ```

mod irc_client_tests {
    use crate::helpers::*;
    use std::time::Duration;

    /// Nick/user/realname are pinned rather than left to the client's defaults so the server's
    /// mocks can match on exact lines.
    fn open_client_action(port: u16, instruction: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "open_client",
            "remote_addr": format!("127.0.0.1:{}", port),
            "protocol": "IRC",
            "instruction": instruction,
            "startup_params": {
                "nickname": "testbot",
                "username": "testbot",
                "realname": "Test Bot"
            }
        })
    }

    /// Test IRC client connection and registration.
    ///
    /// LLM calls: 2 server (startup, USER) + 2 client (startup, irc_connected). NICK is
    /// answered by the server's mock too, so 5 in total.
    #[tokio::test]
    async fn test_irc_client_connect_and_register() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IRC. Accept client connections and log all messages."
        )
        .with_mock(|mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IRC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IRC",
                        "instruction": "Accept IRC clients and log messages"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: the client's NICK line. One `irc_message_received` per protocol
                // line, carrying `message`.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "NICK")
                .respond_with_actions(serde_json::json!([
                    {"type": "wait_for_more"}
                ]))
                .expect_calls(1)
                .and()
                // Mock 3: the client's USER line completes registration, so answer with 001 —
                // the line the client watches for.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "USER")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "send_irc_message",
                        "message": ":testserver 001 testbot :Welcome to the IRC Network"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to IRC at 127.0.0.1:{} with nickname testbot, wait for registration to complete.",
            server.port
        ))
        .with_mock(|mock| {
            mock
                // Mock 1: Client startup
                .on_instruction_containing("Connect to IRC")
                .and_instruction_containing("testbot")
                .respond_with_actions(serde_json::json!([
                    open_client_action(server.port, "Register with nickname testbot")
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: registration completed. The event id is `irc_connected`; NICK/USER
                // were already sent by the client, so there is nothing to do but acknowledge.
                .on_event("irc_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "wait_for_more"}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        // Registration is 4 messages over loopback plus two mocked LLM answers.
        client
            .wait_for_pattern("registration complete", Duration::from_secs(10))
            .await?;

        println!("✅ IRC client connected and registered");

        // The mocks are the real assertion: mock 2 firing exactly once proves the client
        // detected 001 and raised irc_connected, and mocks 2-3 on the server prove NICK and
        // USER actually went out on the wire.
        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test that the client joins a channel and sends a message when told to.
    #[tokio::test]
    async fn test_irc_client_join_and_message() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IRC. Accept all channel joins and log PRIVMSG commands."
        )
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IRC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IRC",
                        "instruction": "Accept channel joins and log PRIVMSG"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("irc_message_received")
                .and_event_data_contains("message", "NICK")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
                .on_event("irc_message_received")
                .and_event_data_contains("message", "USER")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_irc_message", "message": ":testserver 001 testbot :Welcome"}
                ]))
                .expect_calls(1)
                .and()
                // The client's JOIN, confirmed back so the client sees its own join.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "JOIN #test")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_irc_message", "message": ":testbot JOIN #test"}
                ]))
                .expect_calls(1)
                .and()
                // The message the client was told to send. This rule firing is the proof that
                // send_privmsg reached the wire.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "PRIVMSG #test :Hello, channel!")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to IRC at 127.0.0.1:{} with nickname testbot. After connecting, join #test and say 'Hello, channel!'",
            server.port
        ))
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Connect to IRC")
                .and_instruction_containing("testbot")
                .respond_with_actions(serde_json::json!([
                    open_client_action(server.port, "Register, join #test, and send message")
                ]))
                .expect_calls(1)
                .and()
                .on_event("irc_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "join_channel", "channel": "#test"}
                ]))
                .expect_calls(1)
                .and()
                // The JOIN confirmation comes back as a parsed message whose `command` is JOIN.
                .on_event("irc_message_received")
                .and_event_data_contains("command", "JOIN")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_privmsg", "target": "#test", "message": "Hello, channel!"}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        assert_eq!(client.protocol, "IRC", "Client should be IRC protocol");

        // Wait for the server to log the client's PRIVMSG rather than sleeping a fixed span.
        server
            .wait_for_pattern("Hello, channel!", Duration::from_secs(15))
            .await?;

        println!("✅ IRC client joined channel and sent message");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;

        Ok(())
    }

    /// Test that the client answers a message the server sends it.
    #[tokio::test]
    async fn test_irc_client_responds_to_messages() -> E2EResult<()> {
        let server_config = NetGetConfig::new(
            "Listen on port {AVAILABLE_PORT} via IRC. When a client joins #bot, send them a PRIVMSG saying 'Welcome bot!'"
        )
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Listen on port")
                .and_instruction_containing("IRC")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "IRC",
                        "instruction": "Send welcome PRIVMSG when client joins #bot"
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("irc_message_received")
                .and_event_data_contains("message", "NICK")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
                .on_event("irc_message_received")
                .and_event_data_contains("message", "USER")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_irc_message", "message": ":testserver 001 testbot :Welcome"}
                ]))
                .expect_calls(1)
                .and()
                // Confirm the join, then talk to the client unprompted.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "JOIN #bot")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_irc_message", "message": ":testbot JOIN #bot"},
                    {"type": "send_irc_message", "message": ":testserver PRIVMSG testbot :Welcome bot!"}
                ]))
                .expect_calls(1)
                .and()
                // The client's reply. This rule is the whole point of the test.
                .on_event("irc_message_received")
                .and_event_data_contains("message", "PRIVMSG #bot :Thanks!")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(server_config).await?;

        let client_config = NetGetConfig::new(format!(
            "Connect to IRC at 127.0.0.1:{} with nickname testbot. Join #bot and respond to any messages with 'Thanks!'",
            server.port
        ))
        .with_mock(|mock| {
            mock
                .on_instruction_containing("Connect to IRC")
                .and_instruction_containing("testbot")
                .respond_with_actions(serde_json::json!([
                    open_client_action(server.port, "Join #bot and respond to messages")
                ]))
                .expect_calls(1)
                .and()
                .on_event("irc_connected")
                .respond_with_actions(serde_json::json!([
                    {"type": "join_channel", "channel": "#bot"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("irc_message_received")
                .and_event_data_contains("command", "JOIN")
                .respond_with_actions(serde_json::json!([{"type": "wait_for_more"}]))
                .expect_calls(1)
                .and()
                // PRIVMSG is parsed, so `command` and `message` are separate fields — matching
                // on `message` alone would have to match the trailing text, not the verb.
                .on_event("irc_message_received")
                .and_event_data_contains("command", "PRIVMSG")
                .and_event_data_contains("message", "Welcome bot!")
                .respond_with_actions(serde_json::json!([
                    {"type": "send_privmsg", "target": "#bot", "message": "Thanks!"}
                ]))
                .expect_calls(1)
                .and()
        });

        let mut client = start_netget_client(client_config).await?;

        server
            .wait_for_pattern("Thanks!", Duration::from_secs(15))
            .await?;

        println!("✅ IRC client responded to server messages");

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last response routinely lands
        // after the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        server.stop().await?;
        client.stop().await?;

        Ok(())
    }
}
