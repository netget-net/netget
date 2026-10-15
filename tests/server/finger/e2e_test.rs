//! End-to-end Finger (RFC 1288) tests.
//!
//! **Every test drives a raw TCP socket, and that is a limitation, not a preference.** The
//! real client is `finger(1)`, which is installed on this machine — but its usage is
//! `finger [-46gklmpsho] [user ...] [user@host ...]`: there is no port option, and
//! `user@host:port` is rejected outright ("nodename nor servname provided"). It resolves the
//! `finger` service and always connects to TCP 79, so pointing it at a test server means
//! binding a privileged port. That is why the protocol is rated `Experimental` and why there
//! is deliberately no `#[ignore]`d root test here: an ignored test proves nothing, and a
//! skip-when-missing gate is a silent pass.
//!
//! What a socket *can* prove is proven: the exact bytes on the wire, that the server closes
//! after one answer (a finger client reads until EOF, so this is the property a real client
//! would depend on most), and that a forwarding query is refused before the model is even
//! consulted.
mod finger_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Send one query and read to EOF.
    ///
    /// Reading to EOF rather than one `read()` is the point: RFC 1288 has the server close
    /// when its answer is finished, and this asserts it actually does. If the server kept the
    /// connection open — the WHOIS non-conformance next door — this would hang and the
    /// timeout would name it.
    async fn finger_query(addr: &str, query: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to FINGER server");

        stream
            .write_all(format!("{}\r\n", query).as_bytes())
            .await
            .expect("Failed to send query");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut response))
            .await
            .expect(
                "timed out reading to EOF - the server did not close after answering, which is \
             what every finger client waits for",
            )
            .expect("Failed to read response");

        String::from_utf8_lossy(&response).to_string()
    }

    /// A named user is answered with the conventional block, and the server hangs up.
    #[tokio::test]
    async fn test_finger_user_query() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via finger")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("finger")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "finger",
                            "instruction": "Answer a finger query for alice with a full record"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("finger_query")
                    .and_event_data_contains("username", "alice")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "send_finger_user",
                            "login": "alice",
                            "name": "Alice Smith",
                            "tty": "ttys002",
                            "idle": "5 minutes",
                            "login_time": "Mon Sep  1 09:12",
                            "office": "Room 101",
                            "office_phone": "x1234",
                            "shell": "/bin/sh",
                            "project": "Networking",
                            "plan": "Ship the finger server."
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let response = finger_query(&addr, "alice").await;

        // Byte-exact, not `contains`. This is the whole answer a finger client would read,
        // and the one thing a raw socket can prove better than a real client would: `Login:`
        // padded to column 40 before `Name:`, office and phone on one line, the presence line
        // assembled from login_time + tty + idle, `Project:`/`Plan:` under their own headings,
        // and CRLF everywhere (finger is a line protocol; a bare LF is a conformance bug).
        // src/server/finger/CLAUDE.md quotes this block, so the doc cannot drift from it.
        assert_eq!(
            response,
            "Login: alice                            Name: Alice Smith\r\n\
             Shell: /bin/sh\r\n\
             Office: Room 101, x1234\r\n\
             On since Mon Sep  1 09:12 on ttys002, idle 5 minutes\r\n\
             Project:\r\n\
             Networking\r\n\
             Plan:\r\n\
             Ship the finger server.\r\n",
            "the user block is not byte-for-byte what a finger client expects"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// `/W bob` sets `verbose`; a bare CRLF sets `list_all` and leaves `username` null.
    ///
    /// One rule branching on the event, not two rules on `finger_query` — two rules with no
    /// way to tell them apart is first-match-wins, and the second would report zero calls.
    #[tokio::test]
    async fn test_finger_verbose_and_list_all() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via finger")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("finger")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "finger",
                            "instruction": "Answer finger queries; list everyone for the empty query"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("finger_query")
                    .respond_with_actions_from_event(|e| {
                        let list_all = e["list_all"].as_bool().unwrap_or(false);
                        if list_all {
                            serde_json::json!([{
                                "type": "send_finger_response",
                                "text": "Login     Name          Tty\nalice     Alice Smith   ttys002\nbob       Bob Jones     ttys003"
                            }])
                        } else {
                            // Echo the flags back so the assertions below prove the server
                            // parsed `/W` and the login name, not just that it answered.
                            let login = e["username"].as_str().unwrap_or("unknown").to_string();
                            let verbose = e["verbose"].as_bool().unwrap_or(false);
                            serde_json::json!([{
                                "type": "send_finger_user",
                                "login": login,
                                "name": format!("verbose={verbose}"),
                                "shell": "/bin/sh"
                            }])
                        }
                    })
                    .expect_calls(2)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let verbose = finger_query(&addr, "/W bob").await;
        assert!(
            verbose.contains("Login: bob"),
            "'/W bob' should parse the login as 'bob': {verbose:?}"
        );
        assert!(
            verbose.contains("Name: verbose=true"),
            "'/W' should have set verbose on the event: {verbose:?}"
        );

        // A bare CRLF: RFC 1288's {C}-only query, meaning "everyone".
        let listing = finger_query(&addr, "").await;
        assert!(
            listing.contains("alice") && listing.contains("bob"),
            "the empty query should have been reported as list_all: {listing:?}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// `user@host` is refused, by default, before the model is consulted.
    ///
    /// The `expect_calls(0)` on the event rule is the load-bearing assertion: if forwarding
    /// ever started consulting the model, that rule would fire and verification would fail.
    /// Asserting only on the wire text would not catch it.
    #[tokio::test]
    async fn test_finger_forwarding_is_refused_by_default() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via finger")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("finger")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "finger",
                            "instruction": "Answer finger queries"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("finger_query")
                    .respond_with_actions(serde_json::json!([
                        {"type": "send_finger_error", "message": "this must never be reached"}
                    ]))
                    .expect_calls(0)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let response = finger_query(&addr, "alice@relay.example.invalid").await;

        assert_eq!(
            response, "Finger forwarding service denied.\r\n",
            "a forwarding query must get RFC 1288 3.2.1's refusal and nothing else"
        );
        assert!(
            !response.contains("this must never be reached"),
            "the model was consulted for a forwarding query: {response:?}"
        );
        server.wait_for_log("decision=forward_refused", 10).await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// With `answer_forward_queries: true` the query reaches the model carrying
    /// `forward_host` — and still nothing is contacted, because there is no outbound path.
    #[tokio::test]
    async fn test_finger_forwarding_answered_locally_when_opted_in() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via finger")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("finger")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "finger",
                            "startup_params": {"answer_forward_queries": true},
                            "instruction": "Answer forwarding queries locally"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("finger_query")
                    // Echo the forwarding host back, so the assertion proves the field
                    // reached the model rather than merely that something was answered.
                    .respond_with_actions_from_event(|e| {
                        let host = e["forward_host"].as_str().unwrap_or("<none>").to_string();
                        let user = e["username"].as_str().unwrap_or("<none>").to_string();
                        serde_json::json!([{
                            "type": "send_finger_response",
                            "text": format!("saw user={user} forward_host={host}")
                        }])
                    })
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        let response = finger_query(&addr, "alice@relay.example.invalid").await;

        assert_eq!(
            response, "saw user=alice forward_host=relay.example.invalid\r\n",
            "forward_host and username should both have reached the event: {response:?}"
        );
        server
            .wait_for_log("decision=forward_answered_locally", 10)
            .await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
