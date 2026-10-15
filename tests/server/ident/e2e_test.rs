//! End-to-end Ident (RFC 1413) tests.
//!
//! **Every test here drives a raw `TcpStream`, and that is the ceiling on what this suite can
//! prove.** There is no runnable third-party ident *client* to point at the server: crates.io
//! has no RFC 1413 client, macOS ships no `ident`/`identd` client binary and Homebrew has no
//! formula for one, and PyPI has nothing working. The realistic real-world client is an IRC
//! daemon (`ngircd` links `libident`), but every ident client hardcodes destination port 113
//! — RFC 1413 has no notion of a configurable server port — so none can be aimed at an
//! ephemeral loopback port, and 113 needs root. A client written inside this file is, in this
//! repo's own words, "an independent reading of the spec, not an independent implementation",
//! which is why the protocol is rated `Experimental` and not `Beta`. See
//! `tests/server/ident/CLAUDE.md`.
//!
//! What the raw socket *can* prove is everything below the maturity bar, and the three
//! properties that actually break clients are each pinned here:
//!
//! * the reply echoes the queried port pair **verbatim** — a client matches its query to a
//!   reply by that pair, so getting it wrong is indistinguishable from no reply at all;
//! * whitespace around the comma parses, because that is what the grammar allows and what
//!   real queries carry;
//! * a port outside `1..=65535` is refused **without an LLM call**. That is asserted by
//!   count, not by inspection: the `ident_query` rule expects exactly one call while four
//!   malformed queries are sent, so any of them reaching the model fails `verify_mocks()`.
mod ident_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Send one query and read until EOF.
    ///
    /// Reading to EOF rather than to the first newline is deliberate: RFC 1413 has the server
    /// close once it has answered, so a server that replied but never closed would hang here
    /// and the timeout would name it.
    async fn ident_query(addr: &str, query: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to Ident server");

        stream
            .write_all(query.as_bytes())
            .await
            .expect("Failed to send ident query");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .expect("Timeout reading ident reply - did the server close after answering?")
            .expect("Failed to read ident reply");

        String::from_utf8_lossy(&response).to_string()
    }

    /// The success path, and the property everything else depends on: the reply carries back
    /// exactly the port pair that was queried.
    ///
    /// The mock builds its answer from the event rather than from a literal, which is the
    /// only way the assertion means anything — a hardcoded `6193 , 23` in the mock would pass
    /// even if the event carried the wrong ports.
    #[tokio::test]
    async fn test_ident_userid_reply_echoes_the_port_pair() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via ident")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("ident")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "ident",
                            "instruction": "Answer every ident query with the userid stjohns on UNIX"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("ident_query")
                    .respond_with_actions_from_event(|e| {
                        serde_json::json!([{
                            "type": "send_ident_userid",
                            // Echoed from the event, never hardcoded.
                            "server_port": e["server_port"],
                            "client_port": e["client_port"],
                            "opsys": "UNIX",
                            "userid": "stjohns"
                        }])
                    })
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        // RFC 1413's own worked example.
        let reply = ident_query(&addr, "6193 , 23\r\n").await;

        assert_eq!(
            reply, "6193 , 23 : USERID : UNIX : stjohns\r\n",
            "the reply must be the RFC 1413 USERID line with the queried pair echoed verbatim"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The RFC 1413 error tokens, and the last line of defence on the port pair.
    ///
    /// One rule branching on the event, not four rules on the same event: rules are
    /// first-match-wins, so four indistinguishable `ident_query` rules would send every query
    /// to the first and report zero calls for the rest.
    ///
    /// The fourth query is the interesting one. The handler answers it with a **deliberately
    /// wrong** port pair — the shape of mistake a model makes when it invents the numbers
    /// instead of echoing them — and the server must rewrite the pair to the one queried.
    /// Without that, the reply is unmatchable and the client sees a timeout.
    #[tokio::test]
    async fn test_ident_error_tokens_and_port_pair_correction() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via ident")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("ident")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "ident",
                            "instruction": "Refuse ident queries, choosing the error token by the client port"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("ident_query")
                    .respond_with_actions_from_event(|e| {
                        // The client port selects the token, so one rule covers every case
                        // and each answer is provably derived from its own query.
                        let client_port = e["client_port"].as_u64().unwrap_or(0);
                        let token = match client_port {
                            1 => "NO-USER",
                            2 => "HIDDEN-USER",
                            _ => "UNKNOWN-ERROR",
                        };
                        // Query 4 answers with an invented pair instead of the queried one.
                        let (server_port, echoed_client_port) = if client_port == 4 {
                            (serde_json::json!(9999), serde_json::json!(8888))
                        } else {
                            (e["server_port"].clone(), e["client_port"].clone())
                        };
                        serde_json::json!([{
                            "type": "send_ident_error",
                            "server_port": server_port,
                            "client_port": echoed_client_port,
                            "error": token
                        }])
                    })
                    .expect_calls(4)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        for (client_port, token) in [(1u16, "NO-USER"), (2, "HIDDEN-USER"), (3, "UNKNOWN-ERROR")] {
            let reply = ident_query(&addr, &format!("113 , {}\r\n", client_port)).await;
            assert_eq!(
                reply,
                format!("113 , {} : ERROR : {}\r\n", client_port, token),
                "error reply for client port {client_port}"
            );
        }

        // The handler answered 9999 , 8888; the wire must still carry 113 , 4.
        let reply = ident_query(&addr, "113 , 4\r\n").await;
        assert_eq!(
            reply, "113 , 4 : ERROR : UNKNOWN-ERROR\r\n",
            "a wrong port pair from the handler must be rewritten to the queried pair, or the \
             client cannot match the reply to its query"
        );
        server
            .wait_for_log("the answer carried a different port pair", 10)
            .await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// Whitespace tolerance, and `INVALID-PORT` decided in Rust with no LLM call.
    ///
    /// The two halves share a server on purpose. The `ident_query` rule expects **exactly
    /// one** call, and four malformed queries are sent after the one well-formed query: if
    /// any of them raised `ident_query`, the count would be five and `verify_mocks()` would
    /// fail. That count is the assertion — there is no other way to prove a call did not
    /// happen.
    #[tokio::test]
    async fn test_ident_whitespace_tolerance_and_invalid_port_without_llm() -> E2EResult<()> {
        let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via ident")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("listen on port")
                    .and_instruction_containing("ident")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "ident",
                            "instruction": "Answer well-formed ident queries with the userid nobody"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    .on_event("ident_query")
                    .respond_with_actions_from_event(|e| {
                        serde_json::json!([{
                            "type": "send_ident_userid",
                            "server_port": e["server_port"],
                            "client_port": e["client_port"],
                            "userid": "nobody"
                        }])
                    })
                    // Exactly one: the four malformed queries below must not reach the model.
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(config).await?;
        let addr = format!("127.0.0.1:{}", server.port);

        // Whitespace around the comma is legal and is what real queries carry. `opsys` is
        // omitted by the handler above, so the default UNIX must appear.
        let reply = ident_query(&addr, "   113   ,   49152   \r\n").await;
        assert_eq!(
            reply, "113 , 49152 : USERID : UNIX : nobody\r\n",
            "whitespace around the comma must parse, and opsys must default to UNIX"
        );

        // Each of these is a parse verdict, not a decision. The port pair is still echoed as
        // written, because the client has no other way to match the refusal to its query.
        let cases: [(&str, &str); 4] = [
            // above 65535
            ("113 , 70000\r\n", "113 , 70000 : ERROR : INVALID-PORT\r\n"),
            // zero is out of range: RFC 1413 ports are 1-65535
            ("0 , 22\r\n", "0 , 22 : ERROR : INVALID-PORT\r\n"),
            // not a number at all
            (
                "notaport , 22\r\n",
                "notaport , 22 : ERROR : INVALID-PORT\r\n",
            ),
            // no port pair whatsoever
            ("hello\r\n", "hello : ERROR : INVALID-PORT\r\n"),
        ];

        for (query, expected) in cases {
            let reply = ident_query(&addr, query).await;
            assert_eq!(
                reply, expected,
                "malformed query {:?} must be refused with INVALID-PORT",
                query
            );
        }

        // The log names the in-process decision, so an operator can tell a parse refusal from
        // a model refusal without reading the wire.
        server
            .wait_for_log(
                "decision=invalid_port (rejected in-process, no LLM call)",
                10,
            )
            .await?;

        server.wait_for_mocks(30).await;
        // The real assertion of this test: still exactly one ident_query call.
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
