//! End-to-end Finger (RFC 1288) **client** tests.
//!
//! Two instruments, deliberately, because they prove different things:
//!
//! * **NetGet's own Finger server** is the peer for the round trip. Be clear about what that
//!   is worth: it is *same-project evidence*. It shows the two halves of NetGet agree with each
//!   other, not that either half matches RFC 1288 — the circular-evidence class the root
//!   `CLAUDE.md` names, and the reason this client is rated `Experimental`.
//! * **A raw `TcpListener`** is the peer wherever the assertion is about the bytes this client
//!   emits. Nothing in the loop can talk it into agreeing: the query line is compared literally,
//!   and "no bytes at all" is asserted the same way. That is what makes the forwarding-refusal
//!   test mean something.
//!
//! Everything binds 127.0.0.1 on an ephemeral port. Nothing leaves the host.
mod finger_client_e2e_test {
    use crate::helpers::{start_netget_client, start_netget_server, E2EResult, NetGetConfig};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A finger daemon in fifteen lines: accept, read one CRLF-terminated line, answer, close.
    ///
    /// It is **not** an independent implementation and is not offered as one — it is a probe
    /// that records exactly what arrived. Closing after the answer is the part that matters:
    /// a finger client is defined by reading to EOF, so a peer that never closes would hang
    /// this client, and every test here would notice.
    ///
    /// Returns the address and the shared list of query lines received, in order.
    async fn spawn_fake_fingerd<F>(reply: F) -> (String, Arc<Mutex<Vec<String>>>)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake fingerd");
        let addr = listener
            .local_addr()
            .expect("fake fingerd addr")
            .to_string();

        let queries: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let queries_for_task = queries.clone();
        let reply = Arc::new(reply);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _peer)) = listener.accept().await else {
                    break;
                };
                let queries = queries_for_task.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 256];

                    // Bounded, so the refusal test — where no query is ever sent — finishes
                    // instead of parking until the whole suite times out.
                    let line = tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            match sock.read(&mut chunk).await {
                                Ok(0) => return None,
                                Ok(n) => {
                                    buf.extend_from_slice(&chunk[..n]);
                                    if let Some(idx) = buf.iter().position(|b| *b == b'\n') {
                                        return Some(
                                            String::from_utf8_lossy(&buf[..idx])
                                                .trim_end_matches('\r')
                                                .to_string(),
                                        );
                                    }
                                    if buf.len() > 4096 {
                                        return None;
                                    }
                                }
                                Err(_) => return None,
                            }
                        }
                    })
                    .await
                    .ok()
                    .flatten();

                    if let Some(line) = line {
                        queries.lock().expect("queries lock").push(line.clone());
                        let body = reply(&line);
                        let _ = sock.write_all(body.as_bytes()).await;
                        let _ = sock.flush().await;
                    }

                    // RFC 1288: one query, one answer, close. The client is blocked on this.
                    let _ = sock.shutdown().await;
                });
            }
        });

        (addr, queries)
    }

    /// The round trip, against NetGet's own Finger server.
    ///
    /// LLM calls: 2 on the server (startup + one `finger_query`), 2 on the client (startup +
    /// one `finger_response_received`); the client's connected event is answered by a static
    /// handler and costs nothing.
    ///
    /// The load-bearing assertion is not "it connected". It is the captured
    /// `finger_response_received` event: the server's block reached the model **as text**,
    /// carrying the query that produced it, `eof` proving the server closed, and a
    /// `best_effort` block that is labelled a guess and sits alongside the raw response rather
    /// than replacing it.
    #[tokio::test]
    async fn test_finger_client_round_trip_against_netget_server() -> E2EResult<()> {
        let server_config = NetGetConfig::new("Listen on port {AVAILABLE_PORT} via finger")
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("Listen on port")
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
                            "shell": "/bin/sh",
                            "plan": "Ship the finger client."
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            });

        let server = start_netget_server(server_config).await?;
        let target = format!("127.0.0.1:{}", server.port);

        // The event the client hands the model, captured in-process: the mock's response
        // generator runs inside this test, so this is the model's actual view.
        let observed: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let observed_for_mock = observed.clone();

        let target_for_mock = target.clone();
        let client_config = NetGetConfig::new(format!(
            "Connect to {target} via finger and ask about alice"
        ))
        .with_log_level("info")
        .with_mock(move |mock| {
            mock.on_instruction_containing("Connect to")
                .and_instruction_containing("finger")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "protocol": "finger",
                        "remote_addr": target_for_mock,
                        "instruction": "Ask the finger server about alice and report what it said",
                        "event_handlers": [{
                            "event_pattern": "finger_connected",
                            "handler": {
                                "type": "static",
                                "actions": [{"type": "send_finger_query", "username": "alice"}]
                            }
                        }]
                    }
                ]))
                .expect_calls(1)
                .and()
                .on_event("finger_response_received")
                .respond_with_actions_from_event(move |event| {
                    observed_for_mock
                        .lock()
                        .expect("observed lock")
                        .push(event.clone());
                    serde_json::json!([{"type": "disconnect"}])
                })
                .expect_calls(1)
                .and()
        });

        let client = start_netget_client(client_config).await?;

        server.wait_for_mocks(30).await;
        client.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        client.verify_mocks().await?;

        let events = observed.lock().expect("observed lock").clone();
        assert_eq!(
            events.len(),
            1,
            "exactly one finger_response_received should have reached the model: {events:?}"
        );
        let event = &events[0];

        let response = event["response"].as_str().unwrap_or_default();
        assert!(
            response.contains("Login: alice") && response.contains("Name: Alice Smith"),
            "the server's block should reach the model verbatim as text: {response:?}"
        );
        assert!(
            response.contains("Plan:") && response.contains("Ship the finger client."),
            "the multi-line .plan should survive into the event: {response:?}"
        );
        assert!(
            !response.contains('\r'),
            "line endings should be normalised to LF before the model sees them: {response:?}"
        );
        assert_eq!(
            event["query"].as_str(),
            Some("alice"),
            "the event should name the query that produced it: {event:?}"
        );
        assert_eq!(event["username"].as_str(), Some("alice"), "{event:?}");
        assert_eq!(event["verbose"].as_bool(), Some(false), "{event:?}");
        assert!(event["forward_host"].is_null(), "{event:?}");
        assert_eq!(
            event["eof"].as_bool(),
            Some(true),
            "the server closed after answering, which is what a finger client reads to: {event:?}"
        );
        assert_eq!(event["truncated"].as_bool(), Some(false), "{event:?}");

        // Best-effort means best-effort: it is offered *alongside* the raw text, never
        // instead of it, and its own note says it is a guess.
        assert_eq!(
            event["best_effort"]["logins"],
            serde_json::json!(["alice"]),
            "{event:?}"
        );
        let note = event["best_effort"]["note"].as_str().unwrap_or_default();
        assert!(
            note.contains("GUESS"),
            "the best-effort block must tell the model it is a guess: {note:?}"
        );

        println!("✅ Finger client round trip against NetGet's own Finger server");

        server.stop().await?;
        client.stop().await?;
        Ok(())
    }

    /// The exact bytes of all three RFC 1288 query forms, and the follow-up chain.
    ///
    /// A raw `TcpListener` is the peer, because the assertion is literal: `alice`, then
    /// `/W bob`, then the empty line. It also proves the two structural claims — a follow-up
    /// query opens a **new** connection (three connections, one query each, exactly as RFC 1288
    /// requires) and each answer raises `finger_response_received` again.
    ///
    /// LLM calls: 4 (startup, plus one per response; the connected event is a static handler).
    #[tokio::test]
    async fn test_finger_client_query_forms_and_followups_on_the_wire() -> E2EResult<()> {
        let (addr, queries) = spawn_fake_fingerd(|line| {
            // Echo the query back so a mismatch shows up in the response too, and end with
            // a Login: line so the best-effort scrape has something to find.
            format!("query was: {line}\r\nLogin: someone\r\n")
        })
        .await;

        // Which response we are answering. A stateful generator is fine — the mock renders
        // each response exactly once per request.
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_for_mock = seen.clone();

        let addr_for_mock = addr.clone();
        let client_config =
            NetGetConfig::new(format!("Connect to {addr} via finger and look around"))
                .with_log_level("info")
                .with_mock(move |mock| {
                    mock.on_instruction_containing("Connect to")
                .and_instruction_containing("finger")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_client",
                        "protocol": "finger",
                        "remote_addr": addr_for_mock,
                        "instruction": "Finger alice, then bob in the long format, then everyone",
                        "event_handlers": [{
                            "event_pattern": "finger_connected",
                            "handler": {
                                "type": "static",
                                "actions": [{"type": "send_finger_query", "username": "alice"}]
                            }
                        }]
                    }
                ]))
                .expect_calls(1)
                .and()
                // ONE rule that branches, never three rules on the same event: rules
                // are first-match-wins, so three indistinguishable ones would send
                // every response to the first and report zero calls for the rest.
                .on_event("finger_response_received")
                .respond_with_actions_from_event(move |event| {
                    let query = event["query"].as_str().unwrap_or("<missing>").to_string();
                    let mut guard = seen_for_mock.lock().expect("seen lock");
                    guard.push(query);
                    match guard.len() {
                        1 => serde_json::json!([
                            {"type": "send_finger_query", "username": "bob", "verbose": true}
                        ]),
                        2 => serde_json::json!([{"type": "send_finger_query"}]),
                        _ => serde_json::json!([{"type": "disconnect"}]),
                    }
                })
                .expect_calls(3)
                .and()
                });

        let client = start_netget_client(client_config).await?;

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        let on_the_wire = queries.lock().expect("queries lock").clone();
        assert_eq!(
            on_the_wire,
            vec![
                "alice".to_string(),
                "/W bob".to_string(),
                // RFC 1288's {C}-only query: "everyone". The empty line is the whole query.
                String::new(),
            ],
            "the three RFC 1288 query forms should reach the wire literally, one per \
             connection, in order"
        );

        let answered = seen.lock().expect("seen lock").clone();
        assert_eq!(
            answered,
            vec!["alice".to_string(), "/W bob".to_string(), String::new()],
            "each answer should have raised finger_response_received naming its own query"
        );

        println!("✅ Finger client query encoding and follow-up chain verified byte for byte");

        client.stop().await?;
        Ok(())
    }

    /// `user@host` forwarding is refused, by default, before a single byte is written.
    ///
    /// The peer is a raw listener that records everything it receives, so "nothing was sent"
    /// is asserted directly rather than inferred. RFC 1288 §3.2.1 calls forwarding a security
    /// risk, and as the client we would be the one asking a stranger's server to relay.
    ///
    /// LLM calls: 1 (startup only). The connected event is a static handler and the refused
    /// query never produces a response event, so nothing else reaches the model.
    #[tokio::test]
    async fn test_finger_client_refuses_forwarding_by_default() -> E2EResult<()> {
        let (addr, queries) =
            spawn_fake_fingerd(|_| "this must never be reached\r\n".to_string()).await;

        let addr_for_mock = addr.clone();
        let client_config =
            NetGetConfig::new(format!("Connect to {addr} via finger and relay a query"))
                .with_log_level("info")
                .with_mock(move |mock| {
                    mock.on_instruction_containing("Connect to")
                        .and_instruction_containing("finger")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "protocol": "finger",
                                "remote_addr": addr_for_mock,
                                "instruction": "Ask the server to relay a query",
                                // Two seconds, so the read gives up promptly once it is clear
                                // no query was ever sent.
                                "startup_params": {"response_timeout_secs": 2},
                                "event_handlers": [{
                                    "event_pattern": "finger_connected",
                                    "handler": {
                                        "type": "static",
                                        "actions": [{
                                            "type": "send_finger_query",
                                            "username": "alice",
                                            "forward_host": "relay.example.invalid"
                                        }]
                                    }
                                }]
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        client.wait_for_any(&["decision=forward_refused"], 30).await;
        assert!(
            client.output_contains("decision=forward_refused").await,
            "the refusal must be distinguishable in the log: {:?}",
            client.get_output().await
        );

        assert!(
            queries.lock().expect("queries lock").is_empty(),
            "a forwarding query must never reach the wire while allow_forwarding is false, but \
             the peer received: {:?}",
            queries.lock().expect("queries lock")
        );

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        println!("✅ Finger client refused forwarding and sent nothing");

        client.stop().await?;
        Ok(())
    }

    /// ...and sends it, byte for byte, when the operator turns it on by name.
    ///
    /// The mirror of the test above: same static handler, same peer, one startup parameter
    /// different. Without this the refusal could be a client that cannot build the query at
    /// all, which would prove nothing about the policy.
    ///
    /// LLM calls: 1 (startup only); both events are static handlers.
    #[tokio::test]
    async fn test_finger_client_forwards_only_when_explicitly_enabled() -> E2EResult<()> {
        let (addr, queries) = spawn_fake_fingerd(|_| "relayed\r\n".to_string()).await;

        let addr_for_mock = addr.clone();
        let client_config =
            NetGetConfig::new(format!("Connect to {addr} via finger and relay a query"))
                .with_log_level("info")
                .with_mock(move |mock| {
                    mock.on_instruction_containing("Connect to")
                        .and_instruction_containing("finger")
                        .respond_with_actions(serde_json::json!([
                            {
                                "type": "open_client",
                                "protocol": "finger",
                                "remote_addr": addr_for_mock,
                                "instruction": "Ask the server to relay a query",
                                "startup_params": {"allow_forwarding": true},
                                "event_handlers": [
                                    {
                                        "event_pattern": "finger_connected",
                                        "handler": {
                                            "type": "static",
                                            "actions": [{
                                                "type": "send_finger_query",
                                                "username": "alice",
                                                "forward_host": "relay.example.invalid"
                                            }]
                                        }
                                    },
                                    {
                                        "event_pattern": "finger_response_received",
                                        "handler": {
                                            "type": "static",
                                            "actions": [{"type": "disconnect"}]
                                        }
                                    }
                                ]
                            }
                        ]))
                        .expect_calls(1)
                        .and()
                });

        let client = start_netget_client(client_config).await?;

        // Wait for the query rather than sleeping: the peer records it the moment it lands.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while queries.lock().expect("queries lock").is_empty()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(
            queries.lock().expect("queries lock").clone(),
            vec!["alice@relay.example.invalid".to_string()],
            "with allow_forwarding=true the RFC 1288 {{Q2}} query should reach the wire exactly"
        );

        client.wait_for_mocks(30).await;
        client.verify_mocks().await?;

        println!("✅ Finger client sent the forwarding query only once it was enabled");

        client.stop().await?;
        Ok(())
    }
}
