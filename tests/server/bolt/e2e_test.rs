//! Bolt with a mocked model, driven from a raw socket.
//!
//! One rule answers `bolt_authenticate` and one answers every `bolt_query`, branching on the
//! event — so what the model *saw* comes back on the wire as a record and is asserted there:
//! the parameters decoded to JSON, the database the RUN named, `mode: read` from the RUN's
//! `mode: "r"`, and `in_transaction` inside BEGIN … COMMIT. The credential is asserted absent
//! from the event.
//!
//! LLM calls: 5 — the startup instruction, the login, and three queries (an auto-commit read
//! with parameters, a write inside a transaction, a query the model fails). cypher-shell's
//! connect queries are not sent here; `state_machine_test.rs` covers that they cost nothing.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::e2e --test-threads=100

use super::common::*;
use crate::server::helpers::{self, E2EResult, NetGetConfig};
use netget::server::bolt::packstream::Value;
use serde_json::json;

#[tokio::test]
async fn a_mocked_model_answers_queries_over_a_raw_bolt_session() -> E2EResult<()> {
    let config = NetGetConfig::new("Open a Neo4j Bolt server on port {AVAILABLE_PORT}")
        .with_mock(|mock| {
            mock.on_instruction_containing("Neo4j Bolt server")
                .respond_with_actions(json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "bolt",
                    "instruction": "A graph of film people"
                }]))
                .expect_calls(1)
                .and()
                .on_event("bolt_authenticate")
                // Matches only when the event says the login is not about any query.
                .and_event_data_contains("answer_with", "No query has been sent yet")
                .respond_with_actions_from_event(|event| {
                    // The event names the user and scheme and says a credential was sent;
                    // it never carries the credential.
                    let leaked = event.to_string().contains("s3cret-pw");
                    if leaked
                        || event["principal"] != "alice"
                        || event["scheme"] != "basic"
                        || event["credentials_present"] != true
                    {
                        json!([{"type": "reject_bolt_login", "message": format!("bad event {event}")}])
                    } else {
                        json!([{"type": "accept_bolt_login"}])
                    }
                })
                .expect_calls(1)
                .and()
                .on_event("bolt_query")
                .respond_with_actions_from_event(|event| {
                    let query = event["query"].as_str().unwrap_or("");
                    if query.starts_with("MATCH") {
                        json!([{
                            "type": "send_bolt_records",
                            "fields": ["name", "seen_param", "db", "mode", "in_tx"],
                            "records": [
                                ["Keanu", event["parameters"]["who"], event["database"], event["mode"], event["in_transaction"]],
                                ["Carrie-Anne", null, null, null, null],
                                ["Laurence", null, null, null, null]
                            ]
                        }])
                    } else if query.starts_with("CREATE") {
                        json!([{
                            "type": "send_bolt_records",
                            "fields": ["in_tx"],
                            "records": [[event["in_transaction"]]],
                            "stats": {"nodes_created": 1},
                            "query_type": "w"
                        }])
                    } else {
                        json!([{
                            "type": "send_bolt_failure",
                            "code": "Neo.ClientError.Statement.SyntaxError",
                            "message": "Invalid input 'SELECT'"
                        }])
                    }
                })
                .expect_calls(3)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let mut peer = Peer::connect(server.port).await;
    assert_eq!(peer.handshake(CYPHER_SHELL_PROPOSALS).await, [0, 0, 8, 5]);
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("alice", "s3cret-pw")).await;
    assert_success(&peer.recv().await);

    // An auto-commit read with parameters, pulled two at a time.
    peer.send_all(&[
        run_with(
            "MATCH (p:Person {name: $who}) RETURN p.name AS name",
            Value::map([("who", Value::string("Keanu"))]),
            Value::map([
                ("db", Value::string("movies")),
                ("mode", Value::string("r")),
            ]),
        ),
        pull(2),
    ])
    .await;
    let run_ok = peer.recv().await;
    assert_eq!(
        meta(&run_ok).get("fields"),
        Some(&Value::List(
            ["name", "seen_param", "db", "mode", "in_tx"]
                .into_iter()
                .map(Value::string)
                .collect()
        ))
    );
    assert_eq!(
        record_values(&peer.recv().await),
        [
            Value::string("Keanu"),
            Value::string("Keanu"),
            Value::string("movies"),
            Value::string("read"),
            Value::Bool(false)
        ],
        "what the model saw: the parameter, the database, read mode, auto-commit"
    );
    record_values(&peer.recv().await);
    assert_eq!(
        meta(&peer.recv().await).get("has_more"),
        Some(&Value::Bool(true))
    );
    peer.send(&pull(2)).await;
    assert_eq!(
        record_values(&peer.recv().await)[0],
        Value::string("Laurence")
    );
    let done = peer.recv().await;
    assert_eq!(meta(&done).get("db"), Some(&Value::string("movies")));

    // A write inside a transaction.
    peer.send(&begin()).await;
    assert_success(&peer.recv().await);
    peer.send_all(&[
        run("CREATE (p:Person {name: 'Hugo'}) RETURN true AS in_tx"),
        pull(-1),
    ])
    .await;
    let run_ok = peer.recv().await;
    assert!(meta(&run_ok).get("qid").is_some());
    assert_eq!(record_values(&peer.recv().await), [Value::Bool(true)]);
    let done = peer.recv().await;
    assert_eq!(meta(&done).get("type"), Some(&Value::string("w")));
    assert_eq!(
        meta(&done)
            .get("stats")
            .and_then(|s| s.get("nodes-created")),
        Some(&Value::Int(1))
    );
    peer.send(&commit()).await;
    assert_success(&peer.recv().await);

    // The model fails a query; the client RESETs and carries on.
    peer.send_all(&[run("SELECT * FROM people"), pull(-1)])
        .await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Statement.SyntaxError");
    assert_ignored(&peer.recv().await);
    peer.send(&reset()).await;
    assert_success(&peer.recv().await);
    peer.send(&goodbye()).await;
    peer.expect_eof(10).await;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
