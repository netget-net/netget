//! NetGet owns Bolt's state machine; these drive it from a raw socket with a script-handler
//! graph behind it (no model), and assert on every message the server sends back.
//!
//! What is covered: version negotiation (5.8 from cypher-shell's proposals, 5.4 and 5.0 when
//! those are the best offered, none when nothing overlaps), HELLO/LOGON and Bolt 5.0's
//! HELLO-borne credentials, PULL `n` batching with `has_more`, DISCARD, explicit transactions
//! with two open results addressed by `qid`, FAILURE → IGNORED → RESET, the INTERRUPTED state (a
//! message queued ahead of a RESET is IGNORED), ROUTE, LOGOFF, the admin queries answered without
//! a handler, the pre-5.7 `{code, message}` FAILURE shape, a message the state does not allow,
//! and the configured password.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features bolt --test server -- bolt::state_machine --test-threads=100


use super::common::{self, *};
use netget::server::bolt::packstream::Value;

async fn graph_server() -> (netget::state::app_state::AppState, u16) {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins(), common::graph_handler()],
        None,
    )
    .await;
    (state, port)
}

fn proposal(major: u8, minor: u8, range: u8) -> [u8; 4] {
    [0, range, minor, major]
}

fn proposals(list: &[[u8; 4]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, p) in list.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(p);
    }
    out
}

#[tokio::test]
async fn version_negotiation_picks_the_highest_overlapping_5x() {
    let (_state, port) = graph_server().await;

    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(CYPHER_SHELL_PROPOSALS).await,
        [0, 0, 8, 5],
        "cypher-shell offers the manifest and 5.8..5.0; the manifest is passed over"
    );

    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(proposals(&[proposal(5, 4, 0), proposal(4, 4, 0)]))
            .await,
        [0, 0, 4, 5]
    );

    // A future 5.12 with a range reaching down into ours negotiates our highest.
    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(proposals(&[proposal(5, 12, 6)])).await,
        [0, 0, 8, 5]
    );

    // A range that does not reach 5.8 does not overlap.
    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(proposals(&[proposal(5, 12, 2), proposal(4, 4, 2)]))
            .await,
        [0, 0, 0, 0],
        "nothing in 5.10..=5.12 or 4.x is spoken here"
    );
    peer.expect_eof(10).await;

    // Not Bolt at all: closed without an answer.
    let mut peer = Peer::connect(port).await;
    peer.send_raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn pull_honours_n_with_has_more_and_discard_drops_the_rest() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;

    peer.send_all(&[run("UNWIND range(1, 5) AS x RETURN x"), pull(2)])
        .await;
    let run_ok = peer.recv().await;
    assert_success(&run_ok);
    assert_eq!(
        meta(&run_ok).get("fields"),
        Some(&Value::List(vec![Value::string("x")]))
    );
    assert!(
        meta(&run_ok).get("qid").is_none(),
        "auto-commit RUN has no qid"
    );
    assert_eq!(record_values(&peer.recv().await), [Value::Int(1)]);
    assert_eq!(record_values(&peer.recv().await), [Value::Int(2)]);
    let more = peer.recv().await;
    assert_success(&more);
    assert_eq!(meta(&more).get("has_more"), Some(&Value::Bool(true)));

    peer.send(&pull(1)).await;
    assert_eq!(record_values(&peer.recv().await), [Value::Int(3)]);
    assert_eq!(
        meta(&peer.recv().await).get("has_more"),
        Some(&Value::Bool(true))
    );

    peer.send(&discard(-1)).await;
    let done = peer.recv().await;
    assert_success(&done);
    assert!(meta(&done).get("has_more").is_none(), "{done:?}");
    assert_eq!(meta(&done).get("type"), Some(&Value::string("r")));
    assert_eq!(meta(&done).get("db"), Some(&Value::string("neo4j")));

    // Back in READY: a PULL with nothing open is not allowed.
    peer.send(&pull(-1)).await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Request.Invalid");
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn a_write_summary_carries_stats_and_a_bookmark() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("CREATE (n:Person {name: 'x', born: 1})"), pull(-1)])
        .await;
    let run_ok = peer.recv().await;
    assert_eq!(meta(&run_ok).get("fields"), Some(&Value::List(vec![])));
    let done = peer.recv().await;
    assert_success(&done);
    assert_eq!(meta(&done).get("type"), Some(&Value::string("w")));
    let stats = meta(&done).get("stats").expect("stats");
    assert_eq!(stats.get("nodes-created"), Some(&Value::Int(1)));
    assert_eq!(stats.get("properties-set"), Some(&Value::Int(2)));
    assert_eq!(stats.get("labels-added"), Some(&Value::Int(1)));
    assert_eq!(stats.get("contains-updates"), Some(&Value::Bool(true)));
    assert!(meta(&done)
        .get("bookmark")
        .and_then(Value::as_str)
        .is_some_and(|b| !b.is_empty()));
}

#[tokio::test]
async fn parameters_reach_the_handler_and_every_plain_kind_comes_back() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[
        run_with(
            "RETURN $x",
            Value::map([("x", Value::string("from-a-parameter"))]),
            Value::Map(vec![]),
        ),
        pull(-1),
    ])
    .await;
    assert_success(&peer.recv().await);
    assert_eq!(
        record_values(&peer.recv().await),
        [Value::string("from-a-parameter")]
    );
    assert_success(&peer.recv().await);

    peer.send_all(&[run("RETURN kinds"), pull(-1)]).await;
    assert_success(&peer.recv().await);
    assert_eq!(
        record_values(&peer.recv().await),
        [
            Value::string("text"),
            Value::Int(-17),
            Value::Float(1.5),
            Value::Bool(true),
            Value::Null,
            Value::List(vec![Value::Int(1), Value::string("two")]),
            Value::map([("k", Value::string("v"))]),
        ]
    );
}

#[tokio::test]
async fn a_transaction_holds_two_results_addressed_by_qid_and_commits_with_a_bookmark() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;

    peer.send(&begin()).await;
    assert_success(&peer.recv().await);

    peer.send(&run("MATCH (n:Person) RETURN n.name AS name"))
        .await;
    let first = peer.recv().await;
    let q0 = meta(&first)
        .get("qid")
        .and_then(Value::as_int)
        .expect("qid");
    peer.send(&run("UNWIND range(1, 5) AS x RETURN x")).await;
    let second = peer.recv().await;
    let q1 = meta(&second)
        .get("qid")
        .and_then(Value::as_int)
        .expect("qid");
    assert_ne!(q0, q1);

    // Drain the first by qid while the second stays open.
    peer.send(&pull_qid(-1, q0)).await;
    assert_eq!(record_values(&peer.recv().await), [Value::string("Alice")]);
    assert_eq!(record_values(&peer.recv().await), [Value::string("Bob")]);
    assert_success(&peer.recv().await);

    // qid -1 is "the last one opened".
    peer.send(&pull_qid(-1, -1)).await;
    for i in 1..=5 {
        assert_eq!(record_values(&peer.recv().await), [Value::Int(i)]);
    }
    let done = peer.recv().await;
    assert!(
        meta(&done).get("bookmark").is_none(),
        "results inside a transaction carry no bookmark"
    );

    peer.send(&commit()).await;
    let committed = peer.recv().await;
    assert_success(&committed);
    assert!(meta(&committed).get("bookmark").is_some());

    // ROLLBACK path.
    peer.send(&begin()).await;
    assert_success(&peer.recv().await);
    peer.send(&rollback()).await;
    assert_success(&peer.recv().await);
    peer.send(&goodbye()).await;
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn commit_with_a_result_still_open_is_a_protocol_violation() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send(&begin()).await;
    assert_success(&peer.recv().await);
    peer.send(&run("MATCH (n:Person) RETURN n.name AS name"))
        .await;
    assert_success(&peer.recv().await);
    peer.send(&commit()).await;
    let refused = peer.recv().await;
    assert_failure(&refused, "Neo.ClientError.Request.Invalid");
    assert!(
        meta(&refused)
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("TX_STREAMING")),
        "{refused:?}"
    );
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn a_failure_ignores_everything_until_reset_and_the_connection_recovers() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send_all(&[run("NONSENSE"), pull(-1)]).await;
    let failure = peer.recv().await;
    assert_failure(&failure, "Neo.ClientError.Statement.SyntaxError");
    assert_eq!(
        meta(&failure).get("message"),
        Some(&Value::string("This graph only knows Person nodes"))
    );
    assert_eq!(
        meta(&failure).get("gql_status"),
        Some(&Value::string("50N42")),
        "Bolt 5.7+ FAILURE is the GQL error object"
    );
    assert_ignored(&peer.recv().await);

    peer.send(&run("MATCH (n:Person) RETURN n.name AS name"))
        .await;
    assert_ignored(&peer.recv().await);
    peer.send(&reset()).await;
    assert_success(&peer.recv().await);

    peer.send_all(&[run("MATCH (n:Person) RETURN n.name AS name"), pull(-1)])
        .await;
    assert_success(&peer.recv().await);
    assert_eq!(record_values(&peer.recv().await), [Value::string("Alice")]);
}

#[tokio::test]
async fn messages_queued_ahead_of_a_reset_are_ignored() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    // All three in one write: the server has the RESET in hand before it handles the RUN.
    peer.send_all(&[
        run("MATCH (n:Person) RETURN n.name AS name"),
        pull(-1),
        reset(),
    ])
    .await;
    assert_ignored(&peer.recv().await);
    assert_ignored(&peer.recv().await);
    assert_success(&peer.recv().await);
    // And the connection is READY.
    peer.send_all(&[run("MATCH (n:Person) RETURN n.name AS name"), pull(-1)])
        .await;
    assert_success(&peer.recv().await);
}

#[tokio::test]
async fn route_names_the_address_the_client_dialled() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    let address = format!("127.0.0.1:{port}");
    peer.send(&msg(
        0x66,
        vec![
            Value::map([("address", Value::string(&address))]),
            Value::List(vec![]),
            Value::map([("db", Value::string("movies"))]),
        ],
    ))
    .await;
    let route = peer.recv().await;
    assert_success(&route);
    let rt = meta(&route).get("rt").expect("rt");
    assert_eq!(rt.get("db"), Some(&Value::string("movies")));
    let Some(Value::List(servers)) = rt.get("servers") else {
        panic!("{route:?}")
    };
    let roles: Vec<&str> = servers
        .iter()
        .filter_map(|s| s.get("role").and_then(Value::as_str))
        .collect();
    assert_eq!(roles, ["WRITE", "READ", "ROUTE"]);
    for s in servers {
        assert_eq!(
            s.get("addresses"),
            Some(&Value::List(vec![Value::string(&address)]))
        );
    }
}

#[tokio::test]
async fn cypher_shells_connect_queries_are_answered_without_any_handler() {
    // No bolt_query handler at all and a dead model: these must not need either.
    let state = common::new_state().await;
    let (_id, port, mut rx) = common::start(&state, vec![common::accept_logins()], None).await;
    let mut peer = Peer::connect_and_login(port).await;
    // The login's own decision line is not what this test is about.
    common::drain(&mut rx);
    for (query, fields) in [
        ("CALL db.ping()", vec!["success"]),
        (
            "CALL dbms.licenseAgreementDetails()",
            vec!["status", "daysLeftOnTrial", "totalTrialDays"],
        ),
        (
            "call dbms.components()",
            vec!["name", "versions", "edition"],
        ),
        ("CALL dbms.components() YIELD versions", vec!["versions"]),
    ] {
        peer.send_all(&[run(query), pull(-1)]).await;
        let ok = peer.recv().await;
        assert_eq!(
            meta(&ok).get("fields"),
            Some(&Value::List(
                fields.into_iter().map(Value::string).collect()
            )),
            "{query}"
        );
        let row = record_values(&peer.recv().await);
        assert!(!row.is_empty());
        assert_success(&peer.recv().await);
    }
    let log = common::drain(&mut rx);
    assert!(
        !log.iter().any(|l| l.contains("decision=")),
        "an admin query reached a handler or the model: {log:#?}"
    );
}

#[tokio::test]
async fn logoff_returns_to_authentication() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect_and_login(port).await;
    peer.send(&msg(0x6B, vec![])).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("other", "pw")).await;
    assert_success(&peer.recv().await);
    peer.send_all(&[run("MATCH (n:Person) RETURN n.name AS name"), pull(-1)])
        .await;
    assert_success(&peer.recv().await);
}

#[tokio::test]
async fn a_query_before_logon_is_a_protocol_violation() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect(port).await;
    peer.handshake(CYPHER_SHELL_PROPOSALS).await;
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&run("MATCH (n) RETURN n")).await;
    let refused = peer.recv().await;
    assert_failure(&refused, "Neo.ClientError.Request.Invalid");
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn bolt_5_4_gets_the_legacy_failure_shape() {
    let (_state, port) = graph_server().await;
    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(proposals(&[proposal(5, 4, 0)])).await,
        [0, 0, 4, 5]
    );
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("neo4j", "pw")).await;
    assert_success(&peer.recv().await);
    peer.send_all(&[run("NONSENSE"), pull(-1)]).await;
    let failure = peer.recv().await;
    assert_eq!(
        meta(&failure).get("code"),
        Some(&Value::string("Neo.ClientError.Statement.SyntaxError"))
    );
    assert!(meta(&failure).get("gql_status").is_none(), "{failure:?}");
    // TELEMETRY exists from 5.4.
    peer.send(&reset()).await;
    peer.recv().await;
    peer.send(&msg(0x54, vec![Value::Int(0)])).await;
    assert_success(&peer.recv().await);
}

#[tokio::test]
async fn bolt_5_0_authenticates_inside_hello() {
    let state = common::new_state().await;
    let (_id, port, _rx) = common::start(
        &state,
        vec![common::accept_logins(), common::graph_handler()],
        Some(serde_json::json!({"password": "right"})),
    )
    .await;

    let hello_with = |password: &str| {
        msg(
            0x01,
            vec![Value::map([
                ("user_agent", Value::string("old-driver/5.0")),
                ("scheme", Value::string("basic")),
                ("principal", Value::string("neo4j")),
                ("credentials", Value::string(password)),
            ])],
        )
    };

    let mut peer = Peer::connect(port).await;
    assert_eq!(
        peer.handshake(proposals(&[proposal(5, 0, 0)])).await,
        [0, 0, 0, 5]
    );
    peer.send(&hello_with("right")).await;
    let ok = peer.recv().await;
    assert_success(&ok);
    assert!(meta(&ok)
        .get("server")
        .and_then(Value::as_str)
        .is_some_and(|s| s.starts_with("Neo4j/")));
    peer.send_all(&[run("MATCH (n:Person) RETURN n.name AS name"), pull(-1)])
        .await;
    assert_success(&peer.recv().await);

    let mut peer = Peer::connect(port).await;
    peer.handshake(proposals(&[proposal(5, 0, 0)])).await;
    peer.send(&hello_with("wrong")).await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Security.Unauthorized");
    peer.expect_eof(10).await;
}

#[tokio::test]
async fn a_configured_password_is_checked_by_netget_and_never_reaches_an_event() {
    let state = common::new_state().await;
    // A handler that would accept anything: a wrong password must never get that far.
    let (_id, port, mut rx) = common::start(
        &state,
        vec![common::accept_logins(), common::graph_handler()],
        Some(serde_json::json!({"password": "correct horse"})),
    )
    .await;

    let mut peer = Peer::connect(port).await;
    peer.handshake(CYPHER_SHELL_PROPOSALS).await;
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("neo4j", "battery staple")).await;
    assert_failure(&peer.recv().await, "Neo.ClientError.Security.Unauthorized");
    peer.expect_eof(10).await;
    let log = common::wait_for_log(&mut rx, "decision=reject_bad_credentials", 10).await;
    assert!(
        !log.iter().any(|l| l.contains("battery staple")),
        "the credential reached the log: {log:#?}"
    );

    // The right one reaches the handler, which accepts.
    let mut peer = Peer::connect(port).await;
    peer.handshake(CYPHER_SHELL_PROPOSALS).await;
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("neo4j", "correct horse")).await;
    assert_success(&peer.recv().await);
    let log = common::drain(&mut rx);
    assert!(
        !log.iter().any(|l| l.contains("correct horse")),
        "the credential reached the log: {log:#?}"
    );
}

#[tokio::test]
async fn a_handler_rejection_is_the_code_it_chose_and_a_close() {
    let state = common::new_state().await;
    let reject = serde_json::json!({
        "event_pattern": "bolt_authenticate",
        "handler": {"type": "static", "actions": [{
            "type": "reject_bolt_login",
            "code": "Neo.ClientError.Security.AuthenticationRateLimit",
            "message": "Too many attempts"
        }]}
    });
    let (_id, port, mut rx) = common::start(&state, vec![reject], None).await;
    let mut peer = Peer::connect(port).await;
    peer.handshake(CYPHER_SHELL_PROPOSALS).await;
    peer.send(&hello()).await;
    assert_success(&peer.recv().await);
    peer.send(&logon("neo4j", "pw")).await;
    let refused = peer.recv().await;
    assert_failure(&refused, "Neo.ClientError.Security.AuthenticationRateLimit");
    assert_eq!(
        meta(&refused).get("message"),
        Some(&Value::string("Too many attempts"))
    );
    peer.expect_eof(10).await;
    common::wait_for_log(&mut rx, "decision=model_reject", 10).await;
}
