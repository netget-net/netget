//! Tests for the `DevelopmentState` maturity ordering, its case-insensitive
//! parse, and the `--min-stability` start gate.
//!
//! The ordering/parse tests need no protocol features (metadata is always
//! compiled). The enforcement test needs a Beta protocol and an Experimental
//! one to exist in the registry, so it is gated on `tcp` (Beta) + `redis`
//! (Experimental) — both are in the CI `test` feature set. Nothing here
//! contacts the network: the LLM client points at a closed loopback port and
//! the Experimental protocol is refused *before* any spawn.

use netget::protocol::metadata::DevelopmentState;

#[test]
fn development_state_orders_least_to_most_mature() {
    // Declaration order is the Ord order; this is the invariant every maturity
    // comparison (the --min-stability gate, the /stability listing) relies on.
    assert!(DevelopmentState::Incomplete < DevelopmentState::Experimental);
    assert!(DevelopmentState::Experimental < DevelopmentState::Beta);
    assert!(DevelopmentState::Beta < DevelopmentState::Stable);

    // Transitivity / extremes.
    assert!(DevelopmentState::Incomplete < DevelopmentState::Stable);
    assert_eq!(
        DevelopmentState::ALL.iter().max().copied(),
        Some(DevelopmentState::Stable)
    );
    assert_eq!(
        DevelopmentState::ALL.iter().min().copied(),
        Some(DevelopmentState::Incomplete)
    );

    // `ALL` is declared least-mature first.
    let mut sorted = DevelopmentState::ALL;
    sorted.sort();
    assert_eq!(sorted, DevelopmentState::ALL);
}

#[test]
fn development_state_parses_case_insensitively() {
    use std::str::FromStr;

    for (input, expected) in [
        ("incomplete", DevelopmentState::Incomplete),
        ("Experimental", DevelopmentState::Experimental),
        ("BETA", DevelopmentState::Beta),
        ("  Stable  ", DevelopmentState::Stable),
        ("sTaBlE", DevelopmentState::Stable),
    ] {
        assert_eq!(
            DevelopmentState::parse_ci(input),
            Some(expected),
            "parse_ci {input:?}"
        );
        assert_eq!(
            DevelopmentState::from_str(input.trim()),
            Ok(expected),
            "from_str {input:?}"
        );
    }

    assert_eq!(DevelopmentState::parse_ci("gold"), None);
    assert_eq!(DevelopmentState::parse_ci(""), None);
    assert!(DevelopmentState::from_str("gold").is_err());
}

/// `--min-stability beta` must refuse an Experimental protocol with a clear
/// error and still start a Beta one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn min_stability_beta_refuses_experimental_and_allows_beta() {
    use netget::state::app_state::AppState;
    use std::sync::Arc;

    // The Beta side is pinned to TCP, which is a fixed point of this suite.
    let registry = netget::protocol::server_registry::registry();
    assert_eq!(
        registry.metadata("TCP").map(|m| m.state),
        Some(DevelopmentState::Beta),
        "expected TCP to be Beta"
    );

    // The Experimental side is *derived*, not named.
    //
    // This used to hardcode Redis. Redis was promoted to Beta on 2026-08-25 and this
    // assertion has failed ever since — loudly, as its comment intended, but in a test binary
    // the full-suite runs did not cover. Coupling a gate test to one protocol's maturity
    // rating guarantees it rots the first time that rating is the thing being improved, and
    // the rot looks like a regression in the gate rather than in the fixture.
    //
    // Any Experimental protocol proves the same property, so ask the registry for one.
    let experimental = registry
        .all_protocols()
        .into_iter()
        .find_map(|(name, _)| {
            let m = registry.metadata(&name)?;
            (m.state == DevelopmentState::Experimental).then_some(name)
        })
        .expect(
            "no Experimental protocol is compiled in, so the refusal half of this test cannot \
             run — the min-stability gate's whole point is refusing one, so this is a coverage \
             hole, not a reason to relax the test. Add an Experimental feature to this build's \
             feature set (`finger` and `ident` are Experimental and pull in no dependencies); \
             ci.yml's CI_FEATURES carries `finger` for exactly this. Delete this half only if \
             every protocol in the tree has reached Beta, which is not close to true — the \
             count was 106 Experimental in September 2026.",
        );

    let state = Arc::new(AppState::new());
    // Unreachable on purpose: any LLM call fails on connect instead of reaching
    // a model or the network.
    state
        .set_llm_client(netget::llm::OllamaClient::new("http://127.0.0.1:1"))
        .await;
    state.set_min_stability(Some(DevelopmentState::Beta)).await;

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let drain = tokio::spawn(async move {
        let mut rx = status_rx;
        while rx.recv().await.is_some() {}
    });

    // --- Experimental: must be refused before any spawn ---
    let refused = netget::cli::server_startup::start_server_from_action(
        &state,
        None,
        None,
        None,
        Some(0),
        &experimental,
        false,
        None,
        "min-stability test: should be refused".to_string(),
        None,
        None,
        None,
        None,
        Default::default(),
        status_tx.clone(),
    )
    .await;

    let err = refused.expect_err(&format!(
        "{experimental} (Experimental) must be refused under --min-stability beta"
    ));
    let msg = err.to_string();
    assert!(
        msg.contains("Experimental") && msg.contains("Beta"),
        "refusal must name the protocol, its actual state and the required minimum; got: {msg}"
    );
    // Nothing should have been registered for the refused protocol.
    assert!(
        state.get_all_servers().await.is_empty(),
        "a refused start must leave no server instance behind"
    );

    // --- Beta (tcp): must start ---
    let tcp_result = netget::cli::server_startup::start_server_from_action(
        &state,
        None,
        None,
        None,
        Some(0), // ephemeral loopback port
        "tcp",
        false,
        None,
        "min-stability test: should start".to_string(),
        None,
        None,
        None,
        None,
        Default::default(),
        status_tx.clone(),
    )
    .await;

    let server_id = tcp_result.expect("tcp (Beta) must start under --min-stability beta");
    // Clean up so the ephemeral port is released.
    state.remove_server(server_id).await;

    drop(status_tx);
    drain.abort();
}
