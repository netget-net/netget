//! The Tor client must not reach the public internet by default.
//!
//! `arti_client::TorClient::create_bootstrapped()` contacts the real Tor directory authorities
//! **before it looks at the requested address** — 14 seconds in an unguarded run. So merely
//! opening a Tor client made outbound connections to third parties whatever destination the
//! user asked for, in a tool that binds loopback everywhere else, and the whole-registry
//! startup smoke test had to carve out a named exclusion for Tor rather than run it.
//!
//! `bootstrap_target()` is the guard, and these tests pin it. Nothing here touches the
//! network — that is the point: the refusal happens before any I/O, which is exactly what
//! `connect_without_an_opt_in_is_refused_before_any_network_io` measures.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features tor \
//!     --test client -- client::tor::test --test-threads=100
//! ```

#![cfg(unix)]

use netget::client::tor::{bootstrap_target, BootstrapTarget, ALLOW_PUBLIC_TOR_NETWORK_PARAM};
use netget::llm::actions::client_trait::Client;
use netget::llm::actions::protocol_trait::Protocol;
use netget::llm::ollama_client::OllamaClient;
use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::ClientId;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The default, and the whole point of the change: no bootstrap choice means no bootstrap.
#[test]
fn no_bootstrap_choice_is_refused() {
    let err = bootstrap_target(None, false)
        .expect_err("the default must refuse; silently bootstrapping is the defect");
    let msg = err.to_string();

    assert!(
        msg.contains(ALLOW_PUBLIC_TOR_NETWORK_PARAM),
        "the refusal must name the opt-in parameter so the caller knows how to proceed: {msg}"
    );
    assert!(
        msg.contains("directory_server"),
        "…and the local alternative, which is what a test or an offline user wants: {msg}"
    );
    assert!(
        msg.contains("public internet"),
        "…and why it refused, which is the part a user cannot guess: {msg}"
    );
}

/// Naming a directory is itself an explicit choice, so it needs no second flag. This is the
/// path the existing local-relay e2e test takes.
#[test]
fn a_named_directory_server_is_an_explicit_choice() {
    assert_eq!(
        bootstrap_target(Some("127.0.0.1:9001"), false).unwrap(),
        BootstrapTarget::CustomDirectory("127.0.0.1:9001".to_string())
    );
}

/// Opting in still works — the guard is about consent, not about removing the capability.
#[test]
fn the_public_network_is_reachable_on_explicit_opt_in() {
    assert_eq!(
        bootstrap_target(None, true).unwrap(),
        BootstrapTarget::PublicNetwork
    );
}

/// A contradiction is refused rather than resolved. Guessing which one the caller meant is
/// how a "local test" ends up on the public internet.
#[test]
fn a_directory_server_plus_the_public_opt_in_is_refused() {
    let err = bootstrap_target(Some("127.0.0.1:9001"), true).expect_err("contradictory");
    let msg = err.to_string();
    assert!(
        msg.contains("mutually exclusive"),
        "the refusal must say why, not just fail: {msg}"
    );
}

/// A parameter that is not declared in `get_startup_parameters()` is rejected at startup by
/// name, so an opt-in nobody can pass is no opt-in at all.
#[test]
fn the_opt_in_parameter_is_declared() {
    let params = netget::client::tor::TorClientProtocol::new().get_startup_parameters();
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();

    assert!(
        names.contains(&ALLOW_PUBLIC_TOR_NETWORK_PARAM),
        "the opt-in must be declared or StartupParams rejects it as an unknown key: {names:?}"
    );
    assert!(
        names.contains(&"directory_server"),
        "the local alternative must stay declared: {names:?}"
    );
}

/// `metadata().notes` is where a caller learns this before being surprised by it.
#[test]
fn the_metadata_notes_say_it_does_not_reach_the_internet_by_default() {
    let notes = netget::client::tor::TorClientProtocol::new()
        .metadata()
        .notes
        .unwrap_or_default();

    assert!(
        notes.contains(ALLOW_PUBLIC_TOR_NETWORK_PARAM),
        "notes must name the opt-in: {notes}"
    );
    assert!(
        notes.to_lowercase().contains("public internet"),
        "notes must say what the opt-in permits: {notes}"
    );
}

/// The end-to-end property, through the real `Client::connect`: without an opt-in it returns
/// `Err` **fast**, which is the observable evidence that no bootstrap was attempted.
///
/// The unguarded version took ~14s here because `create_bootstrapped()` runs before the
/// destination is even parsed. A 3s bound cannot be met by anything that contacted a directory
/// authority, so this is a network-reach assertion that itself makes no network call.
#[tokio::test]
async fn connect_without_an_opt_in_is_refused_before_any_network_io() {
    let state = Arc::new(AppState::new());
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    let drain = tokio::spawn(async move { while status_rx.recv().await.is_some() {} });

    let client_id = state
        .add_client(ClientInstance::new(
            ClientId::new(0),
            "example.com:80".to_string(),
            "Tor".to_string(),
            "connect and send a GET".to_string(),
        ))
        .await;

    let ctx = netget::protocol::ConnectContext::new(
        "example.com:80".to_string(),
        // Unroutable: an LLM call would fail on connect rather than reach a model.
        OllamaClient::new("http://127.0.0.1:1"),
        state.clone(),
        status_tx,
        client_id,
    );

    let started = Instant::now();
    let outcome = netget::client::tor::TorClientProtocol::new()
        .connect(ctx)
        .await;
    let elapsed = started.elapsed();
    drain.abort();

    let err = outcome.expect_err("connect must refuse without a bootstrap choice");
    assert!(
        format!("{err:#}").contains(ALLOW_PUBLIC_TOR_NETWORK_PARAM),
        "the error must name the opt-in: {err:#}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "connect took {elapsed:?}; anything near the ~14s bootstrap means it contacted the Tor \
         directory authorities before refusing, which is the defect"
    );
}
