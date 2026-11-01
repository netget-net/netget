//! `provide_feedback` was advertised to clients and no client could execute it.
//!
//! `call_llm_for_client` injects `common::provide_feedback_action()` into the tool list of any
//! client that was started with `feedback_instructions`. Every client then hands the model's
//! actions straight to its own `Client::execute_action`, which knows only its protocol's
//! vocabulary — so a model that used the tool it was offered had the call rejected as an
//! *unknown action*, retried, and finally dropped. The same fail-open shape as elsewhere in
//! this tree, one level up: the model is shown a tool it is then punished for using.
//!
//! The server path never had this problem because `executor::execute_actions` tries
//! `CommonAction::from_json` before the protocol. Clients never reach that executor, so the fix
//! splits the common actions out inside `call_llm_for_client` — the one place that advertises
//! them — and runs them through the very same executor the server path uses.
//!
//! `tests/event_action_declarations_test.rs` cannot catch this: its executor round-trip walks
//! `client_llm_action_set(...)`, which is the union of the *protocol's* declarations and
//! deliberately does not include an action injected by the caller. This file is the guard for
//! the injected half, in both directions — an advertised name with no handler, and a handler
//! for a name nothing advertises.
//!
//! ```bash
//! ./cargo-isolated.sh test --no-default-features --features tcp \
//!     --test client_provide_feedback_test -- --test-threads=100
//! ```

use netget::llm::action_helper::{split_client_common_actions, CLIENT_COMMON_ACTION_NAMES};
use netget::llm::actions::client_trait::client_llm_action_set;
use netget::llm::actions::executor::execute_actions;
use netget::protocol::client_registry::CLIENT_REGISTRY;
use netget::state::app_state::AppState;
use netget::state::client::ClientInstance;
use netget::state::ClientId;

fn feedback_action() -> serde_json::Value {
    serde_json::json!({
        "type": "provide_feedback",
        "feedback": { "observation": "the server keeps closing the connection" }
    })
}

/// A client with `feedback_instructions` set, which is the only condition under which
/// `call_llm_for_client` advertises `provide_feedback` at all.
async fn client_with_feedback_instructions(state: &AppState) -> ClientId {
    let mut instance = ClientInstance::new(
        ClientId::new(0),
        "127.0.0.1:9".to_string(),
        "tcp".to_string(),
        "test".to_string(),
    );
    instance.feedback_instructions = Some("adjust the request rate if the peer throttles".into());
    state.add_client(instance).await
}

/// The defect itself, stated as an invariant: no client protocol implements
/// `provide_feedback`, therefore it *must* be handled centrally. If some client ever does
/// implement it, this fails and the central split can be reconsidered — which is the point of
/// asserting it rather than assuming it.
///
/// Feature-gated by whatever clients this build compiled in; with none it asserts nothing and
/// says so.
#[test]
fn no_client_protocol_executor_can_run_provide_feedback() {
    let mut accepted: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for client in CLIENT_REGISTRY.get_all() {
        checked += 1;
        if client.execute_action(feedback_action()).is_ok() {
            accepted.push(client.protocol_name().to_string());
        }
    }

    eprintln!("probed {checked} registered client(s) with provide_feedback");
    assert!(
        accepted.is_empty(),
        "these clients now accept provide_feedback themselves, so it is executed twice — once \
         centrally and once by the protocol: {accepted:?}"
    );
}

/// Both directions of the advertise/handle contract.
///
/// A name in `CLIENT_COMMON_ACTION_NAMES` that nothing advertises is dead weight; a name
/// advertised by `call_llm_for_client` that is missing from the list goes to the protocol
/// executor and is rejected as unknown, costing two retries and then failing the event.
///
/// `provide_feedback` was the only member until the client path was found to advertise no way
/// to write the client's own memory (`ClientInstance::memory`, which is prefixed to every
/// message it is sent) and no way to say anything to the user. Three client E2E suites —
/// redis, udp, http — were mocking `set_memory` and `show_message` on the assumption that they
/// worked.
#[test]
fn the_centrally_handled_names_are_exactly_the_injected_ones() {
    assert_eq!(
        CLIENT_COMMON_ACTION_NAMES,
        &[
            "provide_feedback",
            "set_memory",
            "append_memory",
            "notify_operator"
        ],
        "these are the actions call_llm_for_client injects that no client declares. If another \
         is added there, add it here too, or the model will be offered a tool its protocol \
         rejects; if one is removed here but still injected, the same happens."
    );

    // …and each name matches the action definition actually injected, not a copy that drifted.
    use netget::llm::actions::common;
    for (injected, listed) in [
        (common::provide_feedback_action().name, "provide_feedback"),
        (common::set_memory_action().name, "set_memory"),
        (common::append_memory_action().name, "append_memory"),
        (common::notify_operator_action().name, "notify_operator"),
    ] {
        assert_eq!(
            injected, listed,
            "the injected action's name and the centrally-handled name must be the same string"
        );
        assert!(
            CLIENT_COMMON_ACTION_NAMES.contains(&listed),
            "{listed} is injected but not centrally handled, so it would reach the protocol \
             executor and be rejected"
        );
    }
}

/// The split: a common action is taken out, protocol actions pass through untouched and in
/// order. Order matters — a client that sends a request and then disconnects must see those
/// two in that sequence.
#[test]
fn provide_feedback_is_split_out_and_protocol_actions_keep_their_order() {
    let (common, protocol) = split_client_common_actions(vec![
        serde_json::json!({"type": "send_data", "data": "first"}),
        feedback_action(),
        serde_json::json!({"type": "disconnect"}),
    ]);

    assert_eq!(common.len(), 1, "the feedback action must be taken out");
    assert_eq!(common[0]["type"], "provide_feedback");

    let names: Vec<&str> = protocol
        .iter()
        .map(|a| a["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["send_data", "disconnect"],
        "protocol actions must reach the client's executor unchanged and in order; \
         provide_feedback must not be among them, because every client rejects it"
    );
}

/// An action with no `type`, or a type that is not a string, must not be swallowed as
/// "common" — it belongs to the protocol, which will report it properly.
#[test]
fn malformed_actions_are_left_to_the_protocol_executor() {
    let (common, protocol) = split_client_common_actions(vec![
        serde_json::json!({"no_type_field": true}),
        serde_json::json!({"type": 7}),
    ]);
    assert!(common.is_empty(), "nothing here is a common action");
    assert_eq!(protocol.len(), 2);
}

/// The other half of the fix: the split-out action is actually *executed*, through the same
/// `executor::execute_actions` the server path uses, and its payload lands in the client's
/// feedback buffer.
#[tokio::test]
async fn provide_feedback_from_a_client_lands_in_its_feedback_buffer() {
    let state = AppState::new();
    let client_id = client_with_feedback_instructions(&state).await;

    let (common, _protocol) = split_client_common_actions(vec![feedback_action()]);
    execute_actions(common, &state, None, None, Some(client_id))
        .await
        .expect("executing a client's common actions must not fail");

    let buffered = state
        .with_client_mut(client_id, |c| c.feedback_buffer.clone())
        .await
        .expect("client still registered");

    assert_eq!(
        buffered.len(),
        1,
        "the feedback the model provided was not stored; the action was advertised, accepted \
         and then went nowhere"
    );
    assert_eq!(
        buffered[0]["observation"], "the server keeps closing the connection",
        "the feedback payload must be stored verbatim, got {:?}",
        buffered[0]
    );
}

/// Fail closed, not open: a client started *without* `feedback_instructions` is never
/// advertised the action, and if the model sends it anyway nothing is stored. The check lives
/// in `AppState::add_client_feedback`; this pins that the central handler does not bypass it.
#[tokio::test]
async fn feedback_is_not_stored_for_a_client_that_configured_none() {
    let state = AppState::new();
    let instance = ClientInstance::new(
        ClientId::new(0),
        "127.0.0.1:9".to_string(),
        "tcp".to_string(),
        "test".to_string(),
    );
    let client_id = state.add_client(instance).await;

    let (common, _) = split_client_common_actions(vec![feedback_action()]);
    execute_actions(common, &state, None, None, Some(client_id))
        .await
        .expect("execution reports the refusal via the log, not as a hard error");

    let buffered = state
        .with_client_mut(client_id, |c| c.feedback_buffer.clone())
        .await
        .expect("client still registered");
    assert!(
        buffered.is_empty(),
        "a client with no feedback_instructions must accumulate nothing, got {buffered:?}"
    );
}

/// Guard against the opposite mistake: `provide_feedback` must **not** be added to
/// `client_llm_action_set`, which is the protocol's own declared vocabulary. If it were, the
/// executor round-trip in `tests/event_action_declarations_test.rs` would fail for every
/// client — correctly, because no protocol implements it.
#[test]
fn provide_feedback_is_not_part_of_any_protocols_declared_action_set() {
    let state = AppState::new();
    let mut offenders: Vec<String> = Vec::new();

    for client in CLIENT_REGISTRY.get_all() {
        if client_llm_action_set(client.as_ref(), &state, None)
            .iter()
            .any(|a| a.name == "provide_feedback")
        {
            offenders.push(client.protocol_name().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "provide_feedback is injected by call_llm_for_client, not declared by a protocol. \
         Declaring it makes the executor round-trip guard fail, because no client can run it: \
         {offenders:?}"
    );
}
