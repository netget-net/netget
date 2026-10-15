//! `/api/embeddings` used to answer without asking anyone.
//!
//! It returned a hardcoded 768-element ramp for every request — no event, no `call_llm`
//! anywhere in the path, no way for the server's instruction to reach it. A server told
//! "this instance serves only llama2, refuse anything else" embedded happily for every model
//! name asked of it. It was the last endpoint on this server still doing that: `/api/show`
//! and the four model-management endpoints had already been converted to decisions.
//!
//! These tests pin the executor half of the conversion: what the model may say, and what it
//! may not. The end-to-end half (the endpoint raising `ollama_embeddings_request` and
//! refusing when nothing answers) is in `e2e_test.rs`.


use netget::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use netget::server::ollama::actions::OllamaProtocol;
use serde_json::json;

/// The vector the executor built, or `None` if it refused the action.
fn embedding_of(action: serde_json::Value) -> Option<Vec<f64>> {
    match OllamaProtocol::new().execute_action(action) {
        Ok(ActionResult::Custom { name, data }) => {
            assert_eq!(name, "ollama_embeddings_response");
            Some(
                data["embedding"]
                    .as_array()
                    .expect("the response carries an embedding array")
                    .iter()
                    .map(|v| v.as_f64().expect("every element is a number"))
                    .collect(),
            )
        }
        Ok(other) => panic!("expected Custom, got {:?}", std::mem::discriminant(&other)),
        Err(_) => None,
    }
}

#[test]
fn dimensions_produces_a_vector_of_that_length() {
    let vector = embedding_of(json!({"type": "ollama_embeddings_response", "dimensions": 768}))
        .expect("768 is the width the endpoint used to hardcode");
    assert_eq!(vector.len(), 768);
    assert!(
        vector.iter().all(|v| (0.0..1.0).contains(v)),
        "the filler ramp stays in [0, 1)"
    );
}

#[test]
fn an_explicit_vector_reaches_the_wire_unchanged() {
    let vector = embedding_of(json!({
        "type": "ollama_embeddings_response",
        "embedding": [0.25, -0.5, 1.75],
    }))
    .expect("an explicit vector is the whole point of the field");
    assert_eq!(vector, vec![0.25, -0.5, 1.75]);
}

#[test]
fn an_unbounded_dimension_count_is_refused() {
    // `dimensions` is model-supplied and the vector is serialised into the reply, so an
    // unbounded value is an allocation one request can name.
    for bad in [0u64, 4097, 100_000, u32::MAX as u64, u64::MAX] {
        assert!(
            embedding_of(json!({"type": "ollama_embeddings_response", "dimensions": bad}))
                .is_none(),
            "dimensions {bad} is out of range and must be refused"
        );
    }
}

#[test]
fn a_malformed_vector_is_refused_rather_than_silently_dropped() {
    for bad in [
        json!({"type": "ollama_embeddings_response", "embedding": []}),
        json!({"type": "ollama_embeddings_response", "embedding": "0.1,0.2"}),
        json!({"type": "ollama_embeddings_response", "embedding": ["0.1", "0.2"]}),
        json!({"type": "ollama_embeddings_response", "embedding": [0.1, null]}),
    ] {
        assert!(
            embedding_of(bad.clone()).is_none(),
            "{bad} is not a usable embedding and must be refused, not truncated"
        );
    }
}

#[test]
fn saying_nothing_useful_is_refused_rather_than_defaulted() {
    // The defect this replaces was exactly a default: no input at all still produced 768
    // dimensions. An action naming neither field must now fail, so the repair loop asks
    // again instead of the peer receiving an invented answer.
    assert!(
        embedding_of(json!({"type": "ollama_embeddings_response"})).is_none(),
        "neither 'embedding' nor 'dimensions' must not fall back to a default vector"
    );
}

#[test]
fn the_endpoint_is_reachable_by_the_model() {
    let protocol = OllamaProtocol::new();

    let event = protocol
        .get_event_types()
        .into_iter()
        .find(|e| e.id == "ollama_embeddings_request")
        .expect("/api/embeddings raises an event the model can answer");

    let offered: Vec<String> = event.actions.iter().map(|a| a.name.clone()).collect();
    assert!(
        offered.iter().any(|n| n == "ollama_embeddings_response"),
        "the event must offer the action that answers it, got {offered:?}"
    );
    assert!(
        offered.iter().any(|n| n == "ollama_error_response"),
        "refusing must stay available on this event, got {offered:?}"
    );

    assert!(
        protocol
            .get_sync_actions()
            .iter()
            .any(|a| a.name == "ollama_embeddings_response"),
        "the action must also be in the protocol's own sync set"
    );
}
