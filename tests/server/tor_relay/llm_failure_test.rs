//! What a Tor peer gets when the LLM backend fails.
//!
//! The failure is forced the way `tests/server/dns/llm_failure_test.rs` forces it: mocks are
//! configured for the startup instruction and for `tor_relay_circuit_created` only, so the
//! circuit comes up normally and then the `tor_relay_relay_cell` event matches no rule, the
//! mock Ollama server answers HTTP 500, and `call_llm` returns `Err`.
//!
//! That event fires for RELAY commands the relay does not implement itself — EXTEND, TRUNCATE,
//! RESOLVE, DROP — so the model *is* the whole answer, and `if let Ok(execution_result) = ...`
//! meant the peer got nothing at all: a circuit that had accepted its cell and would never
//! speak again, until the client's own timeout.
//!
//! Tor's vocabulary for "this relay cannot carry on with your circuit" is a DESTROY cell
//! (tor-spec 5.4) carrying a reason, and reason 2 INTERNAL is precisely "an error at the
//! relay". It also needs no relay-cell encryption, so it is deliverable even when the circuit
//! crypto is what is unhappy. The assertion below is on the bytes of that cell.
//!
//! Everything here is 127.0.0.1. The real Tor network is never contacted, and no exit stream
//! is opened.

#[cfg(unix)]
mod tests {
    use super::super::super::helpers::{self, E2EResult, NetGetConfig};
    use super::super::peer::{
        read_relay_identity, RelayPeer, CELL_CREATED2, CELL_DESTROY, CELL_RELAY,
        DESTROY_REASON_INTERNAL, RELAY_EXTEND,
    };
    use serde_json::json;

    /// An unimplemented RELAY command the model cannot answer must tear the circuit down in
    /// Tor's own vocabulary, not leave the peer waiting on a silent circuit.
    #[tokio::test]
    async fn test_tor_relay_destroys_circuit_when_llm_fails() -> E2EResult<()> {
        let prompt = "listen on port {AVAILABLE_PORT} via tor-relay. Handle TLS connections \
                      and Tor cells.";
        let config = NetGetConfig::new_no_scripts(prompt)
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("tor-relay")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            // The registry name has a space in it; "TorRelay" is rejected.
                            "base_stack": "Tor Relay",
                            "instruction": "Tor relay for LLM-failure testing"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // The circuit must come up, so this event is answered — with an action
                    // that produces no output, since an Output here would replace the
                    // CREATED2 cell the relay is about to send.
                    .on_event("tor_relay_circuit_created")
                    .respond_with_actions(json!([
                        {"type": "detect_relay_cell", "message": "circuit up"}
                    ]))
                    .expect_calls(1)
                    .and()
                // Deliberately NO rule for `tor_relay_relay_cell`: the mock answers 500,
                // which is what drives the RELAY handler down its LLM-failure path.
            });

        let server = helpers::start_netget_server(config).await?;
        let (fingerprint, onion_key) = read_relay_identity(&server).await?;

        let mut peer = RelayPeer::connect(server.port).await?;
        let versions = peer.versions_handshake().await?;
        assert!(
            versions.contains(&4),
            "the relay frames link protocol v4 cells; got {versions:?}"
        );
        peer.create_circuit(&fingerprint, &onion_key).await?;

        // RELAY/EXTEND is not implemented in Rust, so it is handed to the model — which is
        // exactly the path whose failure used to be swallowed.
        peer.send_relay(RELAY_EXTEND, 0, b"extend-me").await?;

        let cell = peer
            .recv_cell(
                "the reply to a RELAY command the model could not answer (the relay went \
                 silent on LLM failure if this times out)",
            )
            .await;

        assert_ne!(
            cell[4], CELL_RELAY,
            "an LLM failure must not be answered with a RELAY cell: the peer would read it as \
             the EXTENDED/RESOLVED/TRUNCATED it asked for"
        );
        assert_eq!(
            cell[4], CELL_DESTROY,
            "an LLM failure on an unimplemented RELAY command must tear the circuit down with \
             a DESTROY (4) cell, got command {}",
            cell[4]
        );
        assert_eq!(
            cell[5], DESTROY_REASON_INTERNAL,
            "the DESTROY reason must be 2 INTERNAL — the fault is the relay's, not the \
             client's and not a protocol violation — got reason {}",
            cell[5]
        );
        assert_eq!(cell.len(), 514, "a v4 fixed cell is 514 bytes");
        assert!(
            cell[6..].iter().all(|&b| b == 0),
            "a DESTROY cell carries only its reason; the rest of the payload must be padding"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// A CREATE2 the model could not rule on must not be admitted.
    ///
    /// CREATED2 completes the ntor handshake and hands the peer a circuit — it *is* admission.
    /// Sending it on an LLM failure turned "the backend is down" into "every circuit is
    /// accepted", which is the fail-open shape the root CLAUDE.md warns about. The relay must
    /// answer with DESTROY / reason 2 INTERNAL instead.
    #[tokio::test]
    async fn test_tor_relay_refuses_circuit_when_llm_fails_on_create2() -> E2EResult<()> {
        let prompt = "listen on port {AVAILABLE_PORT} via tor-relay. Handle TLS connections \
                      and Tor cells.";
        let config = NetGetConfig::new_no_scripts(prompt)
            .with_log_level("info")
            .with_mock(|mock| {
                mock.on_instruction_containing("tor-relay")
                    .respond_with_actions(json!([
                        {
                            "type": "open_server",
                            "port": 0,
                            "base_stack": "Tor Relay",
                            "instruction": "Tor relay for LLM-failure testing"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                // Deliberately NO rule for `tor_relay_circuit_created`: the mock answers 500,
                // which drives CREATE2 down its LLM-failure path.
            });

        let server = helpers::start_netget_server(config).await?;
        let (fingerprint, onion_key) = read_relay_identity(&server).await?;

        let mut peer = RelayPeer::connect(server.port).await?;
        let versions = peer.versions_handshake().await?;
        assert!(
            versions.contains(&4),
            "expected link protocol v4, got {versions:?}"
        );

        let cell = peer
            .send_create2_expecting_any(
                &fingerprint,
                &onion_key,
                "the reply to a CREATE2 the model could not rule on (the relay went silent \
                 on LLM failure if this times out)",
            )
            .await?;

        assert_ne!(
            cell[4], CELL_CREATED2,
            "an LLM failure on CREATE2 must not be answered with CREATED2: that admits the \
             circuit the model was never able to approve"
        );
        assert_eq!(
            cell[4], CELL_DESTROY,
            "an LLM failure on CREATE2 must be answered with DESTROY (4), got command {}",
            cell[4]
        );
        assert_eq!(
            cell[5], DESTROY_REASON_INTERNAL,
            "the DESTROY reason must be 2 INTERNAL, got {}",
            cell[5]
        );
        assert!(
            cell[6..].iter().all(|&b| b == 0),
            "a DESTROY cell carries only its reason; the rest must be padding"
        );

        server
            .wait_for_log("decision=fail_closed_llm_error", 30)
            .await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
