//! What a CTAP host gets when the LLM backend fails.
//!
//! The failure is forced by configuring a mock for the *startup* instruction only. Every event
//! the protocol raises then matches no rule, the mock Ollama server answers HTTP 500, and
//! `call_llm` returns `Err` — the same shape as a real backend outage, an overload, or a
//! malformed model response.
//!
//! FIDO2 already failed *closed*: `ApprovalManager::wait` denies on expiry, so a credential
//! could never be issued by an outage. What it did not do is say so promptly. The host had
//! already been told `KEEPALIVE(UPNEEDED)` and would keep polling for up to
//! `approval_timeout_secs` — 30s by default — for an answer that was never coming, because the
//! LLM error was logged and then dropped on the floor.
//!
//! So the assertion here is two-part, and both halves matter:
//!
//! 1. **The status is `CTAP2_ERR_OPERATION_DENIED` (0x27)** — CTAP2's own word for "the user
//!    said no", which is the same thing an explicit `deny_request` produces and the only
//!    honest thing to say when the decision could not be obtained. Never an attestation.
//! 2. **It arrives in a fraction of the approval window.** The test sets a 30s window and
//!    requires an answer inside 12s, so a regression that goes back to waiting out the timeout
//!    fails here rather than merely being slow.
//!
//! And, because this is the protocol where a fail-open would be worst: after the failure the
//! store must still be empty. A GetAssertion for the same relying party must report
//! `CTAP2_ERR_NO_CREDENTIALS`, which can only hold if no key pair was ever generated.

#[cfg(all(unix, feature = "libusb"))]
mod usb_fido2_llm_failure {
    use std::time::{Duration, Instant};

    use crate::helpers::*;
    use crate::server::usb_fido2::ctaphid_client::*;

    /// The dual-logged ERROR the LLM-failure path emits. `console_error!` writes it through
    /// `tracing::error!` and the status channel at once.
    const LLM_FAILURE_LOG: &str = "LLM call failed for USB FIDO2 connection";
    /// The line that proves the request was refused *here* rather than by the timeout.
    const FAIL_CLOSED_LOG: &str = "DENIED (fail closed)";

    /// How long the server is told to wait for a decision. Deliberately long: the point of the
    /// test is that the answer does not take this long.
    const APPROVAL_WINDOW_SECS: u64 = 30;
    /// The budget the answer must fit inside. Comfortably above a loopback round trip and an
    /// LLM error, comfortably below `APPROVAL_WINDOW_SECS`.
    const ANSWER_BUDGET: Duration = Duration::from_secs(12);

    const CLIENT_DATA_HASH: [u8; 32] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x90,
    ];

    #[tokio::test]
    async fn test_fido2_denies_immediately_when_llm_fails() -> E2EResult<()> {
        let config = NetGetConfig::new_no_scripts(
            "Be a FIDO2 security key on port {AVAILABLE_PORT}.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_instruction_containing("FIDO2 security key")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "usb-fido2",
                    "instruction": "Decide each registration",
                    "startup_params": {
                        "auto_approve": false,
                        "approval_timeout_secs": APPROVAL_WINDOW_SECS
                    }
                }]))
                .expect_calls(1)
                .and()
            // Deliberately NO rule for fido2_device_attached or fido2_register_request: the
            // mock answers 500, which is what drives the server down its LLM-failure path.
        });

        let server = start_netget_server(config).await?;

        let mut key = CtapHidClient::attach(server.port).await?;
        // The attach event fails too; that is informational and has no wire consequence, but it
        // is the cheapest proof the LLM really is unreachable before the interesting call.
        server.wait_for_log(LLM_FAILURE_LOG, 15).await?;
        key.init().await?;

        // The registration. The device asks the model, the call fails, and the model's absence
        // must become a refusal — promptly.
        let started = Instant::now();
        let refused = key
            .cbor(
                &ctap2_make_credential("outage.example", "user@outage.example", &CLIENT_DATA_HASH),
                // Generous, so a hang shows up as a wrong *elapsed* time below rather than as
                // an opaque client timeout.
                Duration::from_secs(APPROVAL_WINDOW_SECS + 20),
            )
            .await?;
        let elapsed = started.elapsed();

        assert_eq!(
            refused.status, CTAP2_ERR_OPERATION_DENIED,
            "an LLM failure must refuse in CTAP2's own vocabulary — \
             CTAP2_ERR_OPERATION_DENIED (0x27) — got {:#04x}",
            refused.status
        );
        assert!(
            refused.payload.is_empty(),
            "a refused MakeCredential must carry no attestation; got {} byte(s)",
            refused.payload.len()
        );
        assert!(
            elapsed < ANSWER_BUDGET,
            "the refusal took {:?}. An LLM failure must deny at once rather than leave the host \
             polling KEEPALIVE for the whole {}s approval window",
            elapsed,
            APPROVAL_WINDOW_SECS
        );

        // The refusal must be recorded, not swallowed — and distinguishably so. A model that
        // says `deny_request` does not log this line; only a failed call does.
        server.wait_for_log(FAIL_CLOSED_LOG, 10).await?;

        // An outage and a policy refusal both reach the host as
        // CTAP2_ERR_OPERATION_DENIED, so the wire cannot tell them apart and the log has to --
        // the discipline `src/server/radius/` sets. Without the tag, "the model said no" and
        // "the model could not be reached" are indistinguishable after the fact, and on an
        // authenticator that is the difference between a decision and an incident.
        server
            .wait_for_log("decision=fail_closed_llm_error", 10)
            .await?;

        // Nothing may have been created along the way. If a key pair had been generated before
        // the decision, this would find it.
        let after = key
            .cbor(
                &ctap2_get_assertion("outage.example", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            after.status, CTAP2_ERR_NO_CREDENTIALS,
            "an LLM failure must store nothing, so GetAssertion must report \
             CTAP2_ERR_NO_CREDENTIALS (0x2e); got {:#04x}",
            after.status
        );

        // The transport must still be alive: a refusal is not a broken device, and a host that
        // retries once the backend recovers has to find a key that still answers.
        let pong = key.ping(b"still here").await?;
        assert_eq!(
            pong, b"still here",
            "the CTAPHID transport must survive a refused command"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }
}
