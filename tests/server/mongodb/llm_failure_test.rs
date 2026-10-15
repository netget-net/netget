//! What a MongoDB driver gets when the LLM backend fails: an `{ok: 0}` command reply.
//!
//! The failure propagated with `?`, which dropped the connection with nothing written. A
//! driver blocks on the reply to every command, so the operation hung until the driver's own
//! timeout and was then reported as a network fault - which sends a replica-set-aware driver
//! looking for another node rather than surfacing a server error.
//!
//! `{ok: 0, code, errmsg}` is the only shape a driver reads as a command failure. Anything
//! with `ok: 1` is a result, and for `find` an empty result means "no documents matched" - a
//! statement about the data that nothing here is in a position to make.
//!
//! The code is `InternalError` (1) whether or not the backend was merely saturated. MongoDB's
//! driver-retryable codes all describe replica-set failover (ShutdownInProgress,
//! PrimarySteppedDown, NotWritablePrimary) and claiming one would send the driver hunting for
//! a new primary that does not exist, so the overload distinction stays in the log.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_mongodb_answers_ok_zero_when_llm_fails() -> E2EResult<()> {
    let prompt = "Open mongodb on port {AVAILABLE_PORT}. Serve a users collection.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("Open mongodb")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "MongoDB",
                    "instruction": "Serve a users collection"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `mongodb_command`. `hello` is answered locally (a driver refuses to use
        // a server that does not advertise a wire-version range), so the handshake completes
        // and the first real command is what fails.
    });

    let server = start_netget_server(config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let uri = format!(
        "mongodb://127.0.0.1:{}/?directConnection=true&serverSelectionTimeoutMS=8000",
        server.port
    );
    let client = mongodb::Client::with_uri_str(&uri).await?;
    let collection = client
        .database("testdb")
        .collection::<mongodb::bson::Document>("users");

    let outcome = tokio::time::timeout(
        Duration::from_secs(25),
        collection.find_one(mongodb::bson::doc! {"name": "alice"}),
    )
    .await
    .map_err(|_| {
        "MongoDB neither answered nor failed within 25s - the server went silent on LLM \
         failure, which is the exact defect this test exists to catch"
    })?;

    let error = match outcome {
        Ok(found) => panic!(
            "MongoDB reported success ({found:?}) despite the backend being unavailable. \
             `None` here means 'no document matched', which is a claim about the data."
        ),
        Err(e) => e,
    };
    println!("MongoDB error: {error:?}");

    let message = error.to_string();
    assert!(
        message.contains("netget"),
        "the errmsg should name the source of the failure: {error:?}"
    );
    assert!(
        !matches!(
            *error.kind,
            mongodb::error::ErrorKind::ServerSelection { .. }
        ),
        "a server-selection failure means the driver never got a reply at all - i.e. the \
         server went silent, which is the defect: {error:?}"
    );

    // The driver must see a *command* failure carrying a code, not a transport error. Code 1
    // is InternalError, the `WireFailure::Unavailable` mapping; the mock backend here is
    // simply unmatched, not saturated, so 365 (`TemporarilyUnavailable`, the `Overloaded`
    // mapping) would be wrong.
    match &*error.kind {
        mongodb::error::ErrorKind::Command(cmd) => {
            assert_eq!(
                cmd.code, 1,
                "expected InternalError (1) for a non-overload backend failure: {error:?}"
            );
        }
        other => panic!("expected a MongoDB command error, got {other:?}"),
    }

    // The category, and nothing derived from the error. If netget's retry text, a backend URL
    // or a model name ever reaches the wire again, this catches it at the driver.
    assert!(
        message.contains("request could not be processed")
            || message.contains("backend at capacity"),
        "errmsg must carry a category only: {error:?}"
    );
    for leak in ["http://", "ollama", "127.0.0.1:11434", "retries", ".rs:"] {
        assert!(
            !message.contains(leak),
            "internal detail `{leak}` reached the wire: {error:?}"
        );
    }

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
