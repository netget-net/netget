//! An OpenAPI server takes unauthenticated POSTs whose bodies it buffers whole.
//!
//! `hyper`'s `Incoming` has no default limit, so `req.into_body().collect()` read whatever the
//! peer chose to send, and the body then goes into the `openapi_request` event and from there
//! into an LLM prompt.
//!
//! The old error arm was worse than merely unbounded: it swallowed the read failure into
//! `Bytes::new()` and carried on, so the model was shown a request with *no* body and answered
//! it as though the peer had sent none. That is the truncated-body trap — the model answers a
//! request it never saw — and it is why the cap returns a distinct 413 rather than an empty
//! body.


use crate::server::helpers::{self, E2EResult, NetGetConfig};

const SPEC: &str = r#"openapi: 3.1.0
info:
  title: Upload API
  version: 1.0.0
paths:
  /notes:
    post:
      operationId: createNote
      responses:
        '201':
          description: created
"#;

#[tokio::test]
async fn an_oversized_request_body_is_refused_without_reaching_the_model() -> E2EResult<()> {
    // The `openapi_request` event is answered by a static rule, so a request that gets past
    // the cap costs no LLM call — which means the mock budget stays at the one startup call
    // and an accidental extra call would show up as a mismatch rather than passing quietly.
    let config =
        NetGetConfig::new("Open an OpenAPI server on port {AVAILABLE_PORT}.").with_mock(|mock| {
            mock.on_instruction_containing("OpenAPI")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "openapi",
                        "instruction": "Serve the notes API",
                        "startup_params": { "spec": SPEC },
                        "event_handlers": [{
                            "event_pattern": "openapi_request",
                            "handler": {
                                "type": "static",
                                "actions": [{
                                    "type": "send_openapi_response",
                                    "status_code": 201,
                                    "headers": {"content-type": "application/json"},
                                    "body": "{\"id\": 1}"
                                }]
                            }
                        }]
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(config).await?;
    let url = format!("http://127.0.0.1:{}/notes", server.port);

    // `start_netget_server` returns when startup has been *parsed*, not when the socket is
    // bound, so the first request can land on a port nothing is listening on yet. A 9 MiB
    // POST failing that way surfaces as a transport error, which reads exactly like the cap
    // not working — wait for the listener instead of assuming. An unmatched route is enough:
    // the point is that something accepted the connection.
    let probe = reqwest::Client::new();
    let mut bound = false;
    for _ in 0..300 {
        if probe
            .get(format!("http://127.0.0.1:{}/", server.port))
            .send()
            .await
            .is_ok()
        {
            bound = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(bound, "the OpenAPI server never bound its port");

    // 9 MiB of note, one megabyte past the 8 MiB cap.
    let refused = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"note": "A".repeat(9 * 1024 * 1024)}))
        .send()
        .await?;
    assert_eq!(
        refused.status(),
        413,
        "a body past the cap must be refused with 413, not buffered — and certainly not \
         silently replaced with an empty body the model then answers"
    );

    // An ordinary request on the same route still works, so the guard is not just refusing
    // everything.
    let accepted = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"note": "hello"}))
        .send()
        .await?;
    assert_eq!(
        accepted.status(),
        201,
        "an ordinary request must not be caught by the body cap"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
