//! Every terminal outcome of a Gopher request is grep-able as `decision=<token>`.
//!
//! Gopher answers a failure with the one error form it has — a type-3 item carrying a
//! `WireFailure` category — and it answers a model that said nothing with *the same item*.
//! The wire therefore cannot distinguish a backend outage from a model that produced no
//! usable action, and the log is the only place that distinction can live. That is what
//! these tests assert: the reply is the category, and the log says which of the two it was.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send one selector and read to EOF, which is the whole Gopher exchange.
async fn gopher_request(addr: &str, selector: &str) -> E2EResult<String> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(format!("{}\r\n", selector).as_bytes())
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response))
        .await
        .map_err(|_| {
            "Gopher did not answer and did not close within 20s; RFC 1436 closes after one reply"
        })??;
    Ok(String::from_utf8_lossy(&response).to_string())
}

fn open_gopher_server() -> serde_json::Value {
    serde_json::json!([
        {
            "type": "open_server",
            "port": 0,
            "base_stack": "gopher",
            "instruction": "Serve a small gopherhole"
        }
    ])
}

/// The backend fails: a type-3 category on the wire, `decision=fail_closed_llm_error` in the
/// log, and nothing derived from the error anywhere near the socket.
#[tokio::test]
async fn test_gopher_llm_failure_is_tagged_fail_closed() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via gopher. Serve a small gopherhole";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via gopher")
            .respond_with_actions(open_gopher_server())
            .expect_calls(1)
            .and()
            // Not JSON and not an action, so the retry/repair loop exhausts and `call_llm`
            // returns Err — the backend-failure path.
            .on_event("gopher_request")
            .respond_with_raw("the backend is having a bad day and this is not an action")
            .expect_at_least(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;
    let reply = gopher_request(&format!("127.0.0.1:{}", server.port), "/about.txt").await?;
    println!("Gopher reply: {:?}", reply);

    assert!(
        reply.starts_with('3'),
        "a failure must be answered with a type-3 error item, got: {reply:?}"
    );
    assert!(
        !reply.contains("LLM") && !reply.contains("Ollama") && !reply.contains("retries"),
        "the peer must get a category, never netget's own error text: {reply:?}"
    );

    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure and a model that answered with nothing produce the same type-3 \
         item, so the log must say which. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The model answers, and the answer is applied: `decision=model_answer`, distinct from every
/// failure token. Without this half the failure assertion above proves nothing — a tag that is
/// emitted on every request would satisfy it too.
#[tokio::test]
async fn test_gopher_successful_answer_is_tagged_model_answer() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via gopher. Serve a small gopherhole";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via gopher")
            .respond_with_actions(open_gopher_server())
            .expect_calls(1)
            .and()
            .on_event("gopher_request")
            .and_event_data_contains("selector", "/about.txt")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "send_gopher_text",
                    "text": "About this hole"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    // Condition, not a fixed sleep: under `--test-threads=100` the listener can be a second
    // or more behind the process starting.
    server.wait_for_any(&["listening on"], 30).await;
    let reply = gopher_request(&format!("127.0.0.1:{}", server.port), "/about.txt").await?;
    assert!(
        reply.contains("About this hole"),
        "expected the mocked document, got: {reply:?}"
    );

    server.wait_for_any(&["decision=model_answer"], 30).await;
    let lines = server.get_output().await;
    assert!(
        lines.iter().any(|l| l.contains("decision=model_answer")),
        "an applied answer must be tagged model_answer. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=fail_closed")),
        "a successful request must not log any fail_closed token. Output was:\n{}",
        lines.join("\n")
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
