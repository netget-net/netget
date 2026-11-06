use super::common::*;
use crate::helpers::real_server::{InstallHint, RealServer};
use serde_json::json;
#[tokio::test]
async fn real_beanstalkd_job_lifecycle_and_tubes() -> crate::helpers::E2EResult<()> {
    let server = RealServer::builder(
        "beanstalkd",
        InstallHint {
            brew: "beanstalkd",
            apt: "beanstalkd",
        },
    )
    // Let the daemon reserve its own port, then read its successful bind from its
    // verbose log. A released probe port could belong to another test by the time
    // the daemon starts, making a TCP-only readiness check accept the wrong peer.
    .args(["-V", "-l", "127.0.0.1", "-p", "0"])
    .port_from_log(r"(?m)^bind [0-9]+ 127\.0\.0\.1:([0-9]+)$")
    .start()
    .await?;
    let state = state();
    let id = client(&state, server.addr(), json!([])).await;
    assert_eq!(
        request(&state, id, json!({"operation":"use","tube":"images"})).await["tube"],
        "images"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"watch","tube":"images"})).await["count"],
        2
    );
    assert_eq!(
        request(&state, id, json!({"operation":"ignore","tube":"default"})).await["count"],
        1
    );
    assert_eq!(
        request(&state, id, json!({"operation":"list_tube_used"})).await["tube"],
        "images"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"list_tubes_watched"})).await["data"],
        json!(["images"])
    );
    let body = "job ✓\r\nDELETED";
    let inserted = request(&state, id, json!({"operation":"put","body":body})).await;
    assert_eq!(inserted["status"], "INSERTED");
    let job = inserted["id"].as_u64().unwrap();
    let reserved = request(&state, id, json!({"operation":"reserve","timeout_secs":1})).await;
    assert_eq!(reserved["id"], job);
    assert_eq!(reserved["body"], body);
    assert_eq!(
        request(&state, id, json!({"operation":"touch","id":job})).await["status"],
        "TOUCHED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"release","id":job})).await["status"],
        "RELEASED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"peek","id":job})).await["body"],
        body
    );
    assert_eq!(
        request(&state, id, json!({"operation":"reserve_job","id":job})).await["status"],
        "RESERVED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"bury","id":job})).await["status"],
        "BURIED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"stats_job","id":job})).await["data"]["state"],
        "buried"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"kick","count":1})).await["count"],
        1
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"stats_tube","tube":"images"})
        )
        .await["data"]["current-jobs-ready"],
        1
    );
    assert!(
        request(&state, id, json!({"operation":"stats"})).await["data"]["total-jobs"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        request(&state, id, json!({"operation":"list_tubes"})).await["data"]
            .as_array()
            .unwrap()
            .contains(&json!("images"))
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"pause_tube","tube":"images","delay":0})
        )
        .await["status"],
        "PAUSED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"delete","id":job})).await["status"],
        "DELETED"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"peek","id":job})).await["status"],
        "NOT_FOUND"
    );
    assert_eq!(
        request(&state, id, json!({"operation":"reserve","timeout_secs":0})).await["status"],
        "TIMED_OUT"
    );
    state.remove_client(id).await;
    Ok(())
}

async fn real_beanstalkd() -> crate::helpers::E2EResult<RealServer> {
    RealServer::builder(
        "beanstalkd",
        InstallHint {
            brew: "beanstalkd",
            apt: "beanstalkd",
        },
    )
    .args(["-V", "-l", "127.0.0.1", "-p", "0"])
    .port_from_log(r"(?m)^bind [0-9]+ 127\.0\.0\.1:([0-9]+)$")
    .start()
    .await
}

/// Read beanstalkd's own state over a socket of the test's, independent of NetGet's client:
/// the commands are written, then `quit`, and everything the daemon answered is returned.
async fn readback(server: &RealServer, commands: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut socket = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    socket
        .write_all(format!("{commands}quit\r\n").as_bytes())
        .await
        .unwrap();
    let mut answer = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.read_to_string(&mut answer),
    )
    .await
    .expect("beanstalkd readback deadline")
    .unwrap();
    answer
}

/// Condition 4 of the client bar, from beanstalkd's side: the mocked model selects a tube, and
/// on the daemon's `USING` puts a job with a priority it chose. The test's own socket then
/// finds that job ready in that tube, with that body and priority.
#[tokio::test]
async fn mocked_model_puts_a_job_that_real_beanstalkd_holds() -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let server = real_beanstalkd().await?;
    let config = MockLlmBuilder::new()
        .on_event("beanstalkd_connected")
        .respond_with_actions(json!([
            {"type":"beanstalkd_request","operation":"use","tube":"model-tube"}
        ]))
        .expect_calls(1)
        .and()
        .on_event("beanstalkd_response")
        .and_event_data_contains("response", "\"status\":\"USING\"")
        .and_event_data_contains("response", "model-tube")
        .respond_with_actions(json!([
            {"type":"beanstalkd_request","operation":"put","body":"chosen by the model","priority":7}
        ]))
        .expect_calls(1)
        .and()
        .on_event("beanstalkd_response")
        .and_event_data_contains("response", "\"status\":\"INSERTED\"")
        .respond_with_actions(json!([]))
        .expect_calls(1)
        .and()
        .build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "beanstalkd".into(),
        remote_addr: Some(server.addr()),
        instruction: Some("Queue one job in model-tube".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    let answer = readback(&server, "use model-tube\r\npeek-ready\r\n").await;
    let lines: Vec<&str> = answer.split("\r\n").collect();
    let found = lines
        .iter()
        .position(|l| l.starts_with("FOUND "))
        .unwrap_or_else(|| panic!("no job ready in model-tube: {answer:?}"));
    assert_eq!(lines[found + 1], "chosen by the model", "{answer:?}");
    let job = lines[found].split(' ').nth(1).unwrap();
    let stats = readback(&server, &format!("stats-job {job}\r\n")).await;
    assert!(
        stats.contains("\ntube: \"model-tube\"\n") || stats.contains("\ntube: model-tube\n"),
        "{stats}"
    );
    assert!(stats.contains("\npri: 7\n"), "{stats}");
    state.remove_client(id).await;
    Ok(())
}

/// A model that answers every response with another request stops after `MAX_FOLLOWUPS`
/// requests, counted by beanstalkd itself.
#[tokio::test]
async fn real_beanstalkd_counts_a_bounded_follow_up_chain() -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let limit = netget::client::beanstalkd::wire::MAX_FOLLOWUPS as usize;
    let server = real_beanstalkd().await?;
    let config = MockLlmBuilder::new()
        .on_event("beanstalkd_connected")
        .respond_with_actions(json!([{"type":"beanstalkd_request","operation":"list_tubes"}]))
        .expect_calls(1)
        .and()
        .on_event("beanstalkd_response")
        .respond_with_actions(json!([{"type":"beanstalkd_request","operation":"list_tubes"}]))
        .expect_calls(limit)
        .and()
        .build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "beanstalkd".into(),
        remote_addr: Some(server.addr()),
        instruction: Some("Keep listing tubes".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    mock.wait_for_expectations(30).await;
    // An unbounded chain keeps going; give it the time to show.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let stats = readback(&server, "stats\r\n").await;
    assert!(
        stats.contains(&format!("\ncmd-list-tubes: {limit}\n")),
        "beanstalkd did not count exactly {limit} list-tubes: {stats}"
    );
    assert_eq!(mock.call_count().await, limit + 1);
    mock.verify_calls().await?;
    state.remove_client(id).await;
    Ok(())
}
