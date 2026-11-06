use super::common::*;
use crate::helpers::real_server::{find_binary, InstallHint, RealServer};
use netget::state::{app_state::AppState, ClientId};
use serde_json::json;
use std::{process::Stdio, time::Duration};
#[tokio::test]
async fn real_dictd_definitions_search_discovery_and_errors() -> crate::helpers::E2EResult<()> {
    let data = tempfile::tempdir()?;
    let source = data.path().join("source.txt");
    std::fs::write(
        &source,
        ":hello: A greeting from the independent server.\n.dot starts here\n:help: Assistance.\n",
    )?;
    let dictfmt = find_binary("dictfmt")
        .expect("dictfmt required: brew install dict / apt-get install dictfmt dictd");
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(dictfmt)
            .args([
                "-j",
                "--utf8",
                "--quiet",
                "--without-headword",
                "--without-time",
                "-s",
                "Fixture dictionary",
            ])
            .arg(data.path().join("fixture"))
            .stdin(Stdio::from(std::fs::File::open(source)?))
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(
        output.status.success(),
        "dictfmt: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let conf=format!("access {{ allow * }}\ndatabase fixture {{ data \"{}/fixture.dict\" index \"{}/fixture.index\" }}\n",data.path().display(),data.path().display());
    let server = RealServer::builder(
        "dictd",
        InstallHint {
            brew: "dict",
            apt: "dictd dictfmt",
        },
    )
    .config_file("dictd.conf", &conf)
    .args([
        "--debug",
        "nodetach",
        "--listen-to",
        "127.0.0.1",
        "--port",
        "{port}",
        "--config",
        "{dir}/dictd.conf",
        "--pid-file",
        "{dir}/dictd.pid",
    ])
    .start()
    .await?;
    let state = state();
    let id = client(&state, server.addr(), json!([])).await;
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"client","name":"NetGet independent test"})
        )
        .await["code"],
        250
    );
    let definitions = request(
        &state,
        id,
        json!({"operation":"define","database":"fixture","word":"hello"}),
    )
    .await;
    assert!(
        definitions["definitions"][0]["text"]
            .as_str()
            .unwrap()
            .contains("independent server"),
        "{definitions}"
    );
    assert!(definitions["definitions"][0]["text"]
        .as_str()
        .unwrap()
        .contains(".dot"));
    let matches = request(
        &state,
        id,
        json!({"operation":"match","database":"fixture","strategy":"prefix","word":"hel"}),
    )
    .await;
    assert!(matches["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["word"] == "hello"));
    let databases = request(&state, id, json!({"operation":"databases"})).await;
    assert_eq!(databases["entries"][0]["name"], "fixture");
    let strategies = request(&state, id, json!({"operation":"strategies"})).await;
    assert!(strategies["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["name"] == "prefix"));
    for operation in ["info", "server", "help"] {
        let r = request(
            &state,
            id,
            json!({"operation":operation,"database":"fixture"}),
        )
        .await;
        assert!(!r["text"].as_str().unwrap().is_empty(), "{r}");
    }
    assert_eq!(
        request(&state, id, json!({"operation":"status"})).await["code"],
        210
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"define","word":"missing-test-word"})
        )
        .await["code"],
        552
    );
    assert_eq!(
        request(
            &state,
            id,
            json!({"operation":"define","database":"absent","word":"hello"})
        )
        .await["code"],
        550
    );
    assert_eq!(
        request(&state, id, json!({"operation":"quit"})).await["code"],
        221
    );
    state.remove_client(id).await;
    Ok(())
}

/// A `dictd` serving the two-word fixture, logging every command it executes (`-l command`)
/// to `dictd.log` in its own directory.
async fn logging_dictd() -> crate::helpers::E2EResult<(RealServer, tempfile::TempDir)> {
    let data = tempfile::tempdir()?;
    let source = data.path().join("source.txt");
    std::fs::write(&source, ":hello: A greeting.\n:help: Assistance.\n")?;
    let dictfmt = find_binary("dictfmt")
        .expect("dictfmt required: brew install dict / apt-get install dictfmt dictd");
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(dictfmt)
            .args([
                "-j",
                "--utf8",
                "--quiet",
                "--without-headword",
                "--without-time",
            ])
            .args(["-s", "Fixture dictionary"])
            .arg(data.path().join("fixture"))
            .stdin(Stdio::from(std::fs::File::open(source)?))
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(
        output.status.success(),
        "dictfmt: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let conf = format!(
        "access {{ allow * }}\ndatabase fixture {{ data \"{0}/fixture.dict\" index \"{0}/fixture.index\" }}\n",
        data.path().display()
    );
    let server = RealServer::builder(
        "dictd",
        InstallHint {
            brew: "dict",
            apt: "dictd dictfmt",
        },
    )
    .config_file("dictd.conf", &conf)
    .args([
        "--debug",
        "nodetach",
        "--listen-to",
        "127.0.0.1",
        "--port",
        "{port}",
        "--config",
        "{dir}/dictd.conf",
        "--pid-file",
        "{dir}/dictd.pid",
        "-L",
        "{dir}/dictd.log",
        "-l",
        "command",
    ])
    .start()
    .await?;
    Ok((server, data))
}

/// The commands dictd logged, in order.
fn commands(server: &RealServer) -> Vec<String> {
    std::fs::read_to_string(server.dir().join("dictd.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(":T: ").map(|(_, c)| c.to_string()))
        .collect()
}

async fn mocked_client(
    server: &RealServer,
    config: crate::helpers::mock_config::MockLlmConfig,
) -> crate::helpers::E2EResult<(
    crate::helpers::mock_ollama::MockOllamaServer,
    AppState,
    ClientId,
)> {
    let mock = crate::helpers::mock_ollama::MockOllamaServer::start(config).await?;
    let state = AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "dict".into(),
        remote_addr: Some(server.addr()),
        instruction: Some("Look words up in the fixture dictionary".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    Ok((mock, state, id))
}

/// Condition 4 of the client bar, from dictd's side: the mocked model chooses a word and a
/// database, dictd's own command log shows that DEFINE, and the model is shown the definition
/// dictd answered it with.
#[tokio::test]
async fn mocked_model_chooses_a_definition_dictd_logs() -> crate::helpers::E2EResult<()> {
    use crate::helpers::mock_builder::MockLlmBuilder;
    let (server, _fixture) = logging_dictd().await?;
    let config = MockLlmBuilder::new()
        .on_event("dict_connected")
        .respond_with_actions(json!([
            {"type":"dict_request","operation":"define","database":"fixture","word":"help"}
        ]))
        .expect_calls(1)
        .and()
        .on_event("dict_response")
        .and_event_data_contains("response", "Assistance")
        .respond_with_actions(json!([]))
        .expect_calls(1)
        .and()
        .build();
    let (mock, state, id) = mocked_client(&server, config).await?;
    mock.wait_for_expectations(30).await;
    mock.verify_calls().await?;
    let logged = commands(&server);
    assert!(
        logged.iter().any(|c| c == "DEFINE \"fixture\" \"help\""),
        "dictd never executed the model's DEFINE: {logged:?}"
    );
    state.remove_client(id).await;
    Ok(())
}

/// A model that answers every response with another request stops after `MAX_FOLLOWUPS`
/// requests, counted in dictd's own command log.
#[tokio::test]
async fn dictd_logs_a_bounded_follow_up_chain() -> crate::helpers::E2EResult<()> {
    use crate::helpers::mock_builder::MockLlmBuilder;
    let limit = netget::client::dict::wire::MAX_FOLLOWUPS as usize;
    let (server, _fixture) = logging_dictd().await?;
    let define =
        json!([{"type":"dict_request","operation":"define","database":"fixture","word":"hello"}]);
    let config = MockLlmBuilder::new()
        .on_event("dict_connected")
        .respond_with_actions(define.clone())
        .expect_calls(1)
        .and()
        .on_event("dict_response")
        .respond_with_actions(define)
        .expect_calls(limit)
        .and()
        .build();
    let (mock, state, id) = mocked_client(&server, config).await?;
    mock.wait_for_expectations(30).await;
    // An unbounded chain keeps going; give it the time to show.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let defines = commands(&server)
        .into_iter()
        .filter(|c| c == "DEFINE \"fixture\" \"hello\"")
        .count();
    assert_eq!(defines, limit, "dictd log: {:?}", commands(&server));
    assert_eq!(mock.call_count().await, limit + 1);
    mock.verify_calls().await?;
    state.remove_client(id).await;
    Ok(())
}
