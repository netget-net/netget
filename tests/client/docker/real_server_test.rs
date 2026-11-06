#![cfg(unix)]
use super::common::*;
use serde_json::json;
use std::time::Duration;
use tokio::{
    net::{TcpListener, UnixStream},
    task::{JoinHandle, JoinSet},
};
async fn socket() -> String {
    if let Ok(path) = std::env::var("NETGET_DOCKER_SOCKET") {
        assert!(path.starts_with('/'));
        return path;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("docker")
            .args([
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("docker context deadline")
    .expect("required Docker CLI missing");
    assert!(
        output.status.success(),
        "docker context inspect: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().strip_prefix("unix://").expect("required independent daemon must expose Unix socket; set NETGET_DOCKER_SOCKET explicitly").to_owned()
}
struct Relay {
    task: JoinHandle<()>,
    address: String,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn relay(socket: String) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut peers = JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let (mut tcp,_)=accepted.unwrap();if peers.len()>=16 {drop(tcp);continue;}let path=socket.clone();peers.spawn(async move{let mut unix=UnixStream::connect(path).await.expect("required independent Docker daemon socket");let _=tokio::time::timeout(Duration::from_secs(35),tokio::io::copy_bidirectional(&mut tcp,&mut unix)).await;});},finished=peers.join_next(),if !peers.is_empty()=>{finished.unwrap().unwrap();}}
        }
    });
    Relay { task, address }
}
#[tokio::test]
async fn independent_engine_read_resources_over_native_unix_and_tcp_bridge() {
    let socket = socket().await;
    let relay = relay(socket.clone()).await;
    let state = state();
    for endpoint in [format!("unix://{socket}"), relay.address.clone()] {
        let id = connected_client(&state, endpoint).await;
        let (_, ready) = event(&state, id, "docker_connected", 0).await;
        assert_eq!(ready["api_version"], "1.47");
        let version = request(&state, id, json!({"operation":"version"})).await;
        assert!(!version["data"]["version"].as_str().unwrap().is_empty());
        assert!(
            netget::client::docker::api_version(version["data"]["api_version"].as_str().unwrap())
                .unwrap()
                >= netget::client::docker::api_version("1.47").unwrap()
        );
        let info = request(&state, id, json!({"operation":"info"})).await;
        assert_eq!(info["data"]["server_version"], version["data"]["version"]);
        assert!(info["data"]["ncpu"].as_u64().unwrap() > 0);
        assert!(info["data"]["memory_total"].as_u64().unwrap() > 0);
        assert!(request(&state,id,json!({"operation":"containers","all":true,"limit":3,"filters":{"label":["netget.protocol.readonly.fixture=nonexistent"]}})).await["data"].as_array().unwrap().is_empty());
        assert!(
            request(&state, id, json!({"operation":"images","digests":true})).await["data"]
                .is_array()
        );
        assert!(
            request(&state, id, json!({"operation":"networks"})).await["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["driver"] == "bridge")
        );
        let volumes=request(&state,id,json!({"operation":"volumes","filters":{"name":["netget-protocol-readonly-nonexistent"]}})).await;
        assert!(
            volumes["data"]["volumes"].is_null()
                || volumes["data"]["volumes"].as_array().unwrap().is_empty()
        );
        let after = latest(&state, id).await;
        send(
            &state,
            id,
            json!({"operation":"container","container_id":"netget-protocol-readonly-nonexistent"}),
        )
        .await;
        let error = event(&state, id, "docker_request_error", after).await.1;
        assert_eq!(error["status"], 404);
        assert!(error["error"]
            .as_str()
            .unwrap()
            .contains("No such container"));
        let ping = request(&state, id, json!({"operation":"ping"})).await;
        assert_eq!(ping["data"]["api_version"], ready["daemon"]["api_version"]);
        state.remove_client(id).await;
    }
}
#[tokio::test]
async fn advertised_static_script_and_action_examples_read_real_daemon() {
    use netget::llm::actions::protocol_trait::Protocol;
    let socket = socket().await;
    let relay = relay(socket).await;
    let state = state();
    let protocol = netget::client::docker::DockerClientProtocol::new();
    let examples = protocol.get_startup_examples();
    examples.validate("Docker").unwrap();
    for example in [examples.static_mode, examples.script_mode] {
        let id = client(
            &state,
            relay.address.clone(),
            json!({}),
            serde_json::from_value(example["event_handlers"].clone()).unwrap(),
        )
        .await;
        let (_, result) = event(&state, id, "docker_response", 0).await;
        assert_eq!(result["operation"], "containers");
        assert!(result["data"].is_array());
        for action in protocol
            .get_async_actions(&state)
            .into_iter()
            .filter(|a| a.name == "docker_request")
        {
            assert!(request(&state, id, action.example).await["data"].is_array());
        }
        state.remove_client(id).await;
    }
}
#[tokio::test]
async fn model_chooses_real_daemon_read_and_shared_memory_reaches_followup(
) -> crate::helpers::E2EResult<()> {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let socket = socket().await;
    let relay = relay(socket).await;
    let config=MockLlmBuilder::new().on_event("docker_connected").respond_with_actions(json!([{ "type":"set_memory","value":"model selected real Docker version"},{"type":"docker_request","operation":"version"}])).expect_calls(1).and().on_event("docker_response").and_prompt_containing("model selected real Docker version").respond_with_actions(json!([])).expect_calls(1).and().build();
    let mock = MockOllamaServer::start(config).await?;
    let state = netget::state::AppState::new_with_options(false, mock.base_url());
    state.set_ollama_model(Some("mock".into())).await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let id = netget::cli::management::ClientForm {
        protocol: "docker".into(),
        remote_addr: Some(relay.address.clone()),
        instruction: Some("Read daemon version once and retain shared memory".into()),
        ..Default::default()
    }
    .create(&state, netget::llm::OllamaClient::new(mock.base_url()), tx)
    .await?;
    let (_, result) = event(&state, id, "docker_response", 0).await;
    assert_eq!(result["operation"], "version");
    // The daemon's own answer, read by Docker's own CLI from the same engine: the version the
    // client reports is the one the engine gave to the request the model chose.
    let cli = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("docker")
            .args([
                "version",
                "--format",
                "{{.Server.Version}}|{{.Server.APIVersion}}",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("docker version deadline")
    .expect("required Docker CLI missing");
    assert!(
        cli.status.success(),
        "docker version: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli = String::from_utf8(cli.stdout)?;
    let (version, api) = cli.trim().split_once('|').unwrap();
    assert_eq!(result["data"]["version"], version);
    assert_eq!(result["data"]["api_version"], api);
    mock.wait_for_expectations(30).await;
    assert_eq!(
        state.get_memory_for_client(id).await.as_deref(),
        Some("model selected real Docker version")
    );
    assert_eq!(mock.call_count().await, 2);
    mock.verify_calls().await?;
    state.remove_client(id).await;
    Ok(())
}
