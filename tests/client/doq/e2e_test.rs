use super::support::*;
use netget::client::doq::exchange;
use netget::state::{client_handles::ClientSendOutcome, AccessLogOwner, ClientStatus};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn injected_queries_response_events_followups_and_disconnect() {
    let fixture = Fixture::standard().await;
    let client=fixture.client(vec![
        json!({"event_pattern":"doq_response_received","handler":{"type":"script","language":"python","code":"import json,sys\nevent=json.load(sys.stdin)['event']\ndef respond(actions):\n    print(json.dumps({'actions':actions}))\nif event['query_type']=='A':\n    respond([{'type':'send_dns_query','domain':'followup.example','query_type':'AAAA'}])\nelse:\n    respond([])"}}),empty_handler()
    ],json!({})).await;
    let outcome = fixture
        .state
        .send_to_client(
            client,
            json!({"type":"send_dns_query","domain":"initial.example","query_type":"A"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ClientSendOutcome::Executed { .. }));
    wait_log(
        &fixture.state,
        AccessLogOwner::Client(client.as_u32()),
        "2001:db8::19",
    )
    .await;
    wait_log(
        &fixture.state,
        AccessLogOwner::Server(fixture.server.as_u32()),
        "followup.example",
    )
    .await;
    let outcome = fixture
        .state
        .send_to_client(client, json!({"type":"disconnect"}), Duration::from_secs(3))
        .await
        .unwrap();
    assert!(matches!(outcome, ClientSendOutcome::Disconnected));
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.state.has_client_handle(client).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture.state.get_client(client).await.unwrap().status,
        ClientStatus::Disconnected
    );
    fixture.close().await;
}

#[tokio::test]
async fn followup_depth_is_bounded() {
    let fixture = Fixture::standard().await;
    let client=fixture.client(vec![json!({"event_pattern":"*","handler":{"type":"static","actions":[{"type":"send_dns_query","domain":"bounded.example","query_type":"A"}]}})],json!({})).await;
    let owner = AccessLogOwner::Server(fixture.server.as_u32());
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if fixture
                .state
                .list_access_logs_for(Some(owner), None)
                .await
                .len()
                >= 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fixture
            .state
            .list_access_logs_for(Some(owner), None)
            .await
            .len(),
        4,
        "one initial query and three followups"
    );
    fixture.state.remove_client(client).await;
    fixture.close().await;
}

#[tokio::test]
async fn untrusted_and_wrong_hostname_fail_before_client_is_connected() {
    use netget::llm::actions::{client_trait::Client, protocol_trait::Protocol};
    use netget::protocol::{ConnectContext, StartupParams};
    let fixture = Fixture::standard().await;
    for params in [
        json!({"server_name":"localhost","handshake_timeout_secs":2}),
        json!({"server_name":"wrong.example","ca_cert_path":fixture.dir.path().join("cert.pem"),"handshake_timeout_secs":2}),
    ] {
        let p = netget::client::doq::actions::DoqClientProtocol::new();
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let ctx = ConnectContext::with_params(
            fixture.addr.to_string(),
            netget::llm::OllamaClient::new("http://127.0.0.1:1"),
            std::sync::Arc::new(fixture.state.clone()),
            tx,
            netget::state::ClientId::new(9999),
            StartupParams::new(params, p.get_startup_parameters()).unwrap(),
        );
        assert!(p.connect(ctx).await.is_err());
    }
    fixture.close().await;
}

#[tokio::test]
async fn timeout_sends_cancellation_and_remove_releases_connection() {
    let fixture = Fixture::new(
        json!({"exchange_timeout_secs":3}),
        Some(json!({"type":"manual","timeout_secs":30})),
    )
    .await;
    let client = fixture
        .client(vec![empty_handler()], json!({"exchange_timeout_secs":1}))
        .await;
    let outcome = fixture
        .state
        .send_to_client(
            client,
            json!({"type":"send_dns_query","domain":"timeout.example","query_type":"A"}),
            Duration::from_secs(3),
        )
        .await;
    assert!(outcome.is_err());
    wait_log(
        &fixture.state,
        AccessLogOwner::Client(client.as_u32()),
        "doq_query_error",
    )
    .await;
    fixture.state.remove_client(client).await;
    assert!(!fixture.state.has_client_handle(client).await);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let s = fixture.state.get_server(fixture.server).await.unwrap();
            if s.connections
                .values()
                .all(|c| c.status != netget::state::server::ConnectionStatus::Active)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn client_rejects_mismatched_question_opcode_nonzero_id_and_missing_fin() {
    // A QUIC transport fixture, not independent DNS interoperability evidence.
    for mode in 0..4 {
        let fixture = Fixture::standard().await;
        let tls = netget::server::tls_cert_manager::load_tls_config_from_files(
            fixture.dir.path().join("cert.pem").to_str().unwrap(),
            fixture.dir.path().join("key.pem").to_str().unwrap(),
        )
        .unwrap();
        let mut tls = (*tls).clone();
        tls.alpn_protocols = vec![b"doq".to_vec()];
        let config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let c = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = c.accept_bi().await.unwrap();
            let bytes = recv.read_to_end(65537).await.unwrap();
            let mut response =
                netget::server::doq::wire::decode(&bytes, hickory_proto::op::MessageType::Query)
                    .unwrap();
            response.metadata.message_type = hickory_proto::op::MessageType::Response;
            if mode == 0 {
                response.queries[0]
                    .set_name(hickory_proto::rr::Name::from_ascii("different.example").unwrap());
            }
            if mode == 3 {
                response.metadata.op_code = hickory_proto::op::OpCode::Status;
            }
            let mut frame = netget::server::doq::wire::encode(&response).unwrap();
            if mode == 1 {
                frame[3] = 7;
            }
            send.write_all(&frame).await.unwrap();
            if mode != 2 {
                send.finish().unwrap();
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), c.closed()).await;
        });
        let endpoint = fixture.endpoint(b"doq");
        let c = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let result = exchange(&c, &query("asked.example", "A"), Duration::from_millis(200)).await;
        assert!(result.is_err(), "mode {mode} accepted bad response");
        c.close(0u32.into(), b"done");
        peer.await.unwrap();
        fixture.close().await;
    }
}

#[tokio::test]
async fn model_response_handler_receives_memory_set_on_connect() {
    use crate::helpers::{mock_builder::MockLlmBuilder, mock_ollama::MockOllamaServer};
    let mock = MockOllamaServer::start(
        MockLlmBuilder::new()
            .on_event("doq_connected")
            .respond_with_actions(json!([
                {"type":"set_memory","value":"doq-memory-marker-681"},
                {"type":"send_dns_query","domain":"remember.example","query_type":"A"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("doq_response_received")
            .and_prompt_containing("doq-memory-marker-681")
            .respond_with_actions(json!([{"type":"disconnect"}]))
            .expect_calls(1)
            .build(),
    )
    .await
    .unwrap();
    let fixture = Fixture::standard().await;
    let llm = netget::llm::OllamaClient::new(mock.base_url());
    fixture.state.set_llm_client(llm.clone()).await;
    fixture
        .state
        .set_ollama_model(Some("test-model".into()))
        .await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let client = netget::cli::management::ClientForm {
        protocol: "doq".into(),
        remote_addr: Some(fixture.addr.to_string()),
        instruction: Some("Remember state across DNS queries".into()),
        startup_params: Some(
            json!({"server_name":"localhost","ca_cert_path":fixture.dir.path().join("cert.pem")}),
        ),
        ..Default::default()
    }
    .create(&fixture.state, llm, tx)
    .await
    .unwrap();
    mock.wait_for_expectations(8).await;
    mock.verify_calls().await.unwrap();
    assert_eq!(
        fixture.state.get_memory_for_client(client).await.as_deref(),
        Some("doq-memory-marker-681")
    );
    fixture.state.remove_client(client).await;
    fixture.close().await;
}

#[tokio::test]
async fn connect_returns_the_owned_local_udp_address() {
    use netget::llm::actions::{client_trait::Client, protocol_trait::Protocol};
    use netget::protocol::{ConnectContext, StartupParams};
    let fixture = Fixture::standard().await;
    let id = fixture
        .state
        .add_client(netget::state::client::ClientInstance::new(
            netget::state::ClientId::new(0),
            fixture.addr.to_string(),
            "DoQ".into(),
            String::new(),
        ))
        .await;
    let protocol = netget::client::doq::actions::DoqClientProtocol::new();
    let params = StartupParams::new(
        json!({"server_name":"localhost","ca_cert_path":fixture.dir.path().join("cert.pem")}),
        protocol.get_startup_parameters(),
    )
    .unwrap();
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let local = protocol
        .connect(ConnectContext::with_params(
            fixture.addr.to_string(),
            netget::llm::OllamaClient::new("http://127.0.0.1:1"),
            std::sync::Arc::new(fixture.state.clone()),
            tx,
            id,
            params,
        ))
        .await
        .unwrap();
    assert_ne!(local.port(), fixture.addr.port());
    assert_ne!(local.port(), 0);
    assert!(
        std::net::UdpSocket::bind(local).is_err(),
        "the returned address must be owned by the live client"
    );
    fixture.state.remove_client(id).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if std::net::UdpSocket::bind(local).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.close().await;
}
