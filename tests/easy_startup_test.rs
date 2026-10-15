//! Easy action execution preserves the regular startup contract. Local sockets only.
use netget::cli::easy_startup::{execute_easy_startup_action, EasyUnderlyingId};
use netget::state::AppState;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn easy_client_starts_through_normal_forms_and_preserves_handlers_and_memory() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let llm = netget::llm::OllamaClient::new("http://127.0.0.1:1");
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let action = json!({"type":"open_client", "protocol":"tcp", "remote_addr":listener.local_addr().unwrap().to_string(),
        "initial_memory":"retained", "event_handlers":[{"event_pattern":"*", "handler":{"type":"static", "actions":[]}}]});
    let result = execute_easy_startup_action(&action, &state, &llm)
        .await
        .unwrap();
    let EasyUnderlyingId::Client(id) = result else {
        panic!("expected client")
    };
    let (_peer, _) = listener.accept().await.unwrap();
    let client = state.get_client(id).await.unwrap();
    assert_eq!(client.memory, "retained");
    assert!(client.event_handler_config.is_some());
    state.remove_client(id).await;
}

#[tokio::test]
async fn easy_server_preserves_static_handlers_and_rejects_out_of_range_ports() {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".into());
    let llm = netget::llm::OllamaClient::new("http://127.0.0.1:1");
    state.set_llm_client(llm.clone()).await;
    let mut action = json!({"type":"open_server", "protocol":"http", "port":65536,
        "event_handlers":[{"event_pattern":"http_request", "handler":{"type":"static", "actions":[{"type":"send_http_response", "status":200, "body":"easy-static"}]}}]});
    assert!(execute_easy_startup_action(&action, &state, &llm)
        .await
        .is_err());
    assert!(state.get_all_servers().await.is_empty());
    action["port"] = json!(0);
    let EasyUnderlyingId::Server(id) = execute_easy_startup_action(&action, &state, &llm)
        .await
        .unwrap()
    else {
        panic!("expected server")
    };
    let addr = state.get_server(id).await.unwrap().local_addr.unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(String::from_utf8_lossy(&response).contains("easy-static"));
    state.remove_server(id).await;
}
